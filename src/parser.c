typedef struct Parser
{
    Compiler *compiler;
    Lexer *lexer;
    Ast *ast;
    size_t pos;
} Parser;

static inline bool parser_is_at_end(Parser *p, size_t offset)
{
    return (p->pos + offset) >= p->lexer->tokens.len;
}

static inline Token *parser_peek(Parser *p, size_t offset)
{
    if (p->pos + offset >= p->lexer->tokens.len)
    {
        return &p->lexer->tokens.ptr[p->pos];
    }
    return &p->lexer->tokens.ptr[p->pos + offset];
}

static inline Token *parser_next(Parser *p, size_t count)
{
    if (!parser_is_at_end(p, 0)) p->pos += count;
    return &p->lexer->tokens.ptr[p->pos - count];
}

static inline Token *parser_consume(Parser *p, TokenKind tok_type)
{
    if (parser_is_at_end(p, 0))
    {
        Token *tok = &p->lexer->tokens.ptr[p->lexer->tokens.len - 1];
        compile_error(
            p->compiler,
            tok->loc,
            "expected: '%s', reached end of input",
            token_strings[tok_type]);
        return NULL;
    }

    Token *tok = parser_peek(p, 0);
    if (tok->type != tok_type)
    {
        Location loc = tok->loc;
        tok = parser_peek(p, -1);
        compile_error(
            p->compiler,
            loc,
            "expected: '%s' after '%.*s'",
            token_strings[tok_type],
            tok->loc.length,
            tok->loc.buf);
        return NULL;
    }

    return parser_next(p, 1);
}

static bool parse_expr(Parser *p, Ast *ast, bool parsing_type);

static bool parse_primary_expr(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_IDENT:
    case TOKEN_TRUE:
    case TOKEN_FALSE:
    case TOKEN_VOID:
    case TOKEN_NULL:
    case TOKEN_BOOL:
    case TOKEN_STRING_LIT:
    case TOKEN_CSTRING_LIT:
    case TOKEN_CHAR_LIT:
    case TOKEN_STRING:
    case TOKEN_ANY:
    case TOKEN_U8:
    case TOKEN_U16:
    case TOKEN_U32:
    case TOKEN_U64:
    case TOKEN_I8:
    case TOKEN_I16:
    case TOKEN_I32:
    case TOKEN_I64:
    case TOKEN_UINT:
    case TOKEN_INT:
    case TOKEN_FLOAT:
    case TOKEN_CHAR:
    case TOKEN_DOUBLE:
    case TOKEN_INT_LIT:
    case TOKEN_FLOAT_LIT: {
        parser_next(p, 1);
        ast->type = AST_PRIMARY;
        ast->primary.tok = tok;
        break;
    }

    case TOKEN_LPAREN: {
        parser_next(p, 1);

        if (!parse_expr(p, ast, parsing_type)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        break;
    }

    case TOKEN_ELLIPSIS: {
        parser_next(p, 1);

        ast->type = AST_VARIADIC_ARG;
        ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(ast->expr, 0, sizeof(*ast->expr));
        if (!parse_expr(p, ast->expr, parsing_type)) res = false;

        break;
    }

    default: {
        parser_next(p, 1);
        res = false;
        compile_error(
            p->compiler,
            tok->loc,
            "unexpected token: '%.*s'",
            tok->loc.length,
            tok->loc.buf);
        break;
    }
    }

    return res;
}

static bool parse_proc_call(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_primary_expr(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LPAREN && !parser_is_at_end(p, 0))
    {
        // Proc call
        Ast expr = *ast;

        ast->type = AST_PROC_CALL;
        memset(&ast->proc_call, 0, sizeof(ast->proc_call));

        ast->proc_call.expr =
            bump_alloc(&p->compiler->bump, sizeof(*ast->proc_call.expr));
        *ast->proc_call.expr = expr;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
               !parser_is_at_end(p, 0))
        {
            Ast param = {0};
            if (parse_expr(p, &param, parsing_type))
                array_push(&ast->proc_call.params, param);
            else
                res = false;

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;
    }

    return res;
}

static bool parse_array_type(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    switch (parser_peek(p, 0)->type)
    {
    case TOKEN_LBRACK: {
        parser_next(p, 1);

        if (parser_peek(p, 0)->type == TOKEN_RBRACK)
        {
            ast->type = AST_SLICE_TYPE;
        }
        else if (parser_peek(p, 0)->type == TOKEN_DYN)
        {
            parser_next(p, 1);
            ast->type = AST_DYNAMIC_ARRAY_TYPE;
        }
        else
        {
            ast->type = AST_ARRAY_TYPE;

            Ast size = {.loc = parser_peek(p, 0)->loc};
            if (parse_expr(p, &size, false))
            {
                Location last_loc = parser_peek(p, -1)->loc;
                size.loc.length = last_loc.buf + last_loc.length - size.loc.buf;

                ast->array_type.size = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->array_type.size));
                *ast->array_type.size = size;
            }
            else
            {
                res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RBRACK)) res = false;

        if (ast->array_type.size && parser_peek(p, 0)->type == TOKEN_ARROW)
        {
            ast->type = AST_VECTOR_TYPE;
            parser_next(p, 1);
        }

        Ast sub = {0};
        if (parse_expr(p, &sub, true))
        {
            ast->array_type.sub =
                bump_alloc(&p->compiler->bump, sizeof(*ast->array_type.sub));
            *ast->array_type.sub = sub;
        }
        else
        {
            res = false;
        }

        break;
    }
    default: {
        if (!parse_proc_call(p, ast, parsing_type)) res = false;
        break;
    }
    }

    return res;
}

static bool parse_dereference(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_array_type(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_DOT &&
           parser_peek(p, 1)->type == TOKEN_ASTERISK && !parser_is_at_end(p, 1))
    {
        parser_next(p, 2);

        Ast expr = *ast;
        memset(&ast->unop, 0, sizeof(ast->unop));

        ast->type = AST_UNARY_EXPR;
        ast->unop.type = UNOP_DEREFERENCE;

        ast->unop.sub = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *ast->unop.sub = expr;
    }

    return res;
}

static bool parse_subscript(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_dereference(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LBRACK && !parser_is_at_end(p, 0))
    {
        Ast expr = *ast;

        parser_next(p, 1);

        if (parser_peek(p, 0)->type == TOKEN_COLON)
        {
            parser_next(p, 1);

            if (!parser_consume(p, TOKEN_RBRACK)) res = false;

            if (res)
            {
                ast->type = AST_SUBSCRIPT_SLICE;

                ast->subscript_slice.left = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.left));
                *ast->subscript_slice.left = expr;

                ast->subscript_slice.lower = NULL;
                ast->subscript_slice.upper = NULL;
            }

            continue;
        }

        Ast lower = {0};
        if (!parse_expr(p, &lower, parsing_type)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_COLON)
        {
            parser_next(p, 1);

            // Subscript slice
            Ast upper = {0};
            if (!parse_expr(p, &upper, parsing_type)) res = false;

            if (!parser_consume(p, TOKEN_RBRACK)) res = false;

            if (res)
            {
                ast->type = AST_SUBSCRIPT_SLICE;

                ast->subscript_slice.left = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.left));
                *ast->subscript_slice.left = expr;

                ast->subscript_slice.lower = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript_slice.lower));
                *ast->subscript_slice.lower = lower;

                ast->subscript_slice.upper = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript_slice.upper));
                *ast->subscript_slice.upper = upper;
            }
        }
        else
        {
            // Regular subscript
            if (!parser_consume(p, TOKEN_RBRACK)) res = false;

            if (res)
            {
                ast->type = AST_SUBSCRIPT;
                ast->subscript.left = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.left));
                *ast->subscript.left = expr;
                ast->subscript.right = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.right));
                *ast->subscript.right = lower;
            }
        }
    }

    return res;
}

static bool parse_access(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_subscript(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_DOT && !parser_is_at_end(p, 0))
    {
        Ast expr = *ast;
        memset(&ast->access, 0, sizeof(ast->access));

        parser_next(p, 1);

        ast->type = AST_ACCESS;
        ast->access.left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *ast->access.left = expr;

        Ast right = {0};
        right.loc = parser_peek(p, 0)->loc;
        if (parse_subscript(p, &right, parsing_type))
        {
            Location last_loc = parser_peek(p, -1)->loc;
            right.loc.length = last_loc.buf + last_loc.length - right.loc.buf;

            ast->access.right =
                bump_alloc(&p->compiler->bump, sizeof(*ast->access.right));
            *ast->access.right = right;
        }
        else
        {
            res = false;
        }
    }

    return res;
}

static bool parse_intrinsic_call(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (parser_peek(p, 0)->type == TOKEN_IDENT &&
        parser_peek(p, 1)->type == TOKEN_LPAREN && !parser_is_at_end(p, 1))
    {
        // Intrinsic call
        ast->type = AST_INTRINSIC_CALL;
        String intrin_name = parser_peek(p, 0)->str;

        if (string_equals(intrin_name, STR("size_of")))
        {
            ast->intrinsic_call.type = INTRINSIC_SIZE_OF;
        }
        else if (string_equals(intrin_name, STR("align_of")))
        {
            ast->intrinsic_call.type = INTRINSIC_ALIGN_OF;
        }
        else if (string_equals(intrin_name, STR("type_info_of")))
        {
            ast->intrinsic_call.type = INTRINSIC_TYPE_INFO_OF;
        }
        else if (string_equals(intrin_name, STR("alloc")))
        {
            ast->intrinsic_call.type = INTRINSIC_ALLOC;
        }
        else if (string_equals(intrin_name, STR("realloc")))
        {
            ast->intrinsic_call.type = INTRINSIC_REALLOC;
        }
        else if (string_equals(intrin_name, STR("dealloc")))
        {
            ast->intrinsic_call.type = INTRINSIC_DEALLOC;
        }
        else if (string_equals(intrin_name, STR("new")))
        {
            ast->intrinsic_call.type = INTRINSIC_NEW;
        }
        else if (string_equals(intrin_name, STR("make")))
        {
            ast->intrinsic_call.type = INTRINSIC_MAKE;
        }
        else if (string_equals(intrin_name, STR("delete")))
        {
            ast->intrinsic_call.type = INTRINSIC_DELETE;
        }
        else if (string_equals(intrin_name, STR("append")))
        {
            ast->intrinsic_call.type = INTRINSIC_APPEND;
        }
        else
        {
            return parse_access(p, ast, parsing_type);
        }

        if (!parser_consume(p, TOKEN_IDENT))
        {
            res = false;
            return res;
        }

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            return res;
        }

        while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
               !parser_is_at_end(p, 0))
        {
            Ast param = {0};
            if (parse_expr(p, &param, parsing_type))
                array_push(&ast->intrinsic_call.params, param);
            else
                res = false;

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;
    }
    else
    {
        return parse_access(p, ast, parsing_type);
    }

    return res;
}

static bool parse_compound_literal(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_intrinsic_call(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    if (!parsing_type && parser_peek(p, 0)->type == TOKEN_LCURLY)
    {
        Ast *type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *type_expr = *ast;

        parser_next(p, 1);

        ast->type = AST_COMPOUND_LIT;
        memset(&ast->compound, 0, sizeof(ast->compound));
        ast->compound.type_expr = type_expr;

        if (parser_peek(p, 0)->type == TOKEN_IDENT &&
            parser_peek(p, 1)->type == TOKEN_ASSIGN)
        {
            // Named struct initializer
            ast->compound.is_named = true;

            while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                   !parser_is_at_end(p, 0))
            {
                Token *ident = parser_consume(p, TOKEN_IDENT);
                if (!ident)
                {
                    res = false;
                    break;
                }

                String name = ident->str;

                if (!parser_consume(p, TOKEN_ASSIGN))
                {
                    res = false;
                    break;
                }

                Ast value = {0};
                if (parse_expr(p, &value, parsing_type))
                {
                    array_push(&ast->compound.names, name);
                    array_push(&ast->compound.values, value);
                }
                else
                {
                    res = false;
                }

                if (parser_peek(p, 0)->type == TOKEN_RCURLY) break;

                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }
        else
        {
            // Nameless initializer
            while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                   !parser_is_at_end(p, 0))
            {
                Ast value = {0};
                if (parse_expr(p, &value, parsing_type))
                {
                    array_push(&ast->compound.values, value);
                }
                else
                {
                    res = false;
                }

                if (parser_peek(p, 0)->type == TOKEN_RCURLY) break;

                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;
    }

    return res;
}

static bool parse_unary_expr(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);

    switch (tok->type)
    {
    case TOKEN_MINUS:
    case TOKEN_NOT:
    case TOKEN_ASTERISK:
    case TOKEN_AMPERSAND: {
        parser_next(p, 1);

        ast->type = AST_UNARY_EXPR;
        switch (tok->type)
        {
        case TOKEN_ASTERISK: ast->type = AST_POINTER_TYPE; break;
        case TOKEN_AMPERSAND: ast->unop.type = UNOP_ADDRESS; break;
        case TOKEN_MINUS: ast->unop.type = UNOP_NEG; break;
        case TOKEN_NOT: ast->unop.type = UNOP_NOT; break;

        default: assert(0); break;
        }

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_unary_expr(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        switch (tok->type)
        {
        case TOKEN_ASTERISK: {
            ast->expr = right;
            break;
        }

        case TOKEN_AMPERSAND:
        case TOKEN_MINUS:
        case TOKEN_NOT: {
            ast->unop.sub = right;
            break;
        }

        default: assert(0); break;
        }

        break;
    }

    case TOKEN_UNION:
    case TOKEN_STRUCT: {
        ast->type = AST_STRUCT;
        parser_next(p, 1);

        if (tok->type == TOKEN_UNION)
        {
            ast->structure.is_union = true;
        }

        if (!parser_consume(p, TOKEN_LCURLY))
        {
            res = false;
            break;
        }

        memset(&ast->structure.fields, 0, sizeof(ast->structure.fields));

        while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
               !parser_is_at_end(p, 0))
        {
            Ast field = {0};
            field.loc = parser_peek(p, 0)->loc;
            field.type = AST_STRUCT_FIELD;

            if (parser_peek(p, 0)->type == TOKEN_USING)
            {
                parser_next(p, 1);
                field.flags |= AST_FLAG_USING;
            }

            Token *name_tok = parser_consume(p, TOKEN_IDENT);
            if (!name_tok)
                res = false;
            else
                field.struct_field.name = name_tok->str;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            Ast type = {0};
            if (parse_expr(p, &type, true))
            {
                field.struct_field.type_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                *field.struct_field.type_expr = type;
            }
            else
            {
                res = false;
            }

            Location last_loc = parser_peek(p, -1)->loc;
            field.loc.length = last_loc.buf + last_loc.length - field.loc.buf;

            if (res)
            {
                field.struct_field.index = ast->structure.fields.len;
                array_push(&ast->structure.fields, field);
            }

            if (parser_peek(p, 0)->type == TOKEN_RCURLY) break;

            if (!parser_consume(p, TOKEN_COMMA)) res = false;
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }

    case TOKEN_ENUM: {
        ast->type = AST_ENUM;
        parser_next(p, 1);

        ast->enumeration.type_expr =
            bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->enumeration.type_expr, true)) res = false;

        if (!parser_consume(p, TOKEN_LCURLY))
        {
            res = false;
            break;
        }

        memset(&ast->enumeration.fields, 0, sizeof(ast->enumeration.fields));

        while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
               !parser_is_at_end(p, 0))
        {
            Ast field = {0};
            field.loc = parser_peek(p, 0)->loc;
            field.type = AST_ENUM_FIELD;

            Token *name_tok = parser_consume(p, TOKEN_IDENT);
            if (!name_tok)
                res = false;
            else
                field.enum_field.name = name_tok->str;

            if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

            Ast type = {0};
            if (parse_expr(p, &type, false))
            {
                field.enum_field.value_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                *field.enum_field.value_expr = type;
            }
            else
            {
                res = false;
            }

            Location last_loc = parser_peek(p, -1)->loc;
            field.loc.length = last_loc.buf + last_loc.length - field.loc.buf;

            if (res)
            {
                array_push(&ast->enumeration.fields, field);
            }

            if (parser_peek(p, 0)->type == TOKEN_RCURLY) break;

            if (!parser_consume(p, TOKEN_COMMA)) res = false;
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }

    case TOKEN_CAST: {
        ast->type = AST_CAST;
        parser_next(p, 1);

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        Ast type = {0};
        if (parse_expr(p, &type, parsing_type))
        {
            ast->cast.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->cast.type_expr = type;
        }
        else
        {
            res = false;
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        Ast value = {0};
        value.loc = parser_peek(p, 0)->loc;
        if (parse_unary_expr(p, &value, parsing_type))
        {
            ast->cast.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->cast.value_expr = value;
        }
        else
        {
            res = false;
        }
        Location last_loc = parser_peek(p, -1)->loc;
        value.loc.length = last_loc.buf + last_loc.length - value.loc.buf;

        break;
    }

    case TOKEN_EXTERN: {
        parser_next(p, 1);

        if (parser_peek(p, 0)->type == TOKEN_FN)
        {
            ast->flags |= AST_FLAG_EXTERN;
            goto parse_fn_type;
        }
        else
        {
            res = false;
        }

        break;
    }

    case TOKEN_FN: {
    parse_fn_type:
        parser_next(p, 1);

        ast->type = AST_PROC_TYPE;

        if (!parser_consume(p, TOKEN_ASTERISK)) res = false;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
               !parser_is_at_end(p, 0))
        {
            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->flags |= AST_FLAG_FUNCTION_IS_C_VARARGS;
                break;
            }

            Ast param = {0};
            param.type = AST_PROC_PARAM;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (ident_tok)
            {
                param.loc = ident_tok->loc;
                param.proc_param.name = ident_tok->str;
            }
            else
            {
                res = false;
                break;
            }

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr, parsing_type))
                res = false;

            array_push(&ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->proc.return_type = NULL;
        if (parser_peek(p, 0)->type == TOKEN_ARROW)
        {
            parser_next(p, 1);

            if (parser_peek(p, 0)->type == TOKEN_LPAREN)
            {
                // Init return type
                ast->proc.return_type =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                memset(ast->proc.return_type, 0, sizeof(Ast));
                ast->proc.return_type->type = AST_TUPLE_TYPE;
                ast->proc.return_type->loc = parser_peek(p, 0)->loc;

                parser_next(p, 1);

                ArrayOfAst return_types = {0};

                while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                       !parser_is_at_end(p, 0))
                {
                    if (return_types.len > 0)
                    {
                        if (!parser_consume(p, TOKEN_COMMA))
                        {
                            res = false;
                            break;
                        }
                    }

                    Ast return_type = {0};
                    if (!parse_expr(p, &return_type, true))
                    {
                        res = false;
                        break;
                    }
                    array_push(&return_types, return_type);
                }

                if (!parser_consume(p, TOKEN_RPAREN))
                {
                    res = false;
                    break;
                }

                ast->proc.return_type->tuple_type.fields = return_types;

                Location last_loc = parser_peek(p, -1)->loc;
                ast->proc.return_type->loc.length =
                    last_loc.buf + last_loc.length -
                    ast->proc.return_type->loc.buf;
            }
            else
            {
                ast->proc.return_type =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->proc.return_type, true))
                {
                    res = false;
                    break;
                }
            }
        }

        break;
    }

    default: {
        res = parse_compound_literal(p, ast, parsing_type);
        break;
    }
    }

    return res;
}

static bool parse_multiplication(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_unary_expr(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_ASTERISK) ||
            (parser_peek(p, 0)->type == TOKEN_SLASH) ||
            (parser_peek(p, 0)->type == TOKEN_PERCENT)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_unary_expr(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_ASTERISK: ast->binop.type = BINOP_MUL; break;
        case TOKEN_SLASH: ast->binop.type = BINOP_DIV; break;
        case TOKEN_PERCENT: ast->binop.type = BINOP_MOD; break;
        default: break;
        }
    }

    return res;
}

static bool parse_addition(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_multiplication(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_PLUS) ||
            (parser_peek(p, 0)->type == TOKEN_MINUS)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_multiplication(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_PLUS: ast->binop.type = BINOP_ADD; break;
        case TOKEN_MINUS: ast->binop.type = BINOP_SUB; break;
        default: break;
        }
    }

    return res;
}

static bool parse_bitshift(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_addition(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_RSHIFT) ||
            (parser_peek(p, 0)->type == TOKEN_LSHIFT)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_addition(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_RSHIFT: ast->binop.type = BINOP_RSHIFT; break;
        case TOKEN_LSHIFT: ast->binop.type = BINOP_LSHIFT; break;
        default: break;
        }
    }

    return res;
}

static bool parse_bitwise(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_bitshift(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_PIPE) ||
            (parser_peek(p, 0)->type == TOKEN_AMPERSAND) ||
            (parser_peek(p, 0)->type == TOKEN_HAT)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_bitshift(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_PIPE: ast->binop.type = BINOP_BITOR; break;
        case TOKEN_AMPERSAND: ast->binop.type = BINOP_BITAND; break;
        case TOKEN_HAT: ast->binop.type = BINOP_BITXOR; break;
        default: break;
        }
    }

    return res;
}

static bool parse_comparison(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_bitwise(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_EQUAL) ||
            (parser_peek(p, 0)->type == TOKEN_NOTEQ) ||
            (parser_peek(p, 0)->type == TOKEN_LESS) ||
            (parser_peek(p, 0)->type == TOKEN_LESSEQ) ||
            (parser_peek(p, 0)->type == TOKEN_GREATER) ||
            (parser_peek(p, 0)->type == TOKEN_GREATEREQ)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_bitwise(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_EQUAL: ast->binop.type = BINOP_EQ; break;
        case TOKEN_NOTEQ: ast->binop.type = BINOP_NOTEQ; break;
        case TOKEN_LESS: ast->binop.type = BINOP_LESS; break;
        case TOKEN_LESSEQ: ast->binop.type = BINOP_LESSEQ; break;
        case TOKEN_GREATER: ast->binop.type = BINOP_GREATER; break;
        case TOKEN_GREATEREQ: ast->binop.type = BINOP_GREATEREQ; break;
        default: break;
        }
    }

    return res;
}

static bool parse_logical(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_comparison(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_AND) ||
            (parser_peek(p, 0)->type == TOKEN_OR)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_comparison(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_AND: ast->binop.type = BINOP_AND; break;
        case TOKEN_OR: ast->binop.type = BINOP_OR; break;
        default: break;
        }
    }

    return res;
}

static bool parse_op_assign(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_logical(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (((parser_peek(p, 0)->type == TOKEN_PLUSEQ) ||
            (parser_peek(p, 0)->type == TOKEN_MINUSEQ) ||
            (parser_peek(p, 0)->type == TOKEN_MULEQ) ||
            (parser_peek(p, 0)->type == TOKEN_DIVEQ) ||
            (parser_peek(p, 0)->type == TOKEN_MODEQ) ||
            (parser_peek(p, 0)->type == TOKEN_ANDEQ) ||
            (parser_peek(p, 0)->type == TOKEN_OREQ) ||
            (parser_peek(p, 0)->type == TOKEN_XOREQ) ||
            (parser_peek(p, 0)->type == TOKEN_LSHIFTEQ) ||
            (parser_peek(p, 0)->type == TOKEN_RSHIFTEQ)) &&
           !parser_is_at_end(p, 0))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_logical(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        ast->binop.assign = true;
        switch (op_tok->type)
        {
        case TOKEN_PLUSEQ: ast->binop.type = BINOP_ADD; break;
        case TOKEN_MINUSEQ: ast->binop.type = BINOP_SUB; break;
        case TOKEN_MULEQ: ast->binop.type = BINOP_MUL; break;
        case TOKEN_DIVEQ: ast->binop.type = BINOP_DIV; break;
        case TOKEN_MODEQ: ast->binop.type = BINOP_MOD; break;
        case TOKEN_ANDEQ: ast->binop.type = BINOP_BITAND; break;
        case TOKEN_OREQ: ast->binop.type = BINOP_BITOR; break;
        case TOKEN_XOREQ: ast->binop.type = BINOP_BITXOR; break;
        case TOKEN_LSHIFTEQ: ast->binop.type = BINOP_LSHIFT; break;
        case TOKEN_RSHIFTEQ: ast->binop.type = BINOP_RSHIFT; break;
        default: break;
        }
    }

    return res;
}

static bool parse_expr(Parser *p, Ast *ast, bool parsing_type)
{
    assert(!parser_is_at_end(p, 0));
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = parse_op_assign(p, ast, parsing_type);
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;
    return res;
}

static bool parse_stmt(Parser *p, Ast *ast, bool need_semi)
{
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = true;

    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_USING: {
        parser_next(p, 1);
        ast->type = AST_USING;

        ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->expr, false)) res = false;

        break;
    }

    case TOKEN_DEFER: {
        parser_next(p, 1);
        ast->type = AST_DEFER;
        need_semi = false;

        ast->stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->stmt, true)) res = false;

        break;
    }

    case TOKEN_LCURLY: {
        parser_next(p, 1);
        need_semi = false;

        ast->type = AST_BLOCK;

        while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
               !parser_is_at_end(p, 0))
        {
            Ast stmt = {0};
            if (!parse_stmt(p, &stmt, true)) res = false;
            array_push(&ast->block.stmts, stmt);
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }

    case TOKEN_EXTERN: {
        parser_next(p, 1);

        ast->flags |= AST_FLAG_EXTERN;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_VAR: {
            goto parse_var_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    case TOKEN_STATIC: {
        parser_next(p, 1);

        ast->flags |= AST_FLAG_STATIC;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_VAR: {
            goto parse_var_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    parse_var_decl:
    case TOKEN_VAR:
    case TOKEN_CONST: {
        Token *kind = parser_next(p, 1);

        if (kind->type == TOKEN_VAR && parser_peek(p, 0)->type == TOKEN_IDENT &&
            parser_peek(p, 1)->type == TOKEN_COMMA)
        {
            ast->type = AST_TUPLE_DECL;
            memset(&ast->tuple_decl, 0, sizeof(ast->tuple_decl));

            while (parser_peek(p, 0)->type != TOKEN_ASSIGN &&
                   !parser_is_at_end(p, 0))
            {
                if (ast->tuple_decl.bindings.len > 0)
                {
                    if (!parser_consume(p, TOKEN_COMMA)) res = false;
                }

                Ast binding = {0};

                Token *binding_name = parser_consume(p, TOKEN_IDENT);
                if (!binding_name)
                {
                    res = false;
                    break;
                }
                else
                {
                    binding.tuple_binding.name = binding_name->str;
                }

                binding.type = AST_TUPLE_BINDING;
                binding.tuple_binding.index = ast->tuple_decl.bindings.len;

                array_push(&ast->tuple_decl.bindings, binding);
            }

            if (!res) break;

            if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

            ast->tuple_decl.value_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->tuple_decl.value_expr, false)) res = false;
        }
        else
        {
            if (kind->type == TOKEN_VAR) ast->type = AST_VAR_DECL;
            if (kind->type == TOKEN_CONST) ast->type = AST_CONST_DECL;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                ast->decl.name = ident_tok->str;

            ast->decl.type_expr = NULL;
            if (parser_peek(p, 0)->type == TOKEN_COLON)
            {
                parser_next(p, 1);

                ast->decl.type_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->decl.type_expr, true)) res = false;
            }

            ast->decl.value_expr = NULL;
            if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
            {
                if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

                ast->decl.value_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->decl.value_expr, false)) res = false;
            }
            else if (kind->type == TOKEN_CONST)
            {
                // Constants must have initializers
                compile_error(
                    p->compiler,
                    ident_tok->loc,
                    "constant declaration must have initializer");
            }
        }

        break;
    }

    case TOKEN_RETURN: {
        parser_next(p, 1);

        ast->type = AST_RETURN;
        need_semi = true;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            Location first_loc = parser_peek(p, 0)->loc;

            Ast value = {0};
            if (!parse_expr(p, &value, false)) res = false;

            if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
            {
                ArrayOfAst values = {0};
                array_push(&values, value);

                while (parser_peek(p, 0)->type != TOKEN_SEMICOLON &&
                       !parser_is_at_end(p, 0))
                {
                    if (!parser_consume(p, TOKEN_COMMA))
                    {
                        res = false;
                        break;
                    }

                    if (!parse_expr(p, &value, false)) res = false;
                    array_push(&values, value);
                }

                ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
                memset(ast->expr, 0, sizeof(Ast));

                ast->expr->type = AST_TUPLE_LIT;
                ast->expr->tuple_lit.values = values;

                // Set location
                ast->expr->loc = first_loc;
                Location last_loc = parser_peek(p, -1)->loc;
                ast->expr->loc.length =
                    last_loc.buf + last_loc.length - ast->expr->loc.buf;
            }
            else
            {
                ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
                *ast->expr = value;
            }
        }

        break;
    }

    case TOKEN_VERSION: {
        parser_next(p, 1);

        ast->type = AST_VERSION_BLOCK;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        Token *version_ident = parser_consume(p, TOKEN_IDENT);
        if (version_ident)
            ast->version_block.version = version_ident->str;
        else
            res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_LCURLY)
        {
            if (!parser_consume(p, TOKEN_LCURLY))
            {
                res = false;
                break;
            }

            while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                   !parser_is_at_end(p, 0))
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true)) res = false;
                array_push(&ast->version_block.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            Ast stmt = {0};
            if (!parse_stmt(p, &stmt, true)) res = false;
            array_push(&ast->version_block.stmts, stmt);
        }

        if (parser_peek(p, 0)->type == TOKEN_ELSE)
        {
            parser_next(p, 1);

            if (parser_peek(p, 0)->type == TOKEN_LCURLY)
            {
                if (!parser_consume(p, TOKEN_LCURLY))
                {
                    res = false;
                    break;
                }

                while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                       !parser_is_at_end(p, 0))
                {
                    Ast stmt = {0};
                    if (!parse_stmt(p, &stmt, true)) res = false;
                    array_push(&ast->version_block.else_stmts, stmt);
                }

                if (!parser_consume(p, TOKEN_RCURLY)) res = false;
            }
            else
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true)) res = false;
                array_push(&ast->version_block.else_stmts, stmt);
            }
        }

        break;
    }

    case TOKEN_IF: {
        parser_next(p, 1);

        ast->type = AST_IF;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        ast->if_stmt.cond_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->if_stmt.cond_expr, false)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->if_stmt.cond_stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->if_stmt.cond_stmt, true)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_ELSE)
        {
            parser_next(p, 1);

            ast->if_stmt.else_stmt =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->if_stmt.else_stmt, true)) res = false;
        }

        break;
    }

    case TOKEN_SWITCH: {
        parser_next(p, 1);
        need_semi = false;

        ast->type = AST_SWITCH;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        ast->switch_stmt.expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->switch_stmt.expr, false)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        if (!parser_consume(p, TOKEN_LCURLY))
        {
            res = false;
            break;
        }

        memset(&ast->switch_stmt.vals, 0, sizeof(ast->switch_stmt.vals));
        memset(&ast->switch_stmt.stmts, 0, sizeof(ast->switch_stmt.stmts));

        while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
               !parser_is_at_end(p, 0))
        {
            if (parser_peek(p, 0)->type == TOKEN_DEFAULT)
            {
                parser_next(p, 1);
                if (!parser_consume(p, TOKEN_COLON)) res = false;

                Ast block = {0};
                block.type = AST_BLOCK;

                while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                       parser_peek(p, 0)->type != TOKEN_CASE &&
                       parser_peek(p, 0)->type != TOKEN_DEFAULT &&
                       !parser_is_at_end(p, 0))
                {
                    Ast stmt = {0};
                    if (!parse_stmt(p, &stmt, true)) res = false;
                    array_push(&block.block.stmts, stmt);
                }

                if (res)
                {
                    Ast val = {.type = AST_NOTHING};
                    array_push(&ast->switch_stmt.vals, val);
                    array_push(&ast->switch_stmt.stmts, block);
                }
            }
            else if (parser_peek(p, 0)->type == TOKEN_CASE)
            {
                parser_next(p, 1);
                Ast val = {0};
                if (!parse_expr(p, &val, false)) res = false;

                if (!parser_consume(p, TOKEN_COLON)) res = false;

                Ast block = {0};
                block.type = AST_BLOCK;

                while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                       parser_peek(p, 0)->type != TOKEN_CASE &&
                       parser_peek(p, 0)->type != TOKEN_DEFAULT &&
                       !parser_is_at_end(p, 0))
                {
                    Ast stmt = {0};
                    if (!parse_stmt(p, &stmt, true)) res = false;
                    array_push(&block.block.stmts, stmt);
                }

                if (res)
                {
                    array_push(&ast->switch_stmt.vals, val);
                    array_push(&ast->switch_stmt.stmts, block);
                }
            }
            else
            {
                res = false;
                break;
            }
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }

    case TOKEN_WHILE: {
        parser_next(p, 1);

        ast->type = AST_WHILE;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        ast->while_stmt.cond = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->while_stmt.cond, false)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->while_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->while_stmt.stmt, true)) res = false;

        break;
    }

    case TOKEN_FOR: {
        parser_next(p, 1);

        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        if ((parser_peek(p, 0)->type == TOKEN_IDENT &&
             parser_peek(p, 1)->type == TOKEN_IN) ||
            (parser_peek(p, 0)->type == TOKEN_ASTERISK &&
             parser_peek(p, 1)->type == TOKEN_IDENT &&
             parser_peek(p, 2)->type == TOKEN_IN))
        {
            // Foreach
            ast->type = AST_FOREACH;

            if (parser_peek(p, 0)->type == TOKEN_ASTERISK)
            {
                parser_next(p, 1);
                ast->flags |= AST_FLAG_FOREACH_PTR;
            }

            Token *elem_name_tok = parser_consume(p, TOKEN_IDENT);
            if (!elem_name_tok)
            {
                res = false;
                break;
            }
            ast->foreach_stmt.elem_name = elem_name_tok->str;

            if (!parser_consume(p, TOKEN_IN))
            {
                res = false;
                break;
            }

            ast->foreach_stmt.iterator =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->foreach_stmt.iterator, false)) res = false;

            if (!parser_consume(p, TOKEN_RPAREN))
            {
                res = false;
                break;
            }

            ast->foreach_stmt.stmt =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->foreach_stmt.stmt, true)) res = false;
        }
        else
        {
            // C-style For
            ast->type = AST_FOR;

            if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
            {
                ast->for_stmt.init =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_stmt(p, ast->for_stmt.init, false)) res = false;
            }

            if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

            if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
            {
                ast->for_stmt.cond =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->for_stmt.cond, false)) res = false;
            }

            if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                ast->for_stmt.inc = bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_stmt(p, ast->for_stmt.inc, false)) res = false;
            }

            if (!parser_consume(p, TOKEN_RPAREN)) res = false;

            ast->for_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->for_stmt.stmt, true)) res = false;
        }

        break;
    }

    case TOKEN_BREAK: {
        parser_next(p, 1);
        ast->type = AST_BREAK;
        need_semi = true;
        break;
    }

    case TOKEN_CONTINUE: {
        parser_next(p, 1);
        ast->type = AST_CONTINUE;
        need_semi = true;
        break;
    }

    default: {
        if (parser_peek(p, 0)->type == TOKEN_IDENT &&
            parser_peek(p, 1)->type == TOKEN_COLON &&
            parser_peek(p, 2)->type == TOKEN_ASSIGN)
        {
            ast->type = AST_VAR_DECL;
            ast->decl.type_expr = NULL;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                ast->decl.name = ident_tok->str;

            parser_next(p, 1); // colon
            parser_next(p, 1); // assign

            ast->decl.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->decl.value_expr, false)) res = false;

            break;
        }

        Ast expr = {0};
        if (!parse_expr(p, &expr, false)) res = false;

        if (res)
        {
            if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
            {
                ast->type = AST_VAR_ASSIGN;

                ast->assign.assigned_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                *ast->assign.assigned_expr = expr;

                if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

                ast->assign.value_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->assign.value_expr, false)) res = false;
            }
            else
            {
                ast->type = AST_EXPR_STMT;

                ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
                *ast->expr = expr;
            }
        }

        break;
    }
    }

    if (need_semi)
    {
        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;
    }

    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    return res;
}

static bool parse_top_level_stmt(Parser *p, Ast *ast)
{
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = true;

    ast->flags |= AST_FLAG_IS_TOP_LEVEL;

    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_HASH: {
        parser_next(p, 1);

        ArrayOfAstAttribute attributes = {0};
        if (!parser_consume(p, TOKEN_LBRACK)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RBRACK &&
               !parser_is_at_end(p, 0))
        {
            AstAttribute attr = {0};

            Token *name_tok = parser_next(p, 1);
            if (name_tok->type == TOKEN_IDENT)
            {
                attr.name = name_tok->str;
            }
            else
            {
                res = false;
            }

            if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
            {
                parser_next(p, 1);
                Ast *value = bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (parse_expr(p, value, false))
                {
                    attr.value = value;
                }
                else
                {
                    res = false;
                }
            }

            if (res)
            {
                array_push(&attributes, attr);
            }

            if (parser_peek(p, 0)->type != TOKEN_RBRACK)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RBRACK)) res = false;

        ast->attributes = attributes;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_FN: {
            goto parse_top_level_fn_decl;
            break;
        }

        case TOKEN_EXTERN: {
            goto parse_top_level_extern_decl;
            break;
        }

        case TOKEN_STATIC: {
            goto parse_top_level_static_decl;
            break;
        }

        case TOKEN_PUB: {
            goto parse_top_level_pub_decl;
            break;
        }

        case TOKEN_VAR: {
            goto parse_top_level_var_decl;
            break;
        }

        case TOKEN_CONST: {
            goto parse_top_level_const_decl;
            break;
        }

        case TOKEN_TYPEDEF: {
            goto parse_top_level_typedef_decl;
            break;
        }

        case TOKEN_IMPORT: {
            goto parse_top_level_import_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    parse_top_level_pub_decl:
    case TOKEN_PUB: {
        parser_next(p, 1);

        ast->flags |= AST_FLAG_PUBLIC;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_FN: {
            goto parse_top_level_fn_decl;
            break;
        }

        case TOKEN_CONST: {
            goto parse_top_level_const_decl;
            break;
        }

        case TOKEN_VAR: {
            goto parse_top_level_var_decl;
            break;
        }

        case TOKEN_TYPEDEF: {
            goto parse_top_level_typedef_decl;
            break;
        }

        case TOKEN_EXTERN: {
            goto parse_top_level_extern_decl;
            break;
        }

        case TOKEN_STATIC: {
            goto parse_top_level_static_decl;
            break;
        }

        case TOKEN_IMPORT: {
            goto parse_top_level_import_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    parse_top_level_extern_decl:
    case TOKEN_EXTERN: {
        parser_next(p, 1);

        ast->flags |= AST_FLAG_EXTERN;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_FN: {
            goto parse_top_level_fn_decl;
            break;
        }

        case TOKEN_VAR: {
            goto parse_top_level_var_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    parse_top_level_static_decl:
    case TOKEN_STATIC: {
        parser_next(p, 1);

        ast->flags |= AST_FLAG_STATIC;

        switch (parser_peek(p, 0)->type)
        {
        case TOKEN_VAR: {
            goto parse_top_level_var_decl;
            break;
        }

        default: res = false; break;
        }

        break;
    }

    parse_top_level_fn_decl:
    case TOKEN_FN: {
        parser_next(p, 1);

        ast->type = AST_PROC_DECL;

        Token *proc_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!proc_name_tok)
            res = false;
        else
            ast->proc.name = proc_name_tok->str;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        bool is_template = false;

        size_t lookahead = 0;
        while (parser_peek(p, lookahead)->type != TOKEN_RPAREN &&
               !parser_is_at_end(p, lookahead))
        {
            ++lookahead;
        }

        ++lookahead;

        if (parser_is_at_end(p, lookahead))
        {
            break;
        }

        if (parser_peek(p, lookahead)->type == TOKEN_LPAREN)
        {
            is_template = true;
        }

        if (is_template)
        {
            ast->flags |= AST_FLAG_IS_TEMPLATE;

            while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                   !parser_is_at_end(p, 0))
            {
                Token *param_name = parser_consume(p, TOKEN_IDENT);
                if (param_name)
                {
                    array_push(&ast->proc.template_params, param_name->str);
                }
                else
                {
                    res = false;
                }

                if (parser_peek(p, 0)->type != TOKEN_RPAREN)
                {
                    if (!parser_consume(p, TOKEN_COMMA)) res = false;
                }
            }

            if (!parser_consume(p, TOKEN_RPAREN)) res = false;

            if (!parser_consume(p, TOKEN_LPAREN))
            {
                res = false;
                break;
            }
        }

        while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
               !parser_is_at_end(p, 0))
        {
            Ast param = {0};
            param.type = AST_PROC_PARAM;

            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->flags |= AST_FLAG_FUNCTION_IS_C_VARARGS;
                break;
            }
            else if (parser_peek(p, 0)->type == TOKEN_USING)
            {
                parser_next(p, 1);
                param.flags |= AST_FLAG_USING;
            }

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (ident_tok)
            {
                param.loc = ident_tok->loc;
                param.proc_param.name = ident_tok->str;
            }
            else
            {
                res = false;
                break;
            }

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr, true)) res = false;

            array_push(&ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        // Parse return type
        ast->proc.return_type = NULL;
        if (parser_peek(p, 0)->type == TOKEN_ARROW)
        {
            // Init return type
            ast->proc.return_type = bump_alloc(&p->compiler->bump, sizeof(Ast));
            memset(ast->proc.return_type, 0, sizeof(Ast));
            ast->proc.return_type->type = AST_TUPLE_TYPE;
            ast->proc.return_type->loc = parser_peek(p, 0)->loc;

            parser_next(p, 1);

            if (parser_peek(p, 0)->type == TOKEN_LPAREN)
            {
                parser_next(p, 1);

                ArrayOfAst return_types = {0};

                while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                       !parser_is_at_end(p, 0))
                {
                    if (return_types.len > 0)
                    {
                        if (!parser_consume(p, TOKEN_COMMA))
                        {
                            res = false;
                            break;
                        }
                    }

                    Ast return_type = {0};
                    if (!parse_expr(p, &return_type, true))
                    {
                        res = false;
                        break;
                    }
                    array_push(&return_types, return_type);
                }

                if (!parser_consume(p, TOKEN_RPAREN))
                {
                    res = false;
                    break;
                }

                // Init return type
                ast->proc.return_type->tuple_type.fields = return_types;

                // Set location
                Location last_loc = parser_peek(p, -1)->loc;
                ast->proc.return_type->loc.length =
                    last_loc.buf + last_loc.length -
                    ast->proc.return_type->loc.buf;
            }
            else
            {
                ast->proc.return_type =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                if (!parse_expr(p, ast->proc.return_type, true))
                {
                    res = false;
                    break;
                }
            }
        }

        memset(&ast->proc.stmts, 0, sizeof(ast->proc.stmts));

        if (parser_peek(p, 0)->type == TOKEN_LCURLY)
        {
            parser_next(p, 1);
            ast->flags |= AST_FLAG_FUNCTION_HAS_BODY;

            while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                   !parser_is_at_end(p, 0))
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true)) res = false;
                array_push(&ast->proc.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            ast->flags = ast->flags & ~AST_FLAG_FUNCTION_HAS_BODY;
            if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;
        }

        break;
    }

    parse_top_level_import_decl:
    case TOKEN_IMPORT: {
        parser_next(p, 1);
        ast->type = AST_IMPORT;

        Token *path_tok = parser_consume(p, TOKEN_STRING_LIT);
        if (path_tok)
            ast->import.path = path_tok->str;
        else
            res = false;

        break;
    }

    parse_top_level_var_decl:
    parse_top_level_const_decl:
    case TOKEN_VAR:
    case TOKEN_CONST: {
        Token *kind = parser_next(p, 1);

        if (kind->type == TOKEN_VAR) ast->type = AST_VAR_DECL;
        if (kind->type == TOKEN_CONST) ast->type = AST_CONST_DECL;

        Token *ident_tok = parser_consume(p, TOKEN_IDENT);
        if (!ident_tok)
            res = false;
        else
            ast->decl.name = ident_tok->str;

        ast->decl.type_expr = NULL;
        if (parser_peek(p, 0)->type == TOKEN_COLON)
        {
            parser_next(p, 1);

            ast->decl.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->decl.type_expr, true)) res = false;
        }

        ast->decl.value_expr = NULL;
        if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
        {
            if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

            ast->decl.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->decl.value_expr, false)) res = false;
        }
        else if (kind->type == TOKEN_CONST)
        {
            // Constants must have initializers
            compile_error(
                p->compiler,
                ident_tok->loc,
                "constant declaration must have initializer");
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        break;
    }

    parse_top_level_typedef_decl:
    case TOKEN_TYPEDEF: {
        parser_next(p, 1);

        ast->type = AST_TYPEDEF;

        Token *type_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!type_name_tok)
            res = false;
        else
            ast->type_def.name = type_name_tok->str;

        if (parser_peek(p, 0)->type == TOKEN_LPAREN)
        {
            parser_next(p, 1);
            ast->flags |= AST_FLAG_IS_TEMPLATE;

            while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                   !parser_is_at_end(p, 0))
            {
                Token *param_name = parser_consume(p, TOKEN_IDENT);
                if (param_name)
                {
                    array_push(&ast->type_def.template_params, param_name->str);
                }
                else
                {
                    res = false;
                }

                if (parser_peek(p, 0)->type != TOKEN_RPAREN)
                {
                    if (!parser_consume(p, TOKEN_COMMA)) res = false;
                }
            }

            if (!parser_consume(p, TOKEN_RPAREN)) res = false;
        }

        ast->type_def.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->type_def.type_expr, true)) res = false;

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        break;
    }

    case TOKEN_VERSION: {
        parser_next(p, 1);

        ast->type = AST_VERSION_BLOCK;

        if (!parser_consume(p, TOKEN_LPAREN))
        {
            res = false;
            break;
        }

        Token *version_ident = parser_consume(p, TOKEN_IDENT);
        if (version_ident)
            ast->version_block.version = version_ident->str;
        else
            res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_LCURLY)
        {
            if (!parser_consume(p, TOKEN_LCURLY))
            {
                res = false;
                break;
            }

            while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                   !parser_is_at_end(p, 0))
            {
                Ast stmt = {0};
                if (!parse_top_level_stmt(p, &stmt)) res = false;
                array_push(&ast->version_block.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            Ast stmt = {0};
            if (!parse_top_level_stmt(p, &stmt)) res = false;
            array_push(&ast->version_block.stmts, stmt);
        }

        if (!parser_is_at_end(p, 0) && parser_peek(p, 0)->type == TOKEN_ELSE)
        {
            parser_next(p, 1);

            if (parser_peek(p, 0)->type == TOKEN_LCURLY)
            {
                if (!parser_consume(p, TOKEN_LCURLY))
                {
                    res = false;
                    break;
                }

                while (parser_peek(p, 0)->type != TOKEN_RCURLY &&
                       !parser_is_at_end(p, 0))
                {
                    Ast stmt = {0};
                    if (!parse_top_level_stmt(p, &stmt)) res = false;
                    array_push(&ast->version_block.else_stmts, stmt);
                }

                if (!parser_consume(p, TOKEN_RCURLY)) res = false;
            }
            else
            {
                Ast stmt = {0};
                if (!parse_top_level_stmt(p, &stmt)) res = false;
                array_push(&ast->version_block.else_stmts, stmt);
            }
        }

        break;
    }

    default: {
        res = false;
        compile_error(
            p->compiler,
            tok->loc,
            "invalid token for top level declaration",
            tok->loc.length,
            tok->loc.buf);
        parser_next(p, 1);
        break;
    }
    }

    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    return res;
}

static void parse_file(Parser *p, Compiler *compiler, Lexer *lexer)
{
    memset(p, 0, sizeof(*p));
    p->compiler = compiler;
    p->lexer = lexer;

    p->ast = bump_alloc(&p->compiler->bump, sizeof(Ast));
    memset(p->ast, 0, sizeof(*p->ast));
    p->ast->type = AST_ROOT;

    if (!(parser_peek(p, 0)->type == TOKEN_MODULE &&
          parser_peek(p, 1)->type == TOKEN_IDENT))
    {
        compile_error(
            p->compiler, parser_peek(p, 0)->loc, "expected module declaration");
        return;
    }

    parser_next(p, 1);
    Token *name_tok = parser_next(p, 1);
    name_tok->loc.file->module_name = name_tok->str;

    while (!parser_is_at_end(p, 0))
    {
        Ast stmt = {0};
        if (parse_top_level_stmt(p, &stmt))
        {
            array_push(&p->ast->block.stmts, stmt);
        }
    }
}
