typedef struct Parser
{
    Compiler *compiler;
    Lexer *lexer;
    Ast *ast;
    size_t pos;
} Parser;

static inline bool parser_is_at_end(Parser *p)
{
    return p->pos >= array_size(p->lexer->tokens);
}

static inline Token *parser_peek(Parser *p, size_t offset)
{
    if (p->pos + offset >= array_size(p->lexer->tokens))
    {
        return &p->lexer->tokens[p->pos];
    }
    return &p->lexer->tokens[p->pos + offset];
}

static inline Token *parser_next(Parser *p, size_t count)
{
    if (!parser_is_at_end(p)) p->pos += count;
    return &p->lexer->tokens[p->pos - count];
}

static inline Token *parser_consume(Parser *p, TokenType tok_type)
{
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

bool parse_expr(Parser *p, Ast *ast, bool parsing_type);

bool parse_primary_expr(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_IDENT:
    case TOKEN_INTRINSIC:
    case TOKEN_TRUE:
    case TOKEN_FALSE:
    case TOKEN_VOID:
    case TOKEN_NULL:
    case TOKEN_BOOL:
    case TOKEN_STRING_LIT:
    case TOKEN_CSTRING_LIT:
    case TOKEN_CHAR_LIT:
    case TOKEN_U8:
    case TOKEN_U16:
    case TOKEN_U32:
    case TOKEN_U64:
    case TOKEN_I8:
    case TOKEN_I16:
    case TOKEN_I32:
    case TOKEN_I64:
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

        ast->type = AST_PAREN_EXPR;
        ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->expr, parsing_type)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        break;
    }
    default: {
        parser_next(p, 1);
        res = false;
        break;
    }
    }
    return res;
}

bool parse_array_type(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    switch (parser_peek(p, 0)->type)
    {
    case TOKEN_LBRACK: {
        parser_next(p, 1);

        if (parser_peek(p, 0)->type == TOKEN_UNDERSCORE)
        {
            parser_next(p, 1);
            ast->type = AST_SLICE_TYPE;
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
        if (!parse_primary_expr(p, ast, parsing_type)) res = false;
        break;
    }
    }

    return res;
}

bool parse_proc_call(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_array_type(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LPAREN)
    {
        Ast expr = *ast;
        memset(&ast->proc_call, 0, sizeof(ast->proc_call));

        if (expr.type == AST_PRIMARY &&
            expr.primary.tok->type == TOKEN_INTRINSIC)
        {
            // Intrinsic call

            ast->type = AST_INTRINSIC_CALL;
            if (string_equals(expr.primary.tok->str, STR("sizeof")))
            {
                ast->intrinsic_call.type = INTRINSIC_SIZEOF;
            }
            else if (string_equals(expr.primary.tok->str, STR("alignof")))
            {
                ast->intrinsic_call.type = INTRINSIC_ALIGNOF;
            }
            else
            {
                compile_error(
                    p->compiler,
                    expr.loc,
                    "unknown intrinsic: '%.*s'",
                    (int)expr.primary.tok->str.length,
                    expr.primary.tok->str.buf);
                res = false;
            }

            if (!parser_consume(p, TOKEN_LPAREN)) res = false;

            while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                   !parser_is_at_end(p))
            {
                Ast param = {0};
                if (parse_expr(p, &param, parsing_type))
                    array_push(ast->intrinsic_call.params, param);
                else
                    res = false;

                if (parser_peek(p, 0)->type != TOKEN_RPAREN)
                {
                    if (!parser_consume(p, TOKEN_COMMA)) res = false;
                }
            }

            if (!parser_consume(p, TOKEN_RPAREN)) res = false;

            break;
        }

        // Proc call

        ast->type = AST_PROC_CALL;

        ast->proc_call.expr =
            bump_alloc(&p->compiler->bump, sizeof(*ast->proc_call.expr));
        *ast->proc_call.expr = expr;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN && !parser_is_at_end(p))
        {
            Ast param = {0};
            if (parse_expr(p, &param, parsing_type))
                array_push(ast->proc_call.params, param);
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

bool parse_subscript(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_proc_call(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LBRACK)
    {
        Ast expr = *ast;

        parser_next(p, 1);

        Ast lower = {0};
        if (!parse_expr(p, &lower, parsing_type)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_DOTDOT)
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

bool parse_access(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_subscript(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_DOT)
    {
        Ast expr = *ast;
        memset(&ast->access, 0, sizeof(ast->access));

        parser_next(p, 1);
        ast->type = AST_ACCESS;
        ast->access.left =
            bump_alloc(&p->compiler->bump, sizeof(*ast->access.left));
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

bool parse_compound_literal(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_access(p, ast, parsing_type)) res = false;
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

        while (parser_peek(p, 0)->type != TOKEN_RCURLY)
        {

            Ast value = {0};
            if (parse_expr(p, &value, parsing_type))
            {
                array_push(ast->compound.values, value);
            }
            else
            {
                res = false;
            }

            if (parser_peek(p, 0)->type == TOKEN_RCURLY) break;

            if (!parser_consume(p, TOKEN_COMMA)) res = false;
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;
    }

    return res;
}

bool parse_unary_expr(Parser *p, Ast *ast, bool parsing_type)
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
        if (tok->type == TOKEN_ASTERISK) ast->unop.type = UNOP_DEREFERENCE;
        if (tok->type == TOKEN_AMPERSAND) ast->unop.type = UNOP_ADDRESS;
        if (tok->type == TOKEN_MINUS) ast->unop.type = UNOP_NEG;
        if (tok->type == TOKEN_NOT) ast->unop.type = UNOP_NOT;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_unary_expr(p, right, parsing_type)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->unop.sub = right;

        break;
    }
    case TOKEN_STRUCT: {
        ast->type = AST_STRUCT;
        parser_next(p, 1);

        if (!parser_consume(p, TOKEN_LCURLY)) res = false;

        ast->structure.fields = NULL;

        while (parser_peek(p, 0)->type != TOKEN_RCURLY)
        {
            Ast field = {0};
            field.type = AST_STRUCT_FIELD;

            Token *name_tok = parser_consume(p, TOKEN_IDENT);
            if (!name_tok)
                res = false;
            else
                field.field.name = name_tok->str;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            Ast type = {0};
            if (parse_expr(p, &type, parsing_type))
            {
                field.field.type_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                *field.field.type_expr = type;
            }
            else
            {
                res = false;
            }

            if (res)
            {
                field.field.index = array_size(ast->structure.fields);
                array_push(ast->structure.fields, field);
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

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

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
        if (parse_expr(p, &value, parsing_type))
        {
            ast->cast.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->cast.value_expr = value;
        }
        else
        {
            res = false;
        }

        break;
    }
    case TOKEN_PROC: {
        parser_next(p, 1);

        ast->type = AST_PROC_TYPE;

        if (!parser_consume(p, TOKEN_ASTERISK)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
            ast->proc.convention = convention_tok->str;
        }

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->proc.flags |= PROC_FLAG_IS_C_VARARGS;
                break;
            }

            Ast param = {0};
            param.type = AST_PROC_PARAM;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                param.proc_param.name = ident_tok->str;

            if (ident_tok) param.loc = ident_tok->loc;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr, parsing_type))
                res = false;

            array_push(ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->proc.return_type = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->proc.return_type, parsing_type)) res = false;

        break;
    }
    default: {
        res = parse_compound_literal(p, ast, parsing_type);
        break;
    }
    }

    return res;
}

bool parse_multiplication(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_unary_expr(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_ASTERISK) ||
           (parser_peek(p, 0)->type == TOKEN_SLASH) ||
           (parser_peek(p, 0)->type == TOKEN_PERCENT))
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

bool parse_addition(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_multiplication(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PLUS) ||
           (parser_peek(p, 0)->type == TOKEN_MINUS))
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

bool parse_bitshift(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_addition(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_RSHIFT) ||
           (parser_peek(p, 0)->type == TOKEN_LSHIFT))
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

bool parse_bitwise(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_bitshift(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PIPE) ||
           (parser_peek(p, 0)->type == TOKEN_AMPERSAND) ||
           (parser_peek(p, 0)->type == TOKEN_HAT))
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

bool parse_comparison(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_bitwise(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_EQUAL) ||
           (parser_peek(p, 0)->type == TOKEN_NOTEQ) ||
           (parser_peek(p, 0)->type == TOKEN_LESS) ||
           (parser_peek(p, 0)->type == TOKEN_LESSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_GREATER) ||
           (parser_peek(p, 0)->type == TOKEN_GREATEREQ))
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

bool parse_logical(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_comparison(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_AND) ||
           (parser_peek(p, 0)->type == TOKEN_OR))
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

bool parse_op_assign(Parser *p, Ast *ast, bool parsing_type)
{
    bool res = true;

    if (!parse_logical(p, ast, parsing_type)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PLUSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MINUSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MULEQ) ||
           (parser_peek(p, 0)->type == TOKEN_DIVEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MODEQ) ||
           (parser_peek(p, 0)->type == TOKEN_ANDEQ) ||
           (parser_peek(p, 0)->type == TOKEN_OREQ) ||
           (parser_peek(p, 0)->type == TOKEN_XOREQ) ||
           (parser_peek(p, 0)->type == TOKEN_LSHIFTEQ) ||
           (parser_peek(p, 0)->type == TOKEN_RSHIFTEQ))
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

bool parse_expr(Parser *p, Ast *ast, bool parsing_type)
{
    assert(!parser_is_at_end(p));
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = parse_op_assign(p, ast, parsing_type);
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;
    return res;
}

bool parse_stmt(Parser *p, Ast *ast, bool inside_procedure, bool need_semi)
{
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = true;

    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_LCURLY: {
        parser_next(p, 1);
        need_semi = false;

        ast->type = AST_BLOCK;

        while (parser_peek(p, 0)->type != TOKEN_RCURLY)
        {
            Ast stmt = {0};
            if (!parse_stmt(p, &stmt, true, true)) res = false;
            array_push(ast->block.stmts, stmt);
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }
    case TOKEN_PROC: {
        parser_next(p, 1);

        ast->type = AST_PROC_DECL;
        need_semi = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
            ast->proc.convention = convention_tok->str;
        }

        Token *proc_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!proc_name_tok)
            res = false;
        else
            ast->proc.name = proc_name_tok->str;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->proc.flags |= PROC_FLAG_IS_C_VARARGS;
                break;
            }

            Ast param = {0};
            param.type = AST_PROC_PARAM;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                param.proc_param.name = ident_tok->str;

            if (ident_tok) param.loc = ident_tok->loc;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr, true)) res = false;

            array_push(ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        // Parse return type
        ast->proc.return_type = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->proc.return_type, true)) res = false;

        ast->proc.stmts = NULL;

        if (parser_peek(p, 0)->type == TOKEN_LCURLY)
        {
            ast->proc.flags |= PROC_FLAG_HAS_BODY;
            if (!parser_consume(p, TOKEN_LCURLY)) res = false;

            while (parser_peek(p, 0)->type != TOKEN_RCURLY)
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true, true)) res = false;
                array_push(ast->proc.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            ast->proc.flags = ast->proc.flags & ~PROC_FLAG_HAS_BODY;
            need_semi = true;
        }

        break;
    }
    case TOKEN_IMPORT: {
        parser_next(p, 1);
        ast->type = AST_IMPORT;

        Token *name_tok = parser_consume(p, TOKEN_IDENT);
        if (name_tok)
            ast->import.name = name_tok->str;
        else
            res = false;

        Token *path_tok = parser_consume(p, TOKEN_STRING_LIT);
        if (path_tok)
            ast->import.path = path_tok->str;
        else
            res = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
            ast->proc.convention = convention_tok->str;
        }

        break;
    }
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

        if (!parser_consume(p, TOKEN_COLON)) res = false;

        ast->decl.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->decl.type_expr, true)) res = false;

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

        break;
    }
    case TOKEN_TYPEDEF: {
        parser_next(p, 1);

        ast->type = AST_TYPEDEF;

        Token *type_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!type_name_tok)
            res = false;
        else
            ast->type_def.name = type_name_tok->str;

        ast->type_def.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->type_def.type_expr, true)) res = false;

        break;
    }
    case TOKEN_RETURN: {
        parser_next(p, 1);

        ast->type = AST_RETURN;
        need_semi = true;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->expr, false)) res = false;
        }

        break;
    }
    case TOKEN_IF: {
        parser_next(p, 1);

        ast->type = AST_IF;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        ast->if_stmt.cond_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->if_stmt.cond_expr, false)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->if_stmt.cond_stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->if_stmt.cond_stmt, true, true)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_ELSE)
        {
            parser_next(p, 1);

            ast->if_stmt.else_stmt =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->if_stmt.else_stmt, true, true)) res = false;
        }

        break;
    }
    case TOKEN_WHILE: {
        parser_next(p, 1);

        ast->type = AST_WHILE;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        ast->while_stmt.cond = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->while_stmt.cond, false)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->while_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->while_stmt.stmt, true, true)) res = false;

        break;
    }
    case TOKEN_FOR: {
        parser_next(p, 1);

        ast->type = AST_FOR;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->for_stmt.init = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->for_stmt.init, true, false)) res = false;
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->for_stmt.cond = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->for_stmt.cond, false)) res = false;
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            ast->for_stmt.inc = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->for_stmt.inc, true, false)) res = false;
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->for_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->for_stmt.stmt, true, true)) res = false;

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
        Ast expr = {0};
        if (!parse_expr(p, &expr, false)) res = false;

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

            if (!inside_procedure)
            {
                // TODO: maybe this shouldn't be a parser error
                compile_error(
                    p->compiler,
                    tok->loc,
                    "assignment must be inside procedure",
                    tok->loc.length,
                    tok->loc.buf);

                res = false;
                break;
            }
        }
        else
        {
            ast->type = AST_EXPR_STMT;

            ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->expr = expr;
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

void parse_file(Parser *p, Compiler *compiler, Lexer *lexer)
{
    memset(p, 0, sizeof(*p));
    p->compiler = compiler;
    p->lexer = lexer;

    p->ast = bump_alloc(&p->compiler->bump, sizeof(Ast));
    memset(p->ast, 0, sizeof(*p->ast));
    p->ast->type = AST_ROOT;

    while (!parser_is_at_end(p))
    {
        Ast stmt = {0};
        if (parse_stmt(p, &stmt, false, true))
        {
            array_push(p->ast->block.stmts, stmt);
        }
    }
}
