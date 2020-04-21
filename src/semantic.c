typedef struct Analyzer
{
    Compiler *compiler;
    ArrayOfScopePtr scope_stack;
    ArrayOfScopePtr operand_scope_stack;
    ArrayOfAstPtr break_stack;
    ArrayOfAstPtr continue_stack;
} Analyzer;

static TypeInfo *
ast_as_type(Analyzer *a, Scope *scope, Ast *ast, bool is_distinct);

static void create_scopes_ast(Analyzer *a, Ast *ast);

static void register_symbol_ast(Analyzer *a, Ast *ast);
static void register_symbol_asts(Analyzer *a, Ast *asts, size_t ast_count);

static void analyze_ast(Analyzer *a, Ast *ast, TypeInfo *expected_type);
static void analyze_asts(Analyzer *a, Ast *asts, size_t ast_count);

static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast);

#define INSTANTIATE_AST(ELEM)                                                  \
    do                                                                         \
    {                                                                          \
        clone_into->ELEM = bump_alloc(&compiler->bump, sizeof(Ast));           \
        instantiate_template(                                                  \
            compiler,                                                          \
            clone_into->ELEM,                                                  \
            ast->ELEM,                                                         \
            names_to_replace,                                                  \
            replacements);                                                     \
    } while (0)

#define INSTANTIATE_ARRAY(ARRAY)                                               \
    do                                                                         \
    {                                                                          \
        memset(&clone_into->ARRAY, 0, sizeof(clone_into->ARRAY));              \
        array_add(&clone_into->ARRAY, ast->ARRAY.len);                         \
        for (size_t i = 0; i < ast->ARRAY.len; ++i)                            \
        {                                                                      \
            instantiate_template(                                              \
                compiler,                                                      \
                &clone_into->ARRAY.ptr[i],                                     \
                &ast->ARRAY.ptr[i],                                            \
                names_to_replace,                                              \
                replacements);                                                 \
        }                                                                      \
    } while (0)

static void instantiate_template(
    Compiler *compiler,
    Ast *clone_into,
    Ast *ast,
    ArrayOfString names_to_replace,
    ArrayOfAst replacements)
{
    if (ast == NULL) return;

    assert(!ast->scope);
    assert((names_to_replace.len) == (replacements.len));

    *clone_into = *ast;
    clone_into->flags &= ~AST_FLAG_IS_TEMPLATE; // turn off bit

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            for (size_t i = 0; i < names_to_replace.len; ++i)
            {
                if (string_equals(
                        ast->primary.tok->str, names_to_replace.ptr[i]))
                {
                    *clone_into = replacements.ptr[i];
                    break;
                }
            }

            break;
        }

        default: break;
        }

        break;
    }

    case AST_VERSION_BLOCK: {
        INSTANTIATE_ARRAY(version_block.stmts);
        break;
    }

    case AST_ENUM: {
        INSTANTIATE_AST(enumeration.type_expr);
        INSTANTIATE_ARRAY(enumeration.fields);
        break;
    }

    case AST_PROC_TYPE:
    case AST_PROC_DECL: {
        if (ast->proc.return_type) INSTANTIATE_AST(proc.return_type);
        INSTANTIATE_ARRAY(proc.params);
        INSTANTIATE_ARRAY(proc.stmts);
        break;
    }

    case AST_PROC_PARAM: {
        INSTANTIATE_AST(proc_param.type_expr);
        if (ast->proc_param.value_expr) INSTANTIATE_AST(proc_param.value_expr);
        break;
    }

    case AST_BLOCK: {
        INSTANTIATE_ARRAY(block.stmts);
        break;
    }

    case AST_INTRINSIC_CALL: {
        INSTANTIATE_ARRAY(intrinsic_call.params);
        break;
    }

    case AST_PROC_CALL: {
        INSTANTIATE_AST(proc_call.expr);
        INSTANTIATE_ARRAY(proc_call.params);
        break;
    }

    case AST_TYPEDEF: {
        INSTANTIATE_AST(type_def.type_expr);
        break;
    }

    case AST_CAST: {
        INSTANTIATE_AST(cast.type_expr);
        INSTANTIATE_AST(cast.value_expr);
        break;
    }

    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        if (ast->decl.type_expr) INSTANTIATE_AST(decl.type_expr);
        if (ast->decl.value_expr) INSTANTIATE_AST(decl.value_expr);
        break;
    }

    case AST_VAR_ASSIGN: {
        INSTANTIATE_AST(assign.assigned_expr);
        INSTANTIATE_AST(assign.value_expr);
        break;
    }

    case AST_USING:
    case AST_EXPR_STMT:
    case AST_RETURN: {
        if (ast->expr) INSTANTIATE_AST(expr);
        break;
    }

    case AST_DEFER: {
        if (ast->stmt) INSTANTIATE_AST(stmt);
        break;
    }

    case AST_DISTINCT_TYPE: {
        INSTANTIATE_AST(distinct.sub);
        break;
    }

    case AST_SUBSCRIPT: {
        INSTANTIATE_AST(subscript.left);
        INSTANTIATE_AST(subscript.right);
        break;
    }

    case AST_SUBSCRIPT_SLICE: {
        INSTANTIATE_AST(subscript_slice.left);
        if (ast->subscript_slice.lower) INSTANTIATE_AST(subscript_slice.lower);
        if (ast->subscript_slice.upper) INSTANTIATE_AST(subscript_slice.upper);
        break;
    }

    case AST_DYNAMIC_ARRAY_TYPE:
    case AST_SLICE_TYPE:
    case AST_ARRAY_TYPE: {
        if (ast->array_type.size) INSTANTIATE_AST(array_type.size);
        INSTANTIATE_AST(array_type.sub);
        break;
    }

    case AST_ACCESS: {
        INSTANTIATE_AST(access.left);
        INSTANTIATE_AST(access.right);
        break;
    }

    case AST_UNARY_EXPR: {
        INSTANTIATE_AST(unop.sub);
        break;
    }

    case AST_BINARY_EXPR: {
        INSTANTIATE_AST(binop.left);
        INSTANTIATE_AST(binop.right);
        break;
    }

    case AST_ENUM_FIELD: {
        INSTANTIATE_AST(enum_field.value_expr);
        break;
    }

    case AST_STRUCT_FIELD: {
        INSTANTIATE_AST(struct_field.type_expr);
        if (ast->struct_field.value_expr)
            INSTANTIATE_AST(struct_field.value_expr);
        break;
    }

    case AST_STRUCT: {
        INSTANTIATE_ARRAY(structure.fields);
        break;
    }

    case AST_IF: {
        INSTANTIATE_AST(if_stmt.cond_expr);
        INSTANTIATE_AST(if_stmt.cond_stmt);
        if (ast->if_stmt.else_stmt) INSTANTIATE_AST(if_stmt.else_stmt);
        break;
    }

    case AST_SWITCH: {
        INSTANTIATE_AST(switch_stmt.expr);
        INSTANTIATE_ARRAY(switch_stmt.vals);
        INSTANTIATE_ARRAY(switch_stmt.stmts);
        if (ast->switch_stmt.else_stmt) INSTANTIATE_AST(switch_stmt.else_stmt);
        break;
    }

    case AST_WHILE: {
        INSTANTIATE_AST(while_stmt.cond);
        INSTANTIATE_AST(while_stmt.stmt);
        break;
    }

    case AST_FOR: {
        if (ast->for_stmt.init) INSTANTIATE_AST(for_stmt.init);
        if (ast->for_stmt.cond) INSTANTIATE_AST(for_stmt.cond);
        if (ast->for_stmt.inc) INSTANTIATE_AST(for_stmt.inc);
        INSTANTIATE_AST(for_stmt.stmt);
        break;
    }

    case AST_COMPOUND_LIT: {
        INSTANTIATE_AST(compound.type_expr);
        INSTANTIATE_ARRAY(compound.values);
        break;
    }

    case AST_TEMPLATE_INST: {
        INSTANTIATE_AST(template_inst.sub);
        INSTANTIATE_ARRAY(template_inst.params);
        break;
    }

    case AST_BUILTIN_LEN:
    case AST_BUILTIN_PTR:
    case AST_BUILTIN_CAP:
    case AST_BUILTIN_MAX:
    case AST_BUILTIN_MIN:
    case AST_BUILTIN_VEC_ACCESS:
    case AST_CONTINUE:
    case AST_BREAK:
    case AST_STRUCT_FIELD_ALIAS:
    case AST_IMPORT: break;

    case AST_ROOT:
    case AST_UNINITIALIZED: {
        assert(0);
        break;
    }
    }
}

static bool is_expr_const(Compiler *compiler, Scope *scope, Ast *ast)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str, ast->loc.file);

            if (sym)
            {
                switch (sym->type)
                {
                case AST_ENUM_FIELD:
                case AST_PROC_DECL:
                case AST_CONST_DECL: {
                    res = true;
                    break;
                }
                default: break;
                }
            }
            break;
        }
        default: res = true; break;
        }
        break;
    }

    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF:
        case INTRINSIC_ALIGNOF: res = true; break;

        case INTRINSIC_SQRT:
        case INTRINSIC_COS:
        case INTRINSIC_SIN: res = false; break;

        case INTRINSIC_VECTOR_TYPE: res = true; break;
        }
        break;
    }

    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE:
        case UNOP_ADDRESS: res = false; break;
        case UNOP_NOT:
        case UNOP_NEG: {
            res = is_expr_const(compiler, scope, ast->unop.sub);
            break;
        }
        }
        break;
    }

    case AST_BINARY_EXPR: {
        res = true;

        if (!is_expr_const(compiler, scope, ast->binop.left)) res = false;
        if (!is_expr_const(compiler, scope, ast->binop.right)) res = false;

        if (ast->binop.assign) res = false;

        switch (ast->binop.type)
        {
        case BINOP_AND:
        case BINOP_OR: res = false; break;

        case BINOP_ADD:
        case BINOP_SUB:
        case BINOP_MUL:
        case BINOP_DIV:
        case BINOP_MOD:

        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ:

        case BINOP_BITOR:
        case BINOP_BITXOR:
        case BINOP_BITAND:

        case BINOP_LSHIFT:
        case BINOP_RSHIFT: break;
        }
        break;
    }

    case AST_COMPOUND_LIT: {
        res = true;
        for (Ast *value = ast->compound.values.ptr;
             value != ast->compound.values.ptr + ast->compound.values.len;
             ++value)
        {
            if (!is_expr_const(compiler, scope, value))
            {
                res = false;
                break;
            }
        }
        break;
    }

    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);

        if (accessed_scope)
        {
            res = is_expr_const(compiler, accessed_scope, ast->access.right);
        }
        break;
    }

    default: break;
    }

    return res;
}

static bool is_expr_assignable(Compiler *compiler, Scope *scope, Ast *ast)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str, ast->loc.file);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_BUILTIN_VEC_ACCESS:
                case AST_STRUCT_FIELD:
                case AST_VAR_DECL: {
                    res = true;
                    break;
                }

                case AST_BUILTIN_LEN:
                case AST_BUILTIN_PTR:
                case AST_BUILTIN_CAP: {
                    if (sym->sym_scope->type_info->kind != TYPE_ARRAY)
                    {
                        res = true;
                    }
                    break;
                }

                default: break;
                }
            }
            break;
        }
        default: break;
        }
        break;
    }

    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: res = true; break;

        default: break;
        }

        break;
    }

    case AST_SUBSCRIPT: {
        if (is_expr_assignable(compiler, scope, ast->subscript.left))
        {
            res = true;
        }

        break;
    }

    case AST_ACCESS: {
        if (is_expr_const(compiler, scope, ast->access.left))
        {
            break;
        }

        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);

        if (accessed_scope)
        {
            res =
                is_expr_assignable(compiler, accessed_scope, ast->access.right);
        }
        break;
    }

    default: break;
    }

    return res;
}

static bool resolve_expr_int(Analyzer *a, Scope *scope, Ast *ast, int64_t *i64)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_INT_LIT: {
            *i64 = ast->primary.tok->i64;
            res = true;
            break;
        }

        case TOKEN_TRUE:
            *i64 = 1;
            res = true;
            break;

        case TOKEN_FALSE:
            *i64 = 0;
            res = true;
            break;

        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str, ast->loc.file);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_CONST_DECL: {
                    assert(sym->sym_scope);
                    res = resolve_expr_int(
                        a, sym->sym_scope, sym->decl.value_expr, i64);
                    break;
                }

                case AST_ENUM_FIELD: {
                    assert(sym->sym_scope);
                    res = resolve_expr_int(
                        a, sym->sym_scope, sym->enum_field.value_expr, i64);
                    break;
                }

                default: break;
                }
            }
            break;
        }
        default: break;
        }
        break;
    }

    case AST_UNARY_EXPR: {
        res = true;

        int64_t sub_int;
        if (!resolve_expr_int(a, scope, ast->unop.sub, &sub_int)) res = false;

        switch (ast->unop.type)
        {
        case UNOP_NEG: *i64 = -sub_int; break;
        case UNOP_NOT: *i64 = !sub_int; break;
        default: res = false; break;
        }

        break;
    }

    case AST_BINARY_EXPR: {
        res = true;

        int64_t left_int;
        int64_t right_int;
        if (!resolve_expr_int(a, scope, ast->binop.left, &left_int))
            res = false;
        if (!resolve_expr_int(a, scope, ast->binop.right, &right_int))
            res = false;

        switch (ast->binop.type)
        {
        case BINOP_ADD: *i64 = (left_int + right_int); break;
        case BINOP_SUB: *i64 = (left_int - right_int); break;
        case BINOP_MUL: *i64 = (left_int * right_int); break;
        case BINOP_DIV: *i64 = (left_int / right_int); break;
        case BINOP_MOD: *i64 = (left_int % right_int); break;
        case BINOP_LSHIFT: *i64 = (left_int << right_int); break;
        case BINOP_RSHIFT: *i64 = (left_int >> right_int); break;
        case BINOP_BITAND: *i64 = (left_int & right_int); break;
        case BINOP_BITOR: *i64 = (left_int | right_int); break;
        case BINOP_BITXOR: *i64 = (left_int ^ right_int); break;
        case BINOP_EQ: *i64 = (left_int == right_int); break;
        case BINOP_NOTEQ: *i64 = (left_int != right_int); break;
        case BINOP_LESS: *i64 = (left_int < right_int); break;
        case BINOP_LESSEQ: *i64 = (left_int <= right_int); break;
        case BINOP_GREATER: *i64 = (left_int > right_int); break;
        case BINOP_GREATEREQ: *i64 = (left_int >= right_int); break;
        case BINOP_AND: *i64 = (left_int && right_int); break;
        case BINOP_OR: *i64 = (left_int || right_int); break;
        }

        break;
    }

    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];
            TypeInfo *type = NULL;

            if (param->type_info && param->type_info->kind == TYPE_TYPE)
                type = ast_as_type(a, scope, param, false);
            else
                type = param->type_info;

            if (type)
            {
                res = true;
                *i64 = (int64_t)size_of_type(type);
            }

            break;
        }

        case INTRINSIC_ALIGNOF: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];
            TypeInfo *type = NULL;

            if (param->type_info && param->type_info->kind == TYPE_TYPE)
                type = ast_as_type(a, scope, param, false);
            else
                type = param->type_info;

            if (type)
            {
                res = true;
                *i64 = (int64_t)align_of_type(type);
            }

            break;
        }

        default: break;
        }

        break;
    }

    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(a->compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            res = resolve_expr_int(a, accessed_scope, ast->access.right, i64);
        }
        break;
    }

    default: break;
    }

    return res;
}

static TypeInfo *
ast_as_type(Analyzer *a, Scope *scope, Ast *ast, bool is_distinct)
{
    if (ast->as_type) return ast->as_type;

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_U8: ast->as_type = &U8_TYPE; break;

        case TOKEN_U16: ast->as_type = &U16_TYPE; break;

        case TOKEN_U32: ast->as_type = &U32_TYPE; break;

        case TOKEN_U64: ast->as_type = &U64_TYPE; break;

        case TOKEN_CHAR:
        case TOKEN_I8: ast->as_type = &I8_TYPE; break;

        case TOKEN_I16: ast->as_type = &I16_TYPE; break;

        case TOKEN_I32: ast->as_type = &I32_TYPE; break;

        case TOKEN_I64: ast->as_type = &I64_TYPE; break;

        case TOKEN_INT: ast->as_type = &INT_TYPE; break;

        case TOKEN_UINT: ast->as_type = &UINT_TYPE; break;

        case TOKEN_FLOAT: ast->as_type = &FLOAT_TYPE; break;

        case TOKEN_DOUBLE: ast->as_type = &DOUBLE_TYPE; break;

        case TOKEN_BOOL: ast->as_type = &BOOL_TYPE; break;

        case TOKEN_VOID: ast->as_type = &VOID_TYPE; break;

        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str, ast->loc.file);
            if (sym)
            {
                ast->as_type = ast_as_type(a, sym->sym_scope, sym, false);
            }
            break;
        }
        default: break;
        }
        break;
    }

    case AST_TYPEDEF: {
        ast->as_type = ast_as_type(a, scope, ast->type_def.type_expr, false);
        if (ast->type_def.type_expr->as_type)
        {
            ast->type_def.type_expr->as_type->type_def = ast;
        }
        break;
    }

    case AST_TEMPLATE_INST: {
        if (ast->template_inst.sub->type != AST_PRIMARY ||
            ast->template_inst.sub->primary.tok->type != TOKEN_IDENT)
            break;

        String name = ast->template_inst.sub->primary.tok->str;
        Ast *sym = get_symbol(scope, name, ast->loc.file);

        if (sym && sym->type == AST_TYPEDEF)
        {
            if ((sym->type_def.template_params.len) !=
                (ast->template_inst.params.len))
                break;

            assert(sym->type_def.template_cache);

            sb_reset(&a->compiler->sb);
            for (size_t i = 0; i < ast->template_inst.params.len; ++i)
            {
                Ast *param = &ast->template_inst.params.ptr[i];
                sb_append(&a->compiler->sb, STR("$"));
                print_mangled_type(
                    &a->compiler->sb, ast_as_type(a, scope, param, false));
            }
            String mangled_type =
                sb_build(&a->compiler->sb, &a->compiler->bump);

            Ast *cached_ast = NULL;
            if (hash_get(
                    sym->type_def.template_cache,
                    mangled_type,
                    (void **)&cached_ast))
            {
                assert(cached_ast);
                ast->type_info = cached_ast->type_info;
                ast->as_type = cached_ast->as_type;
                break;
            }

            Ast *cloned_ast = bump_alloc(&a->compiler->bump, sizeof(Ast));
            memset(cloned_ast, 0, sizeof(Ast));

            hash_set(sym->type_def.template_cache, mangled_type, cloned_ast);

            instantiate_template(
                a->compiler,
                cloned_ast,
                sym->type_def.type_expr,
                sym->type_def.template_params,
                ast->template_inst.params);

            create_scopes_ast(a, cloned_ast);
            register_symbol_asts(a, cloned_ast, 1);
            analyze_asts(a, cloned_ast, 1);

            ast->as_type = cloned_ast->as_type;
            ast->type_info = cloned_ast->type_info;
            ast->template_inst.resolves_to = cloned_ast;
        }

        break;
    }

    case AST_DISTINCT_TYPE: {
        ast->as_type = ast_as_type(a, scope, ast->distinct.sub, true);
        break;
    }

    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast_as_type(a, scope, ast->unop.sub, false))
            {
                TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_POINTER;
                ty->ptr.sub = ast->unop.sub->as_type;
                ast->as_type = ty;
            }
            break;
        }
        default: break;
        }
        break;
    }

    case AST_ARRAY_TYPE: {
        if (!ast->array_type.size) break;

        int64_t size = 0;
        bool resolves = resolve_expr_int(a, scope, ast->array_type.size, &size);

        if (!ast_as_type(a, scope, ast->array_type.sub, false)) break;

        if (!resolves)
        {
            break;
        }

        if (resolves && size <= 0)
        {
            break;
        }

        ast->as_type =
            create_array_type(a->compiler, ast->array_type.sub->as_type, size);

        break;
    }

    case AST_SLICE_TYPE: {
        if (!ast_as_type(a, scope, ast->array_type.sub, false)) break;

        TypeInfo *ty =
            create_slice_type(a->compiler, ast->array_type.sub->as_type);

        ast->as_type = ty;
        break;
    }

    case AST_DYNAMIC_ARRAY_TYPE: {
        if (!ast_as_type(a, scope, ast->array_type.sub, false)) break;

        TypeInfo *ty = create_dynamic_array_type(
            a->compiler, ast->array_type.sub->as_type);

        ast->as_type = ty;
        break;
    }

    case AST_STRUCT: {
        ArrayOfTypeInfoPtr fields = {0};
        bool res = true;

        // We need to set the type here in advance because of recursive type
        // stuff
        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
        memset(ty, 0, sizeof(*ty));
        ast->as_type = ty;

        for (Ast *field = ast->structure.fields.ptr;
             field != ast->structure.fields.ptr + ast->structure.fields.len;
             ++field)
        {
            if (!ast_as_type(a, scope, field->struct_field.type_expr, false))
            {
                res = false;
            }
            array_push(&fields, field->struct_field.type_expr->as_type);
        }

        if (res)
        {
            ty->kind = TYPE_STRUCT;
            ty->structure.fields = fields;
            ty->scope = ast->scope;
            ty->structure.is_union = ast->structure.is_union;
        }
        else
        {
            ast->as_type = NULL;
        }

        break;
    }

    case AST_ENUM: {
        TypeInfo *underlying_type =
            ast_as_type(a, scope, ast->enumeration.type_expr, false);

        if (underlying_type)
        {
            TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_ENUM;
            ty->scope = ast->scope;
            ty->enumeration.underlying_type = underlying_type;

            ast->as_type = ty;
        }

        break;
    }

    case AST_PROC_TYPE: {
        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        if (ast->proc.flags & PROC_FLAG_IS_C_VARARGS)
        {
            ty->flags |= TYPE_FLAG_C_VARARGS;
        }

        if (ast->flags & AST_FLAG_EXTERN)
        {
            ty->flags |= TYPE_FLAG_EXTERN;
        }

        bool valid = true;

        for (Ast *param = ast->proc.params.ptr;
             param != ast->proc.params.ptr + ast->proc.params.len;
             ++param)
        {
            TypeInfo *param_as_type =
                ast_as_type(a, scope, param->decl.type_expr, false);
            if (!param_as_type)
            {
                valid = false;
                break;
            }

            if ((ty->flags & TYPE_FLAG_EXTERN) == TYPE_FLAG_EXTERN &&
                is_type_compound(param_as_type))
            {
                valid = false;
                break;
            }

            array_push(&ty->proc.params, param_as_type);
        }

        if (ast->proc.return_type)
        {
            ty->proc.return_type =
                ast_as_type(a, scope, ast->proc.return_type, false);
        }
        else
        {
            ty->proc.return_type = &VOID_TYPE;
        }

        if (!ty->proc.return_type)
        {
            valid = false;
        }

        if (valid)
        {
            TypeInfo *ptr_ty = bump_alloc(&a->compiler->bump, sizeof(*ptr_ty));
            memset(ptr_ty, 0, sizeof(*ptr_ty));
            ptr_ty->kind = TYPE_POINTER;
            ptr_ty->ptr.sub = ty;

            ast->as_type = ptr_ty;
        }
        break;
    }

    case AST_INTRINSIC_CALL: {

        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_VECTOR_TYPE: {
            if (ast->intrinsic_call.params.len != 2) break;

            Ast *elem_type = &ast->intrinsic_call.params.ptr[0];
            Ast *vec_width = &ast->intrinsic_call.params.ptr[1];

            ast_as_type(a, scope, elem_type, false);
            if (!elem_type->as_type) break;

            int64_t width;
            if (!resolve_expr_int(a, scope, vec_width, &width)) break;
            if (width <= 0) break;

            ast->as_type = create_vector_type(
                a->compiler, elem_type->as_type, (size_t)width);

            break;
        }

        default: break;
        }

        break;
    }

    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(a->compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            ast->as_type =
                ast_as_type(a, accessed_scope, ast->access.right, false);
        }
        break;
    }

    default: break;
    }

    if (is_distinct && ast->as_type)
    {
        TypeInfo *unique_type =
            bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
        *unique_type = *ast->as_type;
        unique_type->flags |= TYPE_FLAG_DISTINCT;
        ast->as_type = unique_type;
    }

    return ast->as_type;
}

static Ast *get_aliased_expr(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->alias_to) return ast->alias_to;

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str, ast->loc.file);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_IMPORT: ast->alias_to = sym; break;
                default: break;
                }
            }
            break;
        }
        default: break;
        }
        break;
    }

    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            ast->alias_to =
                get_aliased_expr(compiler, accessed_scope, ast->access.right);
        }
        break;
    }

    default: break;
    }

    return ast->alias_to;
}

// Returns the scope represented by the expression
static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->scope) return ast->scope;

    Scope *accessed_scope = NULL;

    Ast *aliased = get_aliased_expr(compiler, scope, ast);
    if (aliased)
    {
        switch (aliased->type)
        {
        case AST_IMPORT: {
            SourceFile *file = NULL;
            if (hash_get(
                    &compiler->files, aliased->import.abs_path, (void **)&file))
            {
                assert(file);
                accessed_scope = file->root->scope;
            }
            break;
        }

        default: break;
        }
    }
    else
    {
        // Type based lookup

        if (!ast->type_info) return NULL;

        switch (ast->type_info->kind)
        {
        case TYPE_TYPE:
            if (ast->as_type) accessed_scope = ast->as_type->scope;
            break;

        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE:
        case TYPE_ARRAY:
        case TYPE_VECTOR:
        case TYPE_STRUCT:
            accessed_scope = ast->type_info->scope;
            assert(accessed_scope);
            break;

        case TYPE_POINTER:
            accessed_scope = ast->type_info->ptr.sub->scope;
            break;

        default: break;
        }
    }

    if (accessed_scope && accessed_scope->type == SCOPE_INSTANCED)
    {
        accessed_scope = scope_clone(compiler, accessed_scope, ast);
    }

    ast->scope = accessed_scope;

    return accessed_scope;
}

static void create_scopes_ast(Analyzer *a, Ast *ast)
{
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        assert(!ast->scope);
        ast->scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->scope, 0, sizeof(*ast->scope));
        scope_init(
            ast->scope, a->compiler, SCOPE_DEFAULT, ast->block.stmts.len, ast);
        if (a->scope_stack.len > 0)
        {
            ast->scope->parent = *array_last(&a->scope_stack);
        }

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *stmt = ast->block.stmts.ptr;
             stmt != ast->block.stmts.ptr + ast->block.stmts.len;
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);

        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(a->compiler, ast->version_block.version))
        {
            for (Ast *stmt = ast->version_block.stmts.ptr;
                 stmt !=
                 ast->version_block.stmts.ptr + ast->version_block.stmts.len;
                 ++stmt)
            {
                create_scopes_ast(a, stmt);
            }
        }

        break;
    }

    case AST_USING: {
        create_scopes_ast(a, ast->expr);
        break;
    }

    case AST_DEFER: {
        create_scopes_ast(a, ast->stmt);
        break;
    }

    case AST_PROC_DECL: {
        if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
        {
            // Create template cache
            ast->proc.template_cache =
                bump_alloc(&a->compiler->bump, sizeof(HashMap));
            hash_init(ast->proc.template_cache, 8);
            break;
        }

        assert(!ast->scope);
        ast->scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->scope, 0, sizeof(*ast->scope));
        scope_init(
            ast->scope,
            a->compiler,
            SCOPE_DEFAULT,
            (ast->proc.stmts.len) + (ast->proc.params.len),
            ast);
        ast->scope->parent = *array_last(&a->scope_stack);

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *stmt = ast->proc.stmts.ptr;
             stmt != ast->proc.stmts.ptr + ast->proc.stmts.len;
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);

        break;
    }

    case AST_COMPOUND_LIT: {
        create_scopes_ast(a, ast->compound.type_expr);

        for (Ast *value = ast->compound.values.ptr;
             value != ast->compound.values.ptr + ast->compound.values.len;
             ++value)
        {
            create_scopes_ast(a, value);
        }

        break;
    }

    case AST_DISTINCT_TYPE: {
        create_scopes_ast(a, ast->distinct.sub);
        break;
    }

    case AST_UNARY_EXPR: {
        create_scopes_ast(a, ast->unop.sub);
        break;
    }

    case AST_BINARY_EXPR: {
        create_scopes_ast(a, ast->binop.left);
        create_scopes_ast(a, ast->binop.right);
        break;
    }

    case AST_IF: {
        create_scopes_ast(a, ast->if_stmt.cond_expr);
        create_scopes_ast(a, ast->if_stmt.cond_stmt);
        if (ast->if_stmt.else_stmt)
        {
            create_scopes_ast(a, ast->if_stmt.else_stmt);
        }
        break;
    }

    case AST_SWITCH: {
        create_scopes_ast(a, ast->switch_stmt.expr);

        for (Ast *val = ast->switch_stmt.vals.ptr;
             val != ast->switch_stmt.vals.ptr + ast->switch_stmt.vals.len;
             ++val)
        {
            create_scopes_ast(a, val);
        }

        for (Ast *stmt = ast->switch_stmt.stmts.ptr;
             stmt != ast->switch_stmt.stmts.ptr + ast->switch_stmt.stmts.len;
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }

        if (ast->switch_stmt.else_stmt)
        {
            create_scopes_ast(a, ast->switch_stmt.else_stmt);
        }
        break;
    }

    case AST_WHILE: {
        create_scopes_ast(a, ast->while_stmt.cond);
        create_scopes_ast(a, ast->while_stmt.stmt);
        break;
    }

    case AST_FOR: {
        assert(!ast->scope);
        ast->scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->scope, 0, sizeof(*ast->scope));
        scope_init(
            ast->scope,
            a->compiler,
            SCOPE_DEFAULT,
            5, // Small number, because there's only gonna be 2 declarations
               // max
            ast);
        if (a->scope_stack.len > 0)
        {
            ast->scope->parent = *array_last(&a->scope_stack);
        }

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        if (ast->for_stmt.init) create_scopes_ast(a, ast->for_stmt.init);
        if (ast->for_stmt.cond) create_scopes_ast(a, ast->for_stmt.cond);
        if (ast->for_stmt.inc) create_scopes_ast(a, ast->for_stmt.inc);
        create_scopes_ast(a, ast->for_stmt.stmt);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_TYPEDEF: {
        if (ast->type_def.template_params.len == 0)
        {
            create_scopes_ast(a, ast->type_def.type_expr);
        }
        else
        {
            // Create template cache
            ast->type_def.template_cache =
                bump_alloc(&a->compiler->bump, sizeof(HashMap));
            hash_init(ast->type_def.template_cache, 8);
        }
        break;
    }

    case AST_CONST_DECL: {
        if (ast->decl.type_expr)
        {
            create_scopes_ast(a, ast->decl.type_expr);
        }
        assert(ast->decl.value_expr);
        create_scopes_ast(a, ast->decl.value_expr);
        break;
    }

    case AST_VAR_DECL: {
        if (ast->decl.type_expr)
        {
            create_scopes_ast(a, ast->decl.type_expr);
        }
        if (ast->decl.value_expr)
        {
            create_scopes_ast(a, ast->decl.value_expr);
        }
        break;
    }

    case AST_STRUCT_FIELD: {
        create_scopes_ast(a, ast->struct_field.type_expr);
        if (ast->struct_field.value_expr)
        {
            create_scopes_ast(a, ast->struct_field.value_expr);
        }
        break;
    }

    case AST_ENUM_FIELD: {
        create_scopes_ast(a, ast->enum_field.value_expr);
        break;
    }

    case AST_STRUCT: {
        assert(!ast->scope);
        ast->scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->scope, 0, sizeof(*ast->scope));
        scope_init(
            ast->scope,
            a->compiler,
            SCOPE_INSTANCED,
            ast->structure.fields.len,
            ast);

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *field = ast->structure.fields.ptr;
             field != ast->structure.fields.ptr + ast->structure.fields.len;
             ++field)
        {
            create_scopes_ast(a, field);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_ENUM: {
        assert(!ast->scope);
        ast->scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->scope, 0, sizeof(*ast->scope));
        scope_init(
            ast->scope,
            a->compiler,
            SCOPE_DEFAULT,
            ast->enumeration.fields.len,
            ast);

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *field = ast->enumeration.fields.ptr;
             field != ast->enumeration.fields.ptr + ast->enumeration.fields.len;
             ++field)
        {
            create_scopes_ast(a, field);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_TEMPLATE_INST:
    case AST_STRUCT_FIELD_ALIAS:
    case AST_BUILTIN_LEN:
    case AST_BUILTIN_PTR:
    case AST_BUILTIN_CAP:
    case AST_BUILTIN_MAX:
    case AST_BUILTIN_MIN:
    case AST_BUILTIN_VEC_ACCESS:
    case AST_UNINITIALIZED:
    case AST_BREAK:
    case AST_CONTINUE:
    case AST_RETURN:
    case AST_PRIMARY:
    case AST_SUBSCRIPT:
    case AST_SUBSCRIPT_SLICE:
    case AST_ARRAY_TYPE:
    case AST_SLICE_TYPE:
    case AST_DYNAMIC_ARRAY_TYPE:
    case AST_EXPR_STMT:
    case AST_ACCESS:
    case AST_PROC_PARAM:
    case AST_CAST:
    case AST_VAR_ASSIGN:
    case AST_INTRINSIC_CALL:
    case AST_PROC_CALL:
    case AST_PROC_TYPE:
    case AST_IMPORT: break;
    }
}

static void register_symbol_ast_leaf(Analyzer *a, Ast *ast, Location *error_loc)
{
    Scope *scope = *array_last(&a->scope_stack);
    assert(scope);
    String sym_name = {0};

    switch (ast->type)
    {
    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        sym_name = ast->decl.name;
        break;
    }

    case AST_PROC_PARAM: {
        sym_name = ast->proc_param.name;
        break;
    }

    case AST_STRUCT_FIELD: {
        sym_name = ast->struct_field.name;
        break;
    }

    case AST_STRUCT_FIELD_ALIAS: {
        sym_name = ast->struct_field_alias.right_name;
        break;
    }

    case AST_ENUM_FIELD: {
        sym_name = ast->enum_field.name;
        break;
    }

    case AST_TYPEDEF: {
        sym_name = ast->type_def.name;
        break;
    }

    case AST_IMPORT: {
        sym_name = ast->import.name;
        break;
    }

    case AST_PROC_DECL: {
        if (ast->proc.template_params.len > 0 &&
            ((ast->flags & AST_FLAG_IS_TEMPLATE) != AST_FLAG_IS_TEMPLATE))
        {
            break;
        }

        sym_name = ast->proc.name;
        break;
    }

    default: return;
    }

    if (sym_name.length > 0)
    {
        if (scope_get_local(*array_last(&a->scope_stack), sym_name))
        {
            compile_error(
                a->compiler,
                *error_loc,
                "duplicate declaration: '%.*s'",
                (int)sym_name.length,
                sym_name.buf);
            return;
        }

        scope_set(scope, sym_name, ast);
    }
}

static void register_symbol_ast(Analyzer *a, Ast *ast)
{
    switch (ast->type)
    {
    case AST_ROOT: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        register_symbol_asts(a, ast->block.stmts.ptr, ast->block.stmts.len);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_BLOCK: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        register_symbol_asts(a, ast->block.stmts.ptr, ast->block.stmts.len);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(a->compiler, ast->version_block.version))
        {
            register_symbol_asts(
                a, ast->version_block.stmts.ptr, ast->version_block.stmts.len);
        }

        break;
    }

    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        if (ast->decl.type_expr)
        {
            register_symbol_ast(a, ast->decl.type_expr);
        }
        if (ast->decl.value_expr)
        {
            register_symbol_ast(a, ast->decl.value_expr);
        }
        break;
    }

    case AST_PROC_PARAM: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        register_symbol_ast(a, ast->proc_param.type_expr);
        if (ast->proc_param.value_expr)
        {
            register_symbol_ast(a, ast->proc_param.value_expr);
        }
        break;
    }

    case AST_STRUCT_FIELD: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        register_symbol_ast(a, ast->struct_field.type_expr);
        if (ast->struct_field.value_expr)
        {
            register_symbol_ast(a, ast->struct_field.value_expr);
        }
        break;
    }

    case AST_ENUM_FIELD: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        break;
    }

    case AST_TYPEDEF: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        if (ast->type_def.template_params.len == 0)
        {
            register_symbol_ast(a, ast->type_def.type_expr);
        }
        break;
    }

    case AST_IMPORT: {
        register_symbol_ast_leaf(a, ast, &ast->loc);
        break;
    }

    case AST_DISTINCT_TYPE: {
        register_symbol_ast(a, ast->distinct.sub);
        break;
    }

    case AST_STRUCT: {
        array_push(&a->scope_stack, ast->scope);
        for (Ast *field = ast->structure.fields.ptr;
             field != ast->structure.fields.ptr + ast->structure.fields.len;
             ++field)
        {
            register_symbol_ast(a, field);
        }
        array_pop(&a->scope_stack);

        break;
    }

    case AST_ENUM: {
        array_push(&a->scope_stack, ast->scope);
        for (Ast *field = ast->enumeration.fields.ptr;
             field != ast->enumeration.fields.ptr + ast->enumeration.fields.len;
             ++field)
        {
            register_symbol_ast(a, field);
        }
        array_pop(&a->scope_stack);

        break;
    }

    case AST_USING: {
        register_symbol_ast(a, ast->expr);
        break;
    }

    case AST_DEFER: {
        register_symbol_ast(a, ast->stmt);
        break;
    }

    case AST_IF: {
        register_symbol_ast(a, ast->if_stmt.cond_stmt);
        if (ast->if_stmt.else_stmt)
        {
            register_symbol_ast(a, ast->if_stmt.else_stmt);
        }
        break;
    }

    case AST_WHILE: {
        register_symbol_ast(a, ast->while_stmt.cond);
        register_symbol_ast(a, ast->while_stmt.stmt);
        break;
    }

    case AST_FOR: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        if (ast->for_stmt.init) register_symbol_ast(a, ast->for_stmt.init);
        if (ast->for_stmt.cond) register_symbol_ast(a, ast->for_stmt.cond);
        if (ast->for_stmt.inc) register_symbol_ast(a, ast->for_stmt.inc);
        register_symbol_ast(a, ast->for_stmt.stmt);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_PROC_DECL: {
        register_symbol_ast_leaf(a, ast, &ast->loc);

        if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
        {
            break;
        }

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *param = ast->proc.params.ptr;
             param != ast->proc.params.ptr + ast->proc.params.len;
             ++param)
        {
            register_symbol_ast(a, param);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);

        break;
    }

    default: return;
    }
}

static void analyze_ast(Analyzer *a, Ast *ast, TypeInfo *expected_type)
{
    bool is_statement = true;

    // Statements
    switch (ast->type)
    {
    case AST_UNINITIALIZED: assert(0); break;

    case AST_RETURN: {
        Scope *scope = *array_last(&a->scope_stack);

        Ast *proc = get_scope_procedure(scope);
        if (!proc)
        {
            compile_error(
                a->compiler, ast->loc, "return needs to be inside a procedure");
            break;
        }

        if (scope->ast && scope->ast->type == AST_PROC_DECL)
        {
            scope->ast->proc.returned = true;
        }

        TypeInfo *return_type = NULL;
        if (proc->type_info)
        {
            assert(proc->type_info->kind == TYPE_POINTER);
            return_type = proc->type_info->ptr.sub->proc.return_type;

            if (!ast->expr)
            {
                if (return_type->kind != TYPE_VOID)
                {
                    compile_error(
                        a->compiler,
                        ast->loc,
                        "procedure does not return void, 'return' must "
                        "contain "
                        "a value");
                    break;
                }
            }
        }

        if (ast->expr)
        {
            analyze_ast(a, ast->expr, return_type);
        }

        break;
    }

    case AST_ROOT: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        analyze_asts(a, ast->block.stmts.ptr, ast->block.stmts.len);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_BLOCK: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        analyze_asts(a, ast->block.stmts.ptr, ast->block.stmts.len);
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(a->compiler, ast->version_block.version))
        {
            analyze_asts(
                a, ast->version_block.stmts.ptr, ast->version_block.stmts.len);
        }

        break;
    }

    case AST_TYPEDEF: {
        if (ast->type_def.template_params.len == 0)
        {
            analyze_ast(a, ast->type_def.type_expr, &TYPE_OF_TYPE);
            if (ast->type_def.type_expr->as_type)
            {
                ast->type_def.type_expr->as_type->type_def = ast;
            }
        }
        break;
    }

    case AST_USING: {
        analyze_ast(a, ast->expr, NULL);

        Scope *expr_scope = get_expr_scope(
            a->compiler, *array_last(&a->scope_stack), ast->expr);

        if (!expr_scope)
        {
            compile_error(
                a->compiler,
                ast->expr->loc,
                "expression does not represent a scope to be used");
            break;
        }

        for (size_t i = 0; i < expr_scope->map->values.len; ++i)
        {
            Ast *sym = expr_scope->map->values.ptr[i];

            Scope *old_scope = sym->sym_scope;
            assert(old_scope);

            register_symbol_ast_leaf(a, sym, &ast->loc);

            sym->sym_scope = old_scope;
        }

        break;
    }

    case AST_DEFER: {
        analyze_ast(a, ast->stmt, NULL);
        break;
    }

    case AST_CONST_DECL: {
        if (ast->decl.type_expr)
        {
            analyze_ast(a, ast->decl.type_expr, &TYPE_OF_TYPE);

            if (!ast->decl.type_expr->as_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            ast->type_info = ast->decl.type_expr->as_type;
        }

        analyze_ast(a, ast->decl.value_expr, ast->type_info);

        if (!ast->type_info)
        {
            if (!ast->decl.value_expr->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not infer type for constant declaration");
                break;
            }

            ast->type_info = ast->decl.value_expr->type_info;
        }

        if (!is_expr_const(
                a->compiler,
                *array_last(&a->scope_stack),
                ast->decl.value_expr))
        {
            compile_error(
                a->compiler,
                ast->decl.value_expr->loc,
                "expression is not constant");
            break;
        }

        break;
    }

    case AST_VAR_DECL: {
        if (ast->decl.type_expr)
        {
            analyze_ast(a, ast->decl.type_expr, &TYPE_OF_TYPE);

            if (!ast->decl.type_expr->as_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            ast->type_info = ast->decl.type_expr->as_type;
        }

        if (ast->decl.value_expr)
        {
            if (ast->decl.type_expr &&
                ast->decl.value_expr->type == AST_PRIMARY &&
                ast->decl.value_expr->primary.tok->type == TOKEN_VOID)
            {
                // Unitialized variable
                ast->decl.uninitialized = true;
                break;
            }

            analyze_ast(a, ast->decl.value_expr, ast->type_info);

            if (!ast->decl.value_expr->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for variable declaration "
                    "initializer");
                break;
            }

            if (!ast->type_info)
            {
                ast->type_info = ast->decl.value_expr->type_info;
            }
        }
        break;
    }

    case AST_PROC_PARAM: {
        analyze_ast(a, ast->proc_param.type_expr, &TYPE_OF_TYPE);
        if (ast->proc_param.value_expr)
        {
            analyze_ast(
                a,
                ast->proc_param.value_expr,
                ast->proc_param.type_expr->as_type);
        }

        ast->type_info = ast->proc_param.type_expr->as_type;

        if (ast->flags & AST_FLAG_USING)
        {
            Scope *expr_scope =
                get_expr_scope(a->compiler, *array_last(&a->scope_stack), ast);

            if (!expr_scope)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "expression does not represent a scope to be used");
                break;
            }

            for (size_t i = 0; i < expr_scope->map->values.len; ++i)
            {
                Ast *sym = expr_scope->map->values.ptr[i];
                Scope *old_scope = sym->sym_scope;
                assert(old_scope);

                register_symbol_ast_leaf(a, sym, &ast->loc);

                sym->sym_scope = old_scope;
            }
        }

        break;
    }

    case AST_STRUCT_FIELD: {
        analyze_ast(a, ast->struct_field.type_expr, &TYPE_OF_TYPE);
        if (ast->struct_field.value_expr)
        {
            analyze_ast(
                a,
                ast->struct_field.value_expr,
                ast->struct_field.type_expr->as_type);
        }

        ast->type_info = ast->struct_field.type_expr->as_type;

        if (ast->flags & AST_FLAG_USING)
        {
            Scope *expr_scope =
                get_expr_scope(a->compiler, *array_last(&a->scope_stack), ast);

            if (!expr_scope)
            {
                compile_error(
                    a->compiler,
                    ast->expr->loc,
                    "expression does not represent a scope to be used");
                break;
            }

            array_push(&a->scope_stack, ast->sym_scope);
            for (size_t i = 0; i < expr_scope->map->size; ++i)
            {
                if (expr_scope->map->hashes[i] != 0)
                {
                    Ast *field_alias =
                        bump_alloc(&a->compiler->bump, sizeof(Ast));
                    memset(field_alias, 0, sizeof(*field_alias));
                    field_alias->loc = ast->loc;
                    field_alias->type = AST_STRUCT_FIELD_ALIAS;
                    field_alias->struct_field_alias.right_name =
                        expr_scope->map->keys[i];
                    field_alias->struct_field_alias.left_name =
                        ast->struct_field.name;

                    analyze_ast(a, field_alias, NULL);

                    register_symbol_ast_leaf(a, field_alias, &ast->loc);
                }
            }
            array_pop(&a->scope_stack);
        }

        break;
    }

    case AST_ENUM_FIELD: {
        if (!is_expr_const(
                a->compiler,
                *array_last(&a->scope_stack),
                ast->enum_field.value_expr))
        {
            compile_error(
                a->compiler,
                ast->enum_field.value_expr->loc,
                "expression is not constant");
            break;
        }

        if (!ast->sym_scope)
        {
            break;
        }

        Ast *enum_ast = ast->sym_scope->ast;
        assert(enum_ast);
        assert(enum_ast->type == AST_ENUM);

        TypeInfo *enum_type = enum_ast->as_type;
        if (!enum_type)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        assert(enum_type->kind == TYPE_ENUM);
        assert(enum_type->enumeration.underlying_type);

        analyze_ast(
            a,
            ast->enum_field.value_expr,
            enum_type->enumeration.underlying_type);

        ast->type_info = enum_ast->as_type;

        break;
    }

    case AST_VAR_ASSIGN: {
        analyze_ast(a, ast->assign.assigned_expr, NULL);
        if (!ast->assign.assigned_expr->type_info)
        {
            compile_error(
                a->compiler,
                ast->assign.assigned_expr->loc,
                "could not resolve type for assign destination expression");
            break;
        }

        analyze_ast(
            a, ast->assign.value_expr, ast->assign.assigned_expr->type_info);

        if (!ast->assign.value_expr->type_info)
        {
            compile_error(
                a->compiler,
                ast->assign.value_expr->loc,
                "could not resolve type for assigned expression");
            break;
        }

        if (!is_expr_assignable(
                a->compiler,
                *array_last(&a->scope_stack),
                ast->assign.assigned_expr))
        {
            compile_error(
                a->compiler,
                ast->assign.assigned_expr->loc,
                "expression is not assignable");
            break;
        }
        break;
    }

    case AST_EXPR_STMT: {
        analyze_ast(a, ast->expr, NULL);
        break;
    }

    case AST_PROC_DECL: {
        if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
        {
            break;
        }

        ast->proc.mangled_name = ast->proc.name;

        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        if (ast->proc.flags & PROC_FLAG_IS_C_VARARGS)
        {
            ty->flags |= TYPE_FLAG_C_VARARGS;
        }

        if (ast->flags & AST_FLAG_EXTERN)
        {
            ty->flags |= TYPE_FLAG_EXTERN;
        }

        bool valid_type = true;

        for (Ast *param = ast->proc.params.ptr;
             param != ast->proc.params.ptr + ast->proc.params.len;
             ++param)
        {
            analyze_ast(a, param, NULL);
            if (!param->decl.type_expr->as_type)
            {
                valid_type = false;
                break;
            }

            if ((ty->flags & TYPE_FLAG_EXTERN) == TYPE_FLAG_EXTERN &&
                is_type_compound(param->decl.type_expr->as_type))
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "extern functions cannot have compound parameters");
            }

            array_push(&ty->proc.params, param->decl.type_expr->as_type);
        }

        if (ast->proc.return_type)
        {
            analyze_ast(a, ast->proc.return_type, &TYPE_OF_TYPE);
            if (ast->proc.return_type->as_type)
            {
                ty->proc.return_type = ast->proc.return_type->as_type;
            }
        }
        else
        {
            ty->proc.return_type = &VOID_TYPE;
        }

        if (!ty->proc.return_type)
        {
            valid_type = false;
        }

        if (valid_type)
        {
            TypeInfo *ptr_ty = bump_alloc(&a->compiler->bump, sizeof(*ptr_ty));
            memset(ptr_ty, 0, sizeof(*ptr_ty));
            ptr_ty->kind = TYPE_POINTER;
            ptr_ty->ptr.sub = ty;
            ast->type_info = ptr_ty;

            TypeInfo *proc_type = ast->type_info->ptr.sub;

            if ((ast->flags & AST_FLAG_EXTERN) != AST_FLAG_EXTERN)
            {
                sb_reset(&a->compiler->sb);
                sb_append(
                    &a->compiler->sb, STR("_F")); // mangled function prefix
                sb_append(&a->compiler->sb, ast->proc.name);

                if (ast->proc.template_params.len > 0)
                {
                    for (size_t i = 0; i < proc_type->proc.params.len; ++i)
                    {
                        TypeInfo *param_type = proc_type->proc.params.ptr[i];
                        sb_append(&a->compiler->sb, STR("$"));
                        print_mangled_type(&a->compiler->sb, param_type);
                    }
                }

                ast->proc.mangled_name =
                    sb_build(&a->compiler->sb, &a->compiler->bump);
            }
        }
        break;
    }

    case AST_IF: {
        analyze_ast(a, ast->if_stmt.cond_expr, NULL);
        analyze_ast(a, ast->if_stmt.cond_stmt, NULL);
        if (ast->if_stmt.else_stmt)
        {
            analyze_ast(a, ast->if_stmt.else_stmt, NULL);
        }

        if (!ast->if_stmt.cond_expr->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (ast->if_stmt.cond_expr->type_info->kind != TYPE_INT &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_FLOAT &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_BOOL &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_POINTER)
        {
            compile_error(
                a->compiler,
                ast->if_stmt.cond_expr->loc,
                "conditional only works for numerical types");
            break;
        }

        break;
    }

    case AST_SWITCH: {
        analyze_ast(a, ast->switch_stmt.expr, NULL);

        TypeInfo *val_type = ast->switch_stmt.expr->type_info;

        if (!val_type)
        {
            compile_error(
                a->compiler,
                ast->switch_stmt.expr->loc,
                "could not resolve type for switch statement value");
            break;
        }

        if (!is_type_basic(val_type))
        {
            compile_error(
                a->compiler,
                ast->switch_stmt.expr->loc,
                "can only switch on basic types");
            break;
        }

        assert((ast->switch_stmt.vals.len) == (ast->switch_stmt.stmts.len));

        for (size_t i = 0; i < ast->switch_stmt.vals.len; ++i)
        {
            analyze_ast(a, &ast->switch_stmt.vals.ptr[i], val_type);

            array_push(&a->break_stack, ast);
            analyze_ast(a, &ast->switch_stmt.stmts.ptr[i], NULL);
            array_pop(&a->break_stack);
        }

        if (ast->switch_stmt.else_stmt)
        {
            array_push(&a->break_stack, ast);
            analyze_ast(a, ast->switch_stmt.else_stmt, NULL);
            array_pop(&a->break_stack);
        }

        break;
    }

    case AST_WHILE: {
        analyze_ast(a, ast->while_stmt.cond, NULL);

        array_push(&a->break_stack, ast);
        array_push(&a->continue_stack, ast);
        analyze_ast(a, ast->while_stmt.stmt, NULL);
        array_pop(&a->continue_stack);
        array_pop(&a->break_stack);

        if (!ast->while_stmt.cond->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (ast->while_stmt.cond->type_info->kind != TYPE_INT &&
            ast->while_stmt.cond->type_info->kind != TYPE_FLOAT &&
            ast->while_stmt.cond->type_info->kind != TYPE_BOOL &&
            ast->while_stmt.cond->type_info->kind != TYPE_POINTER)
        {
            compile_error(
                a->compiler,
                ast->for_stmt.cond->loc,
                "'while' statement only takes numerical types as "
                "conditions");
            break;
        }

        break;
    }

    case AST_FOR: {
        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);

        if (ast->for_stmt.init) analyze_ast(a, ast->for_stmt.init, NULL);
        if (ast->for_stmt.cond) analyze_ast(a, ast->for_stmt.cond, NULL);
        if (ast->for_stmt.inc) analyze_ast(a, ast->for_stmt.inc, NULL);

        array_push(&a->break_stack, ast);
        array_push(&a->continue_stack, ast);
        analyze_ast(a, ast->for_stmt.stmt, NULL);
        array_pop(&a->continue_stack);
        array_pop(&a->break_stack);

        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);

        if (ast->for_stmt.cond)
        {
            if (!ast->for_stmt.cond->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (ast->for_stmt.cond->type_info->kind != TYPE_INT &&
                ast->for_stmt.cond->type_info->kind != TYPE_FLOAT &&
                ast->for_stmt.cond->type_info->kind != TYPE_BOOL &&
                ast->for_stmt.cond->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->for_stmt.cond->loc,
                    "'for' statement only takes numerical types as "
                    "conditions");
                break;
            }
        }

        break;
    }

    case AST_BREAK: {
        if (a->break_stack.len == 0)
        {
            compile_error(
                a->compiler, ast->loc, "'break' outside control structure");
            break;
        }
        break;
    }

    case AST_CONTINUE: {
        if (a->continue_stack.len == 0)
        {
            compile_error(
                a->compiler, ast->loc, "'continue' outside control structure");
            break;
        }
        break;
    }

    default: {
        is_statement = false;
        break;
    }
    }

    if (is_statement)
    {
        return;
    }

    ast_as_type(a, *array_last(&a->scope_stack), ast, false);

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_U8:
        case TOKEN_U16:
        case TOKEN_U32:
        case TOKEN_U64:
        case TOKEN_I8:
        case TOKEN_I16:
        case TOKEN_I32:
        case TOKEN_I64:
        case TOKEN_INT:
        case TOKEN_UINT:
        case TOKEN_CHAR:
        case TOKEN_FLOAT:
        case TOKEN_DOUBLE:
        case TOKEN_BOOL:
        case TOKEN_VOID: {
            ast->type_info = &TYPE_OF_TYPE;
            break;
        }

        case TOKEN_NULL: {
            ast->type_info = &NULL_PTR_TYPE;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_POINTER: {
                    ast->type_info = expected_type;
                    break;
                }

                default: break;
                }
            }
            break;
        }

        case TOKEN_TRUE:
        case TOKEN_FALSE: {
            ast->type_info = &BOOL_TYPE;
            break;
        }

        case TOKEN_INT_LIT: {
            ast->type_info = &INT_LIT_TYPE;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_FLOAT:
                case TYPE_INT: {
                    ast->type_info = expected_type;
                    break;
                }
                default: break;
                }
            }

            break;
        }

        case TOKEN_FLOAT_LIT: {
            ast->type_info = &FLOAT_LIT_TYPE;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_FLOAT: {
                    ast->type_info = expected_type;
                    break;
                }
                default: break;
                }
            }

            break;
        }

        case TOKEN_STRING_LIT: {
            ast->type_info = create_array_type(
                a->compiler, &I8_TYPE, ast->primary.tok->str.length);
            break;
        }

        case TOKEN_CSTRING_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_POINTER,
                .ptr.sub = &I8_TYPE,
            };
            ast->type_info = &ty;
            break;
        }

        case TOKEN_CHAR_LIT: {
            ast->type_info = &I8_TYPE;
            break;
        }

        case TOKEN_IDENT: {
            Ast *sym = get_symbol(
                *array_last(&a->scope_stack),
                ast->primary.tok->str,
                ast->loc.file);

            if (!sym)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "invalid identifier: '%.*s'",
                    (int)ast->primary.tok->str.length,
                    ast->primary.tok->str.buf);
                break;
            }

            switch (sym->type)
            {
            case AST_PROC_DECL:
            case AST_ENUM_FIELD:
            case AST_STRUCT_FIELD:
            case AST_PROC_PARAM:
            case AST_VAR_DECL:
            case AST_CONST_DECL: {
                ast->type_info = sym->type_info;
                break;
            }

            case AST_STRUCT_FIELD_ALIAS: {
                ast->type = AST_ACCESS;

                ast->access.left = bump_alloc(&a->compiler->bump, sizeof(Ast));
                memset(ast->access.left, 0, sizeof(*ast->access.left));
                ast->access.left->loc = ast->loc;
                ast->access.left->type = AST_PRIMARY;
                ast->access.left->primary.tok =
                    bump_alloc(&a->compiler->bump, sizeof(Token));
                memset(
                    ast->access.left->primary.tok,
                    0,
                    sizeof(*ast->access.left->primary.tok));
                ast->access.left->primary.tok->type = TOKEN_IDENT;
                ast->access.left->primary.tok->str =
                    sym->struct_field_alias.left_name;

                ast->access.right = bump_alloc(&a->compiler->bump, sizeof(Ast));
                memset(ast->access.right, 0, sizeof(*ast->access.right));
                ast->access.right->loc = ast->loc;
                ast->access.right->type = AST_PRIMARY;
                ast->access.right->primary.tok =
                    bump_alloc(&a->compiler->bump, sizeof(Token));
                memset(
                    ast->access.right->primary.tok,
                    0,
                    sizeof(*ast->access.right->primary.tok));
                ast->access.right->primary.tok->type = TOKEN_IDENT;
                ast->access.right->primary.tok->str =
                    sym->struct_field_alias.right_name;

                analyze_ast(a, ast, expected_type);
                return;
            }

            case AST_IMPORT: {
                ast->type_info = &NAMESPACE_TYPE;
                break;
            }

            case AST_TYPEDEF: {
                ast->type_info = &TYPE_OF_TYPE;
                break;
            }

            case AST_BUILTIN_MAX:
            case AST_BUILTIN_MIN:
            case AST_BUILTIN_CAP:
            case AST_BUILTIN_PTR:
            case AST_BUILTIN_LEN:
            case AST_BUILTIN_VEC_ACCESS: {
                analyze_ast(a, sym, NULL);
                assert(sym->type_info);
                ast->type_info = sym->type_info;
                break;
            }

            default: break;
            }

            break;
        }

        default: break;
        }
        break;
    }

    case AST_TEMPLATE_INST: {
        Scope *scope = *array_last(&a->scope_stack);

        if (ast->template_inst.sub->type != AST_PRIMARY ||
            ast->template_inst.sub->primary.tok->type != TOKEN_IDENT)
        {
            compile_error(
                a->compiler,
                ast->template_inst.sub->loc,
                "template instantiation subexpression is not an "
                "identifier");
            break;
        }

        String name = ast->template_inst.sub->primary.tok->str;
        Ast *sym = get_symbol(scope, name, ast->loc.file);

        if (!sym)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "template instantiation subexpression does not refer to a "
                "symbol");
            break;
        }

        for (Ast *param = ast->template_inst.params.ptr;
             param !=
             ast->template_inst.params.ptr + ast->template_inst.params.len;
             ++param)
        {
            analyze_ast(a, param, &TYPE_OF_TYPE);
        }

        switch (sym->type)
        {
        case AST_TYPEDEF: {
            if (sym->type_def.template_params.len == 0)
            {
                compile_error(
                    a->compiler, ast->loc, "typedef is not a template");
                break;
            }

            if ((sym->type_def.template_params.len) !=
                (ast->template_inst.params.len))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong count of template parameters");
                break;
            }

            if (!ast->as_type)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "template instantiation did not resolve to a type");
                break;
            }

            ast->type_info = &TYPE_OF_TYPE;
            break;
        }

        case AST_PROC_DECL: {
            if ((sym->flags & AST_FLAG_IS_TEMPLATE) != AST_FLAG_IS_TEMPLATE)
            {
                compile_error(
                    a->compiler, sym->loc, "function is not a template");
                break;
            }

            if ((sym->proc.template_params.len) !=
                (ast->template_inst.params.len))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong count of template parameters");
                break;
            }

            assert(sym->proc.template_cache);

            sb_reset(&a->compiler->sb);
            for (size_t i = 0; i < ast->template_inst.params.len; ++i)
            {
                Ast *param = &ast->template_inst.params.ptr[i];
                sb_append(&a->compiler->sb, STR("$"));
                print_mangled_type(
                    &a->compiler->sb, ast_as_type(a, scope, param, false));
            }
            String mangled_type =
                sb_build(&a->compiler->sb, &a->compiler->bump);

            Ast *cached_ast = NULL;
            if (hash_get(
                    sym->proc.template_cache,
                    mangled_type,
                    (void **)&cached_ast))
            {
                assert(cached_ast);
                ast->type_info = cached_ast->type_info;
                ast->as_type = cached_ast->as_type;
                ast->template_inst.resolves_to = cached_ast;

                break;
            }

            Ast *cloned_ast = bump_alloc(&a->compiler->bump, sizeof(Ast));
            memset(cloned_ast, 0, sizeof(Ast));

            hash_set(sym->proc.template_cache, mangled_type, cloned_ast);

            instantiate_template(
                a->compiler,
                cloned_ast,
                sym,
                sym->proc.template_params,
                ast->template_inst.params);

            create_scopes_ast(a, cloned_ast);
            register_symbol_asts(a, cloned_ast, 1);
            analyze_asts(a, cloned_ast, 1);

            ast->as_type = cloned_ast->as_type;
            ast->type_info = cloned_ast->type_info;
            ast->template_inst.resolves_to = cloned_ast;

            break;
        }

        default: {
            compile_error(
                a->compiler, ast->loc, "tried to instantiate a non-template");
            break;
        }
        }

        if (!ast->type_info)
        {
            compile_error(
                a->compiler, ast->loc, "failed to instantiate template");
            break;
        }

        break;
    }

    case AST_BUILTIN_VEC_ACCESS: {
        Scope *scope = *array_last(&a->scope_stack);
        TypeInfo *type = scope->type_info;

        switch (type->kind)
        {
        case TYPE_VECTOR: ast->type_info = type->array.sub; break;

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_LEN: {
        Scope *scope = *array_last(&a->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE:
        case TYPE_ARRAY:
        case TYPE_VECTOR: ast->type_info = &UINT_TYPE; break;

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_CAP: {
        Scope *scope = *array_last(&a->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY: ast->type_info = &UINT_TYPE; break;

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_PTR: {
        Scope *scope = *array_last(&a->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE:
        case TYPE_ARRAY:
            ast->type_info = bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
            memset(ast->type_info, 0, sizeof(TypeInfo));
            ast->type_info->kind = TYPE_POINTER;
            ast->type_info->ptr.sub = type->array.sub;
            break;

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_MIN:
    case AST_BUILTIN_MAX: {
        Scope *scope = *array_last(&a->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        switch (type->kind)
        {
        case TYPE_FLOAT:
        case TYPE_INT: ast->type_info = type; break;

        default: assert(0); break;
        }

        break;
    }

    case AST_DISTINCT_TYPE: {
        analyze_ast(a, ast->distinct.sub, &TYPE_OF_TYPE);
        ast->type_info = ast->distinct.sub->type_info;
        break;
    }

    case AST_PROC_CALL: {
        analyze_ast(a, ast->proc_call.expr, NULL);
        if (!ast->proc_call.expr->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;

        if (ast->proc_call.expr->type_info->kind != TYPE_POINTER ||
            ast->proc_call.expr->type_info->ptr.sub->kind != TYPE_PROC)
        {
            compile_error(
                a->compiler, ast->loc, "tried to call a non procedure type");
            break;
        }

        TypeInfo *proc_ty = proc_ptr_ty->ptr.sub;

        assert(proc_ty);
        ast->type_info = proc_ty->proc.return_type;

        if ((proc_ty->flags & TYPE_FLAG_C_VARARGS) != TYPE_FLAG_C_VARARGS)
        {
            if ((ast->proc_call.params.len) != (proc_ty->proc.params.len))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong parameter count for function call");
                break;
            }
        }
        else
        {
            if ((ast->proc_call.params.len) < (proc_ty->proc.params.len))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong parameter count for function call");
                break;
            }
        }

        assert(a->operand_scope_stack.len > 0);

        array_push(&a->scope_stack, *array_last(&a->operand_scope_stack));
        for (size_t i = 0; i < ast->proc_call.params.len; ++i)
        {
            TypeInfo *param_expected_type = NULL;
            if (i < proc_ty->proc.params.len)
            {
                param_expected_type = proc_ty->proc.params.ptr[i];
            }
            analyze_ast(a, &ast->proc_call.params.ptr[i], param_expected_type);
        }
        array_pop(&a->scope_stack);
        break;
    }

    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            if (ast->intrinsic_call.params.len != 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@sizeof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params.ptr[0];
            analyze_ast(a, param, NULL);

            if (!param->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (param->type_info->kind == TYPE_VOID ||
                param->type_info->kind == TYPE_NAMESPACE)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "@sizeof does not apply for this type");
                break;
            }

            ast->type_info = &UINT_TYPE;

            break;
        }

        case INTRINSIC_ALIGNOF: {
            if (ast->intrinsic_call.params.len != 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@alignof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params.ptr[0];
            analyze_ast(a, param, NULL);

            if (!param->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (param->type_info->kind == TYPE_VOID ||
                param->type_info->kind == TYPE_NAMESPACE)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "@alignof does not apply for this type");
                break;
            }

            ast->type_info = &UINT_TYPE;

            break;
        }

        case INTRINSIC_COS:
        case INTRINSIC_SIN:
        case INTRINSIC_SQRT: {
            if (ast->intrinsic_call.params.len != 1)
            {
                compile_error(
                    a->compiler, ast->loc, "intrinsic takes one parameter");

                break;
            }

            Ast *param = &ast->intrinsic_call.params.ptr[0];
            analyze_ast(a, param, NULL);

            if (!param->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (param->type_info->kind != TYPE_FLOAT)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "intrinsic does not apply for this type");
                break;
            }

            ast->type_info = param->type_info;

            break;
        }

        case INTRINSIC_VECTOR_TYPE: {
            if (ast->intrinsic_call.params.len != 2)
            {
                compile_error(
                    a->compiler, ast->loc, "intrinsic takes 2 parameters");

                break;
            }

            Ast *elem_type = &ast->intrinsic_call.params.ptr[0];
            Ast *vec_width = &ast->intrinsic_call.params.ptr[1];
            analyze_ast(a, elem_type, &TYPE_OF_TYPE);
            analyze_ast(a, vec_width, &UINT_TYPE);

            if (!elem_type->type_info || !vec_width->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (!elem_type->as_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (elem_type->as_type->kind != TYPE_FLOAT)
            {
                compile_error(
                    a->compiler,
                    elem_type->loc,
                    "intrinsic does not apply for this type");
                break;
            }

            ast->type_info = &TYPE_OF_TYPE;

            break;
        }
        }

        break;
    }

    case AST_PROC_TYPE: {
        for (Ast *param = ast->proc.params.ptr;
             param != ast->proc.params.ptr + ast->proc.params.len;
             ++param)
        {
            analyze_ast(a, param, NULL);

            if (param->decl.type_expr->as_type)
            {
                if ((ast->flags & AST_FLAG_EXTERN) == AST_FLAG_EXTERN &&
                    is_type_compound(param->decl.type_expr->as_type))
                {
                    compile_error(
                        a->compiler,
                        param->loc,
                        "extern functions cannot have compound parameters");
                    break;
                }
            }
        }

        if (!ast->as_type)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "invalid procedure pointer type expression");
            break;
        }

        if (ast->proc.return_type)
        {
            analyze_ast(a, ast->proc.return_type, &TYPE_OF_TYPE);
        }

        ast->type_info = &TYPE_OF_TYPE;

        break;
    }

    case AST_CAST: {
        analyze_ast(a, ast->cast.type_expr, &TYPE_OF_TYPE);
        analyze_ast(a, ast->cast.value_expr, NULL);

        TypeInfo *dest_ty = ast->cast.type_expr->as_type;
        TypeInfo *src_ty = ast->cast.value_expr->type_info;

        if (dest_ty && src_ty)
        {
            // Check if type is castable

            if (!((dest_ty->kind == TYPE_POINTER &&
                   src_ty->kind == TYPE_POINTER) ||
                  (dest_ty->kind == TYPE_POINTER && src_ty->kind == TYPE_INT) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_POINTER) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_INT) ||
                  (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_FLOAT) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_FLOAT) ||
                  (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_INT)))
            {
                compile_error(a->compiler, ast->loc, "invalid cast");
                break;
            }
        }
        else
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        ast->type_info = dest_ty;

        break;
    }

    case AST_UNARY_EXPR: {
        TypeInfo *sub_expected_type = NULL;

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: break;
        case UNOP_ADDRESS: {
            if (expected_type && expected_type->kind == TYPE_POINTER)
            {
                sub_expected_type = expected_type->ptr.sub;
            }
            break;
        }
        case UNOP_NEG: sub_expected_type = expected_type; break;
        case UNOP_NOT: break;
        }

        analyze_ast(a, ast->unop.sub, sub_expected_type);

        if (!ast->unop.sub->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast->unop.sub->type_info->kind == TYPE_TYPE)
            {
                TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_TYPE;
                ast->type_info = ty;
                break;
            }

            if (ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "you can only dereference pointer types");
                break;
            }

            ast->type_info = ast->unop.sub->type_info->ptr.sub;
            break;
        }

        case UNOP_ADDRESS: {
            TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_POINTER;
            ty->ptr.sub = ast->unop.sub->type_info;
            ast->type_info = ty;
            break;
        }

        case UNOP_NEG: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT &&
                ast->unop.sub->type_info->kind != TYPE_VECTOR)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do arithmetic on numeric types");
                break;
            }

            ast->type_info = ast->unop.sub->type_info;

            break;
        }

        case UNOP_NOT: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT &&
                ast->unop.sub->type_info->kind != TYPE_BOOL &&
                ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "operator '!' only works on logical types");
                break;
            }

            ast->type_info = &BOOL_TYPE;
            break;
        }
        }

        break;
    }

    case AST_BINARY_EXPR: {
        switch (ast->binop.type)
        {
        case BINOP_ADD:
        case BINOP_SUB:
        case BINOP_MUL:
        case BINOP_DIV:
        case BINOP_MOD: {
            TypeInfo *operand_expected_type = expected_type;

            if (expected_type && expected_type->kind == TYPE_VECTOR)
            {
                operand_expected_type = NULL;
            }

            analyze_ast(a, ast->binop.left, operand_expected_type);
            analyze_ast(a, ast->binop.right, operand_expected_type);

            TypeInfo *left_type = get_inner_type(ast->binop.left->type_info);
            TypeInfo *right_type = get_inner_type(ast->binop.right->type_info);

            if (!left_type || !right_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (left_type->kind != TYPE_INT && left_type->kind != TYPE_FLOAT &&
                left_type->kind != TYPE_VECTOR)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do arithmetic on numeric types");
                break;
            }

            TypeInfo *result_type = left_type;

            if (left_type->kind == TYPE_VECTOR &&
                right_type->kind != TYPE_VECTOR)
            {
                result_type = left_type;
                left_type = left_type->array.sub;

                TypeInfo *common_type =
                    common_numeric_type(left_type, right_type);
                analyze_ast(a, ast->binop.right, common_type);
                right_type = get_inner_type(ast->binop.right->type_info);
            }
            else if (
                right_type->kind == TYPE_VECTOR &&
                left_type->kind != TYPE_VECTOR && !ast->binop.assign)
            {
                result_type = right_type;
                right_type = right_type->array.sub;

                TypeInfo *common_type =
                    common_numeric_type(left_type, right_type);
                analyze_ast(a, ast->binop.left, common_type);
                left_type = get_inner_type(ast->binop.left->type_info);
            }
            else
            {
                if (expected_type == NULL)
                {
                    TypeInfo *common_type =
                        common_numeric_type(left_type, right_type);
                    analyze_ast(a, ast->binop.left, common_type);
                    analyze_ast(a, ast->binop.right, common_type);
                    left_type = get_inner_type(ast->binop.left->type_info);
                    right_type = get_inner_type(ast->binop.right->type_info);
                    result_type = left_type;
                }
            }

            if (!exact_types(left_type, right_type))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            ast->type_info = result_type;

            break;
        }

        case BINOP_LSHIFT:
        case BINOP_RSHIFT:
        case BINOP_BITAND:
        case BINOP_BITOR:
        case BINOP_BITXOR: {
            analyze_ast(a, ast->binop.left, expected_type);
            analyze_ast(a, ast->binop.right, expected_type);

            TypeInfo *left_type = get_inner_type(ast->binop.left->type_info);
            TypeInfo *right_type = get_inner_type(ast->binop.right->type_info);

            if (!left_type || !right_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (expected_type == NULL)
            {
                TypeInfo *common_type =
                    common_numeric_type(left_type, right_type);
                analyze_ast(a, ast->binop.left, common_type);
                analyze_ast(a, ast->binop.right, common_type);

                left_type = get_inner_type(ast->binop.left->type_info);
                right_type = get_inner_type(ast->binop.right->type_info);
            }

            if (!exact_types(left_type, right_type))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            if (left_type->kind != TYPE_INT && left_type->kind != TYPE_BOOL)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do bitwise operations on integer types");
                break;
            }

            ast->type_info = left_type;

            break;
        }

        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ: {
            analyze_ast(a, ast->binop.left, NULL);
            analyze_ast(a, ast->binop.right, NULL);

            TypeInfo *left_type = get_inner_type(ast->binop.left->type_info);
            TypeInfo *right_type = get_inner_type(ast->binop.right->type_info);

            if (!left_type || !right_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            TypeInfo *common_type = common_numeric_type(left_type, right_type);
            analyze_ast(a, ast->binop.left, common_type);
            analyze_ast(a, ast->binop.right, common_type);
            left_type = get_inner_type(ast->binop.left->type_info);
            right_type = get_inner_type(ast->binop.right->type_info);

            if (!exact_types(left_type, right_type))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "comparison binary operands are of different types");
                break;
            }

            if (left_type->kind != TYPE_BOOL && left_type->kind != TYPE_INT &&
                left_type->kind != TYPE_FLOAT &&
                left_type->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do comparison on numeric types");
                break;
            }

            ast->type_info = &BOOL_TYPE;

            break;
        }

        case BINOP_AND:
        case BINOP_OR: {
            analyze_ast(a, ast->binop.left, NULL);
            analyze_ast(a, ast->binop.right, NULL);

            TypeInfo *left_type = get_inner_type(ast->binop.left->type_info);
            TypeInfo *right_type = get_inner_type(ast->binop.right->type_info);

            if (!left_type || !right_type)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (left_type->kind != TYPE_BOOL && left_type->kind != TYPE_INT &&
                left_type->kind != TYPE_FLOAT &&
                left_type->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.left->loc,
                    "left operand of logical operator has invalid type");
                break;
            }

            if (right_type->kind != TYPE_BOOL && right_type->kind != TYPE_INT &&
                right_type->kind != TYPE_FLOAT &&
                right_type->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.right->loc,
                    "right operand of logical operator has invalid type");
                break;
            }

            ast->type_info = &BOOL_TYPE;

            break;
        }
        }

        break;
    }

    case AST_COMPOUND_LIT: {
        if (ast->compound.type_expr->type == AST_ARRAY_TYPE &&
            !ast->compound.type_expr->array_type.size)
        {
            // Array compound with no size
            Token *tok = bump_alloc(&a->compiler->bump, sizeof(Token));
            memset(tok, 0, sizeof(Token));
            tok->type = TOKEN_INT_LIT;
            tok->loc = ast->compound.type_expr->loc;
            tok->i64 = (int64_t)ast->compound.values.len;

            Ast *size = bump_alloc(&a->compiler->bump, sizeof(Ast));
            memset(size, 0, sizeof(Ast));
            size->type = AST_PRIMARY;
            size->loc = ast->compound.type_expr->loc;
            size->primary.tok = tok;

            ast->compound.type_expr->array_type.size = size;
        }

        analyze_ast(a, ast->compound.type_expr, &TYPE_OF_TYPE);

        if (!ast->compound.type_expr->as_type)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        TypeInfo *compound_type = ast->compound.type_expr->as_type;
        ast->type_info = compound_type;

        switch (compound_type->kind)
        {
        case TYPE_VECTOR:
        case TYPE_ARRAY: {
            if ((ast->compound.values.len) != compound_type->array.size &&
                (ast->compound.values.len) != 1 &&
                (ast->compound.values.len) != 0)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "compound literal has wrong number of values");
            }

            for (Ast *value = ast->compound.values.ptr;
                 value != ast->compound.values.ptr + ast->compound.values.len;
                 ++value)
            {
                analyze_ast(a, value, compound_type->array.sub);
            }

            break;
        }

        case TYPE_STRUCT: {
            if ((ast->compound.values.len) !=
                    (compound_type->structure.fields.len) &&
                (ast->compound.values.len) != 0)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "compound literal has wrong number of values");
            }

            for (size_t i = 0; i < ast->compound.values.len; ++i)
            {
                analyze_ast(
                    a,
                    &ast->compound.values.ptr[i],
                    compound_type->structure.fields.ptr[i]);
            }

            break;
        }

        default: {
            compile_error(
                a->compiler,
                ast->compound.type_expr->loc,
                "type unsupported by compound literal");
            break;
        }
        }

        break;
    }

    case AST_SUBSCRIPT: {
        analyze_ast(a, ast->subscript.left, NULL);

        array_push(&a->scope_stack, *array_last(&a->operand_scope_stack));
        analyze_ast(a, ast->subscript.right, NULL);
        array_pop(&a->scope_stack);

        if (!ast->subscript.left->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (!ast->subscript.right->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (ast->subscript.left->type_info->kind != TYPE_POINTER &&
            ast->subscript.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript.left->type_info->kind != TYPE_VECTOR &&
            ast->subscript.left->type_info->kind != TYPE_SLICE &&
            ast->subscript.left->type_info->kind != TYPE_DYNAMIC_ARRAY)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE:
        case TYPE_VECTOR:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript.left->type_info->array.sub;
            break;
        }

        case TYPE_POINTER: {
            ast->type_info = ast->subscript.left->type_info->ptr.sub;
            break;
        }
        default: assert(0); break;
        }

        if (ast->subscript.right->type_info->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "subscript needs an integer index");
            break;
        }
        break;
    }

    case AST_SUBSCRIPT_SLICE: {
        analyze_ast(a, ast->subscript_slice.left, NULL);
        array_push(&a->scope_stack, *array_last(&a->operand_scope_stack));
        if (ast->subscript_slice.lower)
        {
            analyze_ast(a, ast->subscript_slice.lower, &UINT_TYPE);
        }
        if (ast->subscript_slice.upper)
        {
            analyze_ast(a, ast->subscript_slice.upper, &UINT_TYPE);
        }
        array_pop(&a->scope_stack);

        if (!ast->subscript_slice.left->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (ast->subscript_slice.lower && ast->subscript_slice.upper)
        {
            if (!ast->subscript_slice.lower->type_info ||
                !ast->subscript_slice.upper->type_info)
            {
                assert(a->compiler->errors.len > 0);
                break;
            }

            if (!exact_types(
                    ast->subscript_slice.lower->type_info,
                    ast->subscript_slice.upper->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "slice subscript lower and upper bounds need to be of "
                    "same "
                    "type");
                break;
            }
        }

        if (ast->subscript_slice.left->type_info->kind != TYPE_POINTER &&
            ast->subscript_slice.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript_slice.left->type_info->kind != TYPE_SLICE &&
            ast->subscript_slice.left->type_info->kind != TYPE_DYNAMIC_ARRAY)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        TypeInfo *subtype = NULL;

        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            subtype = ast->subscript_slice.left->type_info->array.sub;
            break;
        }

        case TYPE_POINTER: {
            subtype = ast->subscript_slice.left->type_info->ptr.sub;
            break;
        }
        default: assert(0); break;
        }

        ast->type_info = create_slice_type(a->compiler, subtype);

        break;
    }

    case AST_ARRAY_TYPE: {
        ast->type_info = &TYPE_OF_TYPE;

        analyze_ast(a, ast->array_type.sub, &TYPE_OF_TYPE);

        if (!ast->array_type.size)
        {
            compile_error(a->compiler, ast->loc, "missing size for array type");
            break;
        }

        analyze_ast(a, ast->array_type.size, NULL);

        TypeInfo *size_type = get_inner_type(ast->array_type.size->type_info);
        if (!size_type)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        if (size_type->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "array type needs an integer size");
            break;
        }

        // Recompute as_type after getting the size's type
        ast_as_type(a, *array_last(&a->scope_stack), ast, false);

        if (!ast->as_type)
        {
            if (ast->array_type.sub->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve size for array type");
                break;
            }

            assert(a->compiler->errors.len > 0);
            break;
        }

        if (!ast->array_type.size->type_info)
        {
            assert(a->compiler->errors.len > 0);
            break;
        }

        break;
    }

    case AST_DYNAMIC_ARRAY_TYPE:
    case AST_SLICE_TYPE: {
        ast->type_info = &TYPE_OF_TYPE;
        analyze_ast(a, ast->array_type.sub, &TYPE_OF_TYPE);

        break;
    }

    case AST_STRUCT: {
        ast->type_info = &TYPE_OF_TYPE;

        for (Ast *field = ast->structure.fields.ptr;
             field != ast->structure.fields.ptr + ast->structure.fields.len;
             ++field)
        {
            analyze_ast(a, field, NULL);
        }
        break;
    }

    case AST_ENUM: {
        ast->type_info = &TYPE_OF_TYPE;

        analyze_ast(a, ast->enumeration.type_expr, &TYPE_OF_TYPE);

        array_push(&a->scope_stack, ast->scope);
        array_push(&a->operand_scope_stack, ast->scope);
        for (Ast *field = ast->enumeration.fields.ptr;
             field != ast->enumeration.fields.ptr + ast->enumeration.fields.len;
             ++field)
        {
            analyze_ast(a, field, NULL);
        }
        array_pop(&a->operand_scope_stack);
        array_pop(&a->scope_stack);
        break;
    }

    case AST_ACCESS: {
        analyze_ast(a, ast->access.left, NULL);

        if (!ast->access.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "invalid access: could not resolve type of left "
                "expression");
            break;
        }

        if (ast->access.left->type_info->kind == TYPE_POINTER)
        {
            // Dereference left if it's a pointer

            Ast *new_left = bump_alloc(&a->compiler->bump, sizeof(Ast));
            *new_left = *ast->access.left;

            memset(ast->access.left, 0, sizeof(Ast));
            ast->access.left->loc = new_left->loc;
            ast->access.left->type = AST_UNARY_EXPR;
            ast->access.left->unop.type = UNOP_DEREFERENCE;
            ast->access.left->unop.sub = new_left;

            analyze_ast(a, ast->access.left, NULL);
        }

        Scope *accessed_scope = get_expr_scope(
            a->compiler, *array_last(&a->scope_stack), ast->access.left);

        if (!accessed_scope)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "invalid access: could not get scope for left expression");
            break;
        }

        array_push(&a->scope_stack, accessed_scope);
        analyze_ast(a, ast->access.right, NULL);
        array_pop(&a->scope_stack);

        if (!ast->access.right->type_info)
        {
            compile_error(
                a->compiler,
                ast->access.right->loc,
                "invalid access: could not resolve type of right "
                "expression");
            break;
        }

        ast->type_info = ast->access.right->type_info;

        break;
    }
    default: break;
    }

#if 0
    if (!ast->type_info)
    {
        printf(
            "undefined type: %u:%u (%u)\n",
            ast->loc.line,
            ast->loc.col,
            ast->loc.length);
    }
#endif

    if (ast->type_info && expected_type)
    {
        // Automatically convert arrays to slices
        if (ast->type_info->kind == TYPE_ARRAY &&
            expected_type->kind == TYPE_SLICE)
        {
            if (exact_types(
                    ast->type_info->array.sub, expected_type->array.sub))
            {
                Ast *wrapped = bump_alloc(&a->compiler->bump, sizeof(Ast));
                *wrapped = *ast;

                ast->type = AST_SUBSCRIPT_SLICE;
                ast->subscript_slice.left = wrapped;
                ast->subscript_slice.lower = NULL;
                ast->subscript_slice.upper = NULL;

                analyze_ast(a, ast, expected_type);
                return;
            }
        }

        if (!exact_types(ast->type_info, expected_type) &&
            !compatible_pointer_types(ast->type_info, expected_type))
        {
            sb_reset(&a->compiler->sb);
            sb_append(&a->compiler->sb, STR("wrong type, expected "));
            print_mangled_type(&a->compiler->sb, expected_type);
            sb_append(&a->compiler->sb, STR(", got "));
            print_mangled_type(&a->compiler->sb, ast->type_info);
            String error = sb_build(&a->compiler->sb, &a->compiler->bump);
            compile_error(a->compiler, ast->loc, "%.*s", PRINT_STR(error));
        }
    }
}

static void register_symbol_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_TYPEDEF:
        case AST_PROC_DECL: {
            register_symbol_ast(a, ast);
            break;
        }

        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_TYPEDEF:
        case AST_PROC_DECL: {
            break;
        }

        default: {
            register_symbol_ast(a, ast);
            break;
        }
        }
    }

    // Analyze children ASTs
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: {
            if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
            {
                break;
            }

            array_push(&a->scope_stack, ast->scope);
            array_push(&a->operand_scope_stack, ast->scope);
            register_symbol_asts(a, ast->proc.stmts.ptr, ast->proc.stmts.len);
            array_pop(&a->operand_scope_stack);
            array_pop(&a->scope_stack);
            break;
        }

        default: break;
        }
    }
}

static void analyze_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_TYPEDEF:
        case AST_PROC_DECL: {
            analyze_ast(a, ast, NULL);
            break;
        }

        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_TYPEDEF:
        case AST_PROC_DECL: {
            break;
        }

        default: {
            analyze_ast(a, ast, NULL);
            break;
        }
        }
    }

    // Analyze children ASTs
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: {
            if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
            {
                break;
            }

            array_push(&a->scope_stack, ast->scope);
            array_push(&a->operand_scope_stack, ast->scope);
            analyze_asts(a, ast->proc.stmts.ptr, ast->proc.stmts.len);
            array_pop(&a->operand_scope_stack);
            array_pop(&a->scope_stack);

            TypeInfo *proc_type = ast->type_info;

            if (proc_type)
            {
                assert(proc_type->kind == TYPE_POINTER);
                if (proc_type->ptr.sub->proc.return_type->kind != TYPE_VOID &&
                    (ast->proc.flags & PROC_FLAG_HAS_BODY))
                {
                    if (!ast->proc.returned)
                    {
                        compile_error(
                            a->compiler, ast->loc, "procedure did not return");
                    }
                }
            }

            break;
        }

        default: break;
        }
    }
}
