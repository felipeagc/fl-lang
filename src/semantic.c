typedef struct Analyzer
{
    Compiler *compiler;
    /*array*/ Scope **scope_stack;
    /*array*/ Scope **operand_scope_stack;
    /*array*/ Ast **break_stack;
    /*array*/ Ast **continue_stack;
} Analyzer;

static inline Ast *get_inner_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_PAREN_EXPR: return get_inner_expr(ast->expr);
    default: break;
    }

    return ast;
}

static bool is_expr_const(Scope *scope, Ast *ast)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
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
    case AST_PAREN_EXPR: {
        res = is_expr_const(scope, ast->expr);
        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF:
        case INTRINSIC_ALIGNOF: res = true; break;
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
            res = is_expr_const(scope, ast->unop.sub);
            break;
        }
        }
        break;
    }
    case AST_BINARY_EXPR: {
        res = true;

        if (!is_expr_const(scope, ast->binop.left)) res = false;
        if (!is_expr_const(scope, ast->binop.right)) res = false;

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
    default: break;
    }

    return res;
}

static bool resolve_expr_int(Scope *scope, Ast *ast, int64_t *i64)
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
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_CONST_DECL: {
                    assert(sym->sym_scope);
                    res = resolve_expr_int(
                        sym->sym_scope, sym->decl.value_expr, i64);
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
    case AST_PAREN_EXPR: {
        res = resolve_expr_int(scope, ast->expr, i64);
        break;
    }
    default: break;
    }

    return res;
}

static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast);

static TypeInfo *ast_as_type(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->as_type) return ast->as_type;

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_U8: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 8}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U16: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 16}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U32: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 32}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U64: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 64}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_CHAR:
        case TOKEN_I8: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 8}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I16: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 16}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I32: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 32}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I64: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_FLOAT: {
            static TypeInfo ty = {.kind = TYPE_FLOAT, .floating.num_bits = 32};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_DOUBLE: {
            static TypeInfo ty = {.kind = TYPE_FLOAT, .floating.num_bits = 64};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_BOOL: {
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_VOID};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym && sym->type == AST_TYPEDEF)
            {
                assert(sym->sym_scope);
                if (ast_as_type(
                        compiler, sym->sym_scope, sym->type_def.type_expr))
                {
                    ast->as_type = sym->type_def.type_expr->as_type;
                }
            }

            break;
        }
        default: break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        ast->as_type = ast_as_type(compiler, scope, ast->expr);
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast_as_type(compiler, scope, ast->unop.sub))
            {
                TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
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
        int64_t size = 0;
        bool resolves = resolve_expr_int(scope, ast->array_type.size, &size);
        bool res = true;

        if (!ast_as_type(compiler, scope, ast->array_type.sub)) res = false;

        if (!resolves)
        {
            compile_error(
                compiler,
                ast->array_type.size->loc,
                "expression does not resolve to integer");
            res = false;
        }

        if (resolves && size <= 0)
        {
            compile_error(
                compiler,
                ast->array_type.size->loc,
                "array size must be larger than zero");
            res = false;
        }

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_ARRAY;
            ty->array.sub = ast->array_type.sub->as_type;
            ty->array.size = size;
            ast->as_type = ty;
        }
        break;
    }
    case AST_SLICE_TYPE: {
        bool res = true;

        if (!ast_as_type(compiler, scope, ast->array_type.sub)) res = false;

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_SLICE;
            ty->array.sub = ast->array_type.sub->as_type;
            ast->as_type = ty;
        }
        break;
    }
    case AST_STRUCT: {
        TypeInfo **fields = NULL;
        bool res = true;

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            if (!ast_as_type(compiler, scope, field->field.type_expr))
            {
                res = false;
            }
            array_push(fields, field->field.type_expr->as_type);
        }

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_STRUCT;
            ty->structure.fields = fields;
            ty->structure.scope = ast->structure.scope;
            ast->as_type = ty;
        }
        break;
    }
    case AST_PROC_TYPE: {
        TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            array_push(
                ty->proc.params,
                *ast_as_type(compiler, scope, param->decl.type_expr));
        }

        ty->proc.return_type =
            ast_as_type(compiler, scope, ast->proc.return_type);

        TypeInfo *ptr_ty = bump_alloc(&compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        ast->as_type = ptr_ty;
        break;
    }
    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            ast->as_type =
                ast_as_type(compiler, accessed_scope, ast->access.right);
        }
        break;
    }
    default: break;
    }

    return ast->as_type;
}

static void get_expr_type(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->type_info && !ast->type_info->can_change) return;

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
        case TOKEN_CHAR:
        case TOKEN_FLOAT:
        case TOKEN_DOUBLE:
        case TOKEN_BOOL:
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_TYPE};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_NULL: {
            static TypeInfo void_ty = {.kind = TYPE_VOID};
            static TypeInfo void_ptr_ty = {
                .kind = TYPE_POINTER, .ptr.sub = &void_ty, .can_change = true};
            ast->type_info = &void_ptr_ty;
            break;
        }
        case TOKEN_TRUE:
        case TOKEN_FALSE: {
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_INT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .can_change = true,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_FLOAT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_FLOAT,
                .floating.num_bits = 64,
                .can_change = true,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_CSTRING_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            static TypeInfo ty = {
                .kind = TYPE_POINTER,
                .ptr.sub = &i8_ty,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_CHAR_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            ast->type_info = &i8_ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_VAR_DECL:
                case AST_CONST_DECL: {
                    ast_as_type(compiler, sym->sym_scope, sym->decl.type_expr);
                    ast->type_info = sym->decl.type_expr->as_type;
                    break;
                }
                case AST_PROC_PARAM: {
                    ast_as_type(
                        compiler, sym->sym_scope, sym->proc_param.type_expr);
                    ast->type_info = sym->proc_param.type_expr->as_type;
                    break;
                }
                case AST_STRUCT_FIELD: {
                    ast_as_type(compiler, sym->sym_scope, sym->field.type_expr);
                    ast->type_info = sym->field.type_expr->as_type;
                    break;
                }
                case AST_PROC_DECL: {
                    get_expr_type(compiler, sym->sym_scope, sym);
                    ast->type_info = sym->type_info;
                    break;
                }
                case AST_IMPORT: {
                    static TypeInfo namespace_ty = {.kind = TYPE_NAMESPACE};
                    ast->type_info = &namespace_ty;
                    break;
                }
                case AST_TYPEDEF: {
                    static TypeInfo ty_ty = {.kind = TYPE_TYPE};
                    ast->type_info = &ty_ty;
                    break;
                }
                default: break;
                }
            }

            break;
        }
        default: assert(0); break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        get_expr_type(compiler, scope, ast->expr);
        ast->type_info = ast->expr->type_info;
        break;
    }
    case AST_PROC_CALL: {
        get_expr_type(compiler, scope, ast->proc_call.expr);

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;
        if (proc_ptr_ty && proc_ptr_ty->kind == TYPE_POINTER &&
            proc_ptr_ty->ptr.sub->kind == TYPE_PROC)
        {
            ast->type_info = proc_ptr_ty->ptr.sub->proc.return_type;
        }
        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            ast->type_info = &SIZE_INT_TYPE;
            break;
        }
        case INTRINSIC_ALIGNOF: {
            ast->type_info = &SIZE_INT_TYPE;
            break;
        }
        }

        break;
    }
    case AST_CAST: {
        ast_as_type(compiler, scope, ast->cast.type_expr);
        ast->type_info = ast->cast.type_expr->as_type;

        break;
    }
    case AST_UNARY_EXPR: {
        get_expr_type(compiler, scope, ast->unop.sub);

        if (!ast->unop.sub->type_info)
        {
            break;
        }

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast->unop.sub->type_info->kind == TYPE_TYPE)
            {
                TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_TYPE;
                ast->type_info = ty;
                break;
            }

            if (ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                break;
            }

            ast->type_info = ast->unop.sub->type_info->ptr.sub;
            break;
        }
        case UNOP_ADDRESS: {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_POINTER;
            ty->ptr.sub = ast->unop.sub->type_info;
            ast->type_info = ty;
            break;
        }
        case UNOP_NEG: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT)
            {
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
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
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
            get_expr_type(compiler, scope, ast->binop.left);
            get_expr_type(compiler, scope, ast->binop.right);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                break;
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT)
            {
                break;
            }

            ast->type_info = ast->binop.left->type_info;
            break;
        }
        case BINOP_LSHIFT:
        case BINOP_RSHIFT:
        case BINOP_BITOR:
        case BINOP_BITAND:
        case BINOP_BITXOR: {
            get_expr_type(compiler, scope, ast->binop.left);
            get_expr_type(compiler, scope, ast->binop.right);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                break;
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_BOOL)
            {
                break;
            }

            ast->type_info = ast->binop.left->type_info;
            break;
        }
        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ: {
            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        case BINOP_AND:
        case BINOP_OR: {
            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        }

        break;
    }
    case AST_SUBSCRIPT: {
        get_expr_type(compiler, scope, ast->subscript.left);

        if (!ast->subscript.left->type_info)
        {
            break;
        }

        if (ast->subscript.left->type_info->kind != TYPE_POINTER &&
            ast->subscript.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript.left->type_info->kind != TYPE_SLICE)
        {
            break;
        }

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info = ast->subscript.left->type_info->ptr.sub;
            break;
        }
        default: break;
        }
        break;
    }
    case AST_SUBSCRIPT_SLICE: {
        get_expr_type(compiler, scope, ast->subscript_slice.left);

        if (!ast->subscript_slice.left->type_info)
        {
            break;
        }

        if (ast->subscript_slice.left->type_info->kind != TYPE_POINTER &&
            ast->subscript_slice.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript_slice.left->type_info->kind != TYPE_SLICE)
        {
            break;
        }

        TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_SLICE;
        ast->type_info = ty;

        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info->array.sub =
                ast->subscript_slice.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info->array.sub =
                ast->subscript_slice.left->type_info->ptr.sub;
            break;
        }
        default: break;
        }

        break;
    }
    case AST_ARRAY_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;
        break;
    }
    case AST_STRUCT: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;
        break;
    }
    case AST_ACCESS: {
        get_expr_type(compiler, scope, ast->access.left);

        if (!ast->access.left->type_info)
        {
            break;
        }

        if (ast->access.left->type_info->kind == TYPE_SLICE)
        {
            Ast *right = get_inner_expr(ast->access.right);
            if (right->type == AST_PRIMARY &&
                right->primary.tok->type == TOKEN_IDENT)
            {
                if (string_equals(right->primary.tok->str, STR("len")))
                {
                    ast->type_info = &SIZE_INT_TYPE;
                    break;
                }
                else if (string_equals(right->primary.tok->str, STR("ptr")))
                {
                    ast->type_info = ast->access.right->type_info;

                    TypeInfo *ptr_ty =
                        bump_alloc(&compiler->bump, sizeof(*ptr_ty));
                    memset(ptr_ty, 0, sizeof(*ptr_ty));
                    ptr_ty->kind = TYPE_POINTER;
                    ptr_ty->ptr.sub = ast->access.left->type_info->array.sub;

                    ast->type_info = ptr_ty;
                    break;
                }
            }

            break;
        }

        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);

        if (accessed_scope)
        {
            get_expr_type(compiler, accessed_scope, ast->access.right);
            ast->type_info = ast->access.right->type_info;
        }

        break;
    }
    case AST_PROC_DECL: {
        TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            ast_as_type(compiler, scope, param->decl.type_expr);
            if (!param->decl.type_expr->as_type) return;
            array_push(ty->proc.params, *param->decl.type_expr->as_type);
        }

        ast_as_type(compiler, scope, ast->proc.return_type);
        if (!ast->proc.return_type->as_type) return;
        ty->proc.return_type = ast->proc.return_type->as_type;

        TypeInfo *ptr_ty = bump_alloc(&compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        ast->type_info = ptr_ty;
        break;
    }
    default: break;
    }
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
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
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
    case AST_PAREN_EXPR: {
        ast->alias_to = get_aliased_expr(compiler, scope, ast->expr);
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

static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast)
{
    Scope *accessed_scope = NULL;

    Ast *aliased = get_aliased_expr(compiler, scope, ast);
    if (aliased)
    {
        switch (aliased->type)
        {
        case AST_IMPORT: {
            SourceFile *file =
                hash_get(&compiler->files, aliased->import.abs_path);
            assert(file);
            accessed_scope = file->root->block.scope;
            break;
        }
        default: break;
        }
    }
    else
    {
        // Type based lookup
        get_expr_type(compiler, scope, ast);
        if (!ast->type_info) return NULL;

        if (ast->type_info->kind == TYPE_STRUCT)
        {
            accessed_scope = ast->type_info->structure.scope;
        }
        else if (
            ast->type_info->kind == TYPE_POINTER &&
            ast->type_info->ptr.sub->kind == TYPE_STRUCT)
        {
            accessed_scope = ast->type_info->ptr.sub->structure.scope;
        }
    }

    return accessed_scope;
}

void create_scopes_ast(Analyzer *a, Ast *ast)
{
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        assert(!ast->block.scope);
        ast->block.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->block.scope, 0, sizeof(*ast->block.scope));
        scope_init(
            ast->block.scope,
            a->compiler,
            SCOPE_DEFAULT,
            array_size(ast->block.stmts),
            NULL);
        if (array_size(a->scope_stack) > 0)
        {
            ast->block.scope->parent = *array_last(a->scope_stack);
        }

        array_push(a->scope_stack, ast->block.scope);
        array_push(a->operand_scope_stack, ast->block.scope);
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);

        break;
    }
    case AST_PROC_DECL: {
        assert(!ast->proc.scope);
        ast->proc.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->proc.scope, 0, sizeof(*ast->proc.scope));
        scope_init(
            ast->proc.scope,
            a->compiler,
            SCOPE_DEFAULT,
            array_size(ast->proc.stmts) + array_size(ast->proc.params),
            ast);
        ast->proc.scope->parent = *array_last(a->scope_stack);

        array_push(a->scope_stack, ast->proc.scope);
        array_push(a->operand_scope_stack, ast->proc.scope);
        for (Ast *stmt = ast->proc.stmts;
             stmt != ast->proc.stmts + array_size(ast->proc.stmts);
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            create_scopes_ast(a, ast->unop.sub);
            break;
        }
        default: break;
        }

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
    case AST_WHILE: {
        create_scopes_ast(a, ast->while_stmt.cond);
        create_scopes_ast(a, ast->while_stmt.stmt);
        break;
    }
    case AST_FOR: {
        assert(!ast->for_stmt.scope);
        ast->for_stmt.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->for_stmt.scope, 0, sizeof(*ast->for_stmt.scope));
        scope_init(
            ast->for_stmt.scope,
            a->compiler,
            SCOPE_DEFAULT,
            5, // Small number, because there's only gonna be 2 declarations max
            NULL);
        if (array_size(a->scope_stack) > 0)
        {
            ast->for_stmt.scope->parent = *array_last(a->scope_stack);
        }

        array_push(a->scope_stack, ast->for_stmt.scope);
        array_push(a->operand_scope_stack, ast->for_stmt.scope);
        if (ast->for_stmt.init) create_scopes_ast(a, ast->for_stmt.init);
        if (ast->for_stmt.cond) create_scopes_ast(a, ast->for_stmt.cond);
        if (ast->for_stmt.inc) create_scopes_ast(a, ast->for_stmt.inc);
        create_scopes_ast(a, ast->for_stmt.stmt);
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_PAREN_EXPR: {
        create_scopes_ast(a, ast->expr);
        break;
    }
    case AST_TYPEDEF: {
        create_scopes_ast(a, ast->type_def.type_expr);
        break;
    }
    case AST_CONST_DECL: {
        create_scopes_ast(a, ast->decl.type_expr);
        break;
    }
    case AST_VAR_DECL: {
        create_scopes_ast(a, ast->decl.type_expr);
        break;
    }
    case AST_STRUCT_FIELD: {
        create_scopes_ast(a, ast->field.type_expr);
        break;
    }
    case AST_STRUCT: {
        assert(!ast->structure.scope);
        ast->structure.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->structure.scope, 0, sizeof(*ast->structure.scope));
        scope_init(
            ast->structure.scope,
            a->compiler,
            SCOPE_STRUCT,
            array_size(ast->structure.fields),
            ast);

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            scope_set(ast->structure.scope, field->field.name, field);
        }

        array_push(a->scope_stack, ast->structure.scope);
        array_push(a->operand_scope_stack, ast->structure.scope);
        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            create_scopes_ast(a, field);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_UNINITIALIZED:
    case AST_BREAK:
    case AST_CONTINUE:
    case AST_RETURN:
    case AST_PRIMARY:
    case AST_SUBSCRIPT:
    case AST_SUBSCRIPT_SLICE:
    case AST_ARRAY_TYPE:
    case AST_SLICE_TYPE:
    case AST_EXPR_STMT:
    case AST_ACCESS:
    case AST_PROC_PARAM:
    case AST_CAST:
    case AST_VAR_ASSIGN:
    case AST_BINARY_EXPR:
    case AST_INTRINSIC_CALL:
    case AST_PROC_CALL:
    case AST_PROC_TYPE:
    case AST_IMPORT: break;
    }
}

void register_symbol_ast(Analyzer *a, Ast *ast)
{
    Scope *scope = *array_last(a->scope_stack);
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
        sym_name = ast->field.name;
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
        sym_name = ast->proc.name;

        array_push(a->scope_stack, ast->proc.scope);
        array_push(a->operand_scope_stack, ast->proc.scope);
        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            register_symbol_ast(a, param);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    default: return;
    }

    assert(sym_name.length > 0);

    if (get_symbol(*array_last(a->scope_stack), sym_name))
    {
        compile_error(
            a->compiler,
            ast->loc,
            "duplicate declaration: '%.*s'",
            (int)sym_name.length,
            sym_name.buf);
        return;
    }

    scope_set(scope, sym_name, ast);
}

static void analyze_asts(Analyzer *a, Ast *asts, size_t ast_count);

static void analyze_ast(Analyzer *a, Ast *ast, TypeInfo *expected_type)
{
    bool is_statement = true;

    // Statements
    switch (ast->type)
    {
    case AST_RETURN: {
        Ast *proc = get_scope_procedure(*array_last(a->scope_stack));
        if (!proc)
        {
            compile_error(
                a->compiler, ast->loc, "return needs to be inside a procedure");
            break;
        }

        assert(proc->proc.return_type->as_type);
        if (ast->expr)
        {
            analyze_ast(a, ast->expr, proc->proc.return_type->as_type);
        }
        else
        {
            if (proc->proc.return_type->as_type->kind != TYPE_VOID)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "procedure does not return void, 'return' must contain a "
                    "value");
                break;
            }
        }
        break;
    }

    case AST_BLOCK: {
        array_push(a->scope_stack, ast->block.scope);
        array_push(a->operand_scope_stack, ast->block.scope);
        analyze_asts(a, ast->block.stmts, array_size(ast->block.stmts));
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }

    case AST_TYPEDEF: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->type_def.type_expr, &ty_ty);
        break;
    }

    case AST_CONST_DECL: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->decl.type_expr, &ty_ty);
        analyze_ast(a, ast->decl.value_expr, ast->decl.type_expr->as_type);

        if (!is_expr_const(*array_last(a->scope_stack), ast->decl.value_expr))
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
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->decl.type_expr, &ty_ty);
        if (ast->decl.value_expr)
        {
            analyze_ast(a, ast->decl.value_expr, ast->decl.type_expr->as_type);
        }
        break;
    }

    case AST_PROC_PARAM: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->proc_param.type_expr, &ty_ty);
        if (ast->proc_param.value_expr)
        {
            analyze_ast(
                a,
                ast->proc_param.value_expr,
                ast->proc_param.type_expr->as_type);
        }
        break;
    }

    case AST_STRUCT_FIELD: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->field.type_expr, &ty_ty);
        if (ast->field.value_expr)
        {
            analyze_ast(
                a, ast->field.value_expr, ast->field.type_expr->as_type);
        }
        break;
    }

    case AST_VAR_ASSIGN: {
        analyze_ast(a, ast->assign.assigned_expr, NULL);
        analyze_ast(
            a, ast->assign.value_expr, ast->assign.assigned_expr->type_info);
        break;
    }

    case AST_EXPR_STMT: {
        analyze_ast(a, ast->expr, NULL);
        break;
    }

    case AST_PROC_DECL: {
        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

        bool valid_type = true;

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            analyze_ast(a, param, NULL);
            if (!param->decl.type_expr->as_type)
            {
                valid_type = false;
                break;
            }
            array_push(ty->proc.params, *param->decl.type_expr->as_type);
        }

        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->proc.return_type, &ty_ty);
        if (ast->proc.return_type->as_type)
        {
            ty->proc.return_type = ast->proc.return_type->as_type;
        }

        TypeInfo *ptr_ty = bump_alloc(&a->compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        if (valid_type)
        {
            ast->type_info = ptr_ty;
        }
        break;
    }

    case AST_PROC_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            analyze_ast(a, param, NULL);
        }

        analyze_ast(a, ast->proc.return_type, &ty_ty);

        ast->type_info = &ty_ty;
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
            compile_error(
                a->compiler,
                ast->if_stmt.cond_expr->loc,
                "could not resolve type for 'if' condition");
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

    case AST_WHILE: {
        analyze_ast(a, ast->while_stmt.cond, NULL);

        array_push(a->break_stack, ast);
        array_push(a->continue_stack, ast);
        analyze_ast(a, ast->while_stmt.stmt, NULL);
        array_pop(a->continue_stack);
        array_pop(a->break_stack);

        if (!ast->while_stmt.cond->type_info)
        {
            compile_error(
                a->compiler,
                ast->while_stmt.cond->loc,
                "could not evaluate type for 'while' condition");
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
                "'while' statement only takes numerical types as conditions");
            break;
        }

        break;
    }

    case AST_FOR: {
        array_push(a->scope_stack, ast->for_stmt.scope);
        array_push(a->operand_scope_stack, ast->for_stmt.scope);

        if (ast->for_stmt.init) analyze_ast(a, ast->for_stmt.init, NULL);
        if (ast->for_stmt.cond) analyze_ast(a, ast->for_stmt.cond, NULL);
        if (ast->for_stmt.inc) analyze_ast(a, ast->for_stmt.inc, NULL);

        array_push(a->break_stack, ast);
        array_push(a->continue_stack, ast);
        analyze_ast(a, ast->for_stmt.stmt, NULL);
        array_pop(a->continue_stack);
        array_pop(a->break_stack);

        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);

        if (ast->for_stmt.cond)
        {
            if (!ast->for_stmt.cond->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->for_stmt.cond->loc,
                    "could not evaluate type for 'for' condition");
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
                    "'for' statement only takes numerical types as conditions");
                break;
            }
        }

        break;
    }

    case AST_BREAK: {
        if (array_size(a->break_stack) == 0)
        {
            compile_error(
                a->compiler, ast->loc, "'break' outside control structure");
            break;
        }
        break;
    }

    case AST_CONTINUE: {
        if (array_size(a->continue_stack) == 0)
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

    ast_as_type(a->compiler, *array_last(a->scope_stack), ast);
    get_expr_type(a->compiler, *array_last(a->scope_stack), ast);

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_NULL: {
            assert(ast->type_info);

            if (ast->type_info->can_change && expected_type)
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
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->type_info = &ty;
            break;
        }

        case TOKEN_INT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .can_change = true,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->type_info = &ty;

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
            static TypeInfo ty = {
                .kind = TYPE_FLOAT,
                .floating.num_bits = 64,
                .can_change = true,
            };
            ast->type_info = &ty;

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

        case TOKEN_IDENT: {
            Ast *sym =
                get_symbol(*array_last(a->scope_stack), ast->primary.tok->str);

            if (!sym)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "invalid identifier: '%.*s'",
                    (int)ast->primary.tok->str.length,
                    ast->primary.tok->str.buf);
            }

            break;
        }

        default: break;
        }
        break;
    }

    case AST_PAREN_EXPR: {
        analyze_ast(a, ast->expr, expected_type);
        ast->type_info = ast->expr->type_info;
        break;
    }

    case AST_PROC_CALL: {
        analyze_ast(a, ast->proc_call.expr, NULL);
        if (!ast->proc_call.expr->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for procedure call expression");
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

        if (!proc_ty->proc.is_c_vararg)
        {
            if (array_size(ast->proc_call.params) !=
                array_size(proc_ty->proc.params))
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
            if (array_size(ast->proc_call.params) <
                array_size(proc_ty->proc.params))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong parameter count for function call");
                break;
            }
        }

        assert(array_size(a->operand_scope_stack) > 0);

        array_push(a->scope_stack, *array_last(a->operand_scope_stack));
        for (size_t i = 0; i < array_size(ast->proc_call.params); ++i)
        {
            TypeInfo *param_expected_type = NULL;
            if (i < array_size(proc_ty->proc.params))
            {
                param_expected_type = &proc_ty->proc.params[i];
            }
            analyze_ast(a, &ast->proc_call.params[i], param_expected_type);
        }
        array_pop(a->scope_stack);
        break;
    }

    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            if (array_size(ast->intrinsic_call.params) != 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@sizeof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params[0];
            analyze_ast(a, param, NULL);

            if (!param->type_info)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "could not resolve type for expression");
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

            ast->type_info = &SIZE_INT_TYPE;

            break;
        }

        case INTRINSIC_ALIGNOF: {
            if (array_size(ast->intrinsic_call.params) != 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@alignof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params[0];
            analyze_ast(a, param, NULL);

            if (param->type_info->kind == TYPE_VOID ||
                param->type_info->kind == TYPE_NAMESPACE)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "@alignof does not apply for this type");
                break;
            }

            ast->type_info = &SIZE_INT_TYPE;

            break;
        }
        }

        break;
    }

    case AST_CAST: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        analyze_ast(a, ast->cast.type_expr, &ty_ty);
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
            compile_error(
                a->compiler, ast->loc, "could not resolve types for cast");
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
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for unary operand");
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
                ast->unop.sub->type_info->kind != TYPE_FLOAT)
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

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
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
            analyze_ast(a, ast->binop.left, expected_type);
            analyze_ast(a, ast->binop.right, expected_type);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (expected_type == NULL)
            {
                TypeInfo *common_type = common_numeric_type(
                    ast->binop.left->type_info, ast->binop.right->type_info);
                analyze_ast(a, ast->binop.left, common_type);
                analyze_ast(a, ast->binop.right, common_type);
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do arithmetic on numeric types");
                break;
            }

            ast->type_info = ast->binop.left->type_info;

            break;
        }

        case BINOP_LSHIFT:
        case BINOP_RSHIFT:
        case BINOP_BITAND:
        case BINOP_BITOR:
        case BINOP_BITXOR: {
            analyze_ast(a, ast->binop.left, expected_type);
            analyze_ast(a, ast->binop.right, expected_type);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (expected_type == NULL)
            {
                TypeInfo *common_type = common_numeric_type(
                    ast->binop.left->type_info, ast->binop.right->type_info);
                analyze_ast(a, ast->binop.left, common_type);
                analyze_ast(a, ast->binop.right, common_type);
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_BOOL)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do bitwise operations on integer types");
                break;
            }

            ast->type_info = ast->binop.left->type_info;

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

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            TypeInfo *common_type = common_numeric_type(
                ast->binop.left->type_info, ast->binop.right->type_info);
            analyze_ast(a, ast->binop.left, common_type);
            analyze_ast(a, ast->binop.right, common_type);

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "comparison binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_BOOL &&
                ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT &&
                ast->binop.left->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do comparison on numeric types");
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;

            break;
        }

        case BINOP_AND:
        case BINOP_OR: {
            analyze_ast(a, ast->binop.left, NULL);
            analyze_ast(a, ast->binop.right, NULL);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_BOOL &&
                ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT &&
                ast->binop.left->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.left->loc,
                    "left operand of logical operator has invalid type");
                break;
            }

            if (ast->binop.right->type_info->kind != TYPE_BOOL &&
                ast->binop.right->type_info->kind != TYPE_INT &&
                ast->binop.right->type_info->kind != TYPE_FLOAT &&
                ast->binop.right->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.right->loc,
                    "right operand of logical operator has invalid type");
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;

            break;
        }
        }

        break;
    }

    case AST_SUBSCRIPT: {
        analyze_ast(a, ast->subscript.left, NULL);
        analyze_ast(a, ast->subscript.right, NULL);

        if (!ast->subscript.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for left expression of subscript");
            break;
        }

        if (!ast->subscript.right->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for right expression of subscript");
            break;
        }

        if (ast->subscript.left->type_info->kind != TYPE_POINTER &&
            ast->subscript.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript.left->type_info->kind != TYPE_SLICE)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_SLICE:
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
        analyze_ast(a, ast->subscript_slice.lower, &SIZE_INT_TYPE);
        analyze_ast(a, ast->subscript_slice.upper, &SIZE_INT_TYPE);

        if (!ast->subscript_slice.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for left expression of subscript");
            break;
        }

        if (!ast->subscript_slice.lower->type_info ||
            !ast->subscript_slice.upper->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for bounds of slice subscript");
            break;
        }

        if (!exact_types(
                ast->subscript_slice.lower->type_info,
                ast->subscript_slice.upper->type_info))
        {
            compile_error(
                a->compiler,
                ast->loc,
                "slice subscript lower and upper bounds need to be of same "
                "type");
            break;
        }

        if (ast->subscript_slice.left->type_info->kind != TYPE_POINTER &&
            ast->subscript_slice.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript_slice.left->type_info->kind != TYPE_SLICE)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_SLICE;
        ast->type_info = ty;

        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info->array.sub =
                ast->subscript_slice.left->type_info->array.sub;
            break;
        }

        case TYPE_POINTER: {
            ast->type_info->array.sub =
                ast->subscript_slice.left->type_info->ptr.sub;
            break;
        }
        default: break;
        }

        break;
    }

    case AST_ARRAY_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        analyze_ast(a, ast->array_type.size, NULL);
        analyze_ast(a, ast->array_type.sub, &ty_ty);

        if (ast->array_type.size->type_info->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "array type needs an integer size");
        }

        break;
    }

    case AST_SLICE_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        analyze_ast(a, ast->array_type.sub, &ty_ty);

        break;
    }

    case AST_STRUCT: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            analyze_ast(a, field, NULL);
        }
        break;
    }

    case AST_ACCESS: {
        analyze_ast(a, ast->access.left, NULL);

        if (!ast->type_info)
        {
            compile_error(a->compiler, ast->loc, "invalid access");
            break;
        }

        Scope *accessed_scope = get_expr_scope(
            a->compiler, *array_last(a->scope_stack), ast->access.left);

        if (accessed_scope)
        {
            array_push(a->scope_stack, accessed_scope);
            analyze_ast(a, ast->access.right, NULL);
            array_pop(a->scope_stack);
        }

        break;
    }
    default: break;
    }

    if (!ast->type_info)
    {
        // TODO: remove this, only temporary for debugging
        printf(
            "undefined type: %u:%u (%u)\n",
            ast->loc.line,
            ast->loc.col,
            ast->loc.length);
    }

    if (ast->type_info && expected_type)
    {
        if (!exact_types(ast->type_info, expected_type) &&
            !compatible_pointer_types(ast->type_info, expected_type))
        {
            compile_error(a->compiler, ast->loc, "wrong type");
        }
    }
}

void register_symbol_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
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
        case AST_ROOT:
        case AST_CONST_DECL:
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
        case AST_ROOT: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            register_symbol_asts(
                a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        case AST_PROC_DECL: {
            array_push(a->scope_stack, ast->proc.scope);
            array_push(a->operand_scope_stack, ast->proc.scope);
            register_symbol_asts(
                a, ast->proc.stmts, array_size(ast->proc.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        case AST_BLOCK: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            register_symbol_asts(
                a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        case AST_IF: {
            register_symbol_asts(a, ast->if_stmt.cond_stmt, 1);
            if (ast->if_stmt.else_stmt)
            {
                register_symbol_asts(a, ast->if_stmt.else_stmt, 1);
            }
            break;
        }

        case AST_WHILE: {
            register_symbol_asts(a, ast->while_stmt.cond, 1);
            register_symbol_asts(a, ast->while_stmt.stmt, 1);
            break;
        }

        case AST_FOR: {
            array_push(a->scope_stack, ast->for_stmt.scope);
            array_push(a->operand_scope_stack, ast->for_stmt.scope);
            if (ast->for_stmt.init)
                register_symbol_asts(a, ast->for_stmt.init, 1);
            if (ast->for_stmt.cond)
                register_symbol_asts(a, ast->for_stmt.cond, 1);
            if (ast->for_stmt.inc)
                register_symbol_asts(a, ast->for_stmt.inc, 1);
            register_symbol_asts(a, ast->for_stmt.stmt, 1);
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
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
        case AST_ROOT:
        case AST_CONST_DECL:
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
        case AST_ROOT: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            analyze_asts(a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        case AST_BLOCK: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            analyze_asts(a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        case AST_PROC_DECL: {
            array_push(a->scope_stack, ast->proc.scope);
            array_push(a->operand_scope_stack, ast->proc.scope);
            analyze_asts(a, ast->proc.stmts, array_size(ast->proc.stmts));

            // If the procedure has a void return type or doesn't have a
            // body, say it has returned already
            bool returned = ast->proc.return_type->as_type->kind == TYPE_VOID ||
                            !(ast->proc.flags & PROC_FLAG_HAS_BODY);

            if (!returned)
            {
                for (Ast *stmt = ast->proc.stmts;
                     stmt != ast->proc.stmts + array_size(ast->proc.stmts);
                     ++stmt)
                {
                    if (stmt->type == AST_RETURN) returned = true;
                }
            }

            if (!returned)
            {
                compile_error(
                    a->compiler, ast->loc, "procedure did not return");
            }

            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }

        default: break;
        }
    }
}
