static Ast *create_module_ast(Compiler *compiler)
{
    Ast *module = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(module, 0, sizeof(Ast));
    module->type = AST_ROOT;

    return module;
}

static Ast *add_module_enum(Compiler *compiler, Ast *module, String enum_name)
{
    Ast *enumeration = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(enumeration, 0, sizeof(Ast));
    enumeration->type = AST_ENUM;
    enumeration->enumeration.type_expr =
        bump_alloc(&compiler->bump, sizeof(Ast));
    enumeration->enumeration.fields = NULL;

    memset(enumeration->enumeration.type_expr, 0, sizeof(Ast));
    enumeration->enumeration.type_expr->type = AST_PRIMARY;
    enumeration->enumeration.type_expr->primary.tok =
        bump_alloc(&compiler->bump, sizeof(Token));
    enumeration->enumeration.type_expr->primary.tok->type = TOKEN_UINT;

    Ast type_def = {0};
    type_def.type = AST_TYPEDEF;
    type_def.type_def.name = enum_name;
    type_def.type_def.type_expr = enumeration;

    array_push(module->block.stmts, type_def);
    return enumeration;
}

static void
add_enum_field(Compiler *compiler, Ast *enumeration, String name, int64_t value)
{
    Ast field = {0};
    field.type = AST_ENUM_FIELD;
    field.enum_field.name = name;

    field.enum_field.value_expr = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(field.enum_field.value_expr, 0, sizeof(Ast));
    field.enum_field.value_expr->type = AST_PRIMARY;
    field.enum_field.value_expr->primary.tok =
        bump_alloc(&compiler->bump, sizeof(Token));
    field.enum_field.value_expr->primary.tok->type = TOKEN_INT_LIT;
    field.enum_field.value_expr->primary.tok->i64 = value;

    array_push(enumeration->enumeration.fields, field);
}

static Ast *ident_expr(Compiler *compiler, String name)
{
    Ast *ident = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(ident, 0, sizeof(Ast));
    ident->type = AST_PRIMARY;
    ident->primary.tok = bump_alloc(&compiler->bump, sizeof(Token));
    ident->primary.tok->type = TOKEN_IDENT;
    ident->primary.tok->str = name;

    return ident;
}

static Ast *access_expr(Compiler *compiler, Ast *left, Ast *right)
{
    Ast *expr = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(expr, 0, sizeof(Ast));
    expr->type = AST_ACCESS;
    expr->access.left = left;
    expr->access.right = right;

    return expr;
}

static Ast *
add_module_constant(Compiler *compiler, Ast *module, String name, Ast *value)
{
    Ast constant = {0};
    constant.type = AST_CONST_DECL;
    constant.decl.name = name;
    constant.decl.value_expr = value;

    array_push(module->block.stmts, constant);
    return array_last(module->block.stmts);
}

