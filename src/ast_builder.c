#if 0
static Ast *create_module_ast(Compiler *compiler)
{
    Ast *module = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(module, 0, sizeof(Ast));
    module->type = AST_ROOT;

    return module;
}

static void add_module_typedef(
    Compiler *compiler, Ast *module, String type_name, Ast *type_expr)
{
    Ast type_def = {0};
    type_def.type = AST_TYPEDEF;
    type_def.flags |= AST_FLAG_PUBLIC;
    type_def.type_def.name = type_name;
    type_def.type_def.type_expr = type_expr;
    array_push(&module->block.stmts, type_def);
}

static Ast *create_struct_ast(Compiler *compiler, Ast *module, bool is_union)
{
    Ast *structure = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(structure, 0, sizeof(Ast));
    structure->type = AST_STRUCT;
    structure->structure.is_union = is_union;

    return structure;
}

static void add_struct_field(
    Compiler *compiler, Ast *structure, String name, Ast *type_expr, bool using)
{
    Ast field = {0};
    field.type = AST_STRUCT_FIELD;
    if (using)
    {
        field.flags = AST_FLAG_USING;
    }
    field.struct_field.name = name;
    field.struct_field.index = structure->structure.fields.len;
    field.struct_field.type_expr = type_expr;

    array_push(&structure->structure.fields, field);
}

static Ast *create_enum_ast(Compiler *compiler, Ast *module)
{
    Ast *enumeration = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(enumeration, 0, sizeof(Ast));
    enumeration->type = AST_ENUM;
    enumeration->enumeration.type_expr =
        bump_alloc(&compiler->bump, sizeof(Ast));

    memset(enumeration->enumeration.type_expr, 0, sizeof(Ast));
    enumeration->enumeration.type_expr->type = AST_PRIMARY;
    enumeration->enumeration.type_expr->primary.tok =
        bump_alloc(&compiler->bump, sizeof(Token));
    enumeration->enumeration.type_expr->primary.tok->type = TOKEN_U32;

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

    array_push(&enumeration->enumeration.fields, field);
}

static Ast *create_ident_ast(Compiler *compiler, String name)
{
    Ast *ident = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(ident, 0, sizeof(Ast));
    ident->type = AST_PRIMARY;
    ident->primary.tok = bump_alloc(&compiler->bump, sizeof(Token));
    ident->primary.tok->type = TOKEN_IDENT;
    ident->primary.tok->str = name;

    return ident;
}

static Ast *create_token_ast(Compiler *compiler, TokenKind type)
{
    Ast *token_node = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(token_node, 0, sizeof(Ast));
    token_node->type = AST_PRIMARY;
    token_node->primary.tok = bump_alloc(&compiler->bump, sizeof(Token));
    token_node->primary.tok->type = type;

    return token_node;
}

static Ast *create_access_ast(Compiler *compiler, Ast *left, Ast *right)
{
    Ast *expr = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(expr, 0, sizeof(Ast));
    expr->type = AST_ACCESS;
    expr->access.left = left;
    expr->access.right = right;
    return expr;
}

static Ast *create_deref_ast(Compiler *compiler, Ast *right)
{
    Ast *expr = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(expr, 0, sizeof(Ast));
    expr->type = AST_UNARY_EXPR;
    expr->unop.type = UNOP_DEREFERENCE;
    expr->unop.sub = right;
    return expr;
}

static Ast *create_slice_type_ast(Compiler *compiler, Ast *right)
{
    Ast *expr = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(expr, 0, sizeof(Ast));
    expr->type = AST_SLICE_TYPE;
    expr->array_type.sub = right;
    return expr;
}

static Ast *
add_module_constant(Compiler *compiler, Ast *module, String name, Ast *value)
{
    Ast constant = {0};
    constant.type = AST_CONST_DECL;
    constant.decl.name = name;
    constant.decl.value_expr = value;
    constant.flags |= AST_FLAG_PUBLIC;

    array_push(&module->block.stmts, constant);
    return array_last(&module->block.stmts);
}

static Ast *create_int_ast(Compiler *compiler, int64_t i)
{
    Ast *lit = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(lit, 0, sizeof(*lit));
    lit->type = AST_PRIMARY;
    lit->primary.tok = bump_alloc(&compiler->bump, sizeof(Token));
    memset(lit->primary.tok, 0, sizeof(*lit->primary.tok));
    lit->primary.tok->type = TOKEN_INT_LIT;
    lit->primary.tok->i64 = i;

    return lit;
}
#endif
