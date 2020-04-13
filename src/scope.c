typedef enum ScopeType {
    SCOPE_DEFAULT,
    SCOPE_INSTANCED,
} ScopeType;

typedef struct Scope
{
    ScopeType type;
    HashMap *map;
    struct Scope *parent;
    /*array*/ struct Scope **siblings;
    struct AstValue value;

    struct Ast *ast;
    struct TypeInfo *type_info;
} Scope;

static void scope_init(
    Scope *scope,
    Compiler *compiler,
    ScopeType type,
    size_t size,
    struct Ast *ast)
{
    memset(scope, 0, sizeof(*scope));
    scope->type = type;
    scope->map = bump_alloc(&compiler->bump, sizeof(*scope->map));
    hash_init(scope->map, size);
    scope->ast = ast;
}

static void scope_set(Scope *scope, String name, struct Ast *decl)
{
    decl->sym_scope = scope;
    hash_set(scope->map, name, decl);
}

static Scope *scope_clone(Compiler *compiler, Scope *scope, Ast *owning_ast)
{
    Scope *new_scope = bump_alloc(&compiler->bump, sizeof(Scope));
    *new_scope = *scope;

    HashMap *new_map = bump_alloc(&compiler->bump, sizeof(HashMap));

    // TODO: Maybe just making a function to clone the hashmap is a better idea
    new_map->size = scope->map->size;
    new_map->keys =
        bump_alloc(&compiler->bump, sizeof(*new_map->keys) * scope->map->size);
    memcpy(
        new_map->keys,
        scope->map->keys,
        sizeof(*new_map->keys) * scope->map->size);

    new_map->hashes = bump_alloc(
        &compiler->bump, sizeof(*new_map->hashes) * scope->map->size);
    memcpy(
        new_map->hashes,
        scope->map->hashes,
        sizeof(*new_map->hashes) * scope->map->size);

    new_map->indices = bump_alloc(
        &compiler->bump, sizeof(*new_map->indices) * scope->map->size);
    memcpy(
        new_map->indices,
        scope->map->indices,
        sizeof(*new_map->indices) * scope->map->size);

    new_map->values = NULL;
    array_add(new_map->values, array_size(scope->map->values));
    memcpy(
        new_map->values,
        scope->map->values,
        sizeof(*new_map->values) * array_size(scope->map->values));

    for (size_t i = 0; i < array_size(new_map->values); ++i)
    {
        Ast *sym = new_map->values[i];

        Scope *new_subscope = new_scope;
        if (sym->sym_scope != scope)
        {
            new_subscope =
                scope_clone(compiler, sym->sym_scope, sym->sym_scope->ast);
        }

        Ast *new_sym = bump_alloc(&compiler->bump, sizeof(Ast));
        *new_sym = *sym;
        new_sym->sym_scope = new_subscope;
        new_map->values[i] = new_sym;
    }

    new_scope->map = new_map;

    new_scope->ast = owning_ast;

    return new_scope;
}

struct Ast *scope_get_local(Scope *scope, String name)
{
    Ast *sym = NULL;
    hash_get(scope->map, name, (void **)&sym);
    return sym;
}

struct Ast *get_symbol(Scope *scope, String name, SourceFile *from_file)
{
    struct Ast *sym = scope_get_local(scope, name);
    if (sym && (sym->loc.file == from_file ||
                ((sym->flags & AST_FLAG_PUBLIC) == AST_FLAG_PUBLIC)))
    {
        return sym;
    }

    for (Scope **sibling = scope->siblings;
         sibling != scope->siblings + array_size(scope->siblings);
         ++sibling)
    {
        sym = get_symbol(*sibling, name, from_file);
        if (sym && (sym->loc.file == from_file ||
                    ((sym->flags & AST_FLAG_PUBLIC) == AST_FLAG_PUBLIC)))
            return sym;
    }

    if (scope->parent) return get_symbol(scope->parent, name, from_file);

    return NULL;
}

struct Ast *get_scope_procedure(Scope *scope)
{
    if (scope->ast && scope->ast->type == AST_PROC_DECL) return scope->ast;

    if (scope->parent) return get_scope_procedure(scope->parent);

    return NULL;
}
