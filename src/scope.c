typedef enum ScopeType {
    SCOPE_DEFAULT,
    SCOPE_STRUCT,
} ScopeType;

typedef struct Scope
{
    ScopeType type;
    HashMap *map;
    struct Scope *parent;
    struct Ast *procedure;
    struct AstValue value;
} Scope;

void scope_init(
    Scope *scope,
    Compiler *compiler,
    ScopeType type,
    size_t size,
    struct Ast *procedure)
{
    memset(scope, 0, sizeof(*scope));
    scope->type = type;
    scope->map = bump_alloc(&compiler->bump, sizeof(*scope->map));
    hash_init(scope->map, size);
    scope->procedure = procedure;
}

void scope_set(Scope *scope, String name, struct Ast *decl)
{
    decl->sym_scope = scope;
    hash_set(scope->map, name, decl);
}

struct Ast *scope_get_local(Scope *scope, String name)
{
    return hash_get(scope->map, name);
}

struct Ast *get_symbol(Scope *scope, String name)
{
    struct Ast *sym = scope_get_local(scope, name);
    if (sym) return sym;

    if (scope->parent) return get_symbol(scope->parent, name);

    return NULL;
}

struct Ast *get_scope_procedure(Scope *scope)
{
    if (scope->procedure) return scope->procedure;

    if (scope->parent) return get_scope_procedure(scope->parent);

    return NULL;
}
