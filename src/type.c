typedef enum TypeKind {
    TYPE_UNINITIALIZED,
    TYPE_NONE,
    TYPE_TYPE,
    TYPE_PROC,
    TYPE_STRUCT,
    TYPE_ENUM,
    TYPE_POINTER,
    TYPE_ARRAY,
    TYPE_VECTOR,
    TYPE_SLICE,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_BOOL,
    TYPE_VOID,
    TYPE_NAMESPACE,
} TypeKind;

typedef enum TypeFlags {
    TYPE_FLAG_DISTINCT = 1 << 0,
    TYPE_FLAG_CAN_CHANGE = 1 << 1,
    TYPE_FLAG_EXTERN = 1 << 2,
    TYPE_FLAG_C_VARARGS = 1 << 3,
} TypeFlags;

typedef struct TypeInfo
{
    LLVMTypeRef ref;
    struct Scope *scope;
    TypeKind kind;
    uint32_t flags;

    union
    {
        struct
        {
            uint32_t num_bits;
            bool is_signed;
        } integer;
        struct
        {
            uint32_t num_bits;
        } floating;
        struct
        {
            struct TypeInfo *sub;
        } ptr;
        struct
        {
            struct TypeInfo *sub;
            size_t size;
        } array;
        struct
        {
            struct TypeInfo *return_type;
            /*array*/ struct TypeInfo **params;
        } proc;
        struct
        {
            /*array*/ struct TypeInfo **fields;
        } structure;
        struct
        {
            struct TypeInfo *underlying_type;
        } enumeration;
    };
} TypeInfo;

// Unsigned int types
static TypeInfo U8_TYPE = {.kind = TYPE_INT,
                           .integer = {.is_signed = false, .num_bits = 8}};

static TypeInfo U16_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 16}};

static TypeInfo U32_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 32}};

static TypeInfo U64_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 64}};

// Signed int types
static TypeInfo I8_TYPE = {.kind = TYPE_INT,
                           .integer = {.is_signed = true, .num_bits = 8}};

static TypeInfo I16_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 16}};

static TypeInfo I32_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 32}};

static TypeInfo I64_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 64}};

// Architecture int types
static TypeInfo INT_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 64}};

static TypeInfo UINT_TYPE = {.kind = TYPE_INT,
                             .integer = {.is_signed = false, .num_bits = 64}};

// Numeric literal types
static TypeInfo INT_LIT_TYPE = {.kind = TYPE_INT,
                                .flags = TYPE_FLAG_CAN_CHANGE,
                                .integer = {.is_signed = true, .num_bits = 64}};

static TypeInfo FLOAT_LIT_TYPE = {
    .kind = TYPE_FLOAT, .flags = TYPE_FLAG_CAN_CHANGE, .floating.num_bits = 64};

// Other types
static TypeInfo BOOL_TYPE = {.kind = TYPE_BOOL};

static TypeInfo FLOAT_TYPE = {.kind = TYPE_FLOAT, .floating.num_bits = 32};

static TypeInfo DOUBLE_TYPE = {.kind = TYPE_FLOAT, .floating.num_bits = 64};

static TypeInfo VOID_TYPE = {.kind = TYPE_VOID};

static TypeInfo VOID_PTR_TYPE = {.kind = TYPE_POINTER, .ptr.sub = &VOID_TYPE};

static TypeInfo BOOL_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 8}};

static TypeInfo NAMESPACE_TYPE = {.kind = TYPE_NAMESPACE};

static TypeInfo TYPE_OF_TYPE = {.kind = TYPE_TYPE};

// Type functions

static inline bool is_type_compound(TypeInfo *type)
{
    return (
        type->kind == TYPE_STRUCT || type->kind == TYPE_SLICE ||
        type->kind == TYPE_ARRAY || type->kind == TYPE_VECTOR);
}

static TypeInfo *exact_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind != expected->kind)
    {
        if (received->kind == TYPE_ENUM)
        {
            return exact_types(received->enumeration.underlying_type, expected);
        }
        return NULL;
    }

    if ((received->flags & TYPE_FLAG_DISTINCT) ||
        (expected->flags & TYPE_FLAG_DISTINCT))
    {
        if (expected != received) return NULL;
    }

    switch (received->kind)
    {
    case TYPE_INT: {
        if (received->integer.is_signed != expected->integer.is_signed)
            return NULL;
        if (received->integer.num_bits != expected->integer.num_bits)
            return NULL;
        break;
    }

    case TYPE_FLOAT: {
        if (received->floating.num_bits != expected->floating.num_bits)
            return NULL;
        break;
    }

    case TYPE_POINTER: {
        if (!exact_types(received->ptr.sub, expected->ptr.sub)) return NULL;
        break;
    }

    case TYPE_ARRAY: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        if (received->array.size != expected->array.size) return NULL;
        break;
    }

    case TYPE_VECTOR: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        if (received->array.size != expected->array.size) return NULL;
        break;
    }

    case TYPE_SLICE: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        break;
    }

    case TYPE_ENUM: {
        if (received != expected) return NULL;
        break;
    }

    case TYPE_STRUCT: {
        if (array_size(received->structure.fields) !=
            array_size(expected->structure.fields))
            return NULL;

        size_t field_count = array_size(expected->structure.fields);
        for (size_t i = 0; i < field_count; ++i)
        {
            if (!exact_types(
                    received->structure.fields[i],
                    expected->structure.fields[i]))
            {
                return NULL;
            }
        }
        break;
    }

    case TYPE_PROC: {
        if (!exact_types(
                received->proc.return_type, expected->proc.return_type))
            return NULL;

        if (array_size(received->proc.params) !=
            array_size(expected->proc.params))
            return NULL;

        for (size_t i = 0; i < array_size(received->proc.params); ++i)
        {
            if (!exact_types(
                    received->proc.params[i], expected->proc.params[i]))
                return NULL;
        }

        break;
    }

    case TYPE_NAMESPACE:
    case TYPE_BOOL:
    case TYPE_VOID:
    case TYPE_TYPE:
    case TYPE_UNINITIALIZED:
    case TYPE_NONE: break;
    }

    return received;
}

static TypeInfo *
compatible_pointer_types(TypeInfo *received, TypeInfo *expected)
{
    if (!expected || !received) return NULL;
    if (received->kind == TYPE_POINTER && received->ptr.sub->kind == TYPE_VOID) return expected;
    if (expected->kind == TYPE_POINTER && expected->ptr.sub->kind == TYPE_VOID) return received;

    return NULL;
}

static TypeInfo *common_numeric_type(TypeInfo *a, TypeInfo *b)
{
    TypeInfo *float_type = NULL;
    TypeInfo *other_type = NULL;
    if (a->kind == TYPE_FLOAT)
    {
        float_type = a;
        other_type = b;
    }
    else if (b->kind == TYPE_FLOAT)
    {
        float_type = b;
        other_type = a;
    }

    if (float_type && (other_type->flags & TYPE_FLAG_CAN_CHANGE))
    {
        return float_type;
    }

    if (a->flags & TYPE_FLAG_CAN_CHANGE)
    {
        return b;
    }

    if (b->flags & TYPE_FLAG_CAN_CHANGE)
    {
        return a;
    }

    return NULL;
}

static inline TypeInfo *get_inner_type(TypeInfo *type)
{
    if (!type) return type;

    while (1)
    {
        switch (type->kind)
        {
        case TYPE_ENUM: type = type->enumeration.underlying_type; break;
        default: goto end; break;
        }
    }

end:
    return type;
}

static inline void init_numeric_type(Compiler *compiler, TypeInfo *type)
{
    Ast *min_ast = bump_alloc(&compiler->bump, sizeof(Ast));
    Ast *max_ast = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(min_ast, 0, sizeof(*min_ast));
    memset(max_ast, 0, sizeof(*max_ast));
    min_ast->type = AST_BUILTIN_MIN;
    min_ast->flags = AST_FLAG_PUBLIC;
    max_ast->type = AST_BUILTIN_MAX;
    max_ast->flags = AST_FLAG_PUBLIC;

    Scope *scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(scope, compiler, SCOPE_DEFAULT, 2, NULL);

    type->scope = scope;
    scope->type_info = type;
    scope_set(scope, STR("min"), min_ast);
    scope_set(scope, STR("max"), max_ast);
}

static inline TypeInfo *
create_array_type(Compiler *compiler, TypeInfo *subtype, size_t size)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_ARRAY;
    ty->array.sub = subtype;
    ty->array.size = size;

    ty->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(ty->scope, compiler, SCOPE_INSTANCED, 2, NULL);
    ty->scope->type_info = ty;

    Ast *ptr_ast = bump_alloc(&compiler->bump, sizeof(Ast));
    ptr_ast->type = AST_BUILTIN_PTR;
    ptr_ast->flags = AST_FLAG_PUBLIC;
    scope_set(ty->scope, STR("ptr"), ptr_ast);

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("len"), &len_ast);

    return ty;
}

static inline TypeInfo *
create_vector_type(Compiler *compiler, TypeInfo *subtype, size_t size)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_VECTOR;
    ty->array.sub = subtype;
    ty->array.size = size;

    ty->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(ty->scope, compiler, SCOPE_INSTANCED, 16, NULL);
    ty->scope->type_info = ty;

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("len"), &len_ast);

    if (ty->array.size >= 1)
    {
        static Ast ast = {.type = AST_BUILTIN_VEC_ACCESS,
                          .flags = AST_FLAG_PUBLIC,
                          .vec_access.position = 0};
        scope_set(ty->scope, STR("x"), &ast);
        scope_set(ty->scope, STR("r"), &ast);
    }
    if (ty->array.size >= 2)
    {
        static Ast ast = {.type = AST_BUILTIN_VEC_ACCESS,
                          .flags = AST_FLAG_PUBLIC,
                          .vec_access.position = 1};
        scope_set(ty->scope, STR("y"), &ast);
        scope_set(ty->scope, STR("g"), &ast);
    }
    if (ty->array.size >= 3)
    {
        static Ast ast = {.type = AST_BUILTIN_VEC_ACCESS,
                          .flags = AST_FLAG_PUBLIC,
                          .vec_access.position = 2};
        scope_set(ty->scope, STR("z"), &ast);
        scope_set(ty->scope, STR("b"), &ast);
    }
    if (ty->array.size >= 4)
    {
        static Ast ast = {.type = AST_BUILTIN_VEC_ACCESS,
                          .flags = AST_FLAG_PUBLIC,
                          .vec_access.position = 3};
        scope_set(ty->scope, STR("w"), &ast);
        scope_set(ty->scope, STR("a"), &ast);
    }

    return ty;
}

static inline TypeInfo *create_slice_type(Compiler *compiler, TypeInfo *subtype)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_SLICE;
    ty->array.sub = subtype;

    ty->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(ty->scope, compiler, SCOPE_INSTANCED, 2, NULL);
    ty->scope->type_info = ty;

    Ast *ptr_ast = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(ptr_ast, 0, sizeof(*ptr_ast));
    ptr_ast->type = AST_BUILTIN_PTR;
    ptr_ast->flags = AST_FLAG_PUBLIC;
    scope_set(ty->scope, STR("ptr"), ptr_ast);

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("len"), &len_ast);

    return ty;
}
