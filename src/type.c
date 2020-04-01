typedef enum TypeKind {
    TYPE_UNINITIALIZED,
    TYPE_NONE,
    TYPE_TYPE,
    TYPE_PROC,
    TYPE_STRUCT,
    TYPE_ENUM,
    TYPE_POINTER,
    TYPE_ARRAY,
    TYPE_SLICE,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_BOOL,
    TYPE_VOID,
    TYPE_NAMESPACE,
} TypeKind;

typedef enum TypeFlags {
    TYPE_FLAG_DISTINCT = 1 << 0,
    TYPE_FLAG_CAN_CHANGE = 1 << 7,
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
            bool is_signed;
            uint32_t num_bits;
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
            bool is_c_vararg;
            struct TypeInfo *return_type;
            /*array*/ struct TypeInfo *params;
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
static Scope U8_TYPE_SCOPE = {0};
static TypeInfo U8_TYPE = {.kind = TYPE_INT,
                           .integer = {.is_signed = false, .num_bits = 8},
                           .scope = &U8_TYPE_SCOPE};

static Scope U16_TYPE_SCOPE = {0};
static TypeInfo U16_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 16},
                            .scope = &U16_TYPE_SCOPE};

static Scope U32_TYPE_SCOPE = {0};
static TypeInfo U32_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 32},
                            .scope = &U32_TYPE_SCOPE};

static Scope U64_TYPE_SCOPE = {0};
static TypeInfo U64_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = false, .num_bits = 64},
                            .scope = &U64_TYPE_SCOPE};

// Signed int types
static Scope I8_TYPE_SCOPE = {0};
static TypeInfo I8_TYPE = {.kind = TYPE_INT,
                           .integer = {.is_signed = true, .num_bits = 8},
                           .scope = &I8_TYPE_SCOPE};

static Scope I16_TYPE_SCOPE = {0};
static TypeInfo I16_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 16},
                            .scope = &I16_TYPE_SCOPE};

static Scope I32_TYPE_SCOPE = {0};
static TypeInfo I32_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 32},
                            .scope = &I32_TYPE_SCOPE};

static Scope I64_TYPE_SCOPE = {0};
static TypeInfo I64_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 64},
                            .scope = &I64_TYPE_SCOPE};

// Architecture int types
static Scope INT_TYPE_SCOPE = {0};
static TypeInfo INT_TYPE = {.kind = TYPE_INT,
                            .integer = {.is_signed = true, .num_bits = 64},
                            .scope = &INT_TYPE_SCOPE};

static Scope UINT_TYPE_SCOPE = {0};
static TypeInfo UINT_TYPE = {.kind = TYPE_INT,
                             .integer = {.is_signed = false, .num_bits = 64},
                             .scope = &UINT_TYPE_SCOPE};

// Numeric literal types
static TypeInfo INT_LIT_TYPE = {.kind = TYPE_INT,
                                .flags = TYPE_FLAG_CAN_CHANGE,
                                .integer = {.is_signed = true, .num_bits = 64}};

static TypeInfo FLOAT_LIT_TYPE = {
    .kind = TYPE_FLOAT, .flags = TYPE_FLAG_CAN_CHANGE, .floating.num_bits = 64};

// Other types
static TypeInfo BOOL_TYPE = {.kind = TYPE_BOOL};

static Scope FLOAT_TYPE_SCOPE = {0};
static TypeInfo FLOAT_TYPE = {
    .kind = TYPE_FLOAT, .floating.num_bits = 32, .scope = &FLOAT_TYPE_SCOPE};

static Scope DOUBLE_TYPE_SCOPE = {0};
static TypeInfo DOUBLE_TYPE = {
    .kind = TYPE_FLOAT, .floating.num_bits = 64, .scope = &DOUBLE_TYPE_SCOPE};

static TypeInfo VOID_TYPE = {.kind = TYPE_VOID};

static TypeInfo BOOL_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 8}};

static TypeInfo NAMESPACE_TYPE = {.kind = TYPE_NAMESPACE};

static TypeInfo TYPE_OF_TYPE = {.kind = TYPE_TYPE};

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
                    &received->proc.params[i], &expected->proc.params[i]))
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
compatible_pointer_types_aux(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind == TYPE_POINTER && expected->kind == TYPE_POINTER)
    {
        return compatible_pointer_types_aux(
            received->ptr.sub, expected->ptr.sub);
    }
    else if (received->kind != TYPE_POINTER && expected->kind != TYPE_POINTER)
    {
        if (received->kind == TYPE_VOID) return expected;
        if (expected->kind == TYPE_VOID) return received;
    }

    return NULL;
}

static TypeInfo *
compatible_pointer_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind == TYPE_POINTER && expected->kind == TYPE_POINTER)
    {
        return compatible_pointer_types_aux(
            received->ptr.sub, expected->ptr.sub);
    }

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

static inline TypeInfo *create_array_type(Compiler *compiler, TypeInfo *subtype, size_t size)
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
    ptr_ast->type_info = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    ptr_ast->type_info->kind = TYPE_POINTER;
    ptr_ast->type_info->ptr.sub = ty->array.sub;
    scope_set(ty->scope, STR("ptr"), ptr_ast);

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .type_info = &UINT_TYPE};
    scope_set(ty->scope, STR("len"), &len_ast);

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
    ptr_ast->type = AST_BUILTIN_PTR;
    ptr_ast->type_info = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    ptr_ast->type_info->kind = TYPE_POINTER;
    ptr_ast->type_info->ptr.sub = ty->array.sub;
    scope_set(ty->scope, STR("ptr"), ptr_ast);

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .type_info = &UINT_TYPE};
    scope_set(ty->scope, STR("len"), &len_ast);

    return ty;
}
