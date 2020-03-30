typedef enum TypeKind {
    TYPE_UNINITIALIZED,
    TYPE_NONE,
    TYPE_TYPE,
    TYPE_PROC,
    TYPE_STRUCT,
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
    TypeKind kind;
    LLVMTypeRef ref;
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
            struct Scope *scope;
        } structure;
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

static TypeInfo SIZE_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 64}};

static TypeInfo BOOL_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 8}};

static TypeInfo NAMESPACE_TYPE = {.kind = TYPE_NAMESPACE};

static TypeInfo TYPE_OF_TYPE = {.kind = TYPE_TYPE};

TypeInfo *exact_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind != expected->kind) return NULL;
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

TypeInfo *compatible_pointer_types_aux(TypeInfo *received, TypeInfo *expected)
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

TypeInfo *compatible_pointer_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind == TYPE_POINTER && expected->kind == TYPE_POINTER)
    {
        return compatible_pointer_types_aux(
            received->ptr.sub, expected->ptr.sub);
    }

    return NULL;
}

TypeInfo *common_numeric_type(TypeInfo *a, TypeInfo *b)
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
