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

typedef struct TypeInfo
{
    TypeKind kind;
    LLVMTypeRef ref;
    bool can_change;

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

static TypeInfo SIZE_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 64}};

static TypeInfo BOOL_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 8}};

TypeInfo *exact_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind != expected->kind) return NULL;

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
    case TYPE_NAMESPACE: break;
    case TYPE_BOOL: break;
    case TYPE_VOID: break;
    case TYPE_TYPE: break;
    case TYPE_UNINITIALIZED: break;
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

    if (float_type && other_type->can_change)
    {
        return float_type;
    }

    if (a->can_change)
    {
        return b;
    }

    if (b->can_change)
    {
        return a;
    }

    return NULL;
}
