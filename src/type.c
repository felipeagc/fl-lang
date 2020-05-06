typedef enum TypeKind {
    TYPE_UNINITIALIZED = 0,
    TYPE_NAMED_PLACEHOLDER = 1,
    TYPE_TYPE = 2,
    TYPE_PROC = 3,
    TYPE_STRUCT = 4,
    TYPE_ENUM = 5,
    TYPE_POINTER = 6,
    TYPE_VECTOR = 7,
    TYPE_ARRAY = 8,
    TYPE_SLICE = 9,
    TYPE_DYNAMIC_ARRAY = 10,
    TYPE_INT = 11,
    TYPE_FLOAT = 12,
    TYPE_BOOL = 13,
    TYPE_VOID = 14,
    TYPE_NAMESPACE = 15,
    TYPE_TEMPLATE = 16,
    TYPE_ANY = 17,
    TYPE_UNTYPED_INT = 18,
    TYPE_UNTYPED_FLOAT = 19,
    TYPE_RAW_POINTER = 20,
} TypeKind;

typedef enum TypeFlags {
    TYPE_FLAG_EXTERN = 1 << 0,
    TYPE_FLAG_C_VARARGS = 1 << 1,
    TYPE_FLAG_VARARGS = 1 << 2,
} TypeFlags;

struct TypeInfo
{
    TypeKind kind;
    uint32_t flags;
    uint32_t size;
    uint32_t align;
    uint32_t rtti_index;
    LLVMTypeRef ref;
    LLVMMetadataRef debug_ref;
    SourceFile *file;
    struct Scope *scope;
    String name;

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
            ArrayOfTypeInfoPtr params;
        } proc;
        struct
        {
            ArrayOfTypeInfoPtr fields;
            bool is_union;
        } structure;
        struct
        {
            struct TypeInfo *underlying_type;
        } enumeration;
    };
};

// Type functions

static inline bool is_type_runtime(TypeInfo *type)
{
    return (
        type->kind == TYPE_BOOL || type->kind == TYPE_INT ||
        type->kind == TYPE_FLOAT || type->kind == TYPE_ENUM ||
        type->kind == TYPE_STRUCT || type->kind == TYPE_ARRAY ||
        type->kind == TYPE_POINTER || type->kind == TYPE_RAW_POINTER ||
        type->kind == TYPE_SLICE || type->kind == TYPE_DYNAMIC_ARRAY ||
        type->kind == TYPE_ANY || type->kind == TYPE_VECTOR);
}

static inline bool is_type_compound(TypeInfo *type)
{
    return (
        type->kind == TYPE_STRUCT || type->kind == TYPE_SLICE ||
        type->kind == TYPE_ARRAY || type->kind == TYPE_VECTOR ||
        type->kind == TYPE_DYNAMIC_ARRAY);
}

static inline bool can_type_be_named(TypeInfo *type)
{
    return (type->kind == TYPE_STRUCT || type->kind == TYPE_ENUM);
}

static inline bool is_type_basic(TypeInfo *type)
{
    return (
        type->kind == TYPE_INT || type->kind == TYPE_BOOL ||
        type->kind == TYPE_FLOAT || type->kind == TYPE_ENUM);
}

static inline bool is_type_integer(TypeInfo *type)
{
    return (type->kind == TYPE_INT || type->kind == TYPE_UNTYPED_INT);
}

static inline bool is_type_float(TypeInfo *type)
{
    return (type->kind == TYPE_FLOAT || type->kind == TYPE_UNTYPED_FLOAT);
}

static inline bool is_type_iterable(TypeInfo *type)
{
    return (
        type->kind == TYPE_ARRAY || type->kind == TYPE_SLICE ||
        type->kind == TYPE_DYNAMIC_ARRAY);
}

static inline bool is_type_arithmetic(TypeInfo *type)
{
    return (
        type->kind == TYPE_INT || type->kind == TYPE_FLOAT ||
        type->kind == TYPE_UNTYPED_INT || type->kind == TYPE_UNTYPED_FLOAT ||
        type->kind == TYPE_VECTOR);
}

static inline bool is_type_logic(TypeInfo *type)
{
    return (
        type->kind == TYPE_INT || type->kind == TYPE_FLOAT ||
        type->kind == TYPE_UNTYPED_INT || type->kind == TYPE_UNTYPED_FLOAT ||
        type->kind == TYPE_BOOL || type->kind == TYPE_POINTER ||
        type->kind == TYPE_RAW_POINTER || type->kind == TYPE_ENUM);
}

static inline bool is_type_bitwise(TypeInfo *type)
{
    return (type->kind == TYPE_INT || type->kind == TYPE_UNTYPED_INT);
}

static inline bool is_type_subscript(TypeInfo *type)
{
    return (
        type->kind == TYPE_POINTER || type->kind == TYPE_ARRAY ||
        type->kind == TYPE_VECTOR || type->kind == TYPE_SLICE ||
        type->kind == TYPE_DYNAMIC_ARRAY);
}

static inline bool is_type_subscript_slice(TypeInfo *type)
{
    return (
        type->kind == TYPE_POINTER || type->kind == TYPE_ARRAY ||
        type->kind == TYPE_SLICE || type->kind == TYPE_DYNAMIC_ARRAY);
}

static bool is_type_castable(TypeInfo *src_ty, TypeInfo *dest_ty)
{
    return (
        (dest_ty->kind == TYPE_POINTER && src_ty->kind == TYPE_POINTER) ||

        (dest_ty->kind == TYPE_POINTER && is_type_integer(src_ty)) ||
        (is_type_integer(dest_ty) && src_ty->kind == TYPE_POINTER) ||

        (is_type_integer(dest_ty) && is_type_integer(src_ty)) ||
        (is_type_float(dest_ty) && is_type_float(src_ty)) ||

        (is_type_float(dest_ty) && is_type_integer(src_ty)) ||
        (is_type_integer(dest_ty) && is_type_float(src_ty)));
}

static TypeInfo *common_numeric_type(TypeInfo *a, TypeInfo *b)
{
    if (a->kind == b->kind) return a;

    if (a->kind == TYPE_POINTER && b->kind == TYPE_RAW_POINTER)
    {
        return a;
    }
    else if (b->kind == TYPE_POINTER && a->kind == TYPE_RAW_POINTER)
    {
        return b;
    }

    if (a->kind == TYPE_FLOAT)
    {
        if (b->kind == TYPE_FLOAT || b->kind == TYPE_UNTYPED_FLOAT ||
            b->kind == TYPE_UNTYPED_INT)
        {
            return a;
        }
    }
    else if (b->kind == TYPE_FLOAT)
    {
        if (a->kind == TYPE_FLOAT || a->kind == TYPE_UNTYPED_FLOAT ||
            a->kind == TYPE_UNTYPED_INT)
        {
            return b;
        }
    }
    else if (a->kind == TYPE_UNTYPED_FLOAT)
    {
        if (b->kind == TYPE_UNTYPED_INT || b->kind == TYPE_UNTYPED_FLOAT)
        {
            return a;
        }
    }
    else if (b->kind == TYPE_UNTYPED_FLOAT)
    {
        if (a->kind == TYPE_UNTYPED_INT || a->kind == TYPE_UNTYPED_FLOAT)
        {
            return b;
        }
    }
    else if (a->kind == TYPE_INT)
    {
        if (b->kind == TYPE_INT || b->kind == TYPE_UNTYPED_INT) return a;
    }
    else if (b->kind == TYPE_INT)
    {
        if (a->kind == TYPE_INT || a->kind == TYPE_UNTYPED_INT) return b;
    }
    else if (a->kind == TYPE_UNTYPED_INT)
    {
        return a;
    }
    else if (b->kind == TYPE_UNTYPED_INT)
    {
        return b;
    }

    return NULL;
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

    case TYPE_DYNAMIC_ARRAY:
    case TYPE_SLICE: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        break;
    }

    case TYPE_ENUM: {
        if (received != expected) return NULL;
        break;
    }

    case TYPE_STRUCT: {
        if ((received->name.len > 0) || (expected->name.len > 0))
        {
            if ((received->name.len > 0) && (expected->name.len > 0))
            {
                if (!string_equals(received->name, expected->name))
                {
                    return NULL;
                }
            }
            else
            {
                return NULL;
            }
        }
        else
        {
            if ((received->structure.fields.len) !=
                (expected->structure.fields.len))
                return NULL;

            size_t field_count = expected->structure.fields.len;
            for (size_t i = 0; i < field_count; ++i)
            {
                if (!exact_types(
                        received->structure.fields.ptr[i],
                        expected->structure.fields.ptr[i]))
                {
                    return NULL;
                }
            }
        }

        break;
    }

    case TYPE_PROC: {
        if (!exact_types(
                received->proc.return_type, expected->proc.return_type))
            return NULL;

        if ((received->proc.params.len) != (expected->proc.params.len))
            return NULL;

        for (size_t i = 0; i < received->proc.params.len; ++i)
        {
            if (!exact_types(
                    received->proc.params.ptr[i], expected->proc.params.ptr[i]))
                return NULL;
        }

        break;
    }

    case TYPE_RAW_POINTER:
    case TYPE_UNTYPED_INT:
    case TYPE_UNTYPED_FLOAT:
    case TYPE_ANY:
    case TYPE_NAMESPACE:
    case TYPE_BOOL:
    case TYPE_VOID:
    case TYPE_TYPE:
    case TYPE_TEMPLATE:
    case TYPE_UNINITIALIZED:
    case TYPE_NAMED_PLACEHOLDER: break;
    }

    return received;
}

static TypeInfo *
compatible_pointer_types(TypeInfo *received, TypeInfo *expected)
{
    if (!expected || !received) return NULL;
    if (received->kind == TYPE_POINTER && received->ptr.sub->kind == TYPE_VOID)
        return expected;
    if (expected->kind == TYPE_POINTER && expected->ptr.sub->kind == TYPE_VOID)
        return received;

    if (received->kind == TYPE_RAW_POINTER)
        return expected;
    if (expected->kind == TYPE_RAW_POINTER)
        return received;

    return NULL;
}

static inline TypeInfo *get_inner_primitive_type(TypeInfo *type)
{
    if (!type) return type;

    while (1)
    {
        switch (type->kind)
        {
        case TYPE_ENUM: type = type->enumeration.underlying_type; break;
        default: return type;
        }
    }

    return type;
}

static void print_mangled_type(StringBuilder *sb, TypeInfo *type)
{
    if (type->name.len > 0)
    {
        sb_sprintf(sb, "T%zu%.*s", type->name.len, PRINT_STR(type->name));
        return;
    }

    switch (type->kind)
    {
    case TYPE_TYPE: sb_append(sb, STR("t")); break;
    case TYPE_TEMPLATE: sb_append(sb, STR("m")); break;

    case TYPE_VOID: sb_append(sb, STR("v")); break;

    case TYPE_BOOL: sb_append(sb, STR("b")); break;

    case TYPE_NAMESPACE: sb_append(sb, STR("n")); break;

    case TYPE_RAW_POINTER: sb_append(sb, STR("X")); break;
    case TYPE_UNTYPED_INT: sb_append(sb, STR("I")); break;
    case TYPE_UNTYPED_FLOAT: sb_append(sb, STR("R")); break;

    case TYPE_ANY: sb_append(sb, STR("Q")); break;

    case TYPE_INT: {
        if (type->integer.is_signed)
        {
            switch (type->integer.num_bits)
            {
            case 8: sb_append(sb, STR("c")); break;
            case 16: sb_append(sb, STR("s")); break;
            case 32: sb_append(sb, STR("i")); break;
            case 64: sb_append(sb, STR("l")); break;
            default: assert(0); break;
            }
        }
        else
        {
            switch (type->integer.num_bits)
            {
            case 8: sb_append(sb, STR("uc")); break;
            case 16: sb_append(sb, STR("us")); break;
            case 32: sb_append(sb, STR("ui")); break;
            case 64: sb_append(sb, STR("ul")); break;
            default: assert(0); break;
            }
        }

        break;
    }

    case TYPE_FLOAT: {
        switch (type->integer.num_bits)
        {
        case 32: sb_append(sb, STR("f")); break;
        case 64: sb_append(sb, STR("d")); break;
        default: assert(0); break;
        }

        break;
    }

    case TYPE_ENUM:
        sb_append(sb, STR("e"));
        print_mangled_type(sb, type->enumeration.underlying_type);
        break;

    case TYPE_PROC: {
        sb_append(sb, STR("F"));
        for (size_t i = 0; i < type->proc.params.len; ++i)
        {
            if (i > 0) sb_append_char(sb, ',');
            print_mangled_type(sb, type->proc.params.ptr[i]);
        }
        sb_append_char(sb, ':');
        print_mangled_type(sb, type->proc.return_type);
        if (type->flags & TYPE_FLAG_C_VARARGS)
        {
            sb_append(sb, STR("..."));
        }
        else if (type->flags & TYPE_FLAG_VARARGS)
        {
            sb_append(sb, STR(".."));
        }
        sb_append(sb, STR("E"));
        break;
    }

    case TYPE_POINTER:
        sb_append(sb, STR("P"));
        print_mangled_type(sb, type->ptr.sub);
        break;

    case TYPE_ARRAY:
        sb_sprintf(sb, "A%zu", type->array.size);
        print_mangled_type(sb, type->array.sub);
        break;

    case TYPE_VECTOR: {
        sb_sprintf(sb, "V%zu", type->array.size);
        print_mangled_type(sb, type->array.sub);
        break;
    }

    case TYPE_SLICE:
        sb_append(sb, STR("S"));
        print_mangled_type(sb, type->array.sub);
        break;

    case TYPE_DYNAMIC_ARRAY:
        sb_append(sb, STR("D"));
        print_mangled_type(sb, type->array.sub);
        break;

    case TYPE_STRUCT: {
        sb_append(sb, STR("C"));
        for (size_t i = 0; i < type->structure.fields.len; ++i)
        {
            print_mangled_type(sb, type->structure.fields.ptr[i]);
        }
        sb_append(sb, STR("E"));
        break;
    }

    case TYPE_UNINITIALIZED:
    case TYPE_NAMED_PLACEHOLDER: assert(0); break;
    }
}

static String get_type_mangled_name(Compiler *compiler, TypeInfo *type)
{
    sb_reset(&compiler->sb);
    print_mangled_type(&compiler->sb, type);
    return sb_build(&compiler->sb, &compiler->bump);
}

static void print_type_pretty_name(StringBuilder *sb, TypeInfo *type)
{
    if (type->name.len > 0)
    {
        assert(can_type_be_named(type));
        sb_append(sb, type->name);
        return;
    }

    switch (type->kind)
    {
    case TYPE_TYPE: sb_append(sb, STR("@Type")); break;
    case TYPE_TEMPLATE: sb_append(sb, STR("@Template")); break;

    case TYPE_RAW_POINTER: sb_append(sb, STR("@Pointer")); break;
    case TYPE_UNTYPED_INT: sb_append(sb, STR("@UntypedInt")); break;
    case TYPE_UNTYPED_FLOAT: sb_append(sb, STR("@UntypedFloat")); break;

    case TYPE_VOID: sb_append(sb, STR("void")); break;

    case TYPE_BOOL: sb_append(sb, STR("bool")); break;

    case TYPE_NAMESPACE: sb_append(sb, STR("@Namespace")); break;

    case TYPE_ANY: sb_append(sb, STR("@Any")); break;

    case TYPE_INT: {
        if (type->integer.is_signed)
        {
            switch (type->integer.num_bits)
            {
            case 8: sb_append(sb, STR("i8")); break;
            case 16: sb_append(sb, STR("i16")); break;
            case 32: sb_append(sb, STR("i32")); break;
            case 64: sb_append(sb, STR("i64")); break;
            default: assert(0); break;
            }
        }
        else
        {
            switch (type->integer.num_bits)
            {
            case 8: sb_append(sb, STR("u8")); break;
            case 16: sb_append(sb, STR("u16")); break;
            case 32: sb_append(sb, STR("u32")); break;
            case 64: sb_append(sb, STR("u64")); break;
            default: assert(0); break;
            }
        }

        break;
    }

    case TYPE_FLOAT: {
        switch (type->integer.num_bits)
        {
        case 32: sb_append(sb, STR("float")); break;
        case 64: sb_append(sb, STR("double")); break;
        default: assert(0); break;
        }

        break;
    }

    case TYPE_ENUM:
        sb_append(sb, STR("@Enum("));
        print_type_pretty_name(sb, type->enumeration.underlying_type);
        sb_append(sb, STR(")"));
        break;

    case TYPE_PROC: {
        sb_append(sb, STR("func("));
        for (size_t i = 0; i < type->proc.params.len; ++i)
        {
            if (i > 0) sb_append(sb, STR(", "));
            print_type_pretty_name(sb, type->proc.params.ptr[i]);
        }
        sb_append(sb, STR(") -> "));
        print_type_pretty_name(sb, type->proc.return_type);
        break;
    }

    case TYPE_POINTER:
        sb_append(sb, STR("*"));
        print_type_pretty_name(sb, type->ptr.sub);
        break;

    case TYPE_ARRAY:
        sb_sprintf(sb, "[%zu]", type->array.size);
        print_type_pretty_name(sb, type->array.sub);
        break;

    case TYPE_VECTOR: {
        sb_sprintf(sb, "@vector_type(");
        print_type_pretty_name(sb, type->array.sub);
        sb_sprintf(sb, ", %zu)", type->array.size);
        break;
    }

    case TYPE_SLICE:
        sb_append(sb, STR("[_]"));
        print_type_pretty_name(sb, type->array.sub);
        break;

    case TYPE_DYNAMIC_ARRAY:
        sb_append(sb, STR("[dyn]"));
        print_type_pretty_name(sb, type->array.sub);
        break;

    case TYPE_STRUCT: {
        sb_append(sb, STR("struct{"));
        for (size_t i = 0; i < type->structure.fields.len; ++i)
        {
            if (i > 0) sb_append(sb, STR(", "));
            print_type_pretty_name(sb, type->structure.fields.ptr[i]);
        }
        sb_append(sb, STR("}"));
        break;
    }

    case TYPE_UNINITIALIZED:
    case TYPE_NAMED_PLACEHOLDER: assert(0); break;
    }
}

static String get_type_pretty_name(Compiler *compiler, TypeInfo *type)
{
    if (type->name.len > 0)
    {
        return type->name;
    }

    sb_reset(&compiler->sb);
    print_type_pretty_name(&compiler->sb, type);
    return sb_build(&compiler->sb, &compiler->bump);
}

#define PTR_SIZE 8

static uint32_t pad_to_alignment(uint32_t current, uint32_t align)
{
    assert(align >= 1);

    uint32_t minum = current & (align - 1);
    if (minum)
    {
        assert((current % align) != 0);
        current += align - minum;
    }

    return current;
}

static uint32_t align_of_type(Compiler *compiler, TypeInfo *type)
{
    if (type->align > 0) return type->align;

    uint32_t align = 1;
    switch (type->kind)
    {
    case TYPE_INT: align = type->integer.num_bits / 8; break;
    case TYPE_FLOAT: align = type->floating.num_bits / 8; break;
    case TYPE_BOOL:
        align = compiler->bool_int_type->integer.num_bits / 8;
        break;
    case TYPE_ENUM:
        align = align_of_type(compiler, type->enumeration.underlying_type);
        break;

    case TYPE_ANY: align = PTR_SIZE; break;

    case TYPE_RAW_POINTER:
    case TYPE_POINTER: align = PTR_SIZE; break;

    case TYPE_SLICE: align = PTR_SIZE; break;
    case TYPE_DYNAMIC_ARRAY: align = PTR_SIZE; break;

    case TYPE_VECTOR:
        align = align_of_type(compiler, type->array.sub) * type->array.size;
        break;
    case TYPE_ARRAY: align = align_of_type(compiler, type->array.sub); break;

    case TYPE_STRUCT: {
        for (TypeInfo **field = type->structure.fields.ptr;
             field != type->structure.fields.ptr + type->structure.fields.len;
             ++field)
        {
            uint32_t field_align = align_of_type(compiler, *field);
            if (field_align > align) align = field_align;
        }

        break;
    }

    case TYPE_UNTYPED_INT:
    case TYPE_UNTYPED_FLOAT:
    case TYPE_PROC:
    case TYPE_UNINITIALIZED:
    case TYPE_NAMED_PLACEHOLDER:
    case TYPE_VOID:
    case TYPE_NAMESPACE:
    case TYPE_TEMPLATE:
    case TYPE_TYPE: assert(0); break;
    }

    type->align = align;

    return type->align;
}

static uint32_t size_of_type(Compiler *compiler, TypeInfo *type)
{
    if (type->size > 0) return type->size;

    uint32_t size = 0;

    switch (type->kind)
    {
    case TYPE_INT: size = type->integer.num_bits / 8; break;
    case TYPE_FLOAT: size = type->floating.num_bits / 8; break;
    case TYPE_BOOL: size = compiler->bool_int_type->integer.num_bits / 8; break;
    case TYPE_ENUM:
        size = size_of_type(compiler, type->enumeration.underlying_type);
        break;

    case TYPE_ANY: size = PTR_SIZE * 2; break;

    case TYPE_RAW_POINTER:
    case TYPE_POINTER: size = PTR_SIZE; break;

    case TYPE_SLICE: size = PTR_SIZE * 2; break;
    case TYPE_DYNAMIC_ARRAY: size = PTR_SIZE * 3; break;

    case TYPE_VECTOR:
        size = size_of_type(compiler, type->array.sub) * type->array.size;
        break;
    case TYPE_ARRAY:
        size = size_of_type(compiler, type->array.sub) * type->array.size;
        break;

    case TYPE_STRUCT: {
        if (!type->structure.is_union)
        {
            uint32_t *actual_alignments = bump_alloc(
                &compiler->bump, sizeof(uint32_t) * type->structure.fields.len);

            for (size_t i = 0; i < type->structure.fields.len; ++i)
            {
                TypeInfo *field = type->structure.fields.ptr[i];
                TypeInfo *next_field = type->structure.fields.ptr[i + 1];
                if (i == (type->structure.fields.len - 1))
                {
                    next_field = type->structure.fields.ptr[0];
                }

                actual_alignments[i] = align_of_type(compiler, field);
                uint32_t next_alignment = align_of_type(compiler, next_field);
                actual_alignments[i] =
                    pad_to_alignment(actual_alignments[i], next_alignment);
            }

            for (size_t i = 0; i < type->structure.fields.len; ++i)
            {
                TypeInfo *field = type->structure.fields.ptr[i];
                uint32_t next_index = i + 1;
                if (i == (type->structure.fields.len - 1))
                {
                    next_index = 0;
                }

                uint32_t field_size = size_of_type(compiler, field);

                // Add padding
                uint32_t next_alignment = actual_alignments[next_index];
                size += field_size;
                size = pad_to_alignment(size, next_alignment);
            }
        }
        else
        {
            for (size_t i = 0; i < type->structure.fields.len; ++i)
            {
                TypeInfo *field = type->structure.fields.ptr[i];
                uint32_t field_size = size_of_type(compiler, field);
                if (field_size > size) size = field_size;
            }
        }

        break;
    }

    case TYPE_UNTYPED_INT:
    case TYPE_UNTYPED_FLOAT:
    case TYPE_PROC:
    case TYPE_UNINITIALIZED:
    case TYPE_NAMED_PLACEHOLDER:
    case TYPE_VOID:
    case TYPE_NAMESPACE:
    case TYPE_TEMPLATE:
    case TYPE_TYPE: assert(0); break;
    }

    type->size = size;
    return type->size;
}

static TypeInfo *cache_type(Compiler *compiler, TypeInfo *type)
{
    assert(type);

    String key = get_type_mangled_name(compiler, type);
    TypeInfo *found = NULL;
    if (hash_get(&compiler->types, key, (void **)&found))
    {
        assert(found);
        return found;
    }

    hash_set(&compiler->types, key, type);
    return NULL;
}

static TypeInfo *create_named_placeholder_type(Compiler *compiler, String name)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_NAMED_PLACEHOLDER;
    ty->name = name;
    return ty;
}

static TypeInfo *create_simple_type(Compiler *compiler, TypeKind kind)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = kind;
    return ty;
}

static void init_numeric_type_scope(Compiler *compiler, TypeInfo *type)
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

static TypeInfo *
create_int_type(Compiler *compiler, uint32_t num_bits, bool is_signed)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_INT;
    ty->integer.num_bits = num_bits;
    ty->integer.is_signed = is_signed;
    init_numeric_type_scope(compiler, ty);
    return ty;
}

static TypeInfo *create_float_type(Compiler *compiler, uint32_t num_bits)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_FLOAT;
    ty->floating.num_bits = num_bits;
    init_numeric_type_scope(compiler, ty);
    return ty;
}

static TypeInfo *create_any_type(Compiler *compiler)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_ANY;

    ty->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(ty->scope, compiler, SCOPE_INSTANCED, 2, NULL);
    ty->scope->type_info = ty;

    static Ast ptr_ast = {.type = AST_BUILTIN_PTR, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("ptr"), &ptr_ast);

    static Ast type_info_ast = {.type = AST_BUILTIN_TYPE_INFO,
                                .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("type_info"), &type_info_ast);
    return ty;
}

static TypeInfo *create_pointer_type(Compiler *compiler, TypeInfo *subtype)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_POINTER;
    ty->ptr.sub = subtype;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

    return ty;
}

static TypeInfo *
create_array_type(Compiler *compiler, TypeInfo *subtype, size_t size)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_ARRAY;
    ty->array.sub = subtype;
    ty->array.size = size;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

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

static TypeInfo *
create_vector_type(Compiler *compiler, TypeInfo *subtype, size_t size)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_VECTOR;
    ty->array.sub = subtype;
    ty->array.size = size;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

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

static TypeInfo *create_slice_type(Compiler *compiler, TypeInfo *subtype)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_SLICE;
    ty->array.sub = subtype;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

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

static TypeInfo *
create_dynamic_array_type(Compiler *compiler, TypeInfo *subtype)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_DYNAMIC_ARRAY;
    ty->array.sub = subtype;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

    ty->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(ty->scope, compiler, SCOPE_INSTANCED, 3, NULL);
    ty->scope->type_info = ty;

    Ast *ptr_ast = bump_alloc(&compiler->bump, sizeof(Ast));
    memset(ptr_ast, 0, sizeof(*ptr_ast));
    ptr_ast->type = AST_BUILTIN_PTR;
    ptr_ast->flags = AST_FLAG_PUBLIC;
    scope_set(ty->scope, STR("ptr"), ptr_ast);

    static Ast len_ast = {.type = AST_BUILTIN_LEN, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("len"), &len_ast);

    static Ast cap_ast = {.type = AST_BUILTIN_CAP, .flags = AST_FLAG_PUBLIC};
    scope_set(ty->scope, STR("cap"), &cap_ast);

    return ty;
}

static void init_named_struct_type(
    TypeInfo *ty, Scope *scope, bool is_union, ArrayOfTypeInfoPtr *fields)
{
    ty->kind = TYPE_STRUCT;
    ty->scope = scope;
    memset(&ty->structure, 0, sizeof(ty->structure));
    ty->structure.is_union = is_union;
    ty->structure.fields = *fields;
}

static TypeInfo *create_anonymous_struct_type(
    Compiler *compiler, Scope *scope, bool is_union, ArrayOfTypeInfoPtr *fields)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_STRUCT;
    ty->scope = scope;
    ty->structure.is_union = is_union;
    ty->structure.fields = *fields;
    return ty;
}

static TypeInfo *create_proc_type(
    Compiler *compiler,
    ArrayOfTypeInfoPtr params,
    TypeInfo *return_type,
    uint32_t flags)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_PROC;
    ty->flags = flags;
    ty->proc.params = params;
    ty->proc.return_type = return_type;

    TypeInfo *cached = cache_type(compiler, ty);
    if (cached) return cached;

    return ty;
}

static TypeInfo *
create_enum_type(Compiler *compiler, Scope *scope, TypeInfo *underlying_type)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_ENUM;
    ty->scope = scope;
    ty->enumeration.underlying_type = underlying_type;

    return ty;
}

static void
init_named_enum_type(TypeInfo *ty, Scope *scope, TypeInfo *underlying_type)
{
    ty->kind = TYPE_ENUM;
    ty->scope = scope;
    memset(&ty->enumeration, 0, sizeof(ty->enumeration));
    ty->enumeration.underlying_type = underlying_type;
}
