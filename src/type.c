typedef enum TypeKind {
    TYPE_UNINITIALIZED = 0,
    TYPE_NONE = 1,
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
} TypeKind;

typedef enum TypeFlags {
    TYPE_FLAG_DISTINCT = 1 << 0,
    TYPE_FLAG_EXTERN = 1 << 1,
    TYPE_FLAG_C_VARARGS = 1 << 2,
    TYPE_FLAG_VARARGS = 1 << 3,
    TYPE_FLAG_CAN_CHANGE = 1 << 10,
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
    String pretty_name;

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

static TypeInfo NULL_PTR_TYPE = {
    .kind = TYPE_POINTER, .flags = TYPE_FLAG_CAN_CHANGE, .ptr.sub = &VOID_TYPE};

static TypeInfo VOID_PTR_TYPE = {.kind = TYPE_POINTER, .ptr.sub = &VOID_TYPE};

static TypeInfo BOOL_INT_TYPE = {
    .kind = TYPE_INT, .integer = {.is_signed = false, .num_bits = 8}};

static TypeInfo *STRING_TYPE = NULL;

static TypeInfo ANY_TYPE = {.kind = TYPE_ANY};

static TypeInfo NAMESPACE_TYPE = {.kind = TYPE_NAMESPACE};

static TypeInfo TEMPLATE_TYPE = {.kind = TYPE_TEMPLATE};

static TypeInfo TYPE_OF_TYPE = {.kind = TYPE_TYPE};

static TypeInfo NONE_TYPE = {.kind = TYPE_NONE};

// Type functions

static inline bool is_type_compound(TypeInfo *type)
{
    return (
        type->kind == TYPE_STRUCT || type->kind == TYPE_SLICE ||
        type->kind == TYPE_ARRAY || type->kind == TYPE_VECTOR ||
        type->kind == TYPE_DYNAMIC_ARRAY);
}

static inline bool is_type_basic(TypeInfo *type)
{
    return (
        type->kind == TYPE_INT || type->kind == TYPE_BOOL ||
        type->kind == TYPE_FLOAT || type->kind == TYPE_ENUM);
}

static inline bool is_type_iterable(TypeInfo *type)
{
    return (
        type->kind == TYPE_ARRAY || type->kind == TYPE_SLICE ||
        type->kind == TYPE_DYNAMIC_ARRAY);
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

    if ((expected->flags & TYPE_FLAG_DISTINCT))
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
        if ((received->pretty_name.len > 0) || (expected->pretty_name.len > 0))
        {
            if ((received->pretty_name.len > 0) &&
                (expected->pretty_name.len > 0))
            {
                if (!string_equals(
                        received->pretty_name, expected->pretty_name))
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

    case TYPE_ANY:
    case TYPE_NAMESPACE:
    case TYPE_BOOL:
    case TYPE_VOID:
    case TYPE_TYPE:
    case TYPE_TEMPLATE:
    case TYPE_UNINITIALIZED:
    case TYPE_NONE: break;
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

    return NULL;
}

static TypeInfo *common_numeric_type(TypeInfo *a, TypeInfo *b)
{
    if (a->kind == TYPE_POINTER && b->kind == TYPE_POINTER)
    {
        if (a->flags & TYPE_FLAG_CAN_CHANGE) return b;
        if (b->flags & TYPE_FLAG_CAN_CHANGE) return a;
        return NULL;
    }

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

    if (a->flags & TYPE_FLAG_CAN_CHANGE) return b;
    if (b->flags & TYPE_FLAG_CAN_CHANGE) return a;

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

static void init_numeric_type(Compiler *compiler, TypeInfo *type)
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

static void init_any_type(Compiler *compiler, TypeInfo *type)
{
    type->scope = bump_alloc(&compiler->bump, sizeof(Scope));
    scope_init(type->scope, compiler, SCOPE_INSTANCED, 2, NULL);
    type->scope->type_info = type;

    static Ast ptr_ast = {.type = AST_BUILTIN_PTR, .flags = AST_FLAG_PUBLIC};
    scope_set(type->scope, STR("ptr"), &ptr_ast);

    static Ast type_info_ast = {.type = AST_BUILTIN_TYPE_INFO,
                                .flags = AST_FLAG_PUBLIC};
    scope_set(type->scope, STR("type_info"), &type_info_ast);
}

static TypeInfo *create_pointer_type(Compiler *compiler, TypeInfo *subtype)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_POINTER;
    ty->ptr.sub = subtype;

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

// scope param can be null
static TypeInfo *
create_named_struct_type(Compiler *compiler, Scope *scope, bool is_union)
{
    TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
    memset(ty, 0, sizeof(*ty));
    ty->kind = TYPE_STRUCT;
    ty->scope = scope;
    ty->structure.is_union = is_union;
    return ty;
}

static void
set_struct_type_fields(TypeInfo *struct_type, ArrayOfTypeInfoPtr *fields)
{
    struct_type->structure.fields = *fields;
}

static void print_mangled_type(StringBuilder *sb, TypeInfo *type)
{
    if (type->pretty_name.len > 0)
    {
        sb_sprintf(
            sb,
            "T%zu%.*s",
            type->pretty_name.len,
            PRINT_STR(type->pretty_name));
        return;
    }

    switch (type->kind)
    {
    case TYPE_TYPE: sb_append(sb, STR("t")); break;
    case TYPE_TEMPLATE: sb_append(sb, STR("m")); break;

    case TYPE_VOID: sb_append(sb, STR("v")); break;

    case TYPE_BOOL: sb_append(sb, STR("b")); break;

    case TYPE_NAMESPACE: sb_append(sb, STR("n")); break;

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
        print_mangled_type(sb, type->proc.return_type);
        for (size_t i = 0; i < type->proc.params.len; ++i)
        {
            print_mangled_type(sb, type->proc.params.ptr[i]);
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
    case TYPE_NONE: assert(0); break;
    }
}

static void print_type_pretty_name(StringBuilder *sb, TypeInfo *type)
{
    if (type->pretty_name.len > 0)
    {
        assert(!is_type_basic(type));
        sb_append(sb, type->pretty_name);
        return;
    }

    switch (type->kind)
    {
    case TYPE_TYPE: sb_append(sb, STR("@Type")); break;
    case TYPE_TEMPLATE: sb_append(sb, STR("@Template")); break;

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
        sb_append(sb, STR("enum "));
        print_type_pretty_name(sb, type->enumeration.underlying_type);
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
    case TYPE_NONE: assert(0); break;
    }
}

static String get_type_pretty_name(Compiler *compiler, TypeInfo *type)
{
    if (type->pretty_name.len > 0)
    {
        return type->pretty_name;
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

static uint32_t align_of_type(TypeInfo *type)
{
    if (type->align > 0) return type->align;

    uint32_t align = 1;
    switch (type->kind)
    {
    case TYPE_INT: align = type->integer.num_bits / 8; break;
    case TYPE_FLOAT: align = type->floating.num_bits / 8; break;
    case TYPE_BOOL: align = BOOL_INT_TYPE.integer.num_bits / 8; break;
    case TYPE_ENUM:
        align = align_of_type(type->enumeration.underlying_type);
        break;

    case TYPE_ANY: align = PTR_SIZE; break;
    case TYPE_POINTER: align = PTR_SIZE; break;
    case TYPE_SLICE: align = PTR_SIZE; break;
    case TYPE_DYNAMIC_ARRAY: align = PTR_SIZE; break;

    case TYPE_VECTOR:
        align = align_of_type(type->array.sub) * type->array.size;
        break;
    case TYPE_ARRAY: align = align_of_type(type->array.sub); break;

    case TYPE_STRUCT: {
        for (TypeInfo **field = type->structure.fields.ptr;
             field != type->structure.fields.ptr + type->structure.fields.len;
             ++field)
        {
            uint32_t field_align = align_of_type(*field);
            if (field_align > align) align = field_align;
        }

        break;
    }

    case TYPE_PROC:
    case TYPE_UNINITIALIZED:
    case TYPE_NONE:
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
    case TYPE_BOOL: size = BOOL_INT_TYPE.integer.num_bits / 8; break;
    case TYPE_ENUM:
        size = size_of_type(compiler, type->enumeration.underlying_type);
        break;

    case TYPE_ANY: size = PTR_SIZE * 2; break;
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

                actual_alignments[i] = align_of_type(field);
                uint32_t next_alignment = align_of_type(next_field);
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

    case TYPE_PROC:
    case TYPE_UNINITIALIZED:
    case TYPE_NONE:
    case TYPE_VOID:
    case TYPE_NAMESPACE:
    case TYPE_TEMPLATE:
    case TYPE_TYPE: assert(0); break;
    }

    type->size = size;
    return type->size;
}

static bool is_type_castable(TypeInfo *src_ty, TypeInfo *dest_ty)
{
    return (
        (dest_ty->kind == TYPE_POINTER && src_ty->kind == TYPE_POINTER) ||
        (dest_ty->kind == TYPE_POINTER && src_ty->kind == TYPE_INT) ||
        (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_POINTER) ||
        (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_INT) ||
        (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_FLOAT) ||
        (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_FLOAT) ||
        (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_INT));
}
