#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <clang-c/Index.h>
#include "../string.c"
#include "../hashmap.c"
#include "../array.c"
#include "../filesystem.c"

static size_t g_indent = 0;
static HashMap g_symbol_map = {0};
static const char **g_to_parse = {0};
static char *g_dir;

#define PRINT_INDENT(sb)                                                       \
    for (size_t i = 0; i < g_indent; ++i)                                      \
    {                                                                          \
        sb_append(sb, STR(" "));                                               \
    }

typedef struct StringBuilder
{
    char *buf;
    char *scratch;
    size_t len;
    size_t cap;
} StringBuilder;

static void sb_init(StringBuilder *sb)
{
    sb->len = 0;
    sb->cap = 1 << 16;
    sb->buf = malloc(sb->cap);     // 64k
    sb->scratch = malloc(sb->cap); // 64k
}

static void sb_grow(StringBuilder *sb)
{
    sb->cap *= 2;
    sb->buf = realloc(sb->buf, sb->cap);
    sb->scratch = realloc(sb->scratch, sb->cap);
}

static void sb_append(StringBuilder *sb, String str)
{
    if (str.length + sb->len >= sb->cap)
    {
        sb_grow(sb);
    }
    strncpy(&sb->buf[sb->len], str.buf, str.length);
    sb->len += str.length;
}

static void sb_sprintf(StringBuilder *sb, const char *fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);
    size_t len = vsnprintf(sb->scratch, sb->cap, fmt, vl);
    va_end(vl);
    sb_append(sb, (String){.length = len, .buf = sb->scratch});
}

static String sb_build(StringBuilder *sb)
{
    String result = {0};
    result.length = sb->len;
    result.buf = malloc(result.length);
    strncpy(result.buf, sb->buf, result.length);
    return result;
}

static const char *USAGE[] = {
    "Usage:\n",
    "  %s <filename>        Generates bindings for file.\n",
    NULL,
};

static void print_usage(int argc, char **argv)
{
    const char **line = USAGE;
    while (*line)
    {
        fprintf(stderr, *line, argv[0]);
        line++;
    }
}

static void print_ident(StringBuilder *sb, String ident)
{
    sb_append(sb, ident);

    if (string_equals(ident, STR("fn")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("version")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("import")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("cast")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("var")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("dynamic")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("byte")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("uint")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("u8")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("u16")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("u32")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("u64")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("i8")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("i16")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("i32")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("i64")))
        sb_append(sb, STR("_"));
}

static void print_type(StringBuilder *sb, CXType type, bool named);

static enum CXChildVisitResult
struct_field_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    StringBuilder *sb = (StringBuilder *)client_data;

    switch (clang_getCursorKind(cursor))
    {
    case CXCursor_FieldDecl: {
        PRINT_INDENT(sb);

        char *field_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String field_name = CSTR(field_name_c);

        print_ident(sb, field_name);

        sb_append(sb, STR(": "));
        print_type(sb, clang_getCursorType(cursor), true);
        sb_append(sb, STR(",\n"));
        break;
    }

    default: break;
    }

    return CXChildVisit_Continue;
}

static void print_type(StringBuilder *sb, CXType type, bool named)
{
    enum CXTypeKind kind = type.kind;

    switch (kind)
    {
    case CXType_Void: sb_append(sb, STR("void")); break;
    case CXType_Bool: sb_append(sb, STR("bool")); break;

    case CXType_Char_U:
    case CXType_UChar:
    case CXType_UShort:
    case CXType_UInt:
    case CXType_ULong:
    case CXType_ULongLong:
    case CXType_UInt128: {
        size_t size = clang_Type_getSizeOf(type);

        if (size == 1)
            sb_append(sb, STR("u8"));
        else if (size == 2)
            sb_append(sb, STR("u16"));
        else if (size == 4)
            sb_append(sb, STR("u32"));
        else if (size == 8)
            sb_append(sb, STR("u64"));
        else
            assert(0);

        break;
    }

    case CXType_Char_S:
    case CXType_SChar:
    case CXType_WChar:
    case CXType_Short:
    case CXType_Int:
    case CXType_Long:
    case CXType_LongLong:
    case CXType_Int128: {
        size_t size = clang_Type_getSizeOf(type);

        if (size == 1)
            sb_append(sb, STR("i8"));
        else if (size == 2)
            sb_append(sb, STR("i16"));
        else if (size == 4)
            sb_append(sb, STR("i32"));
        else if (size == 8)
            sb_append(sb, STR("i64"));
        else
            assert(0);

        break;
    }

    case CXType_Float16:
    case CXType_Half:
    case CXType_Float:
    case CXType_Double:
    case CXType_LongDouble:
    case CXType_Float128: {
        size_t size = clang_Type_getSizeOf(type);

        if (size == 4)
            sb_append(sb, STR("float"));
        else if (size == 8)
            sb_append(sb, STR("double"));
        else
            assert(0);

        break;
    }

    case CXType_Record: {
        CXCursor struct_decl = clang_getTypeDeclaration(type);

        char *struct_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(struct_decl));
        String struct_name = CSTR(struct_name_c);

        if (struct_name.length == 0 || !named)
        {
            sb_append(sb, STR("struct {\n"));

            g_indent += 4;
            clang_visitChildren(struct_decl, struct_field_visitor, sb);
            g_indent -= 4;

            PRINT_INDENT(sb);
            sb_append(sb, STR("}"));
            break;
        }

        sb_append(sb, struct_name);

        break;
    }

    case CXType_Pointer: {
        CXType pointee = clang_getPointeeType(type);
        if (pointee.kind == CXType_FunctionProto)
        {
            print_type(sb, pointee, true);
            break;
        }

        sb_append(sb, STR("*"));
        print_type(sb, pointee, true);
        break;
    }

    case CXType_FunctionProto: {
        CXCursor decl = clang_getTypeDeclaration(type);

        sb_append(sb, STR("fn* ("));
        size_t arg_count = clang_getNumArgTypes(type);
        for (int i = 0; i < arg_count; ++i)
        {
            if (i > 0)
            {
                sb_append(sb, STR(", "));
            }

            CXCursor arg = clang_Cursor_getArgument(decl, (unsigned)i);
            char *arg_name =
                (char *)clang_getCString(clang_getCursorSpelling(arg));
            if (strlen(arg_name) > 0)
            {
                print_ident(sb, CSTR(arg_name));
            }
            else
            {
                sb_append(sb, STR("_"));
            }
            sb_append(sb, STR(": "));
            print_type(sb, clang_getArgType(type, i), true);
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getResultType(type);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type, true);
        }

        break;
    }

    case CXType_Typedef: {
        char *type_name_c =
            (char *)clang_getCString(clang_getTypedefName(type));
        String type_name = CSTR(type_name_c);

        if (string_equals(type_name, STR("uint8_t")))
            sb_append(sb, STR("u8"));
        else if (string_equals(type_name, STR("uint16_t")))
            sb_append(sb, STR("u16"));
        else if (string_equals(type_name, STR("uint32_t")))
            sb_append(sb, STR("u32"));
        else if (string_equals(type_name, STR("uint64_t")))
            sb_append(sb, STR("u64"));
        else if (string_equals(type_name, STR("int8_t")))
            sb_append(sb, STR("i8"));
        else if (string_equals(type_name, STR("int16_t")))
            sb_append(sb, STR("i16"));
        else if (string_equals(type_name, STR("int32_t")))
            sb_append(sb, STR("i32"));
        else if (string_equals(type_name, STR("int64_t")))
            sb_append(sb, STR("i64"));
        else if (string_equals(type_name, STR("size_t")))
            sb_append(sb, STR("uint"));
        else if (string_equals(type_name, STR("FILE")))
            sb_append(sb, STR("void"));
        else
            sb_append(sb, type_name);

        break;
    }

    case CXType_Elaborated: {
        print_type(sb, clang_Type_getNamedType(type), true);
        break;
    }

    case CXType_ConstantArray: {
        size_t element_count = clang_getNumElements(type);
        sb_sprintf(sb, "[%d]", (int)element_count);
        CXType element_type = clang_getArrayElementType(type);

        print_type(sb, element_type, true);
        break;
    }

    case CXType_IncompleteArray: {
        sb_append(sb, STR("*"));
        CXType element_type = clang_getArrayElementType(type);
        print_type(sb, element_type, true);
        break;
    }

    case CXType_Enum: {
        CXCursor decl = clang_getTypeDeclaration(type);
        print_type(sb, clang_getEnumDeclIntegerType(decl), true);
        break;
    }

    default:
        fprintf(stderr, "Can't print type: %u\n", kind);
        assert(0);
        break;
    }
}

static enum CXChildVisitResult
visitor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    StringBuilder *sb = (StringBuilder *)client_data;

    CXSourceLocation loc = clang_getCursorLocation(cursor);
    CXFile file = {0};
    clang_getFileLocation(loc, &file, NULL, NULL, NULL);

    bool same_dir = false;

    CXString cx_path = clang_File_tryGetRealPathName(file);
    const char *path = clang_getCString(cx_path);
    if (path)
    {
        char *dir = get_file_dir(path);
        if (strncmp(dir, g_dir, strlen(g_dir)) == 0)
        {
            same_dir = true;
        }

        free(dir);
        clang_disposeString(cx_path);
    }

    if (!same_dir) return CXChildVisit_Continue;

    switch (clang_getCursorKind(cursor))
    {
    case CXCursor_TypedefDecl: {
        char *typedef_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String typedef_name = CSTR(typedef_name_c);

        if (hash_get(&g_symbol_map, typedef_name, NULL)) break;

        sb_append(sb, STR("pub typedef "));
        sb_append(sb, typedef_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getTypedefDeclUnderlyingType(cursor), true);
        sb_append(sb, STR(";\n"));

        hash_set(&g_symbol_map, typedef_name, NULL);

        break;
    }

    case CXCursor_StructDecl: {
        char *struct_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String struct_name = CSTR(struct_name_c);

        if (struct_name.length == 0)
        {
            break;
        }

        if (hash_get(&g_symbol_map, struct_name, NULL)) break;

        sb_append(sb, STR("pub typedef "));
        sb_append(sb, struct_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getCursorType(cursor), false);
        sb_append(sb, STR(";\n"));

        hash_set(&g_symbol_map, struct_name, NULL);

        break;
    }

    case CXCursor_UnionDecl: {
        fprintf(stderr, "Error: unions not implemented\n");
        exit(1);
        break;
    }

    case CXCursor_FunctionDecl: {
        cursor = clang_getCanonicalCursor(cursor);

        char *fun_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String fun_name = CSTR(fun_name_c);

        if (hash_get(&g_symbol_map, fun_name, NULL)) break;
        hash_set(&g_symbol_map, fun_name, NULL);

        sb_append(sb, STR("pub extern fn "));
        sb_append(sb, fun_name);
        sb_append(sb, STR("("));

        int num_args = clang_Cursor_getNumArguments(cursor);
        for (int i = 0; i < num_args; ++i)
        {
            if (i > 0)
            {
                sb_append(sb, STR(", "));
            }

            CXCursor arg = clang_Cursor_getArgument(cursor, (unsigned)i);
            char *arg_name =
                (char *)clang_getCString(clang_getCursorSpelling(arg));
            print_ident(sb, CSTR(arg_name));

            sb_append(sb, STR(": "));
            print_type(sb, clang_getCursorType(arg), true);
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getCursorResultType(cursor);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type, true);
        }

        sb_append(sb, STR(";\n"));

        break;
    }

    case CXCursor_EnumDecl: {
        return CXChildVisit_Recurse;
    }

    case CXCursor_EnumConstantDecl: {
        sb_append(sb, STR("pub const "));
        sb_append(
            sb,
            CSTR((char *)clang_getCString(clang_getCursorSpelling(cursor))));
        sb_append(sb, STR(": "));
        print_type(sb, clang_getCursorType(cursor), true);
        sb_sprintf(sb, " = %lld", clang_getEnumConstantDeclValue(cursor));
        sb_append(sb, STR(";\n"));
        break;
    }

    default: return CXChildVisit_Recurse;
    }

    return CXChildVisit_Continue;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    if (argc == 2)
    {
        array_push(g_to_parse, argv[1]);
        g_dir = get_file_dir(argv[1]);

        while (array_size(g_to_parse))
        {
            const char *path = *array_pop(g_to_parse);

            StringBuilder sb;
            sb_init(&sb);
            hash_init(&g_symbol_map, 64);
            const char *args[] = {"-x", "c++"};

            CXIndex index = clang_createIndex(0, 0);
            CXTranslationUnit unit = clang_parseTranslationUnit(
                index,
                path,
                args,
                sizeof(args) / sizeof(args[0]),
                NULL,
                0,
                CXTranslationUnit_SkipFunctionBodies |
                    CXTranslationUnit_DetailedPreprocessingRecord);
            if (unit == NULL)
            {
                fprintf(stderr, "Failed to parse file: %s\n", path);
            }

            if (unit)
            {
                CXCursor cursor = clang_getTranslationUnitCursor(unit);
                clang_visitChildren(cursor, visitor, &sb);

                String output = sb_build(&sb);
                fprintf(stdout, "%.*s\n", (int)output.length, output.buf);

                clang_disposeTranslationUnit(unit);
            }

            clang_disposeIndex(index);

            hash_destroy(&g_symbol_map);
        }
    }

    return 0;
}
