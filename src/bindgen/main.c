#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <clang-c/Index.h>
#include "../src/string.c"
#include "../src/hashmap.c"

static size_t g_indent = 0;
static HashMap symbol_map = {0};

typedef struct StringBuilder
{
    char *buf;
    size_t len;
    size_t cap;
} StringBuilder;

static void sb_init(StringBuilder *sb)
{
    sb->len = 0;
    sb->cap = 1 << 16;
    sb->buf = malloc(sb->cap); // 64k
}

static void sb_append(StringBuilder *sb, String str)
{
    strncpy(&sb->buf[sb->len], str.buf, str.length);
    sb->len += str.length;
}

void sb_sprintf(StringBuilder *sb, const char *fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);
    sb->len += vsnprintf(&sb->buf[sb->len], sb->cap, fmt, vl);
    va_end(vl);
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

static void print_type(StringBuilder *sb, CXType type);

static enum CXChildVisitResult
struct_field_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    StringBuilder *sb = (StringBuilder *)client_data;

    switch (clang_getCursorKind(cursor))
    {
    case CXCursor_FieldDecl: {
        for (size_t i = 0; i < g_indent; ++i)
        {
            sb_append(sb, STR(" "));
        }

        char *field_name =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        sb_append(sb, CSTR(field_name));
        sb_append(sb, STR(": "));
        print_type(sb, clang_getCursorType(cursor));
        sb_append(sb, STR(",\n"));
        break;
    }

    default: break;
    }

    return CXChildVisit_Continue;
}

static void print_type(StringBuilder *sb, CXType type)
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
        struct_decl = clang_getCanonicalCursor(struct_decl);

        sb_append(sb, STR("struct {\n"));
        g_indent += 4;
        clang_visitChildren(struct_decl, struct_field_visitor, sb);
        g_indent -= 4;
        sb_append(sb, STR("}"));

        break;
    }

    case CXType_Pointer: {
        CXType pointee = clang_getPointeeType(type);
        if (pointee.kind == CXType_FunctionProto)
        {
            print_type(sb, pointee);
            break;
        }

        sb_append(sb, STR("*"));
        print_type(sb, pointee);
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
                sb_append(sb, CSTR(arg_name));
            }
            else
            {
                sb_append(sb, STR("_"));
            }
            sb_append(sb, STR(": "));
            print_type(sb, clang_getArgType(type, i));
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getResultType(type);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type);
        }

        break;
    }

    case CXType_Typedef: {
        char *type_name_c =
            (char *)clang_getCString(clang_getTypedefName(type));
        String type_name = CSTR(type_name_c);
        sb_append(sb, type_name);

        break;
    }

    case CXType_Elaborated: {
        print_type(sb, clang_Type_getNamedType(type));
        break;
    }

    case CXType_ConstantArray: {
        size_t element_count = clang_getNumElements(type);
        sb_sprintf(sb, "[%d]", (int)element_count);
        CXType element_type = clang_getArrayElementType(type);

        print_type(sb, element_type);
        break;
    }

    case CXType_IncompleteArray: {
        sb_append(sb, STR("*"));
        CXType element_type = clang_getArrayElementType(type);
        print_type(sb, element_type);
        break;
    }

    default:
        printf("Can't print type: %u\n", kind);
        assert(0);
        break;
    }
}

static enum CXChildVisitResult
visitor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    StringBuilder *sb = (StringBuilder *)client_data;

    switch (clang_getCursorKind(cursor))
    {
    case CXCursor_TypedefDecl: {
        char *typedef_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String typedef_name = CSTR(typedef_name_c);

        if (hash_get(&symbol_map, typedef_name, NULL)) break;
        hash_set(&symbol_map, typedef_name, NULL);

        sb_append(sb, STR("pub typedef "));
        sb_append(sb, typedef_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getTypedefDeclUnderlyingType(cursor));
        sb_append(sb, STR(";\n"));
        break;
    }

    case CXCursor_FunctionDecl: {
        cursor = clang_getCanonicalCursor(cursor);

        char *fun_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String fun_name = CSTR(fun_name_c);

        if (hash_get(&symbol_map, fun_name, NULL)) break;
        hash_set(&symbol_map, fun_name, NULL);

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
            sb_append(sb, CSTR(arg_name));

            sb_append(sb, STR(": "));
            print_type(sb, clang_getCursorType(arg));
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getCursorResultType(cursor);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type);
        }

        sb_append(sb, STR(";\n"));

        break;
    }

    default: break;
    }

    return CXChildVisit_Recurse;
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
        StringBuilder sb;
        sb_init(&sb);

        hash_init(&symbol_map, 64);

        char *path = argv[1];

        const char *args[] = {"-x", "c++"};

        CXIndex index = clang_createIndex(0, 0);
        CXTranslationUnit unit = clang_parseTranslationUnit(
            index,
            path,
            args,
            sizeof(args) / sizeof(args[0]),
            NULL,
            0,
            CXTranslationUnit_SingleFileParse |
                CXTranslationUnit_SkipFunctionBodies |
                CXTranslationUnit_DetailedPreprocessingRecord);
        if (unit == NULL)
        {
            fprintf(stderr, "Failed to parse header\n");
            exit(EXIT_FAILURE);
        }

        CXCursor cursor = clang_getTranslationUnitCursor(unit);
        clang_visitChildren(cursor, visitor, &sb);

        String output = sb_build(&sb);
        printf("%.*s\n", (int)output.length, output.buf);

        clang_disposeTranslationUnit(unit);
        clang_disposeIndex(index);
        hash_destroy(&symbol_map);
    }

    return 0;
}
