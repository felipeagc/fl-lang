#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>

#include <clang-c/Index.h>

#include "../os_includes.h"

#include "../array.c"
#include "../string.c"
#include "../hashmap.c"
#include "../bump_alloc.c"
#include "../string_builder.c"
#include "../filesystem.c"

typedef struct CliArgs
{
    ArrayOfCharPtr prefixes;
    char *module_name;
} CliArgs;

static size_t g_indent = 0;
static HashMap g_symbol_map = {0};
static ArrayOfCharPtr g_to_parse = {0};
static char *g_dir;
static size_t g_struct_member_index;
static CliArgs g_args = {0};
static StringBuilder types_sb;
static StringBuilder consts_sb;
static StringBuilder functions_sb;

#define PRINT_INDENT(sb)                                                       \
    for (size_t i = 0; i < g_indent; ++i)                                      \
    {                                                                          \
        sb_append(sb, STR(" "));                                               \
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

static char *get_prefix(String name)
{
    for (char **prefix = g_args.prefixes.ptr;
         prefix != g_args.prefixes.ptr + g_args.prefixes.len;
         ++prefix)
    {
        if (strncmp(*prefix, name.ptr, strlen(*prefix)) == 0)
        {
            return *prefix;
        }
    }

    return NULL;
}

static void print_name(StringBuilder *sb, String name)
{
    char *prefix = get_prefix(name);
    if (!prefix)
    {
        sb_append(sb, name);
        return;
    }

    size_t prefix_len = strlen(prefix);
    sb_append(
        sb,
        (String){.ptr = name.ptr + prefix_len, .len = name.len - prefix_len});
}

static void print_ident(StringBuilder *sb, String ident)
{
    sb_append(sb, ident);

    if (string_equals(ident, STR("func")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("version")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("import")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("cast")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("var")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("dyn")))
        sb_append(sb, STR("_"));
    else if (string_equals(ident, STR("module")))
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

static void
print_type(StringBuilder *sb, CXType type, bool named, bool is_param);

static enum CXChildVisitResult
struct_field_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data)
{
    StringBuilder *sb = (StringBuilder *)client_data;
    if (g_struct_member_index == 0)
    {
        sb_append(sb, STR("\n"));
    }
    g_struct_member_index++;

    switch (clang_getCursorKind(cursor))
    {
    case CXCursor_FieldDecl: {
        PRINT_INDENT(sb);

        char *field_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String field_name = CSTR(field_name_c);

        print_ident(sb, field_name);

        sb_append(sb, STR(" "));
        print_type(sb, clang_getCursorType(cursor), true, false);
        sb_append(sb, STR(",\n"));
        break;
    }

    default: break;
    }

    return CXChildVisit_Continue;
}

static void
print_type(StringBuilder *sb, CXType type, bool named, bool is_param)
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
        CXCursor decl = clang_getTypeDeclaration(type);
        enum CXCursorKind cursor_kind = clang_getCursorKind(decl);

        char *struct_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(decl));
        String struct_name = CSTR(struct_name_c);

        if (struct_name.len == 0 || !named)
        {
            if (cursor_kind == CXCursor_StructDecl)
            {
                sb_append(sb, STR("struct {"));
            }
            else if (cursor_kind == CXCursor_UnionDecl)
            {
                sb_append(sb, STR("union {"));
            }
            else
            {
                assert(0);
            }

            g_struct_member_index = 0;
            g_indent += 4;
            clang_visitChildren(decl, struct_field_visitor, sb);
            g_indent -= 4;

            PRINT_INDENT(sb);
            sb_append(sb, STR("}"));
        }
        else
        {
            if (!hash_get(&g_symbol_map, struct_name, NULL))
            {
                sb_append(sb, STR("struct{}"));
            }
            else
            {
                print_name(sb, struct_name);
            }
        }

        break;
    }

    case CXType_Pointer: {
        CXType pointee = clang_getPointeeType(type);
        if (pointee.kind == CXType_FunctionProto)
        {
            print_type(sb, pointee, true, false);
            break;
        }

        sb_append(sb, STR("*"));
        print_type(sb, pointee, true, false);
        break;
    }

    case CXType_FunctionProto: {
        CXCursor decl = clang_getTypeDeclaration(type);

        sb_append(sb, STR("func* ("));
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
            sb_append(sb, STR(" "));
            print_type(sb, clang_getArgType(type, i), true, true);
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getResultType(type);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type, true, true);
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
            print_name(sb, type_name);

        break;
    }

    case CXType_Elaborated: {
        print_type(sb, clang_Type_getNamedType(type), true, is_param);
        break;
    }

    case CXType_ConstantArray: {
        if (is_param)
        {
            sb_append(sb, STR("*"));
        }
        else
        {
            size_t element_count = clang_getNumElements(type);
            sb_sprintf(sb, "[%d]", (int)element_count);
        }

        CXType element_type = clang_getArrayElementType(type);
        print_type(sb, element_type, true, false);
        break;
    }

    case CXType_IncompleteArray: {
        sb_append(sb, STR("*"));
        CXType element_type = clang_getArrayElementType(type);
        print_type(sb, element_type, true, false);
        break;
    }

    case CXType_Enum: {
        CXCursor decl = clang_getTypeDeclaration(type);
        print_type(sb, clang_getEnumDeclIntegerType(decl), true, is_param);
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
    CXSourceLocation loc = clang_getCursorLocation(cursor);
    CXFile file = {0};
    clang_getFileLocation(loc, &file, NULL, NULL, NULL);

    bool same_dir = false;

    CXString cx_path = clang_File_tryGetRealPathName(file);
    const char *path = clang_getCString(cx_path);
    if (path)
    {
        char *dir = get_path_dir(path);
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
        StringBuilder *sb = &types_sb;

        char *typedef_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String typedef_name = CSTR(typedef_name_c);

        if (hash_get(&g_symbol_map, typedef_name, NULL)) break;

        sb_append(sb, STR("pub typedef "));
        print_name(sb, typedef_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getTypedefDeclUnderlyingType(cursor), true, false);
        sb_append(sb, STR(";\n"));

        hash_set(&g_symbol_map, typedef_name, NULL);

        break;
    }

    case CXCursor_StructDecl: {
        StringBuilder *sb = &types_sb;

        char *struct_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String struct_name = CSTR(struct_name_c);

        if (struct_name.len == 0)
        {
            break;
        }

        if (hash_get(&g_symbol_map, struct_name, NULL)) break;

        sb_append(sb, STR("pub typedef "));
        print_name(sb, struct_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getCursorType(cursor), false, false);
        sb_append(sb, STR(";\n"));

        hash_set(&g_symbol_map, struct_name, NULL);

        break;
    }

    case CXCursor_UnionDecl: {
        StringBuilder *sb = &types_sb;

        char *struct_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String struct_name = CSTR(struct_name_c);

        if (struct_name.len == 0)
        {
            break;
        }

        if (hash_get(&g_symbol_map, struct_name, NULL)) break;

        sb_append(sb, STR("pub typedef "));
        print_name(sb, struct_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getCursorType(cursor), false, false);
        sb_append(sb, STR(";\n"));

        hash_set(&g_symbol_map, struct_name, NULL);
        break;
    }

    case CXCursor_FunctionDecl: {
        StringBuilder *sb = &functions_sb;

        cursor = clang_getCanonicalCursor(cursor);

        char *fun_name_c =
            (char *)clang_getCString(clang_getCursorSpelling(cursor));
        String fun_name = CSTR(fun_name_c);

        if (hash_get(&g_symbol_map, fun_name, NULL)) break;
        hash_set(&g_symbol_map, fun_name, NULL);

        if (get_prefix(fun_name) != NULL)
        {
            sb_append(sb, STR("#[link_name=\""));
            sb_append(sb, fun_name);
            sb_append(sb, STR("\"]\n"));
        }

        sb_append(sb, STR("pub extern func \"c\" "));
        print_name(sb, fun_name);
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
            if (strlen(arg_name) > 0)
            {
                print_ident(sb, CSTR(arg_name));
            }
            else
            {
                sb_append(sb, STR("_"));
            }

            sb_append(sb, STR(" "));
            print_type(sb, clang_getCursorType(arg), true, true);
        }

        sb_append(sb, STR(")"));

        CXType return_type = clang_getCursorResultType(cursor);
        if (return_type.kind != CXType_Void)
        {
            sb_append(sb, STR(" -> "));
            print_type(sb, return_type, true, false);
        }

        sb_append(sb, STR(";\n"));

        break;
    }

    case CXCursor_EnumDecl: {
        return CXChildVisit_Recurse;
    }

    case CXCursor_EnumConstantDecl: {
        StringBuilder *sb = &consts_sb;

        sb_append(sb, STR("pub const "));
        String enum_field_name =
            CSTR((char *)clang_getCString(clang_getCursorSpelling(cursor)));
        print_name(sb, enum_field_name);
        sb_append(sb, STR(" "));
        print_type(sb, clang_getCursorType(cursor), true, false);
        sb_sprintf(sb, " = %lld", clang_getEnumConstantDeclValue(cursor));
        sb_append(sb, STR(";\n"));
        break;
    }

    default: return CXChildVisit_Recurse;
    }

    return CXChildVisit_Continue;
}

static void parse_cli_args(int argc, char **argv)
{
    memset(&g_args, 0, sizeof(g_args));
    g_args.module_name = "main";

    for (int i = 1; i < argc; ++i)
    {
        if (strncmp("-p=", argv[i], 3) == 0)
        {
            array_push(&g_args.prefixes, &argv[i][3]);
        }
        if (strncmp("-m=", argv[i], 3) == 0)
        {
            g_args.module_name = &argv[i][3];
        }
    }
}

int main(int argc, char **argv)
{
    parse_cli_args(argc, argv);

    if (argc <= 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }
    else
    {
        array_push(&g_to_parse, argv[1]);
        g_dir = get_path_dir(argv[1]);

        while (g_to_parse.len)
        {
            const char *path = *array_pop(&g_to_parse);

            BumpAlloc bump;
            bump_init(&bump, 1 << 16);

            StringBuilder sb;
            sb_init(&sb);

            sb_init(&types_sb);
            sb_init(&consts_sb);
            sb_init(&functions_sb);
            hash_init(&g_symbol_map, 64);

            const char *clang_args[] = {"-x", "c++"};

            CXIndex index = clang_createIndex(0, 0);
            CXTranslationUnit unit = clang_parseTranslationUnit(
                index,
                path,
                clang_args,
                sizeof(clang_args) / sizeof(clang_args[0]),
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
                sb_append(&sb, STR("module "));
                sb_append(&sb, CSTR(g_args.module_name));
                sb_append(&sb, STR("\n\n"));

                CXCursor cursor = clang_getTranslationUnitCursor(unit);
                clang_visitChildren(cursor, visitor, &sb);

                sb_append(&sb, sb_build(&types_sb, &bump));
                sb_append(&sb, STR("\n"));
                sb_append(&sb, sb_build(&consts_sb, &bump));
                sb_append(&sb, STR("\n"));
                sb_append(&sb, sb_build(&functions_sb, &bump));

                String output = sb_build(&sb, &bump);
                fprintf(stdout, "%.*s\n", PRINT_STR(output));

                clang_disposeTranslationUnit(unit);
            }

            clang_disposeIndex(index);

            hash_destroy(&g_symbol_map);
            sb_destroy(&sb);
            bump_destroy(&bump);
        }
    }

    return 0;
}
