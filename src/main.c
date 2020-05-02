#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
#include <assert.h>

#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>
#include <llvm-c/Transforms/PassManagerBuilder.h>

#include "os_includes.h"

#if defined(_WIN32)
typedef struct VSFindResult
{
    int windows_sdk_version; // Zero if no Windows SDK found.

    wchar_t *windows_sdk_root;
    wchar_t *windows_sdk_um_library_path;
    wchar_t *windows_sdk_ucrt_library_path;

    wchar_t *vs_exe_path;
    wchar_t *vs_library_path;
} VSFindResult;

VSFindResult find_visual_studio_and_windows_sdk();
#endif

#define LANG_FILE_EXTENSION ".lang"

#if defined(__unix__) || defined(__APPLE__)
#define TMP_OBJECT_NAME "tmp.o"
#elif defined(_WIN32)
#define TMP_OBJECT_NAME "tmp.obj"
#else
#error OS not supported
#endif

#if defined(__unix__) || defined(__APPLE__)
#define DEFAULT_EXE_NAME "a.out"
#elif defined(_WIN32)
#define DEFAULT_EXE_NAME "a.exe"
#else
#error OS not supported
#endif

#include "filesystem.c"
#include "array.c"
#include "string.c"
#include "hashmap.c"
#include "bump_alloc.c"
#include "string_builder.c"

#include "location.c"
#include "token.c"
#include "ast.c"
#include "cli_args.c"

typedef struct TypeInfo TypeInfo;
typedef ARRAY_OF(TypeInfo *) ArrayOfTypeInfoPtr;

typedef struct Compiler
{
    BumpAlloc bump;
    StringBuilder sb;

    ArrayOfError errors;
    HashMap files;
    HashMap versions;
    struct LLContext *backend;
    String compiler_path;
    String compiler_dir;
    String corelib_dir;

    Arguments args;

    Ast *runtime_module;

    struct TypeInfo *type_info_type;
    ArrayOfTypeInfoPtr rtti_type_infos;
} Compiler;

static SourceFile *process_file(Compiler *compiler, String absolute_path);

static void
compile_error(Compiler *compiler, Location loc, const char *fmt, ...)
{
    char buf[2048];
    assert(loc.file);

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    String message = bump_strdup(&compiler->bump, CSTR(buf));

    Error err = {.loc = loc, .message = message};
    array_push(&compiler->errors, err);
}

static bool compiler_has_version(Compiler *compiler, String version)
{
    return hash_get(&compiler->versions, version, NULL);
}

static void print_errors(Compiler *compiler)
{
    if (compiler->errors.len > 0)
    {
        for (Error *err = compiler->errors.ptr;
             err != compiler->errors.ptr + compiler->errors.len;
             ++err)
        {
            fprintf(
                stderr,
                "%.*s:%u:%u: error: %.*s\n",
                PRINT_STR(err->loc.file->path),
                err->loc.line,
                err->loc.col,
                PRINT_STR(err->message));
        }
        exit(1);
    }
}

#include "ast_builder.c"

#include "lexer.c"
#include "scope.c"
#include "type.c"
#include "printing.c"

#include "parser.c"
#include "semantic.c"
#include "llvm.c"

static void
process_imports(Compiler *compiler, SourceFile *file, Scope *scope, Ast *ast);

static void process_ast(Compiler *compiler, SourceFile *file, Ast *ast);

static void compiler_init(Compiler *compiler)
{
    memset(compiler, 0, sizeof(*compiler));
    bump_init(&compiler->bump, 1 << 16);
    sb_init(&compiler->sb);
    hash_init(&compiler->files, 512);
    hash_init(&compiler->versions, 16);

    compiler->backend = bump_alloc(&compiler->bump, sizeof(*compiler->backend));
    memset(compiler->backend, 0, sizeof(*compiler->backend));
    llvm_init(compiler->backend, compiler);

    static TypeInfo blank_type_info = {0};
    array_push(
        &compiler->rtti_type_infos, &blank_type_info); // Reserve the 0 index

    char *c_compiler_path = get_exe_path();
    char *c_compiler_dir = get_file_dir(c_compiler_path);
    compiler->compiler_path = CSTR(c_compiler_path);
    compiler->compiler_dir = CSTR(c_compiler_dir);
    compiler->corelib_dir =
        bump_str_join(&compiler->bump, compiler->compiler_dir, STR("core/"));

    // Initialize runtime scopes
    {
        init_numeric_type(compiler, &U8_TYPE);
        init_numeric_type(compiler, &U16_TYPE);
        init_numeric_type(compiler, &U32_TYPE);
        init_numeric_type(compiler, &U64_TYPE);

        init_numeric_type(compiler, &I8_TYPE);
        init_numeric_type(compiler, &I16_TYPE);
        init_numeric_type(compiler, &I32_TYPE);
        init_numeric_type(compiler, &I64_TYPE);

        init_numeric_type(compiler, &UINT_TYPE);
        init_numeric_type(compiler, &INT_TYPE);

        init_numeric_type(compiler, &FLOAT_TYPE);
        init_numeric_type(compiler, &DOUBLE_TYPE);

        init_any_type(compiler, &ANY_TYPE);

        STRING_TYPE = create_slice_type(compiler, &I8_TYPE);
    }

#if defined(__linux__)
    hash_set(&compiler->versions, STR("linux"), NULL);
    hash_set(&compiler->versions, STR("glibc"), NULL);
    hash_set(&compiler->versions, STR("posix"), NULL);
#elif defined(__APPLE__)
    hash_set(&compiler->versions, STR("apple"), NULL);
    hash_set(&compiler->versions, STR("darwin"), NULL);
    hash_set(&compiler->versions, STR("posix"), NULL);
#elif defined(_WIN32)
    hash_set(&compiler->versions, STR("windows"), NULL);
#else
#error OS not supported
#endif

    hash_set(&compiler->versions, STR("x86"), NULL);
    hash_set(&compiler->versions, STR("x86_64"), NULL);
    hash_set(&compiler->versions, STR("x86_any"), NULL);
    hash_set(&compiler->versions, STR("debug"), NULL);

    // Initialize runtime module
    String runtime_abs_path = bump_str_join(
        &compiler->bump,
        compiler->corelib_dir,
        STR("runtime" LANG_FILE_EXTENSION));
    SourceFile *runtime_file = process_file(compiler, runtime_abs_path);
    compiler->runtime_module = runtime_file->root;

    Ast *type_info_structure = get_symbol(
        compiler->runtime_module->scope, STR("TypeInfo"), runtime_file);
    assert(type_info_structure);
    compiler->type_info_type = type_info_structure->as_type;
    assert(compiler->type_info_type);
}

static void compiler_destroy(Compiler *compiler)
{
    hash_destroy(&compiler->versions);
    hash_destroy(&compiler->files);
    sb_destroy(&compiler->sb);
    bump_destroy(&compiler->bump);
}

static void source_file_init(SourceFile *file, Compiler *compiler, String path)
{
    memset(file, 0, sizeof(*file));

    file->path = bump_strdup(&compiler->bump, path);

    FILE *f = fopen(bump_c_str(&compiler->bump, file->path), "rb");
    if (!f)
    {
        fprintf(stderr, "Failed to open file: %.*s", PRINT_STR(file->path));
        abort();
    }

    fseek(f, 0, SEEK_END);
    file->content.len = (uint32_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    file->content.ptr = malloc(file->content.len);
    fread(file->content.ptr, 1, file->content.len, f);
    fclose(f);
}

static void process_ast(Compiler *compiler, SourceFile *file, Ast *ast)
{
    Analyzer *analyzer = bump_alloc(&compiler->bump, sizeof(*analyzer));
    memset(analyzer, 0, sizeof(*analyzer));
    analyzer->compiler = compiler;

    create_scopes_ast(analyzer, ast);
    print_errors(compiler);

    process_imports(compiler, file, NULL, ast);

    register_symbol_asts(analyzer, ast, 1);
    print_errors(compiler);

    analyze_asts(analyzer, ast, 1);
    print_errors(compiler);

    if (file->main_function_ast)
    {
        check_used_asts(analyzer, file->main_function_ast);
    }
}

static SourceFile *process_file(Compiler *compiler, String absolute_path)
{
    SourceFile *file = NULL;
    if (hash_get(&compiler->files, absolute_path, (void **)&file))
    {
        assert(file);
        return file;
    }

    file = bump_alloc(&compiler->bump, sizeof(*file));
    source_file_init(file, compiler, absolute_path);

    hash_set(&compiler->files, absolute_path, file);

    Lexer *lexer = bump_alloc(&compiler->bump, sizeof(*lexer));
    lex_file(lexer, compiler, file);
    print_errors(compiler);

    Parser *parser = bump_alloc(&compiler->bump, sizeof(*parser));
    parse_file(parser, compiler, lexer);
    print_errors(compiler);
    file->root = parser->ast;

    process_ast(compiler, file, parser->ast);

    return file;
}

static void
process_imports(Compiler *compiler, SourceFile *file, Scope *scope, Ast *ast)
{
    switch (ast->type)
    {
    case AST_IMPORT: {
        bool import_exists = true;

        char *c_imported = bump_c_str(&compiler->bump, ast->import.path);
        static char *core_prefix = "core:";

        if (strncmp(c_imported, core_prefix, strlen(core_prefix)) == 0)
        {
            // Core import

            char *file_name_without_extension =
                c_imported + strlen(core_prefix);

            String import_file_name = bump_str_join(
                &compiler->bump,
                CSTR(file_name_without_extension),
                CSTR(LANG_FILE_EXTENSION));

            ast->import.abs_path = bump_str_join(
                &compiler->bump, compiler->corelib_dir, import_file_name);

            char *abs_path_c =
                bump_c_str(&compiler->bump, ast->import.abs_path);
            if (!file_exists(abs_path_c))
            {
                import_exists = false;
            }
        }
        else
        {
            // Relative import
            char *c_dir = get_file_dir(bump_c_str(&compiler->bump, file->path));

            size_t new_path_size = strlen(c_dir) + 1 + strlen(c_imported) + 1;
            char *c_new_path = bump_alloc(&compiler->bump, new_path_size);
            snprintf(c_new_path, new_path_size, "%s/%s", c_dir, c_imported);

            // Normalize the path
            char *abs_path_c = get_absolute_path(c_new_path);
            if (abs_path_c)
            {
                ast->import.abs_path = CSTR(abs_path_c);
            }
            else
            {
                import_exists = false;
            }
        }

        if (!import_exists)
        {
            compile_error(
                compiler,
                ast->loc,
                "imported file does not exist: '%.*s'",
                PRINT_STR(ast->import.path));
            break;
        }

        SourceFile *imported_file =
            process_file(compiler, ast->import.abs_path);

        if (ast->import.name.ptr == NULL)
        {
            array_push(&scope->siblings, imported_file->root->scope);
        }

        break;
    }
    default: break;
    }

    // Analyze children ASTs
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        for (Ast *stmt = ast->block.stmts.ptr;
             stmt != ast->block.stmts.ptr + ast->block.stmts.len;
             ++stmt)
        {
            process_imports(compiler, file, ast->scope, stmt);
        }
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(compiler, ast->version_block.version))
        {
            for (Ast *stmt = ast->version_block.stmts.ptr;
                 stmt !=
                 ast->version_block.stmts.ptr + ast->version_block.stmts.len;
                 ++stmt)
            {
                process_imports(compiler, file, scope, stmt);
            }
        }

        break;
    }

    case AST_PROC_DECL: {
        for (Ast *stmt = ast->proc.stmts.ptr;
             stmt != ast->proc.stmts.ptr + ast->proc.stmts.len;
             ++stmt)
        {
            process_imports(compiler, file, ast->scope, stmt);
        }
        break;
    }
    default: break;
    }
}

static void compile_file(Compiler *compiler, String filepath)
{
    SourceFile *file = process_file(compiler, filepath);

    llvm_generate_runtime_variables(compiler->backend, &compiler->backend->mod);

    file->did_codegen = true;
    llvm_codegen_ast(
        compiler->backend, &compiler->backend->mod, file->root, false, NULL);

    llvm_generate_runtime_functions(compiler->backend, &compiler->backend->mod);

    llvm_verify_module(compiler->backend);
    llvm_optimize_module(compiler->backend);

    if (compiler->args.print_llvm)
    {
        fprintf(
            stderr,
            "%s\n",
            LLVMPrintModuleToString(compiler->backend->mod.mod));
    }
}

static void link_module(Compiler *compiler, LLModule *mod, String out_file_path)
{
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmParsers();
    LLVMInitializeAllAsmPrinters();

    char *triple = LLVMGetDefaultTargetTriple();

    LLVMTargetRef target;
    char *error = NULL;
    if (LLVMGetTargetFromTriple(triple, &target, &error))
    {
        fprintf(stderr, "Failed to get target from triple: %s", error);
        exit(1);
    }

    char *cpu = "generic";
    char *features = "";
    LLVMTargetMachineRef target_machine = LLVMCreateTargetMachine(
        target,
        triple,
        cpu,
        features,
        LLVMCodeGenLevelNone,
        LLVMRelocDefault,
        LLVMCodeModelDefault);

    LLVMTargetDataRef data_layout = LLVMCreateTargetDataLayout(target_machine);
    char *data_layout_str = LLVMCopyStringRepOfTargetData(data_layout);

    LLVMSetDataLayout(mod->mod, data_layout_str);
    LLVMSetTarget(mod->mod, triple);

    if (LLVMTargetMachineEmitToFile(
            target_machine, mod->mod, TMP_OBJECT_NAME, LLVMObjectFile, &error))
    {
        remove(TMP_OBJECT_NAME);
        fprintf(stderr, "LLVM codegen error: %s", error);
        exit(1);
    }

#if defined(__linux__) || defined(__APPLE__)
#define LINKER_PATH "clang"
    char *c_out_file_path = bump_c_str(&compiler->bump, out_file_path);

    ArrayOfCharPtr args = {0};
    array_push(&args, LINKER_PATH);
    array_push(&args, TMP_OBJECT_NAME);
    array_push(&args, "-lm");
    array_push(&args, "-o");
    array_push(&args, c_out_file_path);

    for (size_t i = 0; i < compiler->args.library_paths.len; ++i)
    {
        char arg[256] = {0};
        sprintf(arg, "-L%s", compiler->args.library_paths.ptr[i]);
        array_push(&args, strdup(arg));
    }

    for (size_t i = 0; i < compiler->args.link_libraries.len; ++i)
    {
        char arg[256] = {0};
        sprintf(arg, "-l%s", compiler->args.link_libraries.ptr[i]);
        array_push(&args, strdup(arg));
    }

    array_push(&args, NULL);

    pid_t pid;
    int status = posix_spawnp(&pid, LINKER_PATH, NULL, NULL, args.ptr, environ);
    if (status == 0)
    {
        if (waitpid(pid, &status, 0) == -1)
        {
            remove(TMP_OBJECT_NAME);
            fprintf(stderr, "Linking failed 1!\n");
            exit(status);
        }

        if (status != 0)
        {
            remove(TMP_OBJECT_NAME);
            fprintf(stderr, "Linking failed 2!\n");
            exit(status);
        }
    }
    else
    {
        fprintf(stderr, "Linking failed 3!\n");
        exit(status);
    }

    remove(TMP_OBJECT_NAME);
#elif defined(_WIN32)
    sb_reset(&compiler->sb);

    VSFindResult find_result = find_visual_studio_and_windows_sdk();
    char *link_exe_path = utf16_to_utf8(find_result.vs_exe_path);
    char *vs_lib_path = utf16_to_utf8(find_result.vs_library_path);
    char *win_crt_lib_path =
        utf16_to_utf8(find_result.windows_sdk_ucrt_library_path);
    char *win_um_lib_path =
        utf16_to_utf8(find_result.windows_sdk_um_library_path);

    sb_sprintf(&compiler->sb, "\"%s\\link.exe\"", link_exe_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", vs_lib_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", win_crt_lib_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", win_um_lib_path);
    sb_append(
        &compiler->sb,
        STR(" /nologo /defaultlib:libcmt /ENTRY:mainCRTStartup"));
    sb_append(&compiler->sb, STR(" -OUT:\""));
    sb_append(&compiler->sb, out_file_path);
    sb_append(&compiler->sb, STR("\" "));
    sb_append(&compiler->sb, STR(TMP_OBJECT_NAME));
    for (size_t i = 0; i < array_size(compiler->args.library_paths); ++i)
    {
        sb_sprintf(
            &compiler->sb,
            " /LIBPATH:\"%s\"",
            compiler->args.link_libraries[i]);
    }
    for (size_t i = 0; i < array_size(compiler->args.link_libraries); ++i)
    {
        sb_sprintf(&compiler->sb, " \"%s\"", compiler->args.link_libraries[i]);
    }

    String cmd_line = sb_build(&compiler->sb, &compiler->bump);
    char *cmd_line_c = bump_c_str(&compiler->bump, cmd_line);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL result = CreateProcessA(
        NULL, cmd_line_c, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (!result)
    {
        fprintf(stderr, "Failed to start linker!\n");
        exit(1);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!DeleteFileA(TMP_OBJECT_NAME))
    {
        fprintf(stderr, "Failed to delete temporary object\n");
    }

#else
#error OS not supported
#endif
}

static const char *COMPILER_USAGE[] = {
    "Usage:\n",
    "  %s <inputs>\t\tRuns compiler on inputs.\n",
    "\n",
    "Options:\n",
    "  -r\t\t\t\tRuns the input files without creating executable.\n",
    "  -o=<output path>\t\tSets the output path.\n",
    "  -l=<library>\t\t\tLinks with library.\n",
    "  -lp=<path>\t\t\tAdds a library path.\n",
    "  -ll\t\t\t\tPrints the generated LLVM IR.\n",
    "  -opt=<level>\t\t\tAdds optimization (level = 0..3).\n",
    NULL,
};

static void print_usage(int argc, char **argv)
{
    const char **line = COMPILER_USAGE;
    while (*line)
    {
        fprintf(stderr, *line, argv[0]);
        line++;
    }
}

int main(int argc, char **argv)
{
    Compiler *compiler = malloc(sizeof(*compiler));
    compiler_init(compiler);
    parse_args(&compiler->args, argc, argv);

    if (compiler->args.in_paths.len != 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    char *in_path = compiler->args.in_paths.ptr[0];

    char *absolute_path = get_absolute_path(in_path);
    String filepath = CSTR(absolute_path);
    compile_file(compiler, filepath);

    if (!compiler->args.should_run)
    {
        link_module(
            compiler, &compiler->backend->mod, CSTR(compiler->args.out_path));
    }
    else
    {
        llvm_run_module(compiler->backend);
    }

    compiler_destroy(compiler);
    free(compiler);
    return EXIT_SUCCESS;
}
