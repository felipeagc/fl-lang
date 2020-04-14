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

#ifdef __linux__
#include <sys/types.h>
#include <sys/wait.h>
#endif

#define LANG_FILE_EXTENSION ".lang"
#define TMP_OBJECT_NAME "tmp.o"

#include "filesystem.c"
#include "string.c"
#include "array.c"
#include "hashmap.c"
#include "bump_alloc.c"
#include "string_builder.c"

#include "location.c"
#include "token.c"
#include "ast.c"
#include "cli_args.c"

typedef struct Compiler
{
    BumpAlloc bump;
    StringBuilder sb;

    /*array*/ Error *errors;
    HashMap files;
    HashMap versions;
    struct LLContext *backend;
    String compiler_path;
    String compiler_dir;
    String corelib_dir;

    Arguments args;

    Ast *builtin_module;
} Compiler;

static void
compile_error(Compiler *compiler, Location loc, const char *fmt, ...)
{
    char buf[2048];
    assert(loc.file);

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    String message = bump_strdup(
        &compiler->bump, (String){.buf = buf, .length = strlen(buf)});

    Error err = {.loc = loc, .message = message};
    array_push(compiler->errors, err);
}

static bool compiler_has_version(Compiler *compiler, String version)
{
    return hash_get(&compiler->versions, version, NULL);
}

static void print_errors(Compiler *compiler)
{
    if (array_size(compiler->errors) > 0)
    {
        for (Error *err = compiler->errors;
             err != compiler->errors + array_size(compiler->errors);
             ++err)
        {
            fprintf(
                stderr,
                "%.*s:%u:%u: error: %.*s\n",
                (int)err->loc.file->path.length,
                err->loc.file->path.buf,
                err->loc.line,
                err->loc.col,
                (int)err->message.length,
                err->message.buf);
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

    char *c_compiler_path = get_exe_path();
    char *c_compiler_dir = get_file_dir(c_compiler_path);
    compiler->compiler_path = CSTR(c_compiler_path);
    compiler->compiler_dir = CSTR(c_compiler_dir);
    compiler->corelib_dir =
        bump_str_join(&compiler->bump, compiler->compiler_dir, STR("core/"));

    // Initialize builtin scopes
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
    }

    // Initialize builtin module
    compiler->builtin_module = create_module_ast(compiler);

    hash_set(&compiler->versions, STR("linux"), NULL);
    hash_set(&compiler->versions, STR("posix"), NULL);
    hash_set(&compiler->versions, STR("x86_64"), NULL);
    hash_set(&compiler->versions, STR("debug"), NULL);

    String core_builtin_path = STR("core:builtin");

    SourceFile *file = bump_alloc(&compiler->bump, sizeof(*file));
    memset(file, 0, sizeof(*file));
    file->root = compiler->builtin_module;
    hash_set(&compiler->files, core_builtin_path, file);

    process_ast(compiler, file, compiler->builtin_module);
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
        fprintf(
            stderr,
            "Failed to open file: %.*s",
            (int)file->path.length,
            file->path.buf);
        abort();
    }

    fseek(f, 0, SEEK_END);
    file->content.length = (uint32_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    file->content.buf = malloc(file->content.length);
    fread(file->content.buf, 1, file->content.length, f);
    fclose(f);
}

static SourceFile *process_file(Compiler *compiler, String absolute_path);

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
        char *c_imported = bump_c_str(&compiler->bump, ast->import.path);
        static char *core_prefix = "core:";
        String abs_path = {0};

        if (strncmp(c_imported, core_prefix, strlen(core_prefix)) == 0)
        {
            // Core import

            if (strcmp(c_imported, "core:builtin") == 0)
            {
                abs_path = STR("core:builtin");
            }
            else
            {
                char *file_name_without_extension =
                    c_imported + strlen(core_prefix);

                String import_file_name = bump_str_join(
                    &compiler->bump,
                    CSTR(file_name_without_extension),
                    CSTR(LANG_FILE_EXTENSION));

                abs_path = bump_str_join(
                    &compiler->bump, compiler->corelib_dir, import_file_name);
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
            char *c_abs_path = get_absolute_path(c_new_path);
            abs_path = CSTR(c_abs_path);
        }

        ast->import.abs_path = abs_path;
        SourceFile *imported_file = process_file(compiler, abs_path);

        if (ast->import.name.buf == NULL)
        {
            array_push(scope->siblings, imported_file->root->scope);
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
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            process_imports(compiler, file, ast->scope, stmt);
        }
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(compiler, ast->version_block.version))
        {
            for (Ast *stmt = ast->version_block.stmts;
                 stmt != ast->version_block.stmts + array_size(ast->version_block.stmts);
                 ++stmt)
            {
                process_imports(compiler, file, scope, stmt);
            }
        }

        break;
    }

    case AST_PROC_DECL: {
        for (Ast *stmt = ast->proc.stmts;
             stmt != ast->proc.stmts + array_size(ast->proc.stmts);
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

    file->did_codegen = true;
    llvm_codegen_ast(
        compiler->backend, &compiler->backend->mod, file->root, false, NULL);

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

    char *c_out_file_path = bump_c_str(&compiler->bump, out_file_path);

    pid_t pid = fork();
    if (pid == 0)
    {
        char **args = NULL;
        array_push(args, "clang");
        array_push(args, TMP_OBJECT_NAME);
        array_push(args, "-lm");
        array_push(args, "-o");
        array_push(args, c_out_file_path);

        for (size_t i = 0; i < array_size(compiler->args.library_paths); ++i)
        {
            char arg[256] = {0};
            sprintf(arg, "-L%s", compiler->args.library_paths[i]);
            array_push(args, strdup(arg));
        }

        for (size_t i = 0; i < array_size(compiler->args.link_libraries); ++i)
        {
            char arg[256] = {0};
            sprintf(arg, "-l%s", compiler->args.link_libraries[i]);
            array_push(args, strdup(arg));
        }

        array_push(args, NULL);
        execvp("clang", args);
    }

    int status;
    waitpid(pid, &status, 0);
    if (status != 0)
    {
        remove(TMP_OBJECT_NAME);
        fprintf(stderr, "Linking failed!\n");
        exit(status);
    }

    remove(TMP_OBJECT_NAME);
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

    if (array_size(compiler->args.in_paths) != 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    char *in_path = compiler->args.in_paths[0];

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
