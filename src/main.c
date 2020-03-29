#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

#ifdef __unix__
#include <limits.h>
#include <unistd.h>
#endif

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

#include "compiler.c"

#include "token.c"
#include "printing.c"
#include "lexer.c"
#include "type.c"
#include "ast.c"
#include "scope.c"

#include "parser.c"
#include "semantic.c"
#include "llvm.c"

SourceFile *process_file(Compiler *compiler, String absolute_path);

void process_imports(Compiler *compiler, SourceFile *file, Ast *ast)
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

            char *file_name_without_extension =
                c_imported + strlen(core_prefix);

            String import_file_name = bump_str_join(
                &compiler->bump,
                CSTR(file_name_without_extension),
                CSTR(LANG_FILE_EXTENSION));

            abs_path = bump_str_join(
                &compiler->bump, compiler->corelib_dir, import_file_name);
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
        process_file(compiler, abs_path);
        break;
    }
    default: break;
    }

    // Analyze children ASTs
    switch (ast->type)
    {
    case AST_ROOT: {
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            process_imports(compiler, file, stmt);
        }
        break;
    }
    case AST_PROC_DECL: {
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            process_imports(compiler, file, stmt);
        }
        break;
    }
    default: break;
    }
}

SourceFile *process_file(Compiler *compiler, String absolute_path)
{
    SourceFile *file = hash_get(&compiler->files, absolute_path);
    if (file)
    {
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

    process_imports(compiler, file, parser->ast);

    Analyzer *analyzer = bump_alloc(&compiler->bump, sizeof(*analyzer));
    memset(analyzer, 0, sizeof(*analyzer));
    analyzer->compiler = compiler;

    create_scopes_ast(analyzer, parser->ast);
    print_errors(compiler);

    register_symbol_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    symbol_check_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    type_check_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    llvm_codegen_ast(
        compiler->backend, &compiler->backend->mod, file->root, false, NULL);

    return file;
}

void compile_file(Compiler *compiler, String filepath)
{
    LLContext *llvm_context =
        bump_alloc(&compiler->bump, sizeof(*llvm_context));
    memset(llvm_context, 0, sizeof(*llvm_context));
    llvm_init(llvm_context, compiler);
    compiler->backend = llvm_context;

    process_file(compiler, filepath);

    llvm_verify_module(llvm_context);
}

void link_module(Compiler *compiler, LLModule *mod, String out_file_path)
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
        execlp("clang", "clang", TMP_OBJECT_NAME, "-o", c_out_file_path, NULL);
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
    "  %s <filename>        Compiles file.\n",
    "  %s run <filename>    Runs file.\n",
    NULL,
};

void print_usage(int argc, char **argv)
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

    if (argc <= 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    if (argc == 2)
    {
        char *absolute_path = get_absolute_path(argv[1]);
        String filepath = CSTR(absolute_path);
        compile_file(compiler, filepath);
        link_module(compiler, &compiler->backend->mod, STR("a.out"));
    }
    else if (argc == 3)
    {
        if (strcmp(argv[1], "run") == 0)
        {
            char *absolute_path = get_absolute_path(argv[2]);
            String filepath = CSTR(absolute_path);
            compile_file(compiler, filepath);
            llvm_run_module(compiler->backend);
        }
    }
    else
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    compiler_destroy(compiler);
    free(compiler);
    return EXIT_SUCCESS;
}
