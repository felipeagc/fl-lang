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

#include "cli_args.c"

#include "compiler.h"
#include "token.c"
#include "ast.c"

#include "lexer.c"
#include "scope.c"
#include "type.c"

#include "parser.c"
#include "semantic.c"
#include "llvm.c"

#include "location.c"
#include "compiler.c"
#include "compiler_api.c"

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
    compile_file_to_object(compiler, filepath);

    if (!compiler->args.should_run)
    {
        compiler_link_module(
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
