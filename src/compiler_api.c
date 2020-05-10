struct CompilerApiArguments
{
    String input;
    String output;
    SLICE_OF(String) link_with;
    SLICE_OF(String) library_paths;
    uint32_t opt_level;
};

static void
compiler_api__convert_args(Compiler *compiler, CompilerApiArguments *args)
{
    compiler->args.opt_level = args->opt_level;

    if (args->output.len)
    {
        compiler->args.out_path = bump_c_str(&compiler->bump, args->output);
    }

    if (args->input.len)
    {
        array_push(
            &compiler->args.in_paths, bump_c_str(&compiler->bump, args->input));
    }

    for (size_t i = 0; i < args->link_with.len; ++i)
    {
        array_push(
            &compiler->args.link_libraries,
            bump_c_str(&compiler->bump, args->link_with.ptr[i]));
    }

    for (size_t i = 0; i < args->library_paths.len; ++i)
    {
        array_push(
            &compiler->args.library_paths,
            bump_c_str(&compiler->bump, args->library_paths.ptr[i]));
    }
}

static void compiler_api_compile(CompilerApiArguments *args)
{
    Compiler *compiler = malloc(sizeof(*compiler));
    compiler_init(compiler);
    compiler_api__convert_args(compiler, args);

    assert(compiler->args.in_paths.len == 1);
    char *in_path = compiler->args.in_paths.ptr[0];

    char *absolute_path = get_absolute_path(in_path);
    String filepath = CSTR(absolute_path);
    compile_file_to_object(compiler, filepath);

    compiler_link_module(
        compiler, &compiler->backend->mod, CSTR(compiler->args.out_path));

    compiler_destroy(compiler);
    free(compiler);
}

