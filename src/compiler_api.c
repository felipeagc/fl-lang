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

Compiler *compiler_api_create_compiler(CompilerApiArguments *args)
{
    Compiler *compiler = malloc(sizeof(*compiler));
    compiler_init(compiler);
    compiler_api__convert_args(compiler, args);
    return compiler;
}

void compiler_api_destroy_compiler(Compiler *compiler)
{
    compiler_destroy(compiler);
    free(compiler);
}

void compiler_api_compile(Compiler *compiler)
{
    assert(compiler->args.in_paths.len == 1);
    char *in_path = compiler->args.in_paths.ptr[0];

    char *absolute_path = get_absolute_path(in_path);
    String filepath = CSTR(absolute_path);
    compile_file_to_object(compiler, filepath);

    compiler_link_module(
        compiler, &compiler->backend->mod, CSTR(compiler->args.out_path));
}

void
compiler_api_get_file_deps(Compiler *compiler, size_t *count, String *buf)
{
    assert(count);
    *count = 0;

    String first_path = CSTR(compiler->args.in_paths.ptr[0]);

    SourceFile *main_file = compiler_syntax_stage(compiler, first_path);
    if (buf)
    {
        buf[*count] = main_file->path;
    }
    (*count)++;

    HashMap set = {0};
    hash_init(&set, 32);

    // Process all files
    while (!syntax_queue_is_empty(&compiler->syntax_queue))
    {
        String abs_path = syntax_queue_next(&compiler->syntax_queue);

        SourceFile *file = compiler_syntax_stage(compiler, abs_path);

        if (hash_get(&set, file->path, NULL))
        {
            continue;
        }

        hash_set(&set, file->path, NULL);
        if (buf)
        {
            buf[*count] = file->path;
        }
        (*count)++;
    }

    hash_destroy(&set);
}

