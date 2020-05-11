typedef enum {
    COMPILER_ACTION_NONE = 0,
    COMPILER_ACTION_COMPILE_FILE = 1,
    COMPILER_ACTION_EXECUTE_BUILD_SCRIPT = 2,
} CompilerActionType;

typedef struct Arguments
{
    bool invalid;
    CompilerActionType action;
    ArrayOfCharPtr in_paths;
    char *out_path;
    ArrayOfCharPtr link_libraries;
    ArrayOfCharPtr library_paths;
    bool should_run;
    bool print_llvm;
    uint32_t opt_level;
    const char *abs_build_dir;
} Arguments;

static void parse_args(Arguments *args, int argc, char **argv)
{
    memset(args, 0, sizeof(*args));

    if (argc == 1) return;

    if (strcmp(argv[1], "build") == 0)
    {
        if (argc == 2)
        {
            args->action = COMPILER_ACTION_EXECUTE_BUILD_SCRIPT;
            args->abs_build_dir = get_current_dir();
        }
        else if (argc == 3)
        {
            args->action = COMPILER_ACTION_EXECUTE_BUILD_SCRIPT;
            args->abs_build_dir = get_absolute_path(argv[2]);
            if (!args->abs_build_dir)
            {
                fprintf(stderr, "invalid build dir\n");
                exit(1);
            }
        }
        else
        {
            args->action = COMPILER_ACTION_NONE;
        }
    }
    else
    {
        args->action = COMPILER_ACTION_COMPILE_FILE;
        args->out_path = DEFAULT_EXE_NAME;

        for (int i = 1; i < argc; ++i)
        {
            if (argv[i][0] == '-')
            {
                switch (argv[i][1])
                {
                case 'o': {
                    switch (argv[i][2])
                    {
                    case '=': args->out_path = &argv[i][3]; break;
                    default: {
                        if (strncmp(&argv[i][1], "opt", 3) == 0)
                        {
                            char level = argv[i][5] - '0';
                            args->opt_level = (uint32_t)level;
                        }
                        break;
                    }
                    }
                    break;
                }

                case 'l': {
                    switch (argv[i][2])
                    {
                    case '=':
                        array_push(&args->link_libraries, &argv[i][3]);
                        break;
                    case 'p': {
                        if (argv[i][3] == '=')
                        {
                            array_push(&args->library_paths, &argv[i][4]);
                        }
                        break;
                    }
                    case 'l': {
                        if (argv[i][3] == '\0')
                        {
                            args->print_llvm = true;
                        }
                        break;
                    }
                    default: break;
                    }
                    break;
                }

                case 'r': {
                    if (argv[i][2] == '\0')
                    {
                        args->should_run = true;
                    }
                    break;
                }

                default: break;
                }
            }
            else
            {
                array_push(&args->in_paths, argv[i]);
            }
        }
    }
}
