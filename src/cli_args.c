typedef struct Arguments
{
    char **in_paths;
    char *out_path;
    char **link_libraries;
    char **library_paths;
    bool should_run;
    bool print_llvm;
} Arguments;

static void parse_args(Arguments *args, int argc, char **argv)
{
    memset(args, 0, sizeof(*args));

    args->out_path = "a.out";

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
            case 'o': {
                if (argv[i][2] == '=')
                {
                    args->out_path = &argv[i][3];
                }
                break;
            }

            case 'l': {
                switch (argv[i][2])
                {
                case '=': array_push(args->link_libraries, &argv[i][3]); break;
                case 'p': {
                    if (argv[i][3] == '=')
                    {
                        array_push(args->library_paths, &argv[i][4]);
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
            array_push(args->in_paths, argv[i]);
        }
    }
}
