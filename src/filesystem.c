char *get_absolute_path(const char *relative_path)
{
#if defined(__unix__) || defined(__APPLE__)
    return realpath(relative_path, NULL);
#else
#error OS not supported
#endif
}

char *get_file_dir(const char *path)
{
    char *abs = get_absolute_path(path);
    for (int i = strlen(abs) - 1; i >= 0; i--)
    {
        if (abs[i] == '/')
        {
            abs[i + 1] = '\0';
            break;
        }
    }
    return abs;
}

char *get_exe_path(void)
{
#if defined(__linux__)
    char buf[PATH_MAX];
    memset(buf, 0, sizeof(buf));
    if (readlink("/proc/self/exe", buf, sizeof(buf)))
    {
        size_t string_length = strlen(buf) + 1;
        char *s = malloc(string_length);
        memcpy(s, buf, string_length);
        return s;
    }
    return NULL;
#elif defined(__APPLE__)
    uint32_t pathlen = 0;
    _NSGetExecutablePath(NULL, &pathlen);
    char* exe_path = malloc(pathlen);
    if (_NSGetExecutablePath(exe_path, &pathlen)) {
        fprintf(stderr, "unable to get launcher executable path\n");
        abort();
    }

    return exe_path;
#else
#error OS not supported
#endif
}
