#if defined(_WIN32)
static void replace_slashes(char *path)
{
    for (int i = 0; i < strlen(path); ++i)
    {
        if (path[i] == '\\') path[i] = '/';
    }
}
#endif

static char *get_absolute_path(const char *relative_path)
{
#if defined(__unix__) || defined(__APPLE__)
    return realpath(relative_path, NULL);
#elif defined(_WIN32)
    DWORD length = GetFullPathNameA(relative_path, 0, NULL, NULL);
    char *buf = malloc(length);
    GetFullPathNameA(relative_path, length, buf, NULL);
    replace_slashes(buf);
    return buf;
#else
#error OS not supported
#endif
}

static bool file_exists(const char *path)
{
#if defined(__unix__) || defined(__APPLE__)
    return (access(path, F_OK) != -1);
#elif defined(_WIN32)
    return (bool)PathFileExistsA(path);
#else
#error OS not supported
#endif
}

static char *get_path_dir(const char *path)
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

static const char *get_path_filename(const char *path)
{
    char *abs = get_absolute_path(path);
    for (int i = strlen(abs) - 1; i >= 0; i--)
    {
        if (abs[i] == '/')
        {
            if (i < (strlen(abs) - 1))
            {
                return &abs[i + 1];
            }
        }
    }
    return path;
}

static char *get_current_dir(void)
{
#if defined(__unix__) || defined(__APPLE__)
    return getcwd(NULL, 0);
#elif defined(_WIN32)
    DWORD required_size = GetCurrentDirectory(0, NULL);
    TCHAR *buf = malloc(sizeof(TCHAR) * required_size);
    GetCurrentDirectory(required_size, buf);
    if (sizeof(TCHAR) == sizeof(char))
    {
        return buf;
    }
    else
    {
        assert(sizeof(TCHAR) == sizeof(wchar_t));
        return utf16_to_utf8((wchar_t*)buf);
    }

    return NULL;
#else
#error OS not supported
#endif
}

static void set_current_dir(const char *dir)
{
#if defined(__unix__) || defined(__APPLE__)
    chdir(dir);
#elif defined(_WIN32)
    SetCurrentDirectory(dir);
#else
#error OS not supported
#endif
}

static char *get_exe_path(void)
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
    char *exe_path = malloc(pathlen);
    if (_NSGetExecutablePath(exe_path, &pathlen))
    {
        fprintf(stderr, "unable to get launcher executable path\n");
        abort();
    }

    return exe_path;
#elif defined(_WIN32)
    char tmp_buf[MAX_PATH];
    memset(tmp_buf, 0, sizeof(tmp_buf));
    DWORD length = GetModuleFileNameA(NULL, tmp_buf, sizeof(tmp_buf)) + 1;
    char *buf = malloc(length);
    memcpy(buf, tmp_buf, length);
    replace_slashes(buf);
    return buf;
#else
#error OS not supported
#endif
}
