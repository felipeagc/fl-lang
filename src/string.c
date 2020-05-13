typedef SLICE_OF(char) String;

typedef ARRAY_OF(String) ArrayOfString;
typedef ARRAY_OF(char *) ArrayOfCharPtr;

#define STR(lit)                                                               \
    ((String){                                                                 \
        .ptr = lit,                                                            \
        .len = sizeof(lit) - 1,                                                \
    })

#define CSTR(lit)                                                              \
    ((String){                                                                 \
        .ptr = (lit),                                                          \
        .len = strlen(lit),                                                    \
    })

#define PRINT_STR(str) (int)(str).len, (str).ptr

static inline bool string_equals(String a, String b)
{
    if (a.len != b.len) return false;
    if (a.len == 0) return true;
    return strncmp(a.ptr, b.ptr, a.len) == 0;
}

#if defined(_WIN32)
static char *utf16_to_utf8(wchar_t *source)
{
    size_t required_size =
        WideCharToMultiByte(CP_UTF8, 0, source, -1, NULL, 0, NULL, NULL);
    char *buf = calloc(required_size + 1, sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, source, -1, buf, required_size, NULL, NULL);
    buf[required_size] = 0;
    return buf;
}

static wchar_t *utf8_to_utf16(char *source)
{
    DWORD wpath_len =
        MultiByteToWideChar(CP_UTF8, 0, source, strlen(source), NULL, 0);

    wchar_t *wpath = malloc(sizeof(wchar_t) * (wpath_len + 1));

    MultiByteToWideChar(CP_UTF8, 0, source, strlen(source), wpath, wpath_len);

    wpath[wpath_len] = 0;

    return wpath;
}
#endif
