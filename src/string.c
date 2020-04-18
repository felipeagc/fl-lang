typedef struct String
{
    char *buf;
    size_t length;
} String;

typedef ARRAY_OF(String) ArrayOfString;
typedef ARRAY_OF(char *) ArrayOfCharPtr;

#define STR(lit)                                                               \
    ((String){                                                                 \
        .buf = lit,                                                            \
        .length = sizeof(lit) - 1,                                             \
    })

#define CSTR(lit)                                                              \
    ((String){                                                                 \
        .buf = (lit),                                                          \
        .length = strlen(lit),                                                 \
    })

#define PRINT_STR(str) (int)str.length, str.buf

static inline bool string_equals(String a, String b)
{
    if (a.length != b.length) return false;
    return strncmp(a.buf, b.buf, a.length) == 0;
}

#if defined(_WIN32)
static char *utf16_to_utf8(wchar_t *source)
{
    size_t required_size =
        WideCharToMultiByte(CP_UTF8, 0, source, -1, NULL, 0, NULL, NULL);
    char *buf = calloc(required_size, sizeof(char));
    WideCharToMultiByte(CP_UTF8, 0, source, -1, buf, required_size, NULL, NULL);
    return buf;
}
#endif
