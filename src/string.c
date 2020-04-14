typedef struct String
{
    char *buf;
    size_t length;
} String;

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
