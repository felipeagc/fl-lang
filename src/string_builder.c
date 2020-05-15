typedef struct StringBuilder
{
    char *buf;
    char *scratch;
    size_t len;
    size_t cap;
} StringBuilder;

static void sb_init(StringBuilder *sb)
{
    sb->len = 0;
    sb->cap = 1 << 16; // 64k
    sb->buf = malloc(sb->cap);
    sb->scratch = malloc(sb->cap);
}

static void sb_destroy(StringBuilder *sb)
{
    free(sb->buf);
    free(sb->scratch);
}

static inline void sb_reset(StringBuilder *sb)
{
    sb->len = 0;
}

static inline void sb_grow(StringBuilder *sb)
{
    sb->cap *= 2;
    sb->buf = realloc(sb->buf, sb->cap);
    sb->scratch = realloc(sb->scratch, sb->cap);
}

static inline void sb_append_char(StringBuilder *sb, char c)
{
    while (sb->len + 1 >= sb->cap)
    {
        sb_grow(sb);
    }
    sb->buf[sb->len++] = c;
}

static inline void sb_append(StringBuilder *sb, String str)
{
    while (str.len + sb->len >= sb->cap)
    {
        sb_grow(sb);
    }
    strncpy(&sb->buf[sb->len], str.ptr, str.len);
    sb->len += str.len;
}

static inline void sb_sprintf(StringBuilder *sb, const char *fmt, ...)
{
    va_list vl;
    va_start(vl, fmt);
    size_t len = vsnprintf(sb->scratch, sb->cap, fmt, vl);
    va_end(vl);
    sb_append(sb, (String){.len = len, .ptr = sb->scratch});
}

static inline String sb_build(StringBuilder *sb, BumpAlloc *bump)
{
    String result = {0};
    result.len = sb->len;
    result.ptr = bump_alloc(bump, result.len);
    strncpy(result.ptr, sb->buf, result.len);
    return result;
}
