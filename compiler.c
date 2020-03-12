#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Forward declarations {{{
typedef struct SourceFile SourceFile;
//}}}

// String {{{
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
// }}}

// Array {{{
#define ARRAY_INITIAL_CAPACITY 16

#define array_header(a) ((ArrayHeader *)((char *)(a) - sizeof(ArrayHeader)))

#define array_size(a) ((a) ? array_header(a)->size : 0)

#define array_set_size(a, s) ((a) ? array_header(a)->size = s : 0)

#define array_capacity(a) ((a) ? array_header(a)->capacity : 0)

#define array_full(a)                                                          \
    ((a) ? (array_header(a)->size >= array_header(a)->capacity) : 1)

#define array_last(a) (&(a)[array_size(a) - 1])

#define array_push(a, item)                                                    \
    (array_full(a) ? (a) = array_grow(a, sizeof(*a), 0) : 0,                   \
     (a)[array_header(a)->size++] = (item))

#define array_pop(a)                                                           \
    (array_size(a) > 0 ? (array_header(a)->size--, &a[array_size(a)]) : NULL)

#define array_reserve(a, capacity)                                             \
    (array_full(a) ? (a) = array_grow((a), sizeof(*a), capacity) : 0)

#define array_add(a, count)                                                    \
    do                                                                         \
    {                                                                          \
        array_reserve((a), array_size(a) + count);                             \
        array_header(a)->size = (array_size(a) + count);                       \
    } while (0)

#define array_add_zeroed(a, count)                                             \
    do                                                                         \
    {                                                                          \
        array_reserve((a), array_size(a) + count);                             \
        memset(a + array_size(a), 0, sizeof(*a) * count);                      \
        array_header(a)->size = (array_size(a) + count);                       \
    } while (0)

#define array_free(a)                                                          \
    do                                                                         \
    {                                                                          \
        if (a) free(array_header(a));                                          \
        a = NULL;                                                              \
    } while (0)

typedef struct ArrayHeader
{
    uint64_t size;
    uint64_t capacity;
} ArrayHeader;

void *array_grow(void *a, uint64_t item_size, uint64_t cap)
{
    if (!a)
    {
        uint64_t desired_cap = ((cap == 0) ? ARRAY_INITIAL_CAPACITY : cap);

        a = ((char *)malloc(sizeof(ArrayHeader) + (item_size * desired_cap))) +
            sizeof(ArrayHeader);
        array_header(a)->size = 0;
        array_header(a)->capacity = desired_cap;

        return a;
    }

    uint64_t desired_cap = ((cap == 0) ? (array_header(a)->capacity * 2) : cap);
    array_header(a)->capacity = desired_cap;
    return ((char *)realloc(
               array_header(a),
               sizeof(ArrayHeader) + (desired_cap * item_size))) +
           sizeof(ArrayHeader);
}
// }}}

// HashMap {{{
#define HASH_UNUSED UINT64_MAX
#define HASH_NOT_FOUND UINT64_MAX

typedef struct HashMap
{
    uint64_t *keys;
    uint64_t *values;
    uint32_t size;
} HashMap;

void hash_grow(HashMap *map);

uint64_t hash_str(String str)
{
    uint64_t hash = 5381;

    for (uint32_t i = 0; i < str.length; ++i)
    {
        hash = ((hash << 5) + hash) + str.buf[i]; /* hash * 33 + c */
    }

    return hash;
}

void hash_init(HashMap *map, uint32_t size)
{
    memset(map, 0, sizeof(*map));

    map->size = size;

    map->keys = malloc(sizeof(*map->keys) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);

    memset(map->keys, 0xff, sizeof(*map->keys) * map->size);
}

void hash_clear(HashMap *map)
{
    memset(map->keys, 0xff, sizeof(*map->keys) * map->size);
}

uint64_t hash_set_uint(HashMap *map, uint64_t key, uint64_t value)
{
    uint32_t i = key % map->size;
    uint32_t iters = 0;
    while (map->keys[i] != key && map->keys[i] != HASH_UNUSED &&
           iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }

    if (iters >= map->size)
    {
        hash_grow(map);
        return hash_set_uint(map, key, value);
    }

    map->keys[i] = key;
    map->values[i] = value;

    return value;
}

uint64_t hash_get_uint(HashMap *map, uint64_t key)
{
    uint32_t i = key % map->size;
    uint32_t iters = 0;
    while (map->keys[i] != key && map->keys[i] != HASH_UNUSED &&
           iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }
    if (iters >= map->size)
    {
        return HASH_NOT_FOUND;
    }

    return map->keys[i] == HASH_UNUSED ? HASH_NOT_FOUND : map->values[i];
}

void *hash_set_ptr(HashMap *map, uint64_t key, void *value)
{
    return (void *)hash_set_uint(map, key, (uint64_t)value);
}

void *hash_get_ptr(HashMap *map, uint64_t key)
{
    uint64_t result = hash_get_uint(map, key);
    if (result == HASH_NOT_FOUND) return NULL;
    return (void *)result;
}

void hash_remove(HashMap *map, uint64_t key)
{
    uint32_t i = key % map->size;
    uint32_t iters = 0;
    while (map->keys[i] != key && map->keys[i] != HASH_UNUSED &&
           iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }

    if (iters >= map->size)
    {
        return;
    }

    map->keys[i] = HASH_UNUSED;

    return;
}

void hash_grow(HashMap *map)
{
    uint32_t old_size = map->size;
    uint64_t *old_keys = map->keys;
    uint64_t *old_values = map->values;

    map->size = old_size * 2;
    map->keys = malloc(sizeof(*map->keys) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);
    memset(map->keys, 0xff, sizeof(*map->keys) * map->size);

    for (uint32_t i = 0; i < old_size; i++)
    {
        if (old_keys[i] != HASH_UNUSED)
        {
            hash_set_uint(map, old_keys[i], old_values[i]);
        }
    }

    free(old_keys);
    free(old_values);
}

void hash_destroy(HashMap *map)
{
    free(map->keys);
    free(map->values);
}
// }}}

// Bump allocator {{{
typedef struct BumpBlock
{
    unsigned char *data;
    size_t size;
    size_t pos;
    struct BumpBlock *next;
} BumpBlock;

void block_init(BumpBlock *block, size_t size)
{
    block->data = malloc(size);
    block->size = size;
    block->pos = 0;
    block->next = NULL;
}

void block_destroy(BumpBlock *block)
{
    if (block->next != NULL)
    {
        block_destroy(block->next);
        free(block->next);
        block->next = NULL;
    }

    free(block->data);
}

void *block_alloc(BumpBlock *block, size_t size)
{
    assert((block->size - block->pos) >= size);
    void *data = block->data + block->pos;
    block->pos += size;
    return data;
}

typedef struct BumpAlloc
{
    size_t block_size;
    size_t last_block_size;
    BumpBlock base_block;
    BumpBlock *last_block;
} BumpAlloc;

void bump_init(BumpAlloc *alloc, size_t block_size)
{
    alloc->block_size = block_size;
    alloc->last_block_size = alloc->block_size;
    block_init(&alloc->base_block, block_size);
    alloc->last_block = &alloc->base_block;
}

void *bump_alloc(BumpAlloc *alloc, size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    size_t space = alloc->last_block->size - alloc->last_block->pos;
    if (space < size)
    {
        // Append new block
        alloc->last_block->next = malloc(sizeof(BumpBlock));
        alloc->last_block_size *= 2;
        alloc->last_block_size += size;
        block_init(alloc->last_block->next, alloc->last_block_size);
        alloc->last_block = alloc->last_block->next;
    }

    return block_alloc(alloc->last_block, size);
}

String bump_strdup(BumpAlloc *alloc, String str)
{
    String s;
    s.length = str.length;
    s.buf = bump_alloc(alloc, s.length);
    memcpy(s.buf, str.buf, str.length);
    return s;
}

char *bump_c_str(BumpAlloc *alloc, String str)
{
    char *s;
    s = bump_alloc(alloc, str.length + 1);
    for (size_t i = 0; i < str.length; i++)
    {
        s[i] = str.buf[i];
    }
    s[str.length] = '\0';
    return s;
}

size_t bump_usage(BumpAlloc *alloc)
{
    size_t usage = 0;

    BumpBlock *block = &alloc->base_block;
    while (block)
    {
        usage += block->pos;
        block = block->next;
    }

    return usage;
}

void bump_destroy(BumpAlloc *alloc)
{
    block_destroy(&alloc->base_block);
}
// }}}

// Location {{{
typedef struct Location
{
    SourceFile *file;
    char *buf;
    uint32_t line;
    uint32_t col;
    uint32_t length;
} Location;
// }}}

// Error {{{
typedef struct Error
{
    Location loc;
    String message;
} Error;
// }}}

// Compiler {{{
typedef struct Compiler
{
    BumpAlloc bump;
    /*array*/ Error *errors;
} Compiler;

void compiler_init(Compiler *compiler)
{
    memset(compiler, 0, sizeof(*compiler));
    bump_init(&compiler->bump, 1 << 16);
}

void compiler_destroy(Compiler *compiler)
{
    bump_destroy(&compiler->bump);
}
// }}}

// Source file {{{
typedef struct SourceFile
{
    String path;
    String content;
} SourceFile;

void source_file_init(SourceFile *file, Compiler *compiler, String path)
{
    memset(file, 0, sizeof(*file));

    file->path = bump_strdup(&compiler->bump, path);

    FILE *f = fopen(bump_c_str(&compiler->bump, file->path), "rb");
    if (!f)
    {
        printf(
            "Failed to open file: %.*s",
            (int)file->path.length,
            file->path.buf);
        abort();
    }

    fseek(f, 0, SEEK_END);
    file->content.length = (uint32_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    file->content.buf = malloc(file->content.length);
    fread(file->content.buf, 1, file->content.length, f);
    fclose(f);
}
// }}}

// Token {{{
typedef uint32_t TokenType;
enum {
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACK,
    TOKEN_RBRACK,
    TOKEN_LCURLY,
    TOKEN_RCURLY,

    TOKEN_SEMICOLON,
    TOKEN_COLON,

    TOKEN_ASTERISK,
    TOKEN_AMPERSAND,

    TOKEN_DOT,
    TOKEN_COMMA,

    TOKEN_NOT,       // !
    TOKEN_ASSIGN,    // =
    TOKEN_EQUAL,     // ==
    TOKEN_NOT_EQUAL, // !=

    TOKEN_INT,
    TOKEN_FLOAT,

    TOKEN_IDENT,
    TOKEN_PROC,
    TOKEN_STRUCT,
    TOKEN_UNION,
    TOKEN_FOR,
    TOKEN_WHILE,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_RETURN,
    TOKEN_CONST,
    TOKEN_VAR,

    TOKEN_U8,
    TOKEN_U16,
    TOKEN_U32,
    TOKEN_U64,

    TOKEN_I8,
    TOKEN_I16,
    TOKEN_I32,
    TOKEN_I64,

    TOKEN_F32,
    TOKEN_F64,

    TOKEN_VOID,

    TOKEN_BOOL,
    TOKEN_FALSE,
    TOKEN_TRUE,
};

typedef struct Token
{
    TokenType type;
    Location loc;
    union
    {
        double f64;
        int64_t i64;
    };
} Token;
// }}}

// Lexer {{{
typedef struct Lexer
{
    Compiler *compiler;
    SourceFile *file;
    size_t pos;
    /*array*/ Token *tokens;
} Lexer;

static inline bool is_letter(char c)
{
    return ('z' >= c && c >= 'a') || ('Z' >= c && c >= 'A');
}

static inline bool is_numeric(char c)
{
    return '0' <= c && '9' >= c;
}

static inline bool is_alphanum(char c)
{
    return is_letter(c) || is_numeric(c) || c == '_';
}

static inline bool is_newline(char c)
{
    return c == '\n';
}

static inline bool is_whitespace(char c)
{
    return c == ' ' || c == '\t' || is_newline(c);
}

static inline bool lex_is_at_end(Lexer *l)
{
    return (l->pos >= l->file->content.length) ||
           (l->file->content.buf[l->pos] == '\0');
}

static inline char lex_next(Lexer *l, size_t count)
{
    char c = l->file->content.buf[l->pos];
    l->pos += count;
    return c;
}

static inline char lex_peek(Lexer *l)
{
    return l->file->content.buf[l->pos];
}

static inline char lex_match_str(Lexer *l, String s)
{
    return strncmp(&l->file->content.buf[l->pos], s.buf, s.length) == 0;
}

void lex_token(Lexer *l)
{
    Token tok = {0};
    tok.loc.file = l->file;
    tok.loc.buf = l->file->content.buf + l->pos;
    tok.loc.length = 0;
    char c = lex_peek(l);

    switch (c)
    {
        case '\n':
        case '\r':
        case '\t':
        case ' ': {
            lex_next(l, 1);
            break;
        }
        case '(': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_LPAREN;
            break;
        }
        case ')': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_RPAREN;
            break;
        }
        case '[': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_LBRACK;
            break;
        }
        case ']': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_RBRACK;
            break;
        }
        case '{': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_LCURLY;
            break;
        }
        case '}': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_RCURLY;
            break;
        }
        case '*': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_ASTERISK;
            break;
        }
        case ':': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_COLON;
            break;
        }
        case ';': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_COLON;
            break;
        }
        case '.': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_DOT;
            break;
        }
        case ',': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_COMMA;
            break;
        }
        case '=': {
            tok.loc.length = 1;
            lex_next(l, 1);
            tok.type = TOKEN_ASSIGN;
            if (lex_peek(l) == '=')
            {
                ++tok.loc.length;
                lex_next(l, 1);
                tok.type = TOKEN_EQUAL;
            }
            break;
        }
        default: {
            if (is_letter(c))
            {
                while (is_alphanum(tok.loc.file->content.buf[tok.loc.length]))
                {
                    tok.loc.length++;
                }

                lex_next(l, tok.loc.length);

                tok.type = TOKEN_IDENT;

#define LEX_MATCH_STR(lit, tok_type)                                           \
    if (strncmp(tok.loc.buf, lit, tok.loc.length) == 0)                        \
    {                                                                          \
        tok.type = (tok_type);                                                 \
        break;                                                                 \
    }

                LEX_MATCH_STR("u8", TOKEN_U8);
                LEX_MATCH_STR("u16", TOKEN_U16);
                LEX_MATCH_STR("u32", TOKEN_U32);
                LEX_MATCH_STR("u64", TOKEN_U64);
                LEX_MATCH_STR("i8", TOKEN_I8);
                LEX_MATCH_STR("i16", TOKEN_I16);
                LEX_MATCH_STR("i32", TOKEN_I32);
                LEX_MATCH_STR("i64", TOKEN_I64);
                LEX_MATCH_STR("f32", TOKEN_F32);
                LEX_MATCH_STR("f64", TOKEN_F64);
                LEX_MATCH_STR("void", TOKEN_VOID);
                LEX_MATCH_STR("bool", TOKEN_BOOL);
                LEX_MATCH_STR("true", TOKEN_TRUE);
                LEX_MATCH_STR("false", TOKEN_FALSE);

                LEX_MATCH_STR("var", TOKEN_VAR);
                LEX_MATCH_STR("const", TOKEN_CONST);
                LEX_MATCH_STR("proc", TOKEN_PROC);
                LEX_MATCH_STR("struct", TOKEN_STRUCT);
                LEX_MATCH_STR("union", TOKEN_UNION);
                LEX_MATCH_STR("if", TOKEN_IF);
                LEX_MATCH_STR("else", TOKEN_ELSE);
                LEX_MATCH_STR("while", TOKEN_WHILE);
                LEX_MATCH_STR("for", TOKEN_FOR);
                LEX_MATCH_STR("return", TOKEN_RETURN);

                break;
            }

            if (is_numeric(c))
            {
                bool has_dot = false;

                while (is_numeric(tok.loc.buf[tok.loc.length]) ||
                       tok.loc.buf[tok.loc.length] == '.')
                {
                    if (tok.loc.buf[tok.loc.length])
                    {
                        has_dot = true;
                    }
                    tok.loc.length++;
                }

                lex_next(l, tok.loc.length);

                char *str = bump_c_str(
                    &l->compiler->bump,
                    (String){.buf = tok.loc.buf, .length = tok.loc.length});

                if (has_dot)
                {
                    tok.type = TOKEN_FLOAT;
                    tok.f64 = strtod(str, NULL);
                }
                else
                {
                    tok.type = TOKEN_INT;
                    tok.i64 = strtol(str, NULL, 10);
                }
                break;
            }

            printf("Failed: %d\n", (int)c);
            abort();
            break;
        }
    }

    if (tok.loc.length > 0)
    {
        array_push(l->tokens, tok);
    }
}

void lex_file(Lexer *l, Compiler *compiler, SourceFile *file)
{
    memset(l, 0, sizeof(*l));
    l->compiler = compiler;
    l->file = file;

    while (!lex_is_at_end(l))
    {
        lex_token(l);
    }
}
// }}}

int main(int argc, char **argv)
{
    Compiler compiler;
    compiler_init(&compiler);

    if (argc <= 1)
    {
        printf("Usage: %s <source file>\n", argv[0]);
        exit(1);
    }

    if (argc == 2)
    {
        SourceFile *file = bump_alloc(&compiler.bump, sizeof(SourceFile));
        source_file_init(
            file,
            &compiler,
            (String){.buf = argv[1], .length = strlen(argv[1])});

        Lexer lexer;
        lex_file(&lexer, &compiler, file);

        if (array_size(compiler.errors) > 0)
        {
            for (Error *err = compiler.errors;
                 err != compiler.errors + array_size(compiler.errors);
                 ++err)
            {
                printf(
                    "%.*s (%u:%u): %.*s\n",
                    (int)err->loc.file->path.length,
                    err->loc.file->path.buf,
                    err->loc.line,
                    err->loc.col,
                    (int)err->message.length,
                    err->message.buf);
            }
            exit(1);
        }
    }

    compiler_destroy(&compiler);
    return 0;
}
