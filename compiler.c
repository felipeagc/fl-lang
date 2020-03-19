#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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

static inline bool string_equals(String a, String b)
{
    if (a.length != b.length) return false;
    return strncmp(a.buf, b.buf, a.length) == 0;
}
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
typedef struct HashMap
{
    String *keys;
    uint64_t *hashes;
    void **values;
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
    map->hashes = malloc(sizeof(*map->hashes) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);

    memset(map->keys, 0, sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
}

void hash_clear(HashMap *map)
{
    memset(map->keys, 0, sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
}

void *hash_set(HashMap *map, String key, void *value)
{
    uint64_t hash = hash_str(key);
    uint32_t i = hash % map->size;
    uint32_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }

    if (iters >= map->size)
    {
        hash_grow(map);
        return hash_set(map, key, value);
    }

    map->keys[i] = key;
    map->hashes[i] = hash;
    map->values[i] = value;

    return value;
}

void *hash_get(HashMap *map, String key)
{
    uint64_t hash = hash_str(key);
    uint32_t i = hash % map->size;
    uint32_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }
    if (iters >= map->size)
    {
        return NULL;
    }

    return map->hashes[i] == 0 ? NULL : map->values[i];
}

void hash_remove(HashMap *map, String key)
{
    uint64_t hash = hash_str(key);
    uint64_t i = hash % map->size;
    uint64_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) % map->size;
        iters++;
    }

    if (iters >= map->size)
    {
        return;
    }

    map->hashes[i] = 0;

    return;
}

void hash_grow(HashMap *map)
{
    uint64_t old_size = map->size;
    String *old_keys = map->keys;
    uint64_t *old_hashes = map->hashes;
    void **old_values = map->values;

    map->size = old_size * 2;
    map->hashes = malloc(sizeof(*map->hashes) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);
    map->keys = malloc(sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
    memset(map->keys, 0, sizeof(*map->keys) * map->size);

    for (uint64_t i = 0; i < old_size; i++)
    {
        if (old_hashes[i] != 0)
        {
            hash_set(map, old_keys[i], old_values[i]);
        }
    }

    free(old_hashes);
    free(old_values);
    free(old_keys);
}

void hash_destroy(HashMap *map)
{
    free(map->hashes);
    free(map->values);
    free(map->keys);
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
    uint32_t length;
    uint32_t line;
    uint32_t col;
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

void compile_error(Compiler *compiler, Location loc, const char *fmt, ...)
{
    char buf[2048];
    assert(loc.file);

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    String message = bump_strdup(
        &compiler->bump, (String){.buf = buf, .length = strlen(buf)});

    Error err = {.loc = loc, .message = message};
    array_push(compiler->errors, err);
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
typedef enum TokenType {
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

    TOKEN_IDENT,
    TOKEN_STRING,
    TOKEN_CSTRING,
    TOKEN_PROC,
    TOKEN_TYPEDEF,
    TOKEN_STRUCT,
    TOKEN_UNION,
    TOKEN_ENUM,
    TOKEN_FOR,
    TOKEN_WHILE,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_RETURN,
    TOKEN_CONST,
    TOKEN_VAR,

    TOKEN_INT,
    TOKEN_FLOAT,

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
    TOKEN_NULL,

    TOKEN_BOOL,
    TOKEN_FALSE,
    TOKEN_TRUE,
} TokenType;

static const char *token_strings[] = {
    [TOKEN_LPAREN] = "(",
    [TOKEN_RPAREN] = ")",
    [TOKEN_LBRACK] = "[",
    [TOKEN_RBRACK] = "]",
    [TOKEN_LCURLY] = "{",
    [TOKEN_RCURLY] = "}",

    [TOKEN_SEMICOLON] = ";",
    [TOKEN_COLON] = ":",

    [TOKEN_ASTERISK] = "*",
    [TOKEN_AMPERSAND] = "&",

    [TOKEN_DOT] = ".",
    [TOKEN_COMMA] = ",",

    [TOKEN_NOT] = "!",        // !
    [TOKEN_ASSIGN] = "=",     // =
    [TOKEN_EQUAL] = "==",     // ==
    [TOKEN_NOT_EQUAL] = "!=", // !=

    [TOKEN_IDENT] = "identifier",
    [TOKEN_STRING] = "string literal",
    [TOKEN_CSTRING] = "c-string literal",
    [TOKEN_PROC] = "proc",
    [TOKEN_TYPEDEF] = "typedef",
    [TOKEN_STRUCT] = "struct",
    [TOKEN_UNION] = "union",
    [TOKEN_ENUM] = "enum",
    [TOKEN_FOR] = "for",
    [TOKEN_WHILE] = "while",
    [TOKEN_IF] = "if",
    [TOKEN_ELSE] = "else",
    [TOKEN_RETURN] = "return",
    [TOKEN_CONST] = "const",
    [TOKEN_VAR] = "var",

    [TOKEN_INT] = "integer literal",
    [TOKEN_FLOAT] = "float literal",

    [TOKEN_U8] = "u8",
    [TOKEN_U16] = "u16",
    [TOKEN_U32] = "u32",
    [TOKEN_U64] = "u64",

    [TOKEN_I8] = "i8",
    [TOKEN_I16] = "i16",
    [TOKEN_I32] = "i32",
    [TOKEN_I64] = "i64",

    [TOKEN_F32] = "f32",
    [TOKEN_F64] = "f64",

    [TOKEN_VOID] = "void",
    [TOKEN_NULL] = "null",

    [TOKEN_BOOL] = "bool",
    [TOKEN_FALSE] = "false",
    [TOKEN_TRUE] = "true",
};

typedef struct Token
{
    TokenType type;
    Location loc;
    union
    {
        double f64;
        int64_t i64;
        String str;
    };
} Token;
// }}}

// Printing {{{
void print_token(Token *tok)
{
    printf("(%u:%u) ", tok->loc.line, tok->loc.col);

#define PRINT_TOKEN_TYPE(type)                                                 \
    case type: printf(#type); break

    switch (tok->type)
    {
        PRINT_TOKEN_TYPE(TOKEN_LPAREN);
        PRINT_TOKEN_TYPE(TOKEN_RPAREN);
        PRINT_TOKEN_TYPE(TOKEN_LBRACK);
        PRINT_TOKEN_TYPE(TOKEN_RBRACK);
        PRINT_TOKEN_TYPE(TOKEN_LCURLY);
        PRINT_TOKEN_TYPE(TOKEN_RCURLY);

        PRINT_TOKEN_TYPE(TOKEN_SEMICOLON);
        PRINT_TOKEN_TYPE(TOKEN_COLON);

        PRINT_TOKEN_TYPE(TOKEN_ASTERISK);
        PRINT_TOKEN_TYPE(TOKEN_AMPERSAND);

        PRINT_TOKEN_TYPE(TOKEN_DOT);
        PRINT_TOKEN_TYPE(TOKEN_COMMA);

        PRINT_TOKEN_TYPE(TOKEN_NOT);
        PRINT_TOKEN_TYPE(TOKEN_ASSIGN);
        PRINT_TOKEN_TYPE(TOKEN_EQUAL);
        PRINT_TOKEN_TYPE(TOKEN_NOT_EQUAL);

        PRINT_TOKEN_TYPE(TOKEN_INT);
        PRINT_TOKEN_TYPE(TOKEN_FLOAT);

        PRINT_TOKEN_TYPE(TOKEN_IDENT);
        PRINT_TOKEN_TYPE(TOKEN_PROC);
        PRINT_TOKEN_TYPE(TOKEN_TYPEDEF);
        PRINT_TOKEN_TYPE(TOKEN_STRUCT);
        PRINT_TOKEN_TYPE(TOKEN_UNION);
        PRINT_TOKEN_TYPE(TOKEN_ENUM);
        PRINT_TOKEN_TYPE(TOKEN_FOR);
        PRINT_TOKEN_TYPE(TOKEN_WHILE);
        PRINT_TOKEN_TYPE(TOKEN_IF);
        PRINT_TOKEN_TYPE(TOKEN_ELSE);
        PRINT_TOKEN_TYPE(TOKEN_RETURN);
        PRINT_TOKEN_TYPE(TOKEN_CONST);
        PRINT_TOKEN_TYPE(TOKEN_VAR);

        PRINT_TOKEN_TYPE(TOKEN_U8);
        PRINT_TOKEN_TYPE(TOKEN_U16);
        PRINT_TOKEN_TYPE(TOKEN_U32);
        PRINT_TOKEN_TYPE(TOKEN_U64);

        PRINT_TOKEN_TYPE(TOKEN_I8);
        PRINT_TOKEN_TYPE(TOKEN_I16);
        PRINT_TOKEN_TYPE(TOKEN_I32);
        PRINT_TOKEN_TYPE(TOKEN_I64);

        PRINT_TOKEN_TYPE(TOKEN_F32);
        PRINT_TOKEN_TYPE(TOKEN_F64);

        PRINT_TOKEN_TYPE(TOKEN_VOID);
        PRINT_TOKEN_TYPE(TOKEN_NULL);

        PRINT_TOKEN_TYPE(TOKEN_BOOL);
        PRINT_TOKEN_TYPE(TOKEN_FALSE);
        PRINT_TOKEN_TYPE(TOKEN_TRUE);

        PRINT_TOKEN_TYPE(TOKEN_STRING);
        PRINT_TOKEN_TYPE(TOKEN_CSTRING);
    }

    printf(" \"%.*s\"\n", (int)tok->loc.length, tok->loc.buf);
}
// }}}

// Lexer {{{
typedef struct Lexer
{
    Compiler *compiler;
    SourceFile *file;
    size_t pos;
    uint32_t line;
    uint32_t col;
    /*array*/ Token *tokens;
} Lexer;

static inline bool is_letter(char c)
{
    return (('z' >= c) && (c >= 'a')) || (('Z' >= c) && (c >= 'A'));
}

static inline bool is_numeric(char c)
{
    return ('0' <= c) && ('9' >= c);
}

static inline bool is_alphanum(char c)
{
    return is_letter(c) || is_numeric(c) || c == '_';
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

static inline char lex_peek(Lexer *l, size_t offset)
{
    return l->file->content.buf[l->pos + offset];
}

void lex_token(Lexer *l)
{
    ++l->col;

    Token tok = {0};
    tok.loc.file = l->file;
    tok.loc.buf = &l->file->content.buf[l->pos];
    tok.loc.length = 0;
    tok.loc.line = l->line;
    tok.loc.col = l->col;
    char c = lex_peek(l, 0);

    switch (c)
    {
    case '\n': {
        ++l->line;
        l->col = 0;
    }
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
    case '&': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_AMPERSAND;
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
        tok.type = TOKEN_SEMICOLON;
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
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_EQUAL;
        }
        break;
    }
    default: {
        if ((lex_peek(l, 0) == 'c' && lex_peek(l, 1) == '\"') ||
            (lex_peek(l, 0) == '\"'))
        {
            l->col--;

            if (lex_peek(l, 0) == 'c')
            {
                tok.type = TOKEN_CSTRING;
                tok.loc.length = 2;
                lex_next(l, 2);
            }
            else
            {
                tok.type = TOKEN_STRING;
                tok.loc.length = 1;
                lex_next(l, 1);
            }

            tok.str = (String){0};

            while (lex_peek(l, 0) != '\"' && !lex_is_at_end(l))
            {
                ++tok.loc.length;
                char n = lex_next(l, 1);
                if (n == '\\')
                {
                    ++tok.loc.length;
                    n = lex_next(l, 1);
                }

                array_push(tok.str.buf, n);
            }

            if (tok.type == TOKEN_CSTRING)
            {
                array_push(tok.str.buf, '\0');
            }

            tok.str.length = array_size(tok.str.buf);

            ++tok.loc.length;
            if (lex_next(l, 1) != '\"' || lex_is_at_end(l))
            {
                compile_error(
                    l->compiler,
                    tok.loc,
                    "unclosed string",
                    tok.loc.length,
                    tok.loc.buf);
                tok.loc.length = 0;
            }

            l->col += tok.loc.length;

            break;
        }

        if (is_letter(c))
        {
            l->col--;
            while (is_alphanum(tok.loc.buf[tok.loc.length]))
            {
                tok.loc.length++;
            }

            l->col += tok.loc.length;

            lex_next(l, tok.loc.length);

            tok.type = TOKEN_IDENT;

#define LEX_MATCH_STR(lit, tok_type)                                           \
    if (strlen(lit) == tok.loc.length &&                                       \
        strncmp(tok.loc.buf, lit, tok.loc.length) == 0)                        \
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
            LEX_MATCH_STR("null", TOKEN_NULL);
            LEX_MATCH_STR("bool", TOKEN_BOOL);
            LEX_MATCH_STR("true", TOKEN_TRUE);
            LEX_MATCH_STR("false", TOKEN_FALSE);

            LEX_MATCH_STR("var", TOKEN_VAR);
            LEX_MATCH_STR("const", TOKEN_CONST);
            LEX_MATCH_STR("proc", TOKEN_PROC);
            LEX_MATCH_STR("typedef", TOKEN_TYPEDEF);
            LEX_MATCH_STR("struct", TOKEN_STRUCT);
            LEX_MATCH_STR("union", TOKEN_UNION);
            LEX_MATCH_STR("enum", TOKEN_ENUM);
            LEX_MATCH_STR("if", TOKEN_IF);
            LEX_MATCH_STR("else", TOKEN_ELSE);
            LEX_MATCH_STR("while", TOKEN_WHILE);
            LEX_MATCH_STR("for", TOKEN_FOR);
            LEX_MATCH_STR("return", TOKEN_RETURN);

            if (tok.type == TOKEN_IDENT)
            {
                tok.str.buf = tok.loc.buf;
                tok.str.length = tok.loc.length;
            }

            break;
        }

        if (is_numeric(c))
        {
            l->col--;
            bool has_dot = false;

            while (is_numeric(tok.loc.buf[tok.loc.length]) ||
                   tok.loc.buf[tok.loc.length] == '.')
            {
                if (tok.loc.buf[tok.loc.length] == '.')
                {
                    has_dot = true;
                }
                tok.loc.length++;
            }

            l->col += tok.loc.length;

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

        tok.loc.length = 1;
        compile_error(
            l->compiler,
            tok.loc,
            "invalid token: '%.*s'",
            tok.loc.length,
            tok.loc.buf);
        tok.loc.length = 0;
        lex_next(l, 1);
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
    l->line = 1;

    while (!lex_is_at_end(l))
    {
        lex_token(l);
    }

    /* for (Token *tok = l->tokens; tok != l->tokens + array_size(l->tokens); */
    /*      ++tok) */
    /* { */
    /*     print_token(tok); */
    /* } */
}
// }}}

// Type {{{
typedef enum TypeKind {
    TYPE_UNINITIALIZED,
    TYPE_NONE,
    TYPE_TYPE,
    TYPE_PROC,
    TYPE_PRIMITIVE,
    TYPE_POINTER,
    TYPE_ARRAY,
} TypeKind;

typedef enum PrimitiveType {
    PRIMITIVE_TYPE_U8,
    PRIMITIVE_TYPE_U16,
    PRIMITIVE_TYPE_U32,
    PRIMITIVE_TYPE_U64,
    PRIMITIVE_TYPE_I8,
    PRIMITIVE_TYPE_I16,
    PRIMITIVE_TYPE_I32,
    PRIMITIVE_TYPE_I64,
    PRIMITIVE_TYPE_F32,
    PRIMITIVE_TYPE_F64,
    PRIMITIVE_TYPE_BOOL,
    PRIMITIVE_TYPE_VOID,
} PrimitiveType;

typedef struct TypeInfo
{
    TypeKind kind;
    union
    {
        PrimitiveType primitive;
        struct
        {
            struct TypeInfo *sub;
        } ptr;
        struct
        {
            struct TypeInfo *sub;
            size_t size;
        } array;
        struct
        {
            struct TypeInfo *return_type;
            /*array*/ struct TypeInfo *params;
        } proc;
    };
} TypeInfo;

TypeInfo *exact_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind != expected->kind) return NULL;

    switch (received->kind)
    {
    case TYPE_PRIMITIVE: {
        if (received->primitive != expected->primitive) return NULL;
        break;
    }
    case TYPE_POINTER: {
        if (!exact_types(received->ptr.sub, expected->ptr.sub)) return NULL;
        break;
    }
    case TYPE_ARRAY: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        if (received->array.size != expected->array.size) return NULL;
        break;
    }
    case TYPE_PROC: {
        if (!exact_types(
                received->proc.return_type, expected->proc.return_type))
            return NULL;

        if (array_size(received->proc.params) !=
            array_size(expected->proc.params))
            return NULL;

        for (size_t i = 0; i < array_size(received->proc.params); ++i)
        {
            if (!exact_types(
                    &received->proc.params[i], &expected->proc.params[i]))
                return NULL;
        }

        break;
    }
    case TYPE_TYPE: break;
    case TYPE_UNINITIALIZED: break;
    case TYPE_NONE: break;
    }

    return received;
}

// }}}

// Scope {{{
typedef struct Scope
{
    HashMap map;
    struct Ast *procedure;
} Scope;

void scope_init(Scope *scope, size_t size, struct Ast *procedure)
{
    memset(scope, 0, sizeof(*scope));
    hash_init(&scope->map, size);
    scope->procedure = procedure;
}

void scope_set(Scope *scope, String name, struct Ast *decl)
{
    hash_set(&scope->map, name, decl);
}

struct Ast *scope_get_local(Scope *scope, String name)
{
    return hash_get(&scope->map, name);
}
// }}}

// AST {{{
typedef enum UnOpType {
    UNOP_DEREFERENCE,
    UNOP_ADDRESS,
} UnOpType;

typedef enum BinOpType {
    BINOP_ADD,
    BINOP_SUB,
    BINOP_MUL,
    BINOP_DIV,
} BinOpType;

typedef enum AstType {
    AST_UNINITIALIZED,
    AST_ROOT,
    AST_STRUCT_DECL,
    AST_PROC_DECL,
    AST_BLOCK,
    AST_PROC_CALL,
    AST_UNARY_EXPR,
    AST_BINARY_EXPR,
    AST_TYPEDEF,
    AST_CONST_DECL,
    AST_VAR_DECL,
    AST_VAR_ASSIGN,
    AST_RETURN,
    AST_PRIMARY,
    AST_PAREN_EXPR,
} AstType;

typedef struct Ast
{
    AstType type;
    Location loc;
    TypeInfo *type_info;
    TypeInfo *as_type;

    union
    {
        struct Ast *expr;
        struct
        {
            Token *tok;
        } primary;
        struct
        {
            Scope scope;
            /*array*/ struct Ast *stmts;
        } block;
        struct
        {
            Scope scope;
            String convention;
            String name;
            struct Ast *return_type;
            /*array*/ struct Ast *params;
            /*array*/ struct Ast *stmts;
        } proc;
        struct
        {
            struct Ast *expr;
            /*array*/ struct Ast *params;
        } proc_call;
        struct
        {
            String name;
            struct Ast *type_expr;
        } type_def;
        struct
        {
            String name;
            struct Ast *type_expr;
            struct Ast *value_expr;
        } decl;
        struct
        {
            struct Ast *assigned_expr;
            struct Ast *value_expr;
        } assign;
        struct
        {
            UnOpType type;
            struct Ast *sub;
        } unop;
        struct
        {
            BinOpType type;
            struct Ast *left;
            struct Ast *right;
        } binop;
    };
} Ast;
// }}}

// Parser {{{
typedef struct Parser
{
    Compiler *compiler;
    Lexer *lexer;
    Ast *ast;
    size_t pos;
} Parser;

static inline bool parser_is_at_end(Parser *p)
{
    return p->pos >= array_size(p->lexer->tokens);
}

static inline Token *parser_peek(Parser *p, size_t offset)
{
    if (p->pos + offset >= array_size(p->lexer->tokens))
    {
        return &p->lexer->tokens[p->pos];
    }
    return &p->lexer->tokens[p->pos + offset];
}

static inline Token *parser_next(Parser *p, size_t count)
{
    if (!parser_is_at_end(p)) p->pos += count;
    return &p->lexer->tokens[p->pos - count];
}

static inline Token *parser_consume(Parser *p, TokenType tok_type)
{
    Token *tok = parser_peek(p, 0);
    if (tok->type != tok_type)
    {
        Location loc = tok->loc;
        tok = parser_peek(p, -1);
        compile_error(
            p->compiler,
            loc,
            "expected: '%s' after '%.*s'",
            token_strings[tok_type],
            tok->loc.length,
            tok->loc.buf);
        return NULL;
    }

    return parser_next(p, 1);
}

bool parse_expr(Parser *p, Ast *ast);

bool parse_primery_expr(Parser *p, Ast *ast)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_IDENT:
    case TOKEN_TRUE:
    case TOKEN_FALSE:
    case TOKEN_VOID:
    case TOKEN_NULL:
    case TOKEN_BOOL:
    case TOKEN_STRING:
    case TOKEN_CSTRING:
    case TOKEN_U8:
    case TOKEN_U16:
    case TOKEN_U32:
    case TOKEN_U64:
    case TOKEN_I8:
    case TOKEN_I16:
    case TOKEN_I32:
    case TOKEN_I64:
    case TOKEN_F32:
    case TOKEN_F64:
    case TOKEN_INT:
    case TOKEN_FLOAT: {
        parser_next(p, 1);
        ast->type = AST_PRIMARY;
        ast->primary.tok = tok;
        break;
    }
    case TOKEN_LPAREN: {
        parser_next(p, 1);

        ast->type = AST_PAREN_EXPR;
        ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->expr)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        break;
    }
    default: {
        parser_next(p, 1);
        res = false;
        break;
    }
    }
    return res;
}

bool parse_proc_call(Parser *p, Ast *ast)
{
    bool res = true;

    Ast expr = *ast;
    if (!parse_primery_expr(p, &expr)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    expr.loc.length = last_loc.buf + last_loc.length - expr.loc.buf;

    if (parser_peek(p, 0)->type == TOKEN_LPAREN)
    {
        // Proc call
        ast->type = AST_PROC_CALL;
        ast->proc_call.expr =
            bump_alloc(&p->compiler->bump, sizeof(*ast->proc_call.expr));
        *ast->proc_call.expr = expr;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN && !parser_is_at_end(p))
        {
            Ast param = {0};
            if (!parse_expr(p, &param))
                res = false;
            else
                array_push(ast->proc_call.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;
    }
    else
    {
        *ast = expr;
    }

    return res;
}

bool parse_unary_expr(Parser *p, Ast *ast)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);

    switch (tok->type)
    {
    case TOKEN_ASTERISK:
    case TOKEN_AMPERSAND: {
        parser_next(p, 1);

        ast->type = AST_UNARY_EXPR;
        if (tok->type == TOKEN_ASTERISK) ast->unop.type = UNOP_DEREFERENCE;
        if (tok->type == TOKEN_AMPERSAND) ast->unop.type = UNOP_ADDRESS;

        ast->unop.sub = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->unop.sub)) res = false;

        break;
    }
    default: {
        res = parse_proc_call(p, ast);
        break;
    }
    }

    return res;
}

bool parse_expr(Parser *p, Ast *ast)
{
    assert(!parser_is_at_end(p));
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = parse_unary_expr(p, ast);
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;
    return res;
}

bool parse_stmt(Parser *p, Ast *ast, bool inside_procedure)
{
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = true;

    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_PROC: {
        parser_next(p, 1);

        ast->type = AST_PROC_DECL;

        if (parser_peek(p, 0)->type == TOKEN_STRING)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING);
            ast->proc.convention = convention_tok->str;
        }

        Token *proc_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!proc_name_tok)
            res = false;
        else
            ast->proc.name = proc_name_tok->str;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            Ast param = {0};
            param.type = AST_VAR_DECL;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                param.decl.name = ident_tok->str;

            if (ident_tok) param.loc = ident_tok->loc;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.decl.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.decl.type_expr)) res = false;

            array_push(ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->proc.return_type = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->proc.return_type)) res = false;

        ast->proc.stmts = NULL;

        if (parser_peek(p, 0)->type == TOKEN_LCURLY)
        {
            if (!parser_consume(p, TOKEN_LCURLY)) res = false;

            while (parser_peek(p, 0)->type != TOKEN_RCURLY)
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true)) res = false;
                array_push(ast->proc.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;
        }

        break;
    }
    case TOKEN_VAR:
    case TOKEN_CONST: {
        Token *kind = parser_next(p, 1);

        if (kind->type == TOKEN_VAR) ast->type = AST_VAR_DECL;
        if (kind->type == TOKEN_CONST) ast->type = AST_CONST_DECL;

        Token *ident_tok = parser_consume(p, TOKEN_IDENT);
        if (!ident_tok)
            res = false;
        else
            ast->decl.name = ident_tok->str;

        if (!parser_consume(p, TOKEN_COLON)) res = false;

        ast->decl.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->decl.type_expr)) res = false;

        ast->decl.value_expr = NULL;
        if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
        {
            if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

            ast->decl.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->decl.value_expr)) res = false;
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        break;
    }
    case TOKEN_TYPEDEF: {
        parser_next(p, 1);

        ast->type = AST_TYPEDEF;

        Token *type_name_tok = parser_consume(p, TOKEN_IDENT);
        if (!type_name_tok)
            res = false;
        else
            ast->type_def.name = type_name_tok->str;

        ast->type_def.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->type_def.type_expr)) res = false;

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        break;
    }
    case TOKEN_RETURN: {
        parser_next(p, 1);

        ast->type = AST_RETURN;

        ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->expr)) res = false;

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;
        break;
    }
    default: {
        ast->type = AST_VAR_ASSIGN;

        ast->assign.assigned_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->assign.assigned_expr)) res = false;

        if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

        ast->assign.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->assign.value_expr)) res = false;

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        if (!inside_procedure)
        {
            compile_error(
                p->compiler,
                tok->loc,
                "assignment must be inside procedure",
                tok->loc.length,
                tok->loc.buf);

            res = false;
            break;
        }

        break;
    }
    }

    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    return res;
}

void parse_file(Parser *p, Compiler *compiler, Lexer *lexer)
{
    memset(p, 0, sizeof(*p));
    p->compiler = compiler;
    p->lexer = lexer;

    p->ast = bump_alloc(&p->compiler->bump, sizeof(Ast));
    memset(p->ast, 0, sizeof(*p->ast));
    p->ast->type = AST_ROOT;

    while (!parser_is_at_end(p))
    {
        Ast stmt = {0};
        if (parse_stmt(p, &stmt, false))
        {
            array_push(p->ast->block.stmts, stmt);
        }
    }
}
// }}}

// Semantic analyzer {{{
typedef struct Analyzer
{
    Compiler *compiler;
    /*array*/ Scope **scope_stack;
} Analyzer;

Ast *get_symbol(Analyzer *a, String name)
{
    Ast *sym = NULL;
    for (Scope **scope = a->scope_stack + array_size(a->scope_stack) - 1;
         scope >= a->scope_stack;
         --scope)
    {
        sym = scope_get_local(*scope, name);
        if (sym) return sym;
    }

    return NULL;
}

Ast *get_scope_procedure(Analyzer *a)
{
    for (Scope **scope = a->scope_stack + array_size(a->scope_stack) - 1;
         scope >= a->scope_stack;
         --scope)
    {
        if ((*scope)->procedure) return (*scope)->procedure;
    }

    return NULL;
}

#define AS_TYPE_CASE_PRIMITIVE_TYPE(tok_type, prim_type)                       \
    case tok_type: {                                                           \
        static TypeInfo ty = {.kind = TYPE_PRIMITIVE, .primitive = prim_type}; \
        ast->as_type = &ty;                                                    \
        res = true;                                                            \
    }                                                                          \
    break

bool ast_as_type(Analyzer *a, Ast *ast)
{
    bool res = false;
    if (ast->as_type) return true;

    Scope *scope = *array_last(a->scope_stack);
    assert(scope);

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_U8, PRIMITIVE_TYPE_U8);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_U16, PRIMITIVE_TYPE_U16);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_U32, PRIMITIVE_TYPE_U32);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_U64, PRIMITIVE_TYPE_U64);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_I8, PRIMITIVE_TYPE_I8);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_I16, PRIMITIVE_TYPE_I16);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_I32, PRIMITIVE_TYPE_I32);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_I64, PRIMITIVE_TYPE_I64);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_F32, PRIMITIVE_TYPE_F32);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_F64, PRIMITIVE_TYPE_F64);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_BOOL, PRIMITIVE_TYPE_BOOL);
            AS_TYPE_CASE_PRIMITIVE_TYPE(TOKEN_VOID, PRIMITIVE_TYPE_VOID);
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(a, ast->primary.tok->str);
            if (sym && sym->type == AST_TYPEDEF)
            {
                res = ast_as_type(a, sym->type_def.type_expr);
                if (res)
                {
                    ast->as_type = sym->type_def.type_expr->as_type;
                }
            }

            break;
        }
        default: break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        res = ast_as_type(a, ast->expr);
        ast->as_type = ast->expr->as_type;
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            res = ast_as_type(a, ast->unop.sub);
            if (res)
            {
                TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(TypeInfo));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_POINTER;
                ty->ptr.sub = ast->unop.sub->as_type;
                ast->as_type = ty;
            }
            break;
        }
        default: break;
        }
        break;
    }
    default: break;
    }

    return res;
}

void register_symbol_ast(Analyzer *a, Ast *ast)
{
    Scope *scope = *array_last(a->scope_stack);
    assert(scope);
    String sym_name = {0};

    switch (ast->type)
    {
    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        sym_name = ast->decl.name;
        break;
    }
    case AST_TYPEDEF: {
        sym_name = ast->type_def.name;
        break;
    }
    case AST_PROC_DECL: {
        sym_name = ast->proc.name;

        array_push(a->scope_stack, &ast->proc.scope);
        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            register_symbol_ast(a, param);
        }
        array_pop(a->scope_stack);
        break;
    }
    default: return;
    }

    assert(sym_name.length > 0);

    if (get_symbol(a, sym_name))
    {
        compile_error(
            a->compiler,
            ast->loc,
            "duplicate declaration: '%.*s'",
            (int)sym_name.length,
            sym_name.buf);
        return;
    }

    scope_set(scope, sym_name, ast);
}

void symbol_check_ast(Analyzer *a, Ast *ast)
{
    switch (ast->type)
    {
    case AST_RETURN:
    case AST_PAREN_EXPR: {
        symbol_check_ast(a, ast->expr);
        break;
    }
    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        symbol_check_ast(a, ast->decl.type_expr);
        if ((ast->type == AST_VAR_DECL && ast->decl.value_expr) ||
            ast->type == AST_CONST_DECL)
        {
            symbol_check_ast(a, ast->decl.value_expr);
        }
        break;
    }
    case AST_VAR_ASSIGN: {
        symbol_check_ast(a, ast->assign.assigned_expr);
        symbol_check_ast(a, ast->assign.value_expr);
        break;
    }
    case AST_PROC_CALL: {
        symbol_check_ast(a, ast->proc_call.expr);

        for (Ast *param = ast->proc_call.params;
             param != ast->proc_call.params + array_size(ast->proc_call.params);
             ++param)
        {
            symbol_check_ast(a, param);
        }

        break;
    }
    case AST_UNARY_EXPR: {
        symbol_check_ast(a, ast->unop.sub);
        break;
    }
    case AST_BINARY_EXPR: {
        symbol_check_ast(a, ast->binop.left);
        symbol_check_ast(a, ast->binop.right);
        break;
    }
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(a, ast->primary.tok->str);
            if (!sym)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "invalid identifier: '%.*s'",
                    (int)ast->primary.tok->str.length,
                    ast->primary.tok->str.buf);
            }

            break;
        }
        default: break;
        }

        break;
    }
    default: break;
    }
}

#define TYPE_CHECK_CASE_PRIMITIVE_TYPE(prim_type)                              \
    case prim_type: {                                                          \
        static TypeInfo ty = {.kind = TYPE_PRIMITIVE, .primitive = prim_type}; \
        ast->type_info = &ty;                                                  \
    }                                                                          \
    break

bool type_check_ast(Analyzer *a, Ast *ast, TypeInfo *expected_type)
{
    bool res = true;
    bool is_statement = true;

    // Statements
    switch (ast->type)
    {
    case AST_RETURN: {
        Ast *proc = get_scope_procedure(a);
        if (!proc)
        {
            compile_error(
                a->compiler, ast->loc, "return needs to be inside a procedure");
            break;
        }

        assert(proc->proc.return_type->as_type);
        type_check_ast(a, ast->expr, proc->proc.return_type->as_type);
        break;
    }
    case AST_TYPEDEF: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->type_def.type_expr, &ty_ty);
        break;
    }
    case AST_CONST_DECL:
    case AST_VAR_DECL: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->decl.type_expr, &ty_ty);
        if ((ast->type == AST_VAR_DECL && ast->decl.value_expr) ||
            ast->type == AST_CONST_DECL)
        {
            type_check_ast(
                a, ast->decl.value_expr, ast->decl.type_expr->as_type);
        }
        break;
    }
    case AST_VAR_ASSIGN: {
        type_check_ast(a, ast->assign.assigned_expr, NULL);
        type_check_ast(
            a, ast->assign.value_expr, ast->assign.assigned_expr->type_info);
        break;
    }
    case AST_PROC_DECL: {
        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        array_push(a->scope_stack, &ast->proc.scope);

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            if (!type_check_ast(a, param, NULL)) res = false;
            if (res)
            {
                assert(param->decl.type_expr->as_type);
                array_push(ty->proc.params, *param->decl.type_expr->as_type);
            }
        }

        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        if (!type_check_ast(a, ast->proc.return_type, &ty_ty)) res = false;
        if (res)
        {
            assert(ast->proc.return_type->as_type);
            ty->proc.return_type = ast->proc.return_type->as_type;
        }

        array_pop(a->scope_stack);

        ast->type_info = ty;
        break;
    }
    default: {
        is_statement = false;
        break;
    }
    }

    if (is_statement)
    {
        return res;
    }

    ast_as_type(a, ast);

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_U8:
        case TOKEN_U16:
        case TOKEN_U32:
        case TOKEN_U64:
        case TOKEN_I8:
        case TOKEN_I16:
        case TOKEN_I32:
        case TOKEN_I64:
        case TOKEN_F32:
        case TOKEN_F64:
        case TOKEN_BOOL:
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_TYPE};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_TRUE:
        case TOKEN_FALSE: {
            static TypeInfo ty = {
                .kind = TYPE_PRIMITIVE,
                .primitive = PRIMITIVE_TYPE_BOOL,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_INT: {
            static TypeInfo ty = {
                .kind = TYPE_PRIMITIVE,
                .primitive = PRIMITIVE_TYPE_I64,
            };
            ast->type_info = &ty;

            if (expected_type && expected_type->kind == TYPE_PRIMITIVE)
            {
                switch (expected_type->primitive)
                {
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_U8);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_U16);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_U32);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_U64);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_I8);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_I16);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_I32);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_I64);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_F32);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_F64);
                default: break;
                }
            }

            break;
        }
        case TOKEN_FLOAT: {
            static TypeInfo ty = {
                .kind = TYPE_PRIMITIVE,
                .primitive = PRIMITIVE_TYPE_F64,
            };
            ast->type_info = &ty;

            if (expected_type && expected_type->kind == TYPE_PRIMITIVE)
            {
                switch (expected_type->primitive)
                {
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_F32);
                    TYPE_CHECK_CASE_PRIMITIVE_TYPE(PRIMITIVE_TYPE_F64);
                default: break;
                }
            }
            break;
        }
        case TOKEN_CSTRING: {
            static TypeInfo u8_ty = {
                .kind = TYPE_PRIMITIVE,
                .primitive = PRIMITIVE_TYPE_U8,
            };
            static TypeInfo ty = {
                .kind = TYPE_POINTER,
                .ptr.sub = &u8_ty,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(a, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_VAR_DECL:
                case AST_CONST_DECL: {
                    ast->type_info = sym->decl.type_expr->as_type;
                    assert(ast->type_info);
                    break;
                }
                case AST_PROC_DECL: {
                    ast->type_info = sym->type_info;
                    assert(ast->type_info);
                    break;
                }
                case AST_TYPEDEF: {
                    ast->type_info = sym->type_def.type_expr->type_info;
                    assert(ast->type_info);
                    break;
                }
                default: break;
                }
            }

            break;
        }
        default: assert(0); break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        res = type_check_ast(a, ast->expr, expected_type);
        ast->type_info = ast->expr->type_info;
        break;
    }
    case AST_PROC_CALL: {
        if (!type_check_ast(a, ast->proc_call.expr, NULL)) res = false;
        if (!res) break;

        if (ast->proc_call.expr->type_info->kind != TYPE_PROC)
        {
            res = false;
            compile_error(
                a->compiler, ast->loc, "tried to call a non procedure type");
            break;
        }

        assert(ast->proc_call.expr->type_info);
        ast->type_info = ast->proc_call.expr->type_info->proc.return_type;

        if (array_size(ast->proc_call.params) !=
            array_size(ast->proc_call.expr->type_info->proc.params))
        {
            res = false;
            compile_error(
                a->compiler,
                ast->loc,
                "wrong parameter count for function call");
            break;
        }

        for (size_t i = 0; i < array_size(ast->proc_call.params); ++i)
        {
            type_check_ast(
                a,
                &ast->proc_call.params[i],
                &ast->proc_call.expr->type_info->proc.params[i]);
        }
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            res = type_check_ast(a, ast->unop.sub, NULL);

            if (!ast->unop.sub->type_info) break;

            if (ast->unop.sub->type_info->kind == TYPE_TYPE)
            {
                TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_TYPE;
                ast->type_info = ty;
                break;
            }

            if (ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "you can only dereference pointer types");
                break;
            }

            ast->type_info = ast->unop.sub->type_info->ptr.sub;

            break;
        }
        case UNOP_ADDRESS: {
            TypeInfo *sub_expected_type = NULL;
            if (expected_type && expected_type->kind == TYPE_POINTER)
            {
                sub_expected_type = expected_type->ptr.sub;
            }

            res = type_check_ast(a, ast->unop.sub, sub_expected_type);

            if (!ast->unop.sub->type_info) break;

            TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_POINTER;
            ty->ptr.sub = ast->unop.sub->type_info;
            ast->type_info = ty;
            break;
        }
        }
        break;
    }
    case AST_BINARY_EXPR: {
        type_check_ast(a, ast->binop.left, NULL);
        type_check_ast(a, ast->binop.right, NULL);
        break;
    }
    default: break;
    }

    if (!ast->type_info)
    {
        // TODO: remove this, only temporary for debugging
        printf("undefined type: %u:%u\n", ast->loc.line, ast->loc.col);
    }

    if (res && ast->type_info && expected_type)
    {
        if (!exact_types(ast->type_info, expected_type))
        {
            compile_error(a->compiler, ast->loc, "wrong type");
            res = false;
        }
    }

    return res;
}

void analyze_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_ROOT: {
            scope_init(&ast->block.scope, array_size(ast->block.stmts), NULL);
            break;
        }
        case AST_PROC_DECL: {
            scope_init(
                &ast->proc.scope,
                array_size(ast->proc.stmts) + array_size(ast->proc.params),
                ast);
            break;
        }
        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
            register_symbol_ast(a, ast);
            break;
        }
        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
            symbol_check_ast(a, ast);
            type_check_ast(a, ast, NULL);
            break;
        }
        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_ROOT:
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
            break;
        }
        default: {
            register_symbol_ast(a, ast);
            symbol_check_ast(a, ast);
            type_check_ast(a, ast, NULL);
            break;
        }
        }
    }

    // Analyze children ASTs
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_ROOT: {
            array_push(a->scope_stack, &ast->block.scope);
            analyze_asts(a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->scope_stack);
            break;
        }
        case AST_PROC_DECL: {
            array_push(a->scope_stack, &ast->proc.scope);
            analyze_asts(a, ast->proc.stmts, array_size(ast->proc.stmts));
            array_pop(a->scope_stack);
            break;
        }
        default: break;
        }
    }
}

// }}}

// Printing errors {{{
void print_errors(Compiler *compiler)
{
    if (array_size(compiler->errors) > 0)
    {
        for (Error *err = compiler->errors;
             err != compiler->errors + array_size(compiler->errors);
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
// }}}

int main(int argc, char **argv)
{
    Compiler *compiler = malloc(sizeof(*compiler));
    compiler_init(compiler);

    if (argc <= 1)
    {
        printf("Usage: %s <source file>\n", argv[0]);
        exit(1);
    }

    if (argc == 2)
    {
        SourceFile *file = bump_alloc(&compiler->bump, sizeof(*file));
        source_file_init(
            file,
            compiler,
            (String){.buf = argv[1], .length = strlen(argv[1])});

        Lexer *lexer = bump_alloc(&compiler->bump, sizeof(*lexer));
        lex_file(lexer, compiler, file);
        print_errors(compiler);

        Parser *parser = bump_alloc(&compiler->bump, sizeof(*parser));
        parse_file(parser, compiler, lexer);
        print_errors(compiler);

        Analyzer *analyzer = bump_alloc(&compiler->bump, sizeof(*analyzer));
        memset(analyzer, 0, sizeof(*analyzer));
        analyzer->compiler = compiler;
        analyze_asts(analyzer, parser->ast, 1);
        print_errors(compiler);
    }
    else
    {
        printf("Invalid compiler usage\n");
        exit(1);
    }

    compiler_destroy(compiler);
    free(compiler);
    return 0;
}
