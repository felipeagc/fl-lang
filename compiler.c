#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include <llvm-c/Analysis.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

#ifdef __unix__
#include <limits.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <sys/types.h>
#include <sys/wait.h>
#endif

// Defines {{{
#define LANG_FILE_EXTENSION ".lang"
#define TMP_OBJECT_NAME "tmp.o"
// }}}

// Forward declarations {{{
typedef struct SourceFile SourceFile;
//}}}

// Filesystem functions {{{
char *get_absolute_path(char *relative_path)
{
#ifdef __unix__
    return realpath(relative_path, NULL);
#else
#error OS not supported
#endif
}

char *get_file_dir(char *path)
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
#ifdef __linux__
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
#else
#error OS not supported
#endif
}
// }}}

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

#define CSTR(lit)                                                              \
    ((String){                                                                 \
        .buf = (lit),                                                          \
        .length = strlen(lit),                                                 \
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

String bump_str_join(BumpAlloc *alloc, String a, String b)
{
    String s;
    s.length = a.length + b.length;
    s.buf = bump_alloc(alloc, s.length);
    memcpy(s.buf, a.buf, a.length);
    memcpy(s.buf + a.length, b.buf, b.length);
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
    HashMap files;
    struct LLContext *backend;
    String compiler_path;
    String compiler_dir;
    String corelib_dir;
} Compiler;

void compiler_init(Compiler *compiler)
{
    memset(compiler, 0, sizeof(*compiler));
    bump_init(&compiler->bump, 1 << 16);
    hash_init(&compiler->files, 521);

    char *c_compiler_path = get_exe_path();
    char *c_compiler_dir = get_file_dir(c_compiler_path);
    compiler->compiler_path = CSTR(c_compiler_path);
    compiler->compiler_dir = CSTR(c_compiler_dir);
    compiler->corelib_dir =
        bump_str_join(&compiler->bump, compiler->compiler_dir, STR("core/"));
}

void compiler_destroy(Compiler *compiler)
{
    hash_destroy(&compiler->files);
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
    struct Ast *root;
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
    TOKEN_PIPE,
    TOKEN_SLASH,
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_PERCENT,
    TOKEN_HAT,
    TOKEN_TILDE,

    TOKEN_LSHIFT,
    TOKEN_RSHIFT,

    TOKEN_DOT,
    TOKEN_ELLIPSIS,
    TOKEN_COMMA,

    TOKEN_NOT,    // !
    TOKEN_ASSIGN, // =

    TOKEN_EQUAL,     // ==
    TOKEN_NOTEQ,     // !=
    TOKEN_LESS,      // <
    TOKEN_LESSEQ,    // <=
    TOKEN_GREATER,   // >
    TOKEN_GREATEREQ, // >=

    TOKEN_PLUSEQ,  // +=
    TOKEN_MINUSEQ, // -=
    TOKEN_MULEQ,   // *=
    TOKEN_DIVEQ,   // /=
    TOKEN_MODEQ,   // %=

    TOKEN_ANDEQ, // &=
    TOKEN_OREQ,  // |=
    TOKEN_XOREQ, // ^=

    TOKEN_LSHIFTEQ, // <<=
    TOKEN_RSHIFTEQ, // >>=

    TOKEN_AND, // &&
    TOKEN_OR,  // ||

    TOKEN_IDENT,
    TOKEN_INTRINSIC,
    TOKEN_STRING_LIT,
    TOKEN_CSTRING_LIT,
    TOKEN_CHAR_LIT,
    TOKEN_PROC,
    TOKEN_CAST,
    TOKEN_IMPORT,
    TOKEN_TYPEDEF,
    TOKEN_STRUCT,
    TOKEN_UNION,
    TOKEN_ENUM,
    TOKEN_FOR,
    TOKEN_WHILE,
    TOKEN_SWITCH,
    TOKEN_BREAK,
    TOKEN_CONTINUE,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_RETURN,
    TOKEN_CONST,
    TOKEN_VAR,

    TOKEN_INT_LIT,
    TOKEN_FLOAT_LIT,

    TOKEN_U8,
    TOKEN_U16,
    TOKEN_U32,
    TOKEN_U64,

    TOKEN_I8,
    TOKEN_I16,
    TOKEN_I32,
    TOKEN_I64,

    TOKEN_CHAR,
    TOKEN_FLOAT,
    TOKEN_DOUBLE,

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
    [TOKEN_PIPE] = "|",
    [TOKEN_SLASH] = "/",
    [TOKEN_PLUS] = "+",
    [TOKEN_MINUS] = "-",
    [TOKEN_PERCENT] = "%",
    [TOKEN_HAT] = "^",
    [TOKEN_TILDE] = "~",

    [TOKEN_LSHIFT] = "<<",
    [TOKEN_RSHIFT] = ">>",

    [TOKEN_DOT] = ".",
    [TOKEN_ELLIPSIS] = "...",
    [TOKEN_COMMA] = ",",

    [TOKEN_NOT] = "!",
    [TOKEN_ASSIGN] = "=",

    [TOKEN_EQUAL] = "==",
    [TOKEN_NOTEQ] = "!=",
    [TOKEN_LESS] = "<",
    [TOKEN_LESSEQ] = "<=",
    [TOKEN_GREATER] = ">",
    [TOKEN_GREATEREQ] = ">=",

    [TOKEN_PLUSEQ] = "+=",
    [TOKEN_MINUSEQ] = "-=",
    [TOKEN_MULEQ] = "*=",
    [TOKEN_DIVEQ] = "/=",
    [TOKEN_MODEQ] = "%=",

    [TOKEN_ANDEQ] = "&=",
    [TOKEN_OREQ] = "|=",
    [TOKEN_XOREQ] = "^=",

    [TOKEN_LSHIFTEQ] = "<<=",
    [TOKEN_RSHIFTEQ] = ">>=",

    [TOKEN_AND] = "&&",
    [TOKEN_OR] = "||",

    [TOKEN_IDENT] = "identifier",
    [TOKEN_INTRINSIC] = "intrinsic",
    [TOKEN_STRING_LIT] = "string literal",
    [TOKEN_CSTRING_LIT] = "c-string literal",
    [TOKEN_CHAR_LIT] = "char literal",
    [TOKEN_PROC] = "proc",
    [TOKEN_CAST] = "cast",
    [TOKEN_IMPORT] = "import",
    [TOKEN_TYPEDEF] = "typedef",
    [TOKEN_STRUCT] = "struct",
    [TOKEN_UNION] = "union",
    [TOKEN_ENUM] = "enum",
    [TOKEN_FOR] = "for",
    [TOKEN_WHILE] = "while",
    [TOKEN_SWITCH] = "switch",
    [TOKEN_BREAK] = "break",
    [TOKEN_CONTINUE] = "continue",
    [TOKEN_IF] = "if",
    [TOKEN_ELSE] = "else",
    [TOKEN_RETURN] = "return",
    [TOKEN_CONST] = "const",
    [TOKEN_VAR] = "var",

    [TOKEN_INT_LIT] = "integer literal",
    [TOKEN_FLOAT_LIT] = "float literal",

    [TOKEN_U8] = "u8",
    [TOKEN_U16] = "u16",
    [TOKEN_U32] = "u32",
    [TOKEN_U64] = "u64",

    [TOKEN_I8] = "i8",
    [TOKEN_I16] = "i16",
    [TOKEN_I32] = "i32",
    [TOKEN_I64] = "i64",

    [TOKEN_CHAR] = "char",
    [TOKEN_FLOAT] = "float",
    [TOKEN_DOUBLE] = "double",

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
        char chr;
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
        PRINT_TOKEN_TYPE(TOKEN_PIPE);
        PRINT_TOKEN_TYPE(TOKEN_SLASH);
        PRINT_TOKEN_TYPE(TOKEN_PLUS);
        PRINT_TOKEN_TYPE(TOKEN_MINUS);
        PRINT_TOKEN_TYPE(TOKEN_PERCENT);
        PRINT_TOKEN_TYPE(TOKEN_HAT);
        PRINT_TOKEN_TYPE(TOKEN_TILDE);

        PRINT_TOKEN_TYPE(TOKEN_RSHIFT);
        PRINT_TOKEN_TYPE(TOKEN_LSHIFT);

        PRINT_TOKEN_TYPE(TOKEN_DOT);
        PRINT_TOKEN_TYPE(TOKEN_ELLIPSIS);
        PRINT_TOKEN_TYPE(TOKEN_COMMA);

        PRINT_TOKEN_TYPE(TOKEN_NOT);
        PRINT_TOKEN_TYPE(TOKEN_ASSIGN);

        PRINT_TOKEN_TYPE(TOKEN_EQUAL);
        PRINT_TOKEN_TYPE(TOKEN_NOTEQ);
        PRINT_TOKEN_TYPE(TOKEN_LESS);
        PRINT_TOKEN_TYPE(TOKEN_LESSEQ);
        PRINT_TOKEN_TYPE(TOKEN_GREATER);
        PRINT_TOKEN_TYPE(TOKEN_GREATEREQ);

        PRINT_TOKEN_TYPE(TOKEN_PLUSEQ);
        PRINT_TOKEN_TYPE(TOKEN_MINUSEQ);
        PRINT_TOKEN_TYPE(TOKEN_MULEQ);
        PRINT_TOKEN_TYPE(TOKEN_DIVEQ);
        PRINT_TOKEN_TYPE(TOKEN_MODEQ);

        PRINT_TOKEN_TYPE(TOKEN_ANDEQ);
        PRINT_TOKEN_TYPE(TOKEN_OREQ);
        PRINT_TOKEN_TYPE(TOKEN_XOREQ);

        PRINT_TOKEN_TYPE(TOKEN_RSHIFTEQ);
        PRINT_TOKEN_TYPE(TOKEN_LSHIFTEQ);

        PRINT_TOKEN_TYPE(TOKEN_AND);
        PRINT_TOKEN_TYPE(TOKEN_OR);

        PRINT_TOKEN_TYPE(TOKEN_INT_LIT);
        PRINT_TOKEN_TYPE(TOKEN_FLOAT_LIT);

        PRINT_TOKEN_TYPE(TOKEN_IDENT);
        PRINT_TOKEN_TYPE(TOKEN_INTRINSIC);
        PRINT_TOKEN_TYPE(TOKEN_PROC);
        PRINT_TOKEN_TYPE(TOKEN_CAST);
        PRINT_TOKEN_TYPE(TOKEN_IMPORT);
        PRINT_TOKEN_TYPE(TOKEN_TYPEDEF);
        PRINT_TOKEN_TYPE(TOKEN_STRUCT);
        PRINT_TOKEN_TYPE(TOKEN_UNION);
        PRINT_TOKEN_TYPE(TOKEN_ENUM);
        PRINT_TOKEN_TYPE(TOKEN_FOR);
        PRINT_TOKEN_TYPE(TOKEN_WHILE);
        PRINT_TOKEN_TYPE(TOKEN_SWITCH);
        PRINT_TOKEN_TYPE(TOKEN_BREAK);
        PRINT_TOKEN_TYPE(TOKEN_CONTINUE);
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

        PRINT_TOKEN_TYPE(TOKEN_CHAR);
        PRINT_TOKEN_TYPE(TOKEN_FLOAT);
        PRINT_TOKEN_TYPE(TOKEN_DOUBLE);

        PRINT_TOKEN_TYPE(TOKEN_VOID);
        PRINT_TOKEN_TYPE(TOKEN_NULL);

        PRINT_TOKEN_TYPE(TOKEN_BOOL);
        PRINT_TOKEN_TYPE(TOKEN_FALSE);
        PRINT_TOKEN_TYPE(TOKEN_TRUE);

        PRINT_TOKEN_TYPE(TOKEN_STRING_LIT);
        PRINT_TOKEN_TYPE(TOKEN_CSTRING_LIT);
        PRINT_TOKEN_TYPE(TOKEN_CHAR_LIT);
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
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_MULEQ;
        }
        break;
    }
    case '&': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_AMPERSAND;
        if (lex_peek(l, 0) == '&')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_AND;
        }
        else if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_ANDEQ;
        }
        break;
    }
    case '|': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_PIPE;
        if (lex_peek(l, 0) == '|')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_OR;
        }
        else if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_XOREQ;
        }
        break;
    }
    case '/': {
        if (lex_peek(l, 1) == '/')
        {
            // Comment
            lex_next(l, 2);

            while (lex_peek(l, 0) != '\n' && !lex_is_at_end(l))
            {
                lex_next(l, 1);
            }

            break;
        }
        if (lex_peek(l, 1) == '*')
        {
            // Multiline comment
            lex_next(l, 2);

            while ((lex_peek(l, 0) != '*' || lex_peek(l, 1) != '/') &&
                   !lex_is_at_end(l))
            {
                if (lex_peek(l, 0) == '\n')
                {
                    ++l->line;
                    l->col = 0;
                }
                lex_next(l, 1);
            }

            if (!lex_is_at_end(l))
            {
                lex_next(l, 2);
            }
            else
            {
                compile_error(l->compiler, tok.loc, "unclosed comment");
            }

            break;
        }

        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_SLASH;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_DIVEQ;
            break;
        }
        break;
    }
    case '+': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_PLUS;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_PLUSEQ;
        }
        break;
    }
    case '-': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_MINUS;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_MINUSEQ;
        }
        break;
    }
    case '%': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_PERCENT;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_MODEQ;
        }
        break;
    }
    case '^': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_HAT;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_XOREQ;
        }
        break;
    }
    case '~': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_TILDE;
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
        if (lex_peek(l, 0) == '.' && lex_peek(l, 1) == '.')
        {
            lex_next(l, 2);
            tok.type = TOKEN_ELLIPSIS;
            tok.loc.length = 3;
        }
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
    case '!': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_NOT;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_NOTEQ;
        }
        break;
    }
    case '>': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_GREATER;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_GREATEREQ;
        }
        else if (lex_peek(l, 0) == '>')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_RSHIFT;
            if (lex_peek(l, 0) == '=')
            {
                ++tok.loc.length;
                lex_next(l, 1);
                tok.type = TOKEN_RSHIFTEQ;
            }
        }
        break;
    }
    case '<': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_LESS;
        if (lex_peek(l, 0) == '=')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_LESSEQ;
        }
        else if (lex_peek(l, 0) == '<')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_LSHIFT;

            if (lex_peek(l, 0) == '=')
            {
                ++tok.loc.length;
                lex_next(l, 1);
                tok.type = TOKEN_LSHIFTEQ;
            }
        }
        break;
    }
    case '@': {
        tok.loc.length = 1;
        while (is_alphanum(tok.loc.buf[tok.loc.length]))
        {
            tok.loc.length++;
        }

        l->col += tok.loc.length;

        lex_next(l, tok.loc.length);

        tok.type = TOKEN_INTRINSIC;
        tok.str.buf = tok.loc.buf + 1;
        tok.str.length = tok.loc.length - 1;
        break;
    }
    case '\'': {
        tok.type = TOKEN_CHAR_LIT;

        lex_next(l, 1);
        ++tok.loc.length;

        tok.chr = lex_next(l, 1);
        ++tok.loc.length;

        ++tok.loc.length;
        if (lex_next(l, 1) != '\'' || lex_is_at_end(l))
        {
            compile_error(l->compiler, tok.loc, "unclosed char literal");
            tok.loc.length = 0;
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
                tok.type = TOKEN_CSTRING_LIT;
                tok.loc.length = 2;
                lex_next(l, 2);
            }
            else
            {
                tok.type = TOKEN_STRING_LIT;
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
                    switch (n)
                    {
                    case 'a': n = '\a'; break;
                    case 'b': n = '\b'; break;
                    case 'f': n = '\f'; break;
                    case 'n': n = '\n'; break;
                    case 'r': n = '\r'; break;
                    case 't': n = '\t'; break;
                    case 'v': n = '\v'; break;
                    case '0': n = '\0'; break;
                    case '?': n = '\?'; break;
                    case '"': n = '\"'; break;
                    case '\'': n = '\''; break;
                    case '\\': n = '\\'; break;
                    default: break;
                    }
                }

                array_push(tok.str.buf, n);
            }

            if (tok.type == TOKEN_CSTRING_LIT)
            {
                array_push(tok.str.buf, '\0');
            }

            tok.str.length = array_size(tok.str.buf);

            ++tok.loc.length;
            if (lex_next(l, 1) != '\"' || lex_is_at_end(l))
            {
                compile_error(l->compiler, tok.loc, "unclosed string");
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
            LEX_MATCH_STR("char", TOKEN_CHAR);
            LEX_MATCH_STR("float", TOKEN_FLOAT);
            LEX_MATCH_STR("double", TOKEN_DOUBLE);
            LEX_MATCH_STR("void", TOKEN_VOID);
            LEX_MATCH_STR("null", TOKEN_NULL);
            LEX_MATCH_STR("bool", TOKEN_BOOL);
            LEX_MATCH_STR("true", TOKEN_TRUE);
            LEX_MATCH_STR("false", TOKEN_FALSE);

            LEX_MATCH_STR("var", TOKEN_VAR);
            LEX_MATCH_STR("const", TOKEN_CONST);
            LEX_MATCH_STR("proc", TOKEN_PROC);
            LEX_MATCH_STR("cast", TOKEN_CAST);
            LEX_MATCH_STR("import", TOKEN_IMPORT);
            LEX_MATCH_STR("typedef", TOKEN_TYPEDEF);
            LEX_MATCH_STR("struct", TOKEN_STRUCT);
            LEX_MATCH_STR("union", TOKEN_UNION);
            LEX_MATCH_STR("enum", TOKEN_ENUM);
            LEX_MATCH_STR("if", TOKEN_IF);
            LEX_MATCH_STR("else", TOKEN_ELSE);
            LEX_MATCH_STR("while", TOKEN_WHILE);
            LEX_MATCH_STR("switch", TOKEN_SWITCH);
            LEX_MATCH_STR("break", TOKEN_BREAK);
            LEX_MATCH_STR("continue", TOKEN_CONTINUE);
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
                tok.type = TOKEN_FLOAT_LIT;
                tok.f64 = strtod(str, NULL);
            }
            else
            {
                tok.type = TOKEN_INT_LIT;
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
    TYPE_STRUCT,
    TYPE_POINTER,
    TYPE_ARRAY,
    TYPE_SLICE,
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_BOOL,
    TYPE_VOID,
    TYPE_NAMESPACE,
} TypeKind;

typedef struct TypeInfo
{
    TypeKind kind;
    LLVMTypeRef ref;
    bool can_change;

    union
    {
        struct
        {
            bool is_signed;
            uint32_t num_bits;
        } integer;
        struct
        {
            uint32_t num_bits;
        } floating;
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
            bool is_c_vararg;
            struct TypeInfo *return_type;
            /*array*/ struct TypeInfo *params;
        } proc;
        struct
        {
            /*array*/ struct TypeInfo **fields;
            struct Scope *scope;
        } structure;
    };
} TypeInfo;

TypeInfo *exact_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind != expected->kind) return NULL;

    switch (received->kind)
    {
    case TYPE_INT: {
        if (received->integer.is_signed != expected->integer.is_signed)
            return NULL;
        if (received->integer.num_bits != expected->integer.num_bits)
            return NULL;
        break;
    }
    case TYPE_FLOAT: {
        if (received->floating.num_bits != expected->floating.num_bits)
            return NULL;
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
    case TYPE_SLICE: {
        if (!exact_types(received->array.sub, expected->array.sub)) return NULL;
        break;
    }
    case TYPE_STRUCT: {
        if (array_size(received->structure.fields) !=
            array_size(expected->structure.fields))
            return NULL;

        size_t field_count = array_size(expected->structure.fields);
        for (size_t i = 0; i < field_count; ++i)
        {
            if (!exact_types(
                    received->structure.fields[i],
                    expected->structure.fields[i]))
            {
                return NULL;
            }
        }
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
    case TYPE_NAMESPACE: break;
    case TYPE_BOOL: break;
    case TYPE_VOID: break;
    case TYPE_TYPE: break;
    case TYPE_UNINITIALIZED: break;
    case TYPE_NONE: break;
    }

    return received;
}

TypeInfo *compatible_pointer_types_aux(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind == TYPE_POINTER && expected->kind == TYPE_POINTER)
    {
        return compatible_pointer_types_aux(
            received->ptr.sub, expected->ptr.sub);
    }
    else if (received->kind != TYPE_POINTER && expected->kind != TYPE_POINTER)
    {
        return received;
    }

    return NULL;
}

TypeInfo *compatible_pointer_types(TypeInfo *received, TypeInfo *expected)
{
    if (received->kind == TYPE_POINTER && expected->kind == TYPE_POINTER)
    {
        return compatible_pointer_types_aux(
            received->ptr.sub, expected->ptr.sub);
    }

    return NULL;
}

TypeInfo *common_numeric_type(TypeInfo *a, TypeInfo *b)
{
    TypeInfo *float_type = NULL;
    TypeInfo *other_type = NULL;
    if (a->kind == TYPE_FLOAT)
    {
        float_type = a;
        other_type = b;
    }
    else if (b->kind == TYPE_FLOAT)
    {
        float_type = b;
        other_type = a;
    }

    if (float_type && other_type->can_change)
    {
        return float_type;
    }

    if (a->can_change)
    {
        return b;
    }

    if (b->can_change)
    {
        return a;
    }

    return NULL;
}
// }}}

// AST {{{
typedef enum UnOpType {
    UNOP_DEREFERENCE,
    UNOP_ADDRESS,
    UNOP_NEG,
    UNOP_NOT,
} UnOpType;

typedef enum BinOpType {
    BINOP_ADD,
    BINOP_SUB,
    BINOP_MUL,
    BINOP_DIV,
    BINOP_MOD,

    BINOP_EQ,
    BINOP_NOTEQ,
    BINOP_LESS,
    BINOP_LESSEQ,
    BINOP_GREATER,
    BINOP_GREATEREQ,

    BINOP_AND,
    BINOP_OR,

    BINOP_BITOR,
    BINOP_BITXOR,
    BINOP_BITAND,

    BINOP_LSHIFT,
    BINOP_RSHIFT,
} BinOpType;

typedef enum IntrinsicType {
    INTRINSIC_SIZEOF,
    INTRINSIC_ALIGNOF,
} IntrinsicType;

typedef enum AstType {
    AST_UNINITIALIZED,
    AST_ROOT,
    AST_STRUCT,
    AST_PROC_DECL,
    AST_PROC_TYPE,
    AST_IMPORT,
    AST_BLOCK,
    AST_INTRINSIC_CALL,
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
    AST_SUBSCRIPT,
    AST_SUBSCRIPT_SLICE,
    AST_ARRAY_TYPE,
    AST_SLICE_TYPE,
    AST_EXPR_STMT,
    AST_ACCESS,
    AST_STRUCT_FIELD,
    AST_PROC_PARAM,
    AST_CAST,
    AST_IF,
    AST_WHILE,
    AST_FOR,
    AST_BREAK,
    AST_CONTINUE,
} AstType;

typedef struct AstValue
{
    bool is_lvalue;
    LLVMValueRef value;
} AstValue;

enum {
    PROC_FLAG_HAS_BODY = 1 << 1,
    PROC_FLAG_IS_C_VARARGS = 1 << 2,
};

typedef struct Ast
{
    AstType type;
    Location loc;
    TypeInfo *type_info;
    TypeInfo *as_type;
    struct Scope *sym_scope;
    struct Ast *alias_to;

    union
    {
        struct Ast *expr;
        struct
        {
            Token *tok;
        } primary;
        struct
        {
            String name;
            String path;
            String abs_path;
        } import;
        struct
        {
            struct Scope *scope;
            /*array*/ struct Ast *stmts;
        } block;
        struct
        {
            struct Scope *scope;
            String convention;
            String name;
            uint32_t flags;
            struct Ast *return_type;
            /*array*/ struct Ast *params;
            /*array*/ struct Ast *stmts;
            AstValue value;
        } proc;
        struct
        {
            struct Ast *cond_expr;
            struct Ast *cond_stmt;
            struct Ast *else_stmt;
        } if_stmt;
        struct
        {
            struct Ast *cond;
            struct Ast *stmt;
        } while_stmt;
        struct
        {
            struct Scope *scope;

            struct Ast *init;
            struct Ast *cond;
            struct Ast *inc;

            struct Ast *stmt;
        } for_stmt;
        struct
        {
            struct Scope *scope;
            /*array*/ struct Ast *fields;
        } structure;
        struct
        {
            struct Ast *expr;
            /*array*/ struct Ast *params;
        } proc_call;
        struct
        {
            IntrinsicType type;
            /*array*/ struct Ast *params;
        } intrinsic_call;
        struct
        {
            String name;
            struct Ast *type_expr;
        } type_def;
        struct
        {
            struct Ast *type_expr;
            struct Ast *value_expr;
        } cast;
        struct
        {
            String name;
            struct Ast *type_expr;
            struct Ast *value_expr;
            AstValue value;
        } decl;
        struct
        {
            String name;
            struct Ast *type_expr;
            struct Ast *value_expr;
            AstValue value;
        } proc_param;
        struct
        {
            size_t index;
            String name;
            struct Ast *type_expr;
            struct Ast *value_expr;
        } field;
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
            bool assign;
        } binop;
        struct
        {
            struct Ast *left;
            struct Ast *right;
        } subscript;
        struct
        {
            struct Ast *left;
            struct Ast *lower;
            struct Ast *upper;
        } subscript_slice;
        struct
        {
            struct Ast *size;
            struct Ast *sub;
        } array_type;
        struct
        {
            struct Ast *left;
            struct Ast *right;
        } access;
    };
} Ast;
// }}}

// Scope {{{
typedef enum ScopeType {
    SCOPE_DEFAULT,
    SCOPE_STRUCT,
} ScopeType;

typedef struct Scope
{
    ScopeType type;
    HashMap *map;
    struct Scope *parent;
    struct Ast *procedure;
    struct AstValue value;
} Scope;

void scope_init(
    Scope *scope,
    Compiler *compiler,
    ScopeType type,
    size_t size,
    struct Ast *procedure)
{
    memset(scope, 0, sizeof(*scope));
    scope->type = type;
    scope->map = bump_alloc(&compiler->bump, sizeof(*scope->map));
    hash_init(scope->map, size);
    scope->procedure = procedure;
}

void scope_set(Scope *scope, String name, struct Ast *decl)
{
    decl->sym_scope = scope;
    hash_set(scope->map, name, decl);
}

struct Ast *scope_get_local(Scope *scope, String name)
{
    return hash_get(scope->map, name);
}

struct Ast *get_symbol(Scope *scope, String name)
{
    struct Ast *sym = scope_get_local(scope, name);
    if (sym) return sym;

    if (scope->parent) return get_symbol(scope->parent, name);

    return NULL;
}

struct Ast *get_scope_procedure(Scope *scope)
{
    if (scope->procedure) return scope->procedure;

    if (scope->parent) return get_scope_procedure(scope->parent);

    return NULL;
}
// }}}

// Expression utility functions {{{
static inline Ast *get_inner_expr(Ast *ast)
{
    switch (ast->type)
    {
    case AST_PAREN_EXPR: return get_inner_expr(ast->expr);
    default: break;
    }

    return ast;
}

static bool is_expr_const(Scope *scope, Ast *ast)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_PROC_DECL:
                case AST_CONST_DECL: {
                    res = true;
                    break;
                }
                default: break;
                }
            }
            break;
        }
        default: res = true; break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        res = is_expr_const(scope, ast->expr);
        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF:
        case INTRINSIC_ALIGNOF: res = true; break;
        }
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE:
        case UNOP_ADDRESS: res = false; break;
        case UNOP_NOT:
        case UNOP_NEG: {
            res = is_expr_const(scope, ast->unop.sub);
            break;
        }
        }
        break;
    }
    case AST_BINARY_EXPR: {
        res = true;

        if (!is_expr_const(scope, ast->binop.left)) res = false;
        if (!is_expr_const(scope, ast->binop.right)) res = false;

        if (ast->binop.assign) res = false;

        switch (ast->binop.type)
        {
        case BINOP_AND:
        case BINOP_OR: res = false; break;

        case BINOP_ADD:
        case BINOP_SUB:
        case BINOP_MUL:
        case BINOP_DIV:
        case BINOP_MOD:

        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ:

        case BINOP_BITOR:
        case BINOP_BITXOR:
        case BINOP_BITAND:

        case BINOP_LSHIFT:
        case BINOP_RSHIFT: break;
        }
        break;
    }
    default: break;
    }

    return res;
}

static bool resolve_expr_int(Scope *scope, Ast *ast, int64_t *i64)
{
    bool res = false;
    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_INT_LIT: {
            *i64 = ast->primary.tok->i64;
            res = true;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_CONST_DECL: {
                    assert(sym->sym_scope);
                    res = resolve_expr_int(
                        sym->sym_scope, sym->decl.value_expr, i64);
                    break;
                }
                default: break;
                }
            }
            break;
        }
        default: break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        res = resolve_expr_int(scope, ast->expr, i64);
        break;
    }
    default: break;
    }

    return res;
}

static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast);

static TypeInfo *ast_as_type(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->as_type) return ast->as_type;

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_U8: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 8}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U16: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 16}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U32: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 32}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_U64: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = false, .num_bits = 64}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_CHAR:
        case TOKEN_I8: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 8}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I16: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 16}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I32: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 32}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_I64: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_FLOAT: {
            static TypeInfo ty = {.kind = TYPE_FLOAT, .floating.num_bits = 32};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_DOUBLE: {
            static TypeInfo ty = {.kind = TYPE_FLOAT, .floating.num_bits = 64};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_BOOL: {
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_VOID};
            ast->as_type = &ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym && sym->type == AST_TYPEDEF)
            {
                assert(sym->sym_scope);
                if (ast_as_type(
                        compiler, sym->sym_scope, sym->type_def.type_expr))
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
        ast->as_type = ast_as_type(compiler, scope, ast->expr);
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast_as_type(compiler, scope, ast->unop.sub))
            {
                TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
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
    case AST_ARRAY_TYPE: {
        int64_t size = 0;
        bool resolves = resolve_expr_int(scope, ast->array_type.size, &size);
        bool res = true;

        if (!ast_as_type(compiler, scope, ast->array_type.sub)) res = false;

        if (!resolves)
        {
            compile_error(
                compiler,
                ast->array_type.size->loc,
                "expression does not resolve to integer");
            res = false;
        }

        if (resolves && size <= 0)
        {
            compile_error(
                compiler,
                ast->array_type.size->loc,
                "array size must be larger than zero");
            res = false;
        }

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_ARRAY;
            ty->array.sub = ast->array_type.sub->as_type;
            ty->array.size = size;
            ast->as_type = ty;
        }
        break;
    }
    case AST_SLICE_TYPE: {
        bool res = true;

        if (!ast_as_type(compiler, scope, ast->array_type.sub)) res = false;

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_SLICE;
            ty->array.sub = ast->array_type.sub->as_type;
            ast->as_type = ty;
        }
        break;
    }
    case AST_STRUCT: {
        TypeInfo **fields = NULL;
        bool res = true;

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            if (!ast_as_type(compiler, scope, field->field.type_expr))
            {
                res = false;
            }
            array_push(fields, field->field.type_expr->as_type);
        }

        if (res)
        {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(TypeInfo));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_STRUCT;
            ty->structure.fields = fields;
            ty->structure.scope = ast->structure.scope;
            ast->as_type = ty;
        }
        break;
    }
    case AST_PROC_TYPE: {
        TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            array_push(
                ty->proc.params,
                *ast_as_type(compiler, scope, param->decl.type_expr));
        }

        ty->proc.return_type =
            ast_as_type(compiler, scope, ast->proc.return_type);

        TypeInfo *ptr_ty = bump_alloc(&compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        ast->as_type = ptr_ty;
        break;
    }
    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            ast->as_type =
                ast_as_type(compiler, accessed_scope, ast->access.right);
        }
        break;
    }
    default: break;
    }

    return ast->as_type;
}

static void get_ast_type(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->type_info && !ast->type_info->can_change) return;

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
        case TOKEN_CHAR:
        case TOKEN_FLOAT:
        case TOKEN_DOUBLE:
        case TOKEN_BOOL:
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_TYPE};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_NULL: {
            static TypeInfo void_ty = {.kind = TYPE_VOID};
            static TypeInfo void_ptr_ty = {.kind = TYPE_POINTER,
                                           .ptr.sub = &void_ty};
            ast->type_info = &void_ptr_ty;
            break;
        }
        case TOKEN_TRUE:
        case TOKEN_FALSE: {
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_INT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .can_change = true,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_FLOAT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_FLOAT,
                .floating.num_bits = 64,
                .can_change = true,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_CSTRING_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            static TypeInfo ty = {
                .kind = TYPE_POINTER,
                .ptr.sub = &i8_ty,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_CHAR_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            ast->type_info = &i8_ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_VAR_DECL:
                case AST_CONST_DECL: {
                    ast_as_type(compiler, sym->sym_scope, sym->decl.type_expr);
                    ast->type_info = sym->decl.type_expr->as_type;
                    break;
                }
                case AST_PROC_PARAM: {
                    ast_as_type(
                        compiler, sym->sym_scope, sym->proc_param.type_expr);
                    ast->type_info = sym->proc_param.type_expr->as_type;
                    break;
                }
                case AST_STRUCT_FIELD: {
                    ast_as_type(compiler, sym->sym_scope, sym->field.type_expr);
                    ast->type_info = sym->field.type_expr->as_type;
                    break;
                }
                case AST_PROC_DECL: {
                    get_ast_type(compiler, sym->sym_scope, sym);
                    ast->type_info = sym->type_info;
                    break;
                }
                case AST_IMPORT: {
                    static TypeInfo namespace_ty = {.kind = TYPE_NAMESPACE};
                    ast->type_info = &namespace_ty;
                    break;
                }
                case AST_TYPEDEF: {
                    static TypeInfo ty_ty = {.kind = TYPE_TYPE};
                    ast->type_info = &ty_ty;
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
        get_ast_type(compiler, scope, ast->expr);
        ast->type_info = ast->expr->type_info;
        break;
    }
    case AST_PROC_CALL: {
        get_ast_type(compiler, scope, ast->proc_call.expr);

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;
        if (proc_ptr_ty && proc_ptr_ty->kind == TYPE_POINTER &&
            proc_ptr_ty->ptr.sub->kind == TYPE_PROC)
        {
            ast->type_info = proc_ptr_ty->ptr.sub->proc.return_type;
        }
        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            static TypeInfo u64_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = false,
                .integer.num_bits = 64,
            };
            ast->type_info = &u64_ty;
            break;
        }
        case INTRINSIC_ALIGNOF: {
            static TypeInfo u64_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = false,
                .integer.num_bits = 64,
            };
            ast->type_info = &u64_ty;
            break;
        }
        }

        break;
    }
    case AST_CAST: {
        ast_as_type(compiler, scope, ast->cast.type_expr);
        ast->type_info = ast->cast.type_expr->as_type;

        break;
    }
    case AST_UNARY_EXPR: {
        get_ast_type(compiler, scope, ast->unop.sub);

        if (!ast->unop.sub->type_info)
        {
            break;
        }

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            if (ast->unop.sub->type_info->kind == TYPE_TYPE)
            {
                TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
                memset(ty, 0, sizeof(*ty));
                ty->kind = TYPE_TYPE;
                ast->type_info = ty;
                break;
            }

            if (ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                break;
            }

            ast->type_info = ast->unop.sub->type_info->ptr.sub;
            break;
        }
        case UNOP_ADDRESS: {
            TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_POINTER;
            ty->ptr.sub = ast->unop.sub->type_info;
            ast->type_info = ty;
            break;
        }
        case UNOP_NEG: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT)
            {
                break;
            }

            ast->type_info = ast->unop.sub->type_info;

            break;
        }
        case UNOP_NOT: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT &&
                ast->unop.sub->type_info->kind != TYPE_BOOL &&
                ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        }

        break;
    }
    case AST_BINARY_EXPR: {
        switch (ast->binop.type)
        {
        case BINOP_ADD:
        case BINOP_SUB:
        case BINOP_MUL:
        case BINOP_DIV:
        case BINOP_MOD: {
            get_ast_type(compiler, scope, ast->binop.left);
            get_ast_type(compiler, scope, ast->binop.right);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                break;
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT)
            {
                break;
            }

            ast->type_info = ast->binop.left->type_info;
            break;
        }
        case BINOP_LSHIFT:
        case BINOP_RSHIFT:
        case BINOP_BITOR:
        case BINOP_BITAND:
        case BINOP_BITXOR: {
            get_ast_type(compiler, scope, ast->binop.left);
            get_ast_type(compiler, scope, ast->binop.right);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                break;
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_BOOL)
            {
                break;
            }

            ast->type_info = ast->binop.left->type_info;
            break;
        }
        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ: {
            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        case BINOP_AND:
        case BINOP_OR: {
            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        }

        break;
    }
    case AST_SUBSCRIPT: {
        get_ast_type(compiler, scope, ast->subscript.left);

        if (!ast->subscript.left->type_info)
        {
            break;
        }

        if (ast->subscript.left->type_info->kind != TYPE_POINTER &&
            ast->subscript.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript.left->type_info->kind != TYPE_SLICE)
        {
            break;
        }

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info = ast->subscript.left->type_info->ptr.sub;
            break;
        }
        default: break;
        }
        break;
    }
    case AST_SUBSCRIPT_SLICE: {
        get_ast_type(compiler, scope, ast->subscript_slice.left);

        if (!ast->subscript_slice.left->type_info)
        {
            break;
        }

        if (ast->subscript_slice.left->type_info->kind != TYPE_POINTER &&
            ast->subscript_slice.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript_slice.left->type_info->kind != TYPE_SLICE)
        {
            break;
        }

        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript_slice.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info = ast->subscript_slice.left->type_info->ptr.sub;
            break;
        }
        default: break;
        }
        break;
    }
    case AST_ARRAY_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;
        break;
    }
    case AST_STRUCT: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;
        break;
    }
    case AST_ACCESS: {
        get_ast_type(compiler, scope, ast->access.left);

        if (!ast->access.left->type_info)
        {
            break;
        }

        if (ast->access.left->type_info->kind == TYPE_SLICE)
        {
            Ast *right = get_inner_expr(ast->access.right);
            if (right->type == AST_PRIMARY &&
                right->primary.tok->type == TOKEN_IDENT)
            {
                if (string_equals(right->primary.tok->str, STR("len")))
                {
                    static TypeInfo size_type = {.kind = TYPE_INT,
                                                 .integer.num_bits = 64};
                    ast->type_info = &size_type;
                    break;
                }
                else if (string_equals(right->primary.tok->str, STR("ptr")))
                {
                    ast->type_info = ast->access.right->type_info;

                    TypeInfo *ptr_ty =
                        bump_alloc(&compiler->bump, sizeof(*ptr_ty));
                    memset(ptr_ty, 0, sizeof(*ptr_ty));
                    ptr_ty->kind = TYPE_POINTER;
                    ptr_ty->ptr.sub = ast->access.left->type_info->array.sub;

                    ast->type_info = ptr_ty;
                    break;
                }
            }

            break;
        }

        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);

        if (accessed_scope)
        {
            get_ast_type(compiler, accessed_scope, ast->access.right);
            ast->type_info = ast->access.right->type_info;
        }

        break;
    }
    case AST_PROC_DECL: {
        TypeInfo *ty = bump_alloc(&compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            ast_as_type(compiler, scope, param->decl.type_expr);
            if (!param->decl.type_expr->as_type) return;
            array_push(ty->proc.params, *param->decl.type_expr->as_type);
        }

        ast_as_type(compiler, scope, ast->proc.return_type);
        if (!ast->proc.return_type->as_type) return;
        ty->proc.return_type = ast->proc.return_type->as_type;

        TypeInfo *ptr_ty = bump_alloc(&compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        ast->type_info = ptr_ty;
        break;
    }
    default: break;
    }
}

static Ast *get_aliased_expr(Compiler *compiler, Scope *scope, Ast *ast)
{
    if (ast->alias_to) return ast->alias_to;

    switch (ast->type)
    {
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym = get_symbol(scope, ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_IMPORT: ast->alias_to = sym; break;
                default: break;
                }
            }
            break;
        }
        default: break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        ast->alias_to = get_aliased_expr(compiler, scope, ast->expr);
        break;
    }
    case AST_ACCESS: {
        Scope *accessed_scope =
            get_expr_scope(compiler, scope, ast->access.left);
        if (accessed_scope)
        {
            ast->alias_to =
                get_aliased_expr(compiler, accessed_scope, ast->access.right);
        }
        break;
    }
    default: break;
    }

    return ast->alias_to;
}

static Scope *get_expr_scope(Compiler *compiler, Scope *scope, Ast *ast)
{
    Scope *accessed_scope = NULL;

    Ast *aliased = get_aliased_expr(compiler, scope, ast);
    if (aliased)
    {
        switch (aliased->type)
        {
        case AST_IMPORT: {
            SourceFile *file =
                hash_get(&compiler->files, aliased->import.abs_path);
            assert(file);
            accessed_scope = file->root->block.scope;
            break;
        }
        default: break;
        }
    }
    else
    {
        // Type based lookup
        get_ast_type(compiler, scope, ast);
        if (!ast->type_info) return NULL;

        if (ast->type_info->kind == TYPE_STRUCT)
        {
            accessed_scope = ast->type_info->structure.scope;
        }
        else if (
            ast->type_info->kind == TYPE_POINTER &&
            ast->type_info->ptr.sub->kind == TYPE_STRUCT)
        {
            accessed_scope = ast->type_info->ptr.sub->structure.scope;
        }
    }

    return accessed_scope;
}
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

bool parse_primary_expr(Parser *p, Ast *ast)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_IDENT:
    case TOKEN_INTRINSIC:
    case TOKEN_TRUE:
    case TOKEN_FALSE:
    case TOKEN_VOID:
    case TOKEN_NULL:
    case TOKEN_BOOL:
    case TOKEN_STRING_LIT:
    case TOKEN_CSTRING_LIT:
    case TOKEN_CHAR_LIT:
    case TOKEN_U8:
    case TOKEN_U16:
    case TOKEN_U32:
    case TOKEN_U64:
    case TOKEN_I8:
    case TOKEN_I16:
    case TOKEN_I32:
    case TOKEN_I64:
    case TOKEN_FLOAT:
    case TOKEN_CHAR:
    case TOKEN_DOUBLE:
    case TOKEN_INT_LIT:
    case TOKEN_FLOAT_LIT: {
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

bool parse_array_type(Parser *p, Ast *ast)
{
    bool res = true;

    switch (parser_peek(p, 0)->type)
    {
    case TOKEN_LBRACK: {
        parser_next(p, 1);
        ast->type = AST_SLICE_TYPE;

        if (parser_peek(p, 0)->type != TOKEN_RBRACK)
        {
            ast->type = AST_ARRAY_TYPE;

            Ast size = {.loc = parser_peek(p, 0)->loc};
            if (parse_expr(p, &size))
            {
                Location last_loc = parser_peek(p, -1)->loc;
                size.loc.length = last_loc.buf + last_loc.length - size.loc.buf;

                ast->array_type.size = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->array_type.size));
                *ast->array_type.size = size;
            }
            else
            {
                res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RBRACK)) res = false;

        Ast sub = {0};
        if (parse_expr(p, &sub))
        {
            ast->array_type.sub =
                bump_alloc(&p->compiler->bump, sizeof(*ast->array_type.sub));
            *ast->array_type.sub = sub;
        }
        else
        {
            res = false;
        }

        break;
    }
    default: {
        if (!parse_primary_expr(p, ast)) res = false;
        break;
    }
    }

    return res;
}

bool parse_proc_call(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_array_type(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LPAREN)
    {
        Ast expr = *ast;
        memset(&ast->proc_call, 0, sizeof(ast->proc_call));

        if (expr.type == AST_PRIMARY &&
            expr.primary.tok->type == TOKEN_INTRINSIC)
        {
            // Intrinsic call

            ast->type = AST_INTRINSIC_CALL;
            if (string_equals(expr.primary.tok->str, STR("sizeof")))
            {
                ast->intrinsic_call.type = INTRINSIC_SIZEOF;
            }
            else if (string_equals(expr.primary.tok->str, STR("alignof")))
            {
                ast->intrinsic_call.type = INTRINSIC_ALIGNOF;
            }
            else
            {
                compile_error(
                    p->compiler,
                    expr.loc,
                    "unknown intrinsic: '%.*s'",
                    (int)expr.primary.tok->str.length,
                    expr.primary.tok->str.buf);
                res = false;
            }

            if (!parser_consume(p, TOKEN_LPAREN)) res = false;

            while (parser_peek(p, 0)->type != TOKEN_RPAREN &&
                   !parser_is_at_end(p))
            {
                Ast param = {0};
                if (parse_expr(p, &param))
                    array_push(ast->intrinsic_call.params, param);
                else
                    res = false;

                if (parser_peek(p, 0)->type != TOKEN_RPAREN)
                {
                    if (!parser_consume(p, TOKEN_COMMA)) res = false;
                }
            }

            if (!parser_consume(p, TOKEN_RPAREN)) res = false;

            break;
        }

        // Proc call

        ast->type = AST_PROC_CALL;

        ast->proc_call.expr =
            bump_alloc(&p->compiler->bump, sizeof(*ast->proc_call.expr));
        *ast->proc_call.expr = expr;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN && !parser_is_at_end(p))
        {
            Ast param = {0};
            if (parse_expr(p, &param))
                array_push(ast->proc_call.params, param);
            else
                res = false;

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;
    }

    return res;
}

bool parse_subscript(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_proc_call(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_LBRACK)
    {
        Ast expr = *ast;

        parser_next(p, 1);

        Ast lower = {0};
        if (!parse_expr(p, &lower)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_COLON)
        {
            parser_next(p, 1);

            // Subscript slice
            Ast upper = {0};
            if (!parse_expr(p, &upper)) res = false;

            if (!parser_consume(p, TOKEN_RBRACK)) res = false;

            if (res)
            {
                ast->type = AST_SUBSCRIPT_SLICE;

                ast->subscript_slice.left = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.left));
                *ast->subscript_slice.left = expr;

                ast->subscript_slice.lower = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript_slice.lower));
                *ast->subscript_slice.lower = lower;

                ast->subscript_slice.upper = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript_slice.upper));
                *ast->subscript_slice.upper = upper;
            }
        }
        else
        {
            // Regular subscript
            if (!parser_consume(p, TOKEN_RBRACK)) res = false;

            if (res)
            {
                ast->type = AST_SUBSCRIPT;
                ast->subscript.left = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.left));
                *ast->subscript.left = expr;
                ast->subscript.right = bump_alloc(
                    &p->compiler->bump, sizeof(*ast->subscript.right));
                *ast->subscript.right = lower;
            }
        }
    }

    return res;
}

bool parse_access(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_subscript(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while (parser_peek(p, 0)->type == TOKEN_DOT)
    {
        Ast expr = *ast;
        memset(&ast->access, 0, sizeof(ast->access));

        parser_next(p, 1);
        ast->type = AST_ACCESS;
        ast->access.left =
            bump_alloc(&p->compiler->bump, sizeof(*ast->access.left));
        *ast->access.left = expr;

        Ast right = {0};
        right.loc = parser_peek(p, 0)->loc;
        if (parse_subscript(p, &right))
        {
            Location last_loc = parser_peek(p, -1)->loc;
            right.loc.length = last_loc.buf + last_loc.length - right.loc.buf;

            ast->access.right =
                bump_alloc(&p->compiler->bump, sizeof(*ast->access.right));
            *ast->access.right = right;
        }
        else
        {
            res = false;
        }
    }

    return res;
}

bool parse_unary_expr(Parser *p, Ast *ast)
{
    bool res = true;
    Token *tok = parser_peek(p, 0);

    switch (tok->type)
    {
    case TOKEN_MINUS:
    case TOKEN_NOT:
    case TOKEN_ASTERISK:
    case TOKEN_AMPERSAND: {
        parser_next(p, 1);

        ast->type = AST_UNARY_EXPR;
        if (tok->type == TOKEN_ASTERISK) ast->unop.type = UNOP_DEREFERENCE;
        if (tok->type == TOKEN_AMPERSAND) ast->unop.type = UNOP_ADDRESS;
        if (tok->type == TOKEN_MINUS) ast->unop.type = UNOP_NEG;
        if (tok->type == TOKEN_NOT) ast->unop.type = UNOP_NOT;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_unary_expr(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->unop.sub = right;

        break;
    }
    case TOKEN_STRUCT: {
        ast->type = AST_STRUCT;
        parser_next(p, 1);

        if (!parser_consume(p, TOKEN_LCURLY)) res = false;

        ast->structure.fields = NULL;

        while (parser_peek(p, 0)->type != TOKEN_RCURLY)
        {
            Ast field = {0};
            field.type = AST_STRUCT_FIELD;

            Token *name_tok = parser_consume(p, TOKEN_IDENT);
            if (!name_tok)
                res = false;
            else
                field.field.name = name_tok->str;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            Ast type = {0};
            if (parse_expr(p, &type))
            {
                field.field.type_expr =
                    bump_alloc(&p->compiler->bump, sizeof(Ast));
                *field.field.type_expr = type;
            }
            else
            {
                res = false;
            }

            if (res)
            {
                field.field.index = array_size(ast->structure.fields);
                array_push(ast->structure.fields, field);
            }

            if (parser_peek(p, 0)->type == TOKEN_RCURLY)
            {
                break;
            }

            if (!parser_consume(p, TOKEN_COMMA)) res = false;
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }
    case TOKEN_CAST: {
        ast->type = AST_CAST;
        parser_next(p, 1);

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        Ast type = {0};
        if (parse_expr(p, &type))
        {
            ast->cast.type_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->cast.type_expr = type;
        }
        else
        {
            res = false;
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        Ast value = {0};
        if (parse_expr(p, &value))
        {
            ast->cast.value_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->cast.value_expr = value;
        }
        else
        {
            res = false;
        }

        break;
    }
    case TOKEN_PROC: {
        parser_next(p, 1);

        ast->type = AST_PROC_TYPE;

        if (!parser_consume(p, TOKEN_ASTERISK)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
            ast->proc.convention = convention_tok->str;
        }

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        while (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->proc.flags |= PROC_FLAG_IS_C_VARARGS;
                break;
            }

            Ast param = {0};
            param.type = AST_PROC_PARAM;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                param.proc_param.name = ident_tok->str;

            if (ident_tok) param.loc = ident_tok->loc;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr)) res = false;

            array_push(ast->proc.params, param);

            if (parser_peek(p, 0)->type != TOKEN_RPAREN)
            {
                if (!parser_consume(p, TOKEN_COMMA)) res = false;
            }
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->proc.return_type = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->proc.return_type)) res = false;

        break;
    }
    default: {
        res = parse_access(p, ast);
        break;
    }
    }

    return res;
}

bool parse_multiplication(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_unary_expr(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_ASTERISK) ||
           (parser_peek(p, 0)->type == TOKEN_SLASH) ||
           (parser_peek(p, 0)->type == TOKEN_PERCENT))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_unary_expr(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_ASTERISK: ast->binop.type = BINOP_MUL; break;
        case TOKEN_SLASH: ast->binop.type = BINOP_DIV; break;
        case TOKEN_PERCENT: ast->binop.type = BINOP_MOD; break;
        default: break;
        }
    }

    return res;
}

bool parse_addition(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_multiplication(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PLUS) ||
           (parser_peek(p, 0)->type == TOKEN_MINUS))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_multiplication(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_PLUS: ast->binop.type = BINOP_ADD; break;
        case TOKEN_MINUS: ast->binop.type = BINOP_SUB; break;
        default: break;
        }
    }

    return res;
}

bool parse_bitshift(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_addition(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_RSHIFT) ||
           (parser_peek(p, 0)->type == TOKEN_LSHIFT))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_addition(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_RSHIFT: ast->binop.type = BINOP_RSHIFT; break;
        case TOKEN_LSHIFT: ast->binop.type = BINOP_LSHIFT; break;
        default: break;
        }
    }

    return res;
}

bool parse_bitwise(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_bitshift(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PIPE) ||
           (parser_peek(p, 0)->type == TOKEN_AMPERSAND) ||
           (parser_peek(p, 0)->type == TOKEN_HAT))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_bitshift(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_PIPE: ast->binop.type = BINOP_BITOR; break;
        case TOKEN_AMPERSAND: ast->binop.type = BINOP_BITAND; break;
        case TOKEN_HAT: ast->binop.type = BINOP_BITXOR; break;
        default: break;
        }
    }

    return res;
}

bool parse_comparison(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_bitwise(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_EQUAL) ||
           (parser_peek(p, 0)->type == TOKEN_NOTEQ) ||
           (parser_peek(p, 0)->type == TOKEN_LESS) ||
           (parser_peek(p, 0)->type == TOKEN_LESSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_GREATER) ||
           (parser_peek(p, 0)->type == TOKEN_GREATEREQ))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_bitwise(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_EQUAL: ast->binop.type = BINOP_EQ; break;
        case TOKEN_NOTEQ: ast->binop.type = BINOP_NOTEQ; break;
        case TOKEN_LESS: ast->binop.type = BINOP_LESS; break;
        case TOKEN_LESSEQ: ast->binop.type = BINOP_LESSEQ; break;
        case TOKEN_GREATER: ast->binop.type = BINOP_GREATER; break;
        case TOKEN_GREATEREQ: ast->binop.type = BINOP_GREATEREQ; break;
        default: break;
        }
    }

    return res;
}

bool parse_logical(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_comparison(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_AND) ||
           (parser_peek(p, 0)->type == TOKEN_OR))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_comparison(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        switch (op_tok->type)
        {
        case TOKEN_AND: ast->binop.type = BINOP_AND; break;
        case TOKEN_OR: ast->binop.type = BINOP_OR; break;
        default: break;
        }
    }

    return res;
}

bool parse_op_assign(Parser *p, Ast *ast)
{
    bool res = true;

    if (!parse_logical(p, ast)) res = false;
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;

    while ((parser_peek(p, 0)->type == TOKEN_PLUSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MINUSEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MULEQ) ||
           (parser_peek(p, 0)->type == TOKEN_DIVEQ) ||
           (parser_peek(p, 0)->type == TOKEN_MODEQ) ||
           (parser_peek(p, 0)->type == TOKEN_ANDEQ) ||
           (parser_peek(p, 0)->type == TOKEN_OREQ) ||
           (parser_peek(p, 0)->type == TOKEN_XOREQ) ||
           (parser_peek(p, 0)->type == TOKEN_LSHIFTEQ) ||
           (parser_peek(p, 0)->type == TOKEN_RSHIFTEQ))
    {
        Token *op_tok = parser_next(p, 1);

        Ast *left = bump_alloc(&p->compiler->bump, sizeof(Ast));
        *left = *ast;

        Ast *right = bump_alloc(&p->compiler->bump, sizeof(Ast));
        memset(right, 0, sizeof(Ast));
        right->loc = parser_peek(p, 0)->loc;
        if (!parse_logical(p, right)) res = false;
        Location last_loc = parser_peek(p, -1)->loc;
        right->loc.length = last_loc.buf + last_loc.length - right->loc.buf;

        ast->type = AST_BINARY_EXPR;
        ast->binop.left = left;
        ast->binop.right = right;

        ast->binop.assign = true;
        switch (op_tok->type)
        {
        case TOKEN_PLUSEQ: ast->binop.type = BINOP_ADD; break;
        case TOKEN_MINUSEQ: ast->binop.type = BINOP_SUB; break;
        case TOKEN_MULEQ: ast->binop.type = BINOP_MUL; break;
        case TOKEN_DIVEQ: ast->binop.type = BINOP_DIV; break;
        case TOKEN_MODEQ: ast->binop.type = BINOP_MOD; break;
        case TOKEN_ANDEQ: ast->binop.type = BINOP_BITAND; break;
        case TOKEN_OREQ: ast->binop.type = BINOP_BITOR; break;
        case TOKEN_XOREQ: ast->binop.type = BINOP_BITXOR; break;
        case TOKEN_LSHIFTEQ: ast->binop.type = BINOP_LSHIFT; break;
        case TOKEN_RSHIFTEQ: ast->binop.type = BINOP_RSHIFT; break;
        default: break;
        }
    }

    return res;
}

bool parse_expr(Parser *p, Ast *ast)
{
    assert(!parser_is_at_end(p));
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = parse_op_assign(p, ast);
    Location last_loc = parser_peek(p, -1)->loc;
    ast->loc.length = last_loc.buf + last_loc.length - ast->loc.buf;
    return res;
}

bool parse_stmt(Parser *p, Ast *ast, bool inside_procedure, bool need_semi)
{
    memset(ast, 0, sizeof(*ast));
    ast->loc = parser_peek(p, 0)->loc;
    bool res = true;

    Token *tok = parser_peek(p, 0);
    switch (tok->type)
    {
    case TOKEN_LCURLY: {
        parser_next(p, 1);
        need_semi = false;

        ast->type = AST_BLOCK;

        while (parser_peek(p, 0)->type != TOKEN_RCURLY)
        {
            Ast stmt = {0};
            if (!parse_stmt(p, &stmt, true, true)) res = false;
            array_push(ast->block.stmts, stmt);
        }

        if (!parser_consume(p, TOKEN_RCURLY)) res = false;

        break;
    }
    case TOKEN_PROC: {
        parser_next(p, 1);

        ast->type = AST_PROC_DECL;
        need_semi = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
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
            if (parser_peek(p, 0)->type == TOKEN_ELLIPSIS)
            {
                parser_next(p, 1);
                ast->proc.flags |= PROC_FLAG_IS_C_VARARGS;
                break;
            }

            Ast param = {0};
            param.type = AST_PROC_PARAM;

            Token *ident_tok = parser_consume(p, TOKEN_IDENT);
            if (!ident_tok)
                res = false;
            else
                param.proc_param.name = ident_tok->str;

            if (ident_tok) param.loc = ident_tok->loc;

            if (!parser_consume(p, TOKEN_COLON)) res = false;

            param.proc_param.type_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, param.proc_param.type_expr)) res = false;

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
            ast->proc.flags |= PROC_FLAG_HAS_BODY;
            if (!parser_consume(p, TOKEN_LCURLY)) res = false;

            while (parser_peek(p, 0)->type != TOKEN_RCURLY)
            {
                Ast stmt = {0};
                if (!parse_stmt(p, &stmt, true, true)) res = false;
                array_push(ast->proc.stmts, stmt);
            }

            if (!parser_consume(p, TOKEN_RCURLY)) res = false;
        }
        else
        {
            ast->proc.flags = ast->proc.flags & ~PROC_FLAG_HAS_BODY;
            need_semi = true;
        }

        break;
    }
    case TOKEN_IMPORT: {
        parser_next(p, 1);
        ast->type = AST_IMPORT;

        Token *name_tok = parser_consume(p, TOKEN_IDENT);
        if (name_tok)
            ast->import.name = name_tok->str;
        else
            res = false;

        Token *path_tok = parser_consume(p, TOKEN_STRING_LIT);
        if (path_tok)
            ast->import.path = path_tok->str;
        else
            res = false;

        if (parser_peek(p, 0)->type == TOKEN_STRING_LIT)
        {
            Token *convention_tok = parser_consume(p, TOKEN_STRING_LIT);
            ast->proc.convention = convention_tok->str;
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
        else if (kind->type == TOKEN_CONST)
        {
            // Constants must have initializers
            compile_error(
                p->compiler,
                ident_tok->loc,
                "constant declaration must have initializer");
        }

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

        break;
    }
    case TOKEN_RETURN: {
        parser_next(p, 1);

        ast->type = AST_RETURN;
        need_semi = true;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->expr)) res = false;
        }

        break;
    }
    case TOKEN_IF: {
        parser_next(p, 1);

        ast->type = AST_IF;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        ast->if_stmt.cond_expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->if_stmt.cond_expr)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->if_stmt.cond_stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->if_stmt.cond_stmt, true, true)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_ELSE)
        {
            parser_next(p, 1);

            ast->if_stmt.else_stmt =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->if_stmt.else_stmt, true, true)) res = false;
        }

        break;
    }
    case TOKEN_WHILE: {
        parser_next(p, 1);

        ast->type = AST_WHILE;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        ast->while_stmt.cond = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_expr(p, ast->while_stmt.cond)) res = false;

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->while_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->while_stmt.stmt, true, true)) res = false;

        break;
    }
    case TOKEN_FOR: {
        parser_next(p, 1);

        ast->type = AST_FOR;
        need_semi = false;

        if (!parser_consume(p, TOKEN_LPAREN)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->for_stmt.init = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->for_stmt.init, true, false)) res = false;
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_SEMICOLON)
        {
            ast->for_stmt.cond = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->for_stmt.cond)) res = false;
        }

        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;

        if (parser_peek(p, 0)->type != TOKEN_RPAREN)
        {
            ast->for_stmt.inc = bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_stmt(p, ast->for_stmt.inc, true, false)) res = false;
        }

        if (!parser_consume(p, TOKEN_RPAREN)) res = false;

        ast->for_stmt.stmt = bump_alloc(&p->compiler->bump, sizeof(Ast));
        if (!parse_stmt(p, ast->for_stmt.stmt, true, true)) res = false;

        break;
    }
    case TOKEN_BREAK: {
        parser_next(p, 1);
        ast->type = AST_BREAK;
        need_semi = true;
        break;
    }
    case TOKEN_CONTINUE: {
        parser_next(p, 1);
        ast->type = AST_CONTINUE;
        need_semi = true;
        break;
    }
    default: {
        Ast expr = {0};
        if (!parse_expr(p, &expr)) res = false;

        if (parser_peek(p, 0)->type == TOKEN_ASSIGN)
        {
            ast->type = AST_VAR_ASSIGN;

            ast->assign.assigned_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->assign.assigned_expr = expr;

            if (!parser_consume(p, TOKEN_ASSIGN)) res = false;

            ast->assign.value_expr =
                bump_alloc(&p->compiler->bump, sizeof(Ast));
            if (!parse_expr(p, ast->assign.value_expr)) res = false;

            if (!inside_procedure)
            {
                // TODO: maybe this shouldn't be a parser error
                compile_error(
                    p->compiler,
                    tok->loc,
                    "assignment must be inside procedure",
                    tok->loc.length,
                    tok->loc.buf);

                res = false;
                break;
            }
        }
        else
        {
            ast->type = AST_EXPR_STMT;

            ast->expr = bump_alloc(&p->compiler->bump, sizeof(Ast));
            *ast->expr = expr;
        }

        break;
    }
    }

    if (need_semi)
    {
        if (!parser_consume(p, TOKEN_SEMICOLON)) res = false;
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
        if (parse_stmt(p, &stmt, false, true))
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
    /*array*/ Scope **operand_scope_stack;
    /*array*/ Ast **break_stack;
    /*array*/ Ast **continue_stack;
} Analyzer;

void create_scopes_ast(Analyzer *a, Ast *ast)
{
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        assert(!ast->block.scope);
        ast->block.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->block.scope, 0, sizeof(*ast->block.scope));
        scope_init(
            ast->block.scope,
            a->compiler,
            SCOPE_DEFAULT,
            array_size(ast->block.stmts),
            NULL);
        if (array_size(a->scope_stack) > 0)
        {
            ast->block.scope->parent = *array_last(a->scope_stack);
        }

        array_push(a->scope_stack, ast->block.scope);
        array_push(a->operand_scope_stack, ast->block.scope);
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);

        break;
    }
    case AST_PROC_DECL: {
        assert(!ast->proc.scope);
        ast->proc.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->proc.scope, 0, sizeof(*ast->proc.scope));
        scope_init(
            ast->proc.scope,
            a->compiler,
            SCOPE_DEFAULT,
            array_size(ast->proc.stmts) + array_size(ast->proc.params),
            ast);
        ast->proc.scope->parent = *array_last(a->scope_stack);

        array_push(a->scope_stack, ast->proc.scope);
        array_push(a->operand_scope_stack, ast->proc.scope);
        for (Ast *stmt = ast->proc.stmts;
             stmt != ast->proc.stmts + array_size(ast->proc.stmts);
             ++stmt)
        {
            create_scopes_ast(a, stmt);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_UNARY_EXPR: {
        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
            create_scopes_ast(a, ast->unop.sub);
            break;
        }
        default: break;
        }

        break;
    }
    case AST_IF: {
        create_scopes_ast(a, ast->if_stmt.cond_expr);
        create_scopes_ast(a, ast->if_stmt.cond_stmt);
        if (ast->if_stmt.else_stmt)
        {
            create_scopes_ast(a, ast->if_stmt.else_stmt);
        }
        break;
    }
    case AST_WHILE: {
        create_scopes_ast(a, ast->while_stmt.cond);
        create_scopes_ast(a, ast->while_stmt.stmt);
        break;
    }
    case AST_FOR: {
        assert(!ast->for_stmt.scope);
        ast->for_stmt.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->for_stmt.scope, 0, sizeof(*ast->for_stmt.scope));
        scope_init(
            ast->for_stmt.scope,
            a->compiler,
            SCOPE_DEFAULT,
            5, // Small number, because there's only gonna be 2 declarations max
            NULL);
        if (array_size(a->scope_stack) > 0)
        {
            ast->for_stmt.scope->parent = *array_last(a->scope_stack);
        }

        array_push(a->scope_stack, ast->for_stmt.scope);
        array_push(a->operand_scope_stack, ast->for_stmt.scope);
        if (ast->for_stmt.init) create_scopes_ast(a, ast->for_stmt.init);
        if (ast->for_stmt.cond) create_scopes_ast(a, ast->for_stmt.cond);
        if (ast->for_stmt.inc) create_scopes_ast(a, ast->for_stmt.inc);
        create_scopes_ast(a, ast->for_stmt.stmt);
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_PAREN_EXPR: {
        create_scopes_ast(a, ast->expr);
        break;
    }
    case AST_TYPEDEF: {
        create_scopes_ast(a, ast->type_def.type_expr);
        break;
    }
    case AST_CONST_DECL: {
        create_scopes_ast(a, ast->decl.type_expr);
        break;
    }
    case AST_VAR_DECL: {
        create_scopes_ast(a, ast->decl.type_expr);
        break;
    }
    case AST_STRUCT_FIELD: {
        create_scopes_ast(a, ast->field.type_expr);
        break;
    }
    case AST_STRUCT: {
        assert(!ast->structure.scope);
        ast->structure.scope = bump_alloc(&a->compiler->bump, sizeof(Scope));
        memset(ast->structure.scope, 0, sizeof(*ast->structure.scope));
        scope_init(
            ast->structure.scope,
            a->compiler,
            SCOPE_STRUCT,
            array_size(ast->structure.fields),
            ast);

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            scope_set(ast->structure.scope, field->field.name, field);
        }

        array_push(a->scope_stack, ast->structure.scope);
        array_push(a->operand_scope_stack, ast->structure.scope);
        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            create_scopes_ast(a, field);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_UNINITIALIZED:
    case AST_BREAK:
    case AST_CONTINUE:
    case AST_RETURN:
    case AST_PRIMARY:
    case AST_SUBSCRIPT:
    case AST_SUBSCRIPT_SLICE:
    case AST_ARRAY_TYPE:
    case AST_SLICE_TYPE:
    case AST_EXPR_STMT:
    case AST_ACCESS:
    case AST_PROC_PARAM:
    case AST_CAST:
    case AST_VAR_ASSIGN:
    case AST_BINARY_EXPR:
    case AST_INTRINSIC_CALL:
    case AST_PROC_CALL:
    case AST_PROC_TYPE:
    case AST_IMPORT: break;
    }
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
    case AST_PROC_PARAM: {
        sym_name = ast->proc_param.name;
        break;
    }
    case AST_STRUCT_FIELD: {
        sym_name = ast->field.name;
        break;
    }
    case AST_TYPEDEF: {
        sym_name = ast->type_def.name;
        break;
    }
    case AST_IMPORT: {
        sym_name = ast->import.name;
        break;
    }
    case AST_PROC_DECL: {
        sym_name = ast->proc.name;

        array_push(a->scope_stack, ast->proc.scope);
        array_push(a->operand_scope_stack, ast->proc.scope);
        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            register_symbol_ast(a, param);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    default: return;
    }

    assert(sym_name.length > 0);

    if (get_symbol(*array_last(a->scope_stack), sym_name))
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
        if (ast->expr)
        {
            symbol_check_ast(a, ast->expr);
        }
        break;
    }
    case AST_CONST_DECL: {
        symbol_check_ast(a, ast->decl.type_expr);
        symbol_check_ast(a, ast->decl.value_expr);
        if (!is_expr_const(*array_last(a->scope_stack), ast->decl.value_expr))
        {
            compile_error(
                a->compiler,
                ast->decl.value_expr->loc,
                "expression is not constant");
        }
        break;
    }
    case AST_VAR_DECL: {
        symbol_check_ast(a, ast->decl.type_expr);
        if (ast->decl.value_expr)
        {
            symbol_check_ast(a, ast->decl.value_expr);
        }
        break;
    }
    case AST_IF: {
        symbol_check_ast(a, ast->if_stmt.cond_expr);
        symbol_check_ast(a, ast->if_stmt.cond_stmt);
        if (ast->if_stmt.else_stmt)
        {
            symbol_check_ast(a, ast->if_stmt.else_stmt);
        }
        break;
    }
    case AST_WHILE: {
        symbol_check_ast(a, ast->while_stmt.cond);

        array_push(a->break_stack, ast);
        array_push(a->continue_stack, ast);
        symbol_check_ast(a, ast->while_stmt.stmt);
        array_pop(a->continue_stack);
        array_pop(a->break_stack);
        break;
    }
    case AST_FOR: {
        array_push(a->scope_stack, ast->for_stmt.scope);
        array_push(a->operand_scope_stack, ast->for_stmt.scope);

        if (ast->for_stmt.init) symbol_check_ast(a, ast->for_stmt.init);
        if (ast->for_stmt.cond) symbol_check_ast(a, ast->for_stmt.cond);
        if (ast->for_stmt.inc) symbol_check_ast(a, ast->for_stmt.inc);

        array_push(a->break_stack, ast);
        array_push(a->continue_stack, ast);
        symbol_check_ast(a, ast->for_stmt.stmt);
        array_pop(a->continue_stack);
        array_pop(a->break_stack);

        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_BREAK: {
        if (array_size(a->break_stack) == 0)
        {
            compile_error(
                a->compiler, ast->loc, "'break' outside control structure");
            break;
        }
        break;
    }
    case AST_CONTINUE: {
        if (array_size(a->continue_stack) == 0)
        {
            compile_error(
                a->compiler, ast->loc, "'continue' outside control structure");
            break;
        }
        break;
    }
    case AST_BLOCK: {
        array_push(a->scope_stack, ast->block.scope);
        array_push(a->operand_scope_stack, ast->block.scope);
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            symbol_check_ast(a, stmt);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_PROC_DECL: {
        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            symbol_check_ast(a, param);
        }

        symbol_check_ast(a, ast->proc.return_type);
        break;
    }
    case AST_PROC_PARAM: {
        symbol_check_ast(a, ast->proc_param.type_expr);
        if (ast->proc_param.value_expr)
        {
            symbol_check_ast(a, ast->proc_param.value_expr);
        }
        break;
    }
    case AST_STRUCT_FIELD: {
        symbol_check_ast(a, ast->field.type_expr);
        if (ast->field.value_expr)
        {
            symbol_check_ast(a, ast->field.value_expr);
        }
        break;
    }
    case AST_VAR_ASSIGN: {
        symbol_check_ast(a, ast->assign.assigned_expr);
        symbol_check_ast(a, ast->assign.value_expr);
        break;
    }
    case AST_EXPR_STMT: {
        symbol_check_ast(a, ast->expr);
        break;
    }
    case AST_PROC_CALL: {
        symbol_check_ast(a, ast->proc_call.expr);

        assert(array_size(a->operand_scope_stack) > 0);

        array_push(a->scope_stack, *array_last(a->operand_scope_stack));
        for (Ast *param = ast->proc_call.params;
             param != ast->proc_call.params + array_size(ast->proc_call.params);
             ++param)
        {
            symbol_check_ast(a, param);
        }
        array_pop(a->scope_stack);

        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            if (array_size(ast->intrinsic_call.params) > 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@sizeof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params[0];
            symbol_check_ast(a, param);

            break;
        }
        case INTRINSIC_ALIGNOF: {
            if (array_size(ast->intrinsic_call.params) > 1)
            {
                compile_error(
                    a->compiler, ast->loc, "@alignof takes one parameter");
                break;
            }

            Ast *param = &ast->intrinsic_call.params[0];
            symbol_check_ast(a, param);

            break;
        }
        }

        break;
    }
    case AST_CAST: {
        symbol_check_ast(a, ast->cast.type_expr);
        symbol_check_ast(a, ast->cast.value_expr);
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
    case AST_SUBSCRIPT: {
        symbol_check_ast(a, ast->subscript.left);
        symbol_check_ast(a, ast->subscript.right);
        break;
    }
    case AST_SUBSCRIPT_SLICE: {
        symbol_check_ast(a, ast->subscript_slice.left);
        symbol_check_ast(a, ast->subscript_slice.lower);
        symbol_check_ast(a, ast->subscript_slice.upper);
        break;
    }
    case AST_STRUCT: {
        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            symbol_check_ast(a, field);
        }
        break;
    }
    case AST_ARRAY_TYPE: {
        symbol_check_ast(a, ast->array_type.size);
        symbol_check_ast(a, ast->array_type.sub);

        if (!is_expr_const(*array_last(a->scope_stack), ast->array_type.size))
        {
            compile_error(
                a->compiler,
                ast->array_type.size->loc,
                "array type size must be a constant value");
        }

        break;
    }
    case AST_SLICE_TYPE: {
        symbol_check_ast(a, ast->array_type.sub);
        break;
    }
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_IDENT: {
            Ast *sym =
                get_symbol(*array_last(a->scope_stack), ast->primary.tok->str);

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
    case AST_PROC_TYPE: {
        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            symbol_check_ast(a, param);
        }

        symbol_check_ast(a, ast->proc.return_type);

        break;
    }
    case AST_ACCESS: {
        symbol_check_ast(a, ast->access.left);

        get_ast_type(a->compiler, *array_last(a->scope_stack), ast);

        if (!ast->type_info)
        {
            compile_error(a->compiler, ast->loc, "invalid access");
            break;
        }

        Scope *accessed_scope = get_expr_scope(
            a->compiler, *array_last(a->scope_stack), ast->access.left);
        if (accessed_scope)
        {
            array_push(a->scope_stack, accessed_scope);
            symbol_check_ast(a, ast->access.right);
            array_pop(a->scope_stack);
        }
        break;
    }
    default: break;
    }
}

bool type_check_ast(Analyzer *a, Ast *ast, TypeInfo *expected_type)
{
    bool res = true;
    bool is_statement = true;

    // Statements
    switch (ast->type)
    {
    case AST_RETURN: {
        Ast *proc = get_scope_procedure(*array_last(a->scope_stack));
        if (!proc)
        {
            compile_error(
                a->compiler, ast->loc, "return needs to be inside a procedure");
            break;
        }

        assert(proc->proc.return_type->as_type);
        if (ast->expr)
        {
            type_check_ast(a, ast->expr, proc->proc.return_type->as_type);
        }
        else
        {
            if (proc->proc.return_type->as_type->kind != TYPE_VOID)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "procedure does not return void, 'return' must contain a "
                    "value");
                break;
            }
        }
        break;
    }
    case AST_BLOCK: {
        array_push(a->scope_stack, ast->block.scope);
        array_push(a->operand_scope_stack, ast->block.scope);
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            type_check_ast(a, stmt, NULL);
        }
        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);
        break;
    }
    case AST_TYPEDEF: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->type_def.type_expr, &ty_ty);
        break;
    }
    case AST_CONST_DECL: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->decl.type_expr, &ty_ty);
        type_check_ast(a, ast->decl.value_expr, ast->decl.type_expr->as_type);
        break;
    }
    case AST_VAR_DECL: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->decl.type_expr, &ty_ty);
        if (ast->decl.value_expr)
        {
            type_check_ast(
                a, ast->decl.value_expr, ast->decl.type_expr->as_type);
        }
        break;
    }
    case AST_PROC_PARAM: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->proc_param.type_expr, &ty_ty);
        if (ast->proc_param.value_expr)
        {
            type_check_ast(
                a,
                ast->proc_param.value_expr,
                ast->proc_param.type_expr->as_type);
        }
        break;
    }
    case AST_STRUCT_FIELD: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->field.type_expr, &ty_ty);
        if (ast->field.value_expr)
        {
            type_check_ast(
                a, ast->field.value_expr, ast->field.type_expr->as_type);
        }
        break;
    }
    case AST_VAR_ASSIGN: {
        type_check_ast(a, ast->assign.assigned_expr, NULL);
        type_check_ast(
            a, ast->assign.value_expr, ast->assign.assigned_expr->type_info);
        break;
    }
    case AST_EXPR_STMT: {
        type_check_ast(a, ast->expr, NULL);
        break;
    }
    case AST_PROC_DECL: {
        TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
        memset(ty, 0, sizeof(*ty));
        ty->kind = TYPE_PROC;

        ty->proc.is_c_vararg =
            (ast->proc.flags & PROC_FLAG_IS_C_VARARGS) ? true : false;

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

        TypeInfo *ptr_ty = bump_alloc(&a->compiler->bump, sizeof(*ptr_ty));
        memset(ptr_ty, 0, sizeof(*ptr_ty));
        ptr_ty->kind = TYPE_POINTER;
        ptr_ty->ptr.sub = ty;

        ast->type_info = ptr_ty;
        break;
    }
    case AST_PROC_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};

        for (Ast *param = ast->proc.params;
             param != ast->proc.params + array_size(ast->proc.params);
             ++param)
        {
            type_check_ast(a, param, NULL);
        }

        type_check_ast(a, ast->proc.return_type, &ty_ty);

        ast->type_info = &ty_ty;
        break;
    }
    case AST_IF: {
        type_check_ast(a, ast->if_stmt.cond_expr, NULL);
        type_check_ast(a, ast->if_stmt.cond_stmt, NULL);
        if (ast->if_stmt.else_stmt)
        {
            type_check_ast(a, ast->if_stmt.else_stmt, NULL);
        }

        if (!ast->if_stmt.cond_expr->type_info)
        {
            compile_error(
                a->compiler,
                ast->if_stmt.cond_expr->loc,
                "could not resolve type for 'if' condition");
            break;
        }

        if (ast->if_stmt.cond_expr->type_info->kind != TYPE_INT &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_FLOAT &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_BOOL &&
            ast->if_stmt.cond_expr->type_info->kind != TYPE_POINTER)
        {
            compile_error(
                a->compiler,
                ast->if_stmt.cond_expr->loc,
                "conditional only works for numerical types");
            break;
        }

        break;
    }
    case AST_WHILE: {
        type_check_ast(a, ast->while_stmt.cond, NULL);
        type_check_ast(a, ast->while_stmt.stmt, NULL);

        if (!ast->while_stmt.cond->type_info)
        {
            compile_error(
                a->compiler,
                ast->while_stmt.cond->loc,
                "could not evaluate type for 'while' condition");
            break;
        }

        if (ast->while_stmt.cond->type_info->kind != TYPE_INT &&
            ast->while_stmt.cond->type_info->kind != TYPE_FLOAT &&
            ast->while_stmt.cond->type_info->kind != TYPE_BOOL &&
            ast->while_stmt.cond->type_info->kind != TYPE_POINTER)
        {
            compile_error(
                a->compiler,
                ast->for_stmt.cond->loc,
                "'while' statement only takes numerical types as conditions");
            break;
        }

        break;
    }
    case AST_FOR: {
        array_push(a->scope_stack, ast->for_stmt.scope);
        array_push(a->operand_scope_stack, ast->for_stmt.scope);

        if (ast->for_stmt.init) type_check_ast(a, ast->for_stmt.init, NULL);
        if (ast->for_stmt.cond) type_check_ast(a, ast->for_stmt.cond, NULL);
        if (ast->for_stmt.inc) type_check_ast(a, ast->for_stmt.inc, NULL);
        type_check_ast(a, ast->for_stmt.stmt, NULL);

        array_pop(a->operand_scope_stack);
        array_pop(a->scope_stack);

        if (ast->for_stmt.cond)
        {
            if (!ast->for_stmt.cond->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->for_stmt.cond->loc,
                    "could not evaluate type for 'for' condition");
                break;
            }

            if (ast->for_stmt.cond->type_info->kind != TYPE_INT &&
                ast->for_stmt.cond->type_info->kind != TYPE_FLOAT &&
                ast->for_stmt.cond->type_info->kind != TYPE_BOOL &&
                ast->for_stmt.cond->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->for_stmt.cond->loc,
                    "'for' statement only takes numerical types as conditions");
                break;
            }
        }

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

    ast_as_type(a->compiler, *array_last(a->scope_stack), ast);

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
        case TOKEN_CHAR:
        case TOKEN_FLOAT:
        case TOKEN_DOUBLE:
        case TOKEN_BOOL:
        case TOKEN_VOID: {
            static TypeInfo ty = {.kind = TYPE_TYPE};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_NULL: {
            static TypeInfo void_ty = {.kind = TYPE_VOID};
            static TypeInfo void_ptr_ty = {.kind = TYPE_POINTER,
                                           .ptr.sub = &void_ty};
            ast->type_info = &void_ptr_ty;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_POINTER: {
                    ast->type_info = expected_type;
                    break;
                }
                default: break;
                }
            }
            break;
        }
        case TOKEN_TRUE:
        case TOKEN_FALSE: {
            static TypeInfo ty = {.kind = TYPE_BOOL};
            ast->type_info = &ty;
            break;
        }
        case TOKEN_INT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_INT,
                .can_change = true,
                .integer = {.is_signed = true, .num_bits = 64}};
            ast->type_info = &ty;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_FLOAT:
                case TYPE_INT: {
                    ast->type_info = expected_type;
                    break;
                }
                default: break;
                }
            }

            break;
        }
        case TOKEN_FLOAT_LIT: {
            static TypeInfo ty = {
                .kind = TYPE_FLOAT,
                .floating.num_bits = 64,
                .can_change = true,
            };
            ast->type_info = &ty;

            if (expected_type)
            {
                switch (expected_type->kind)
                {
                case TYPE_FLOAT: {
                    ast->type_info = expected_type;
                    break;
                }
                default: break;
                }
            }

            break;
        }
        case TOKEN_CSTRING_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            static TypeInfo ty = {
                .kind = TYPE_POINTER,
                .ptr.sub = &i8_ty,
            };
            ast->type_info = &ty;
            break;
        }
        case TOKEN_CHAR_LIT: {
            static TypeInfo i8_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = true,
                .integer.num_bits = 8,
            };
            ast->type_info = &i8_ty;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym =
                get_symbol(*array_last(a->scope_stack), ast->primary.tok->str);
            if (sym)
            {
                switch (sym->type)
                {
                case AST_VAR_DECL:
                case AST_CONST_DECL: {
                    ast->type_info = sym->decl.type_expr->as_type;
                    break;
                }
                case AST_PROC_PARAM: {
                    ast->type_info = sym->proc_param.type_expr->as_type;
                    break;
                }
                case AST_STRUCT_FIELD: {
                    ast->type_info = sym->field.type_expr->as_type;
                    break;
                }
                case AST_PROC_DECL: {
                    ast->type_info = sym->type_info;
                    break;
                }
                case AST_IMPORT: {
                    static TypeInfo namespace_ty = {.kind = TYPE_NAMESPACE};
                    ast->type_info = &namespace_ty;
                    break;
                }
                case AST_TYPEDEF: {
                    static TypeInfo ty_ty = {.kind = TYPE_TYPE};
                    ast->type_info = &ty_ty;
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

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;

        if (ast->proc_call.expr->type_info->kind != TYPE_POINTER ||
            ast->proc_call.expr->type_info->ptr.sub->kind != TYPE_PROC)
        {
            res = false;
            compile_error(
                a->compiler, ast->loc, "tried to call a non procedure type");
            break;
        }

        TypeInfo *proc_ty = proc_ptr_ty->ptr.sub;

        assert(proc_ty);
        ast->type_info = proc_ty->proc.return_type;

        if (!proc_ty->proc.is_c_vararg)
        {
            if (array_size(ast->proc_call.params) !=
                array_size(proc_ty->proc.params))
            {
                res = false;
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong parameter count for function call");
                break;
            }
        }
        else
        {
            if (array_size(ast->proc_call.params) <
                array_size(proc_ty->proc.params))
            {
                res = false;
                compile_error(
                    a->compiler,
                    ast->loc,
                    "wrong parameter count for function call");
                break;
            }
        }

        array_push(a->scope_stack, *array_last(a->operand_scope_stack));
        for (size_t i = 0; i < array_size(ast->proc_call.params); ++i)
        {
            TypeInfo *param_expected_type = NULL;
            if (i < array_size(proc_ty->proc.params))
            {
                param_expected_type = &proc_ty->proc.params[i];
            }
            type_check_ast(a, &ast->proc_call.params[i], param_expected_type);
        }
        array_pop(a->scope_stack);
        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            Ast *param = &ast->intrinsic_call.params[0];
            type_check_ast(a, param, NULL);

            if (!param->type_info)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "could not resolve type for expression");
                break;
            }

            if (param->type_info->kind == TYPE_VOID ||
                param->type_info->kind == TYPE_NAMESPACE)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "@sizeof does not apply for this type");
                break;
            }

            static TypeInfo u64_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = false,
                .integer.num_bits = 64,
            };
            ast->type_info = &u64_ty;

            break;
        }
        case INTRINSIC_ALIGNOF: {
            Ast *param = &ast->intrinsic_call.params[0];
            type_check_ast(a, param, NULL);

            if (param->type_info->kind == TYPE_VOID ||
                param->type_info->kind == TYPE_NAMESPACE)
            {
                compile_error(
                    a->compiler,
                    param->loc,
                    "@alignof does not apply for this type");
                break;
            }

            static TypeInfo u64_ty = {
                .kind = TYPE_INT,
                .integer.is_signed = false,
                .integer.num_bits = 64,
            };
            ast->type_info = &u64_ty;

            break;
        }
        }

        break;
    }
    case AST_CAST: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        type_check_ast(a, ast->cast.type_expr, &ty_ty);
        type_check_ast(a, ast->cast.value_expr, NULL);

        TypeInfo *dest_ty = ast->cast.type_expr->as_type;
        TypeInfo *src_ty = ast->cast.value_expr->type_info;

        if (dest_ty && src_ty)
        {
            // Check if type is castable

            if (!((dest_ty->kind == TYPE_POINTER &&
                   src_ty->kind == TYPE_POINTER) ||
                  (dest_ty->kind == TYPE_POINTER && src_ty->kind == TYPE_INT) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_POINTER) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_INT) ||
                  (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_FLOAT) ||
                  (dest_ty->kind == TYPE_INT && src_ty->kind == TYPE_FLOAT) ||
                  (dest_ty->kind == TYPE_FLOAT && src_ty->kind == TYPE_INT)))
            {
                compile_error(a->compiler, ast->loc, "invalid cast");
                break;
            }
        }
        else
        {
            compile_error(
                a->compiler, ast->loc, "could not resolve types for cast");
            break;
        }

        ast->type_info = dest_ty;

        break;
    }
    case AST_UNARY_EXPR: {
        TypeInfo *sub_expected_type = NULL;

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: break;
        case UNOP_ADDRESS: {
            if (expected_type && expected_type->kind == TYPE_POINTER)
            {
                sub_expected_type = expected_type->ptr.sub;
            }
            break;
        }
        case UNOP_NEG: sub_expected_type = expected_type; break;
        case UNOP_NOT: break;
        }

        type_check_ast(a, ast->unop.sub, sub_expected_type);

        if (!ast->unop.sub->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for unary operand");
            break;
        }

        switch (ast->unop.type)
        {
        case UNOP_DEREFERENCE: {
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
            TypeInfo *ty = bump_alloc(&a->compiler->bump, sizeof(*ty));
            memset(ty, 0, sizeof(*ty));
            ty->kind = TYPE_POINTER;
            ty->ptr.sub = ast->unop.sub->type_info;
            ast->type_info = ty;
            break;
        }
        case UNOP_NEG: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do arithmetic on numeric types");
                break;
            }

            ast->type_info = ast->unop.sub->type_info;

            break;
        }
        case UNOP_NOT: {
            if (ast->unop.sub->type_info->kind != TYPE_INT &&
                ast->unop.sub->type_info->kind != TYPE_FLOAT &&
                ast->unop.sub->type_info->kind != TYPE_BOOL &&
                ast->unop.sub->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "operator '!' only works on logical types");
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;
            break;
        }
        }

        break;
    }
    case AST_BINARY_EXPR: {
        switch (ast->binop.type)
        {
        case BINOP_ADD:
        case BINOP_SUB:
        case BINOP_MUL:
        case BINOP_DIV:
        case BINOP_MOD: {
            type_check_ast(a, ast->binop.left, expected_type);
            type_check_ast(a, ast->binop.right, expected_type);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (expected_type == NULL)
            {
                TypeInfo *common_type = common_numeric_type(
                    ast->binop.left->type_info, ast->binop.right->type_info);
                type_check_ast(a, ast->binop.left, common_type);
                type_check_ast(a, ast->binop.right, common_type);
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do arithmetic on numeric types");
                break;
            }

            ast->type_info = ast->binop.left->type_info;

            break;
        }
        case BINOP_LSHIFT:
        case BINOP_RSHIFT:
        case BINOP_BITAND:
        case BINOP_BITOR:
        case BINOP_BITXOR: {
            type_check_ast(a, ast->binop.left, expected_type);
            type_check_ast(a, ast->binop.right, expected_type);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (expected_type == NULL)
            {
                TypeInfo *common_type = common_numeric_type(
                    ast->binop.left->type_info, ast->binop.right->type_info);
                type_check_ast(a, ast->binop.left, common_type);
                type_check_ast(a, ast->binop.right, common_type);
            }

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "arithmetic binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_BOOL)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do bitwise operations on integer types");
                break;
            }

            ast->type_info = ast->binop.left->type_info;

            break;
        }
        case BINOP_EQ:
        case BINOP_NOTEQ:
        case BINOP_LESS:
        case BINOP_LESSEQ:
        case BINOP_GREATER:
        case BINOP_GREATEREQ: {
            type_check_ast(a, ast->binop.left, NULL);
            type_check_ast(a, ast->binop.right, NULL);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            TypeInfo *common_type = common_numeric_type(
                ast->binop.left->type_info, ast->binop.right->type_info);
            type_check_ast(a, ast->binop.left, common_type);
            type_check_ast(a, ast->binop.right, common_type);

            if (!exact_types(
                    ast->binop.left->type_info, ast->binop.right->type_info))
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "comparison binary operands are of different types");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_BOOL &&
                ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT &&
                ast->binop.left->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "can only do comparison on numeric types");
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;

            break;
        }
        case BINOP_AND:
        case BINOP_OR: {
            type_check_ast(a, ast->binop.left, NULL);
            type_check_ast(a, ast->binop.right, NULL);

            if (!ast->binop.left->type_info || !ast->binop.right->type_info)
            {
                compile_error(
                    a->compiler,
                    ast->loc,
                    "could not resolve type for binary operands");
                break;
            }

            if (ast->binop.left->type_info->kind != TYPE_BOOL &&
                ast->binop.left->type_info->kind != TYPE_INT &&
                ast->binop.left->type_info->kind != TYPE_FLOAT &&
                ast->binop.left->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.left->loc,
                    "left operand of logical operator has invalid type");
                break;
            }

            if (ast->binop.right->type_info->kind != TYPE_BOOL &&
                ast->binop.right->type_info->kind != TYPE_INT &&
                ast->binop.right->type_info->kind != TYPE_FLOAT &&
                ast->binop.right->type_info->kind != TYPE_POINTER)
            {
                compile_error(
                    a->compiler,
                    ast->binop.right->loc,
                    "right operand of logical operator has invalid type");
                break;
            }

            static TypeInfo bool_ty = {.kind = TYPE_BOOL};
            ast->type_info = &bool_ty;

            break;
        }
        }

        break;
    }
    case AST_SUBSCRIPT: {
        type_check_ast(a, ast->subscript.left, NULL);
        type_check_ast(a, ast->subscript.right, NULL);

        if (!ast->subscript.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for left expression of subscript");
            break;
        }

        if (!ast->subscript.right->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for right expression of subscript");
            break;
        }

        if (ast->subscript.left->type_info->kind != TYPE_POINTER &&
            ast->subscript.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript.left->type_info->kind != TYPE_SLICE)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info = ast->subscript.left->type_info->ptr.sub;
            break;
        }
        default: assert(0); break;
        }

        if (ast->subscript.right->type_info->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "subscript needs an integer index");
            break;
        }
        break;
    }
    case AST_SUBSCRIPT_SLICE: {
        type_check_ast(a, ast->subscript_slice.left, NULL);
        type_check_ast(a, ast->subscript_slice.lower, NULL);
        type_check_ast(a, ast->subscript_slice.upper, NULL);

        if (!ast->subscript_slice.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for left expression of subscript");
            break;
        }

        if (!ast->subscript_slice.lower->type_info ||
            !ast->subscript_slice.upper->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type for bounds of slice subscript");
            break;
        }

        if (ast->subscript_slice.left->type_info->kind != TYPE_POINTER &&
            ast->subscript_slice.left->type_info->kind != TYPE_ARRAY &&
            ast->subscript_slice.left->type_info->kind != TYPE_SLICE)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "subscript only works on pointers or arrays");
            break;
        }

        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_SLICE:
        case TYPE_ARRAY: {
            ast->type_info = ast->subscript_slice.left->type_info->array.sub;
            break;
        }
        case TYPE_POINTER: {
            ast->type_info = ast->subscript_slice.left->type_info->ptr.sub;
            break;
        }
        default: assert(0); break;
        }

        if (ast->subscript_slice.lower->type_info->kind != TYPE_INT ||
            ast->subscript_slice.upper->type_info->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "subscript needs integer bounds");
            break;
        }
        break;
    }
    case AST_ARRAY_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        type_check_ast(a, ast->array_type.size, NULL);
        type_check_ast(a, ast->array_type.sub, &ty_ty);

        if (ast->array_type.size->type_info->kind != TYPE_INT)
        {
            compile_error(
                a->compiler, ast->loc, "array type needs an integer size");
        }

        break;
    }
    case AST_SLICE_TYPE: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        type_check_ast(a, ast->array_type.sub, &ty_ty);

        break;
    }
    case AST_STRUCT: {
        static TypeInfo ty_ty = {.kind = TYPE_TYPE};
        ast->type_info = &ty_ty;

        for (Ast *field = ast->structure.fields;
             field != ast->structure.fields + array_size(ast->structure.fields);
             ++field)
        {
            type_check_ast(a, field, NULL);
        }
        break;
    }
    case AST_ACCESS: {
        type_check_ast(a, ast->access.left, NULL);

        if (!ast->access.left->type_info)
        {
            compile_error(
                a->compiler,
                ast->loc,
                "could not resolve type of left expression in access");
            break;
        }

        Scope *accessed_scope = get_expr_scope(
            a->compiler, *array_last(a->scope_stack), ast->access.left);

        if (accessed_scope)
        {
            array_push(a->scope_stack, accessed_scope);
            type_check_ast(a, ast->access.right, NULL);
            array_pop(a->scope_stack);

            ast->type_info = ast->access.right->type_info;
        }

        break;
    }
    default: break;
    }

    if (!ast->type_info)
    {
        // TODO: remove this, only temporary for debugging
        printf(
            "undefined type: %u:%u (%u)\n",
            ast->loc.line,
            ast->loc.col,
            ast->loc.length);
    }

    if (res && ast->type_info && expected_type)
    {
        if (!exact_types(ast->type_info, expected_type) &&
            !compatible_pointer_types(ast->type_info, expected_type))
        {
            compile_error(a->compiler, ast->loc, "wrong type");
            res = false;
        }
    }

    return res;
}

void register_symbol_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
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
        case AST_ROOT:
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
            break;
        }
        default: {
            register_symbol_ast(a, ast);
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
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            register_symbol_asts(
                a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_PROC_DECL: {
            array_push(a->scope_stack, ast->proc.scope);
            array_push(a->operand_scope_stack, ast->proc.scope);
            register_symbol_asts(
                a, ast->proc.stmts, array_size(ast->proc.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_BLOCK: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            register_symbol_asts(
                a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_IF: {
            register_symbol_asts(a, ast->if_stmt.cond_stmt, 1);
            if (ast->if_stmt.else_stmt)
            {
                register_symbol_asts(a, ast->if_stmt.else_stmt, 1);
            }
            break;
        }
        case AST_WHILE: {
            register_symbol_asts(a, ast->while_stmt.cond, 1);
            register_symbol_asts(a, ast->while_stmt.stmt, 1);
            break;
        }
        case AST_FOR: {
            array_push(a->scope_stack, ast->for_stmt.scope);
            array_push(a->operand_scope_stack, ast->for_stmt.scope);
            if (ast->for_stmt.init)
                register_symbol_asts(a, ast->for_stmt.init, 1);
            if (ast->for_stmt.cond)
                register_symbol_asts(a, ast->for_stmt.cond, 1);
            if (ast->for_stmt.inc)
                register_symbol_asts(a, ast->for_stmt.inc, 1);
            register_symbol_asts(a, ast->for_stmt.stmt, 1);
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        default: break;
        }
    }
}

void symbol_check_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
            symbol_check_ast(a, ast);
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
            symbol_check_ast(a, ast);
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
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            symbol_check_asts(
                a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_PROC_DECL: {
            array_push(a->scope_stack, ast->proc.scope);
            array_push(a->operand_scope_stack, ast->proc.scope);
            symbol_check_asts(a, ast->proc.stmts, array_size(ast->proc.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        default: break;
        }
    }
}

void type_check_asts(Analyzer *a, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_PROC_DECL: {
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
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            type_check_asts(a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_BLOCK: {
            array_push(a->scope_stack, ast->block.scope);
            array_push(a->operand_scope_stack, ast->block.scope);
            type_check_asts(a, ast->block.stmts, array_size(ast->block.stmts));
            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        case AST_IF: {
            type_check_asts(a, ast->if_stmt.cond_stmt, 1);
            if (ast->if_stmt.else_stmt)
            {
                type_check_asts(a, ast->if_stmt.else_stmt, 1);
            }
            break;
        }
        case AST_WHILE: {
            type_check_asts(a, ast->while_stmt.cond, 1);
            type_check_asts(a, ast->while_stmt.stmt, 1);
            break;
        }
        case AST_PROC_DECL: {
            array_push(a->scope_stack, ast->proc.scope);
            array_push(a->operand_scope_stack, ast->proc.scope);
            type_check_asts(a, ast->proc.stmts, array_size(ast->proc.stmts));

            // If the procedure has a void return type or doesn't have a
            // body, say it has returned already
            bool returned = ast->proc.return_type->as_type->kind == TYPE_VOID ||
                            !(ast->proc.flags & PROC_FLAG_HAS_BODY);

            if (!returned)
            {
                for (Ast *stmt = ast->proc.stmts;
                     stmt != ast->proc.stmts + array_size(ast->proc.stmts);
                     ++stmt)
                {
                    if (stmt->type == AST_RETURN) returned = true;
                }
            }

            if (!returned)
            {
                compile_error(
                    a->compiler, ast->loc, "procedure did not return");
            }

            array_pop(a->operand_scope_stack);
            array_pop(a->scope_stack);
            break;
        }
        default: break;
        }
    }
}
// }}}

// LLVM Codegen {{{
typedef struct LLModule
{
    LLVMModuleRef mod;
    LLVMBuilderRef builder;
    LLVMTargetDataRef data;
} LLModule;

typedef struct LLContext
{
    Compiler *compiler;
    LLModule mod;
    /*array*/ Scope **scope_stack;
    /*array*/ Scope **operand_scope_stack;
    /*array*/ LLVMBasicBlockRef *break_block_stack;
    /*array*/ LLVMBasicBlockRef *continue_block_stack;
} LLContext;

static LLVMTypeRef llvm_type(LLContext *l, TypeInfo *type)
{
    if (type->ref) return type->ref;

    switch (type->kind)
    {
    case TYPE_INT: {
        type->ref = LLVMIntType(type->integer.num_bits);
        break;
    }
    case TYPE_FLOAT: {
        switch (type->floating.num_bits)
        {
        case 32: type->ref = LLVMFloatType(); break;
        case 64: type->ref = LLVMDoubleType(); break;
        default: assert(0); break;
        }
        break;
    }
    case TYPE_BOOL: type->ref = LLVMInt8Type(); break;
    case TYPE_VOID: type->ref = LLVMVoidType(); break;

    case TYPE_POINTER: {
        type->ref = LLVMPointerType(llvm_type(l, type->ptr.sub), 0);
        break;
    }
    case TYPE_ARRAY: {
        type->ref =
            LLVMArrayType(llvm_type(l, type->array.sub), type->array.size);
        break;
    }
    case TYPE_SLICE: {
        LLVMTypeRef field_types[2] = {
            LLVMInt64Type(),
            LLVMPointerType(llvm_type(l, type->array.sub), 0),
        };

        type->ref = LLVMStructType(field_types, 2, false);
        break;
    }
    case TYPE_PROC: {
        size_t param_count = array_size(type->proc.params);
        LLVMTypeRef *param_types =
            bump_alloc(&l->compiler->bump, sizeof(LLVMTypeRef) * param_count);
        for (size_t i = 0; i < param_count; i++)
        {
            param_types[i] = llvm_type(l, &type->proc.params[i]);
        }

        LLVMTypeRef return_type = llvm_type(l, type->proc.return_type);

        type->ref = LLVMFunctionType(
            return_type, param_types, param_count, type->proc.is_c_vararg);
        break;
    }
    case TYPE_STRUCT: {
        size_t field_count = array_size(type->structure.fields);
        LLVMTypeRef *field_types =
            bump_alloc(&l->compiler->bump, sizeof(LLVMTypeRef) * field_count);
        for (size_t i = 0; i < field_count; i++)
        {
            field_types[i] = llvm_type(l, type->structure.fields[i]);
        }
        type->ref = LLVMStructType(field_types, field_count, false);
        break;
    }
    case TYPE_NAMESPACE:
    case TYPE_TYPE:
    case TYPE_NONE:
    case TYPE_UNINITIALIZED: assert(0); break;
    }

    return type->ref;
}

static inline LLVMValueRef load_val(LLModule *mod, AstValue *val)
{
    LLVMValueRef ref = val->value;
    if (val->is_lvalue)
    {
        ref = LLVMBuildLoad(mod->builder, ref, "");
    }
    return ref;
}

static inline LLVMValueRef autocast_value(
    LLContext *l,
    LLModule *mod,
    TypeInfo *received,
    TypeInfo *expected,
    LLVMValueRef to_cast)
{
    if (compatible_pointer_types(received, expected) &&
        !exact_types(received, expected))
    {
        to_cast = LLVMBuildPointerCast(
            mod->builder, to_cast, llvm_type(l, expected), "");
    }
    return to_cast;
}

static inline LLVMValueRef bool_value(
    LLContext *l,
    LLModule *mod,
    LLVMValueRef value,
    TypeInfo *type,
    bool is_const)
{
    LLVMValueRef i1_val = NULL;
    if (!is_const)
    {
        switch (type->kind)
        {
        case TYPE_INT:
        case TYPE_BOOL:
            i1_val = LLVMBuildICmp(
                mod->builder,
                LLVMIntNE,
                value,
                LLVMConstInt(llvm_type(l, type), 0, false),
                "");
            break;
        case TYPE_POINTER:
            i1_val = LLVMBuildICmp(
                mod->builder,
                LLVMIntNE,
                value,
                LLVMConstPointerNull(llvm_type(l, type)),
                "");
            break;
        case TYPE_FLOAT:
            i1_val = LLVMBuildFCmp(
                mod->builder,
                LLVMRealUNE,
                value,
                LLVMConstReal(llvm_type(l, type), (double)0.0f),
                "");
            break;
        default: assert(0); break;
        }
    }
    else
    {
        switch (type->kind)
        {
        case TYPE_INT:
        case TYPE_BOOL:
            i1_val = LLVMConstICmp(
                LLVMIntNE, value, LLVMConstInt(llvm_type(l, type), 0, false));
            break;
        case TYPE_POINTER:
            i1_val = LLVMConstICmp(
                LLVMIntNE, value, LLVMConstPointerNull(llvm_type(l, type)));
            break;
        case TYPE_FLOAT:
            i1_val = LLVMConstFCmp(
                LLVMRealUNE,
                value,
                LLVMConstReal(llvm_type(l, type), (double)0.0f));
            break;
        default: assert(0); break;
        }
    }
    return i1_val;
}

static inline LLVMValueRef build_alloca(LLModule *mod, LLVMTypeRef type)
{
    LLVMBasicBlockRef current_block = LLVMGetInsertBlock(mod->builder);

    LLVMValueRef fun = LLVMGetBasicBlockParent(current_block);

    LLVMBasicBlockRef entry_block = LLVMGetEntryBasicBlock(fun);
    LLVMPositionBuilder(
        mod->builder, entry_block, LLVMGetBasicBlockTerminator(entry_block));

    LLVMValueRef alloca = LLVMBuildAlloca(mod->builder, type, "");

    LLVMPositionBuilderAtEnd(mod->builder, current_block);

    return alloca;
}

void llvm_codegen_ast_children(
    LLContext *l, LLModule *mod, Ast *asts, size_t ast_count, bool is_const);

void llvm_add_proc(LLContext *l, LLModule *mod, Ast *ast)
{
    assert(ast->type == AST_PROC_DECL);

    LLVMTypeRef fun_type = llvm_type(l, ast->type_info->ptr.sub);

    char *fun_name = bump_c_str(&l->compiler->bump, ast->proc.name);
    LLVMValueRef fun = LLVMAddFunction(mod->mod, fun_name, fun_type);
    ast->proc.value.value = fun;

    LLVMSetLinkage(fun, LLVMInternalLinkage);
    if (string_equals(ast->proc.convention, STR("c")))
    {
        LLVMSetLinkage(fun, LLVMExternalLinkage);
    }
}

void llvm_codegen_ast(
    LLContext *l, LLModule *mod, Ast *ast, bool is_const, AstValue *out_value)
{
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        array_push(l->scope_stack, ast->block.scope);
        array_push(l->operand_scope_stack, ast->block.scope);
        llvm_codegen_ast_children(
            l, mod, ast->block.stmts, array_size(ast->block.stmts), is_const);
        array_pop(l->operand_scope_stack);
        array_pop(l->scope_stack);
        break;
    }
    case AST_PROC_DECL: {
        assert(ast->type_info->kind == TYPE_POINTER);

        LLVMValueRef fun = ast->proc.value.value;
        assert(fun);

        if (ast->proc.flags & PROC_FLAG_HAS_BODY)
        {
            size_t param_count = array_size(ast->proc.params);
            for (size_t i = 0; i < param_count; i++)
            {
                Ast *param = &ast->proc.params[i];
                param->proc_param.value.is_lvalue = false;
                param->proc_param.value.value = LLVMGetParam(fun, i);

                char *param_name =
                    bump_c_str(&l->compiler->bump, param->proc_param.name);
                LLVMSetValueName(param->proc_param.value.value, param_name);
            }

            LLVMBasicBlockRef alloca_block =
                LLVMAppendBasicBlock(fun, "allocas");
            LLVMBasicBlockRef entry = LLVMAppendBasicBlock(fun, "entry");
            LLVMBasicBlockRef prev_pos = LLVMGetInsertBlock(mod->builder);

            LLVMPositionBuilderAtEnd(mod->builder, alloca_block);
            LLVMBuildBr(mod->builder, entry);

            LLVMPositionBuilderAtEnd(mod->builder, entry);

            array_push(l->scope_stack, ast->proc.scope);
            array_push(l->operand_scope_stack, ast->proc.scope);
            llvm_codegen_ast_children(
                l, mod, ast->proc.stmts, array_size(ast->proc.stmts), is_const);
            array_pop(l->operand_scope_stack);
            array_pop(l->scope_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
            {
                LLVMBuildRetVoid(mod->builder); // Add void return
            }

            LLVMPositionBuilderAtEnd(mod->builder, prev_pos);
        }

        if (out_value) *out_value = ast->proc.value;

        break;
    }
    case AST_PRIMARY: {
        switch (ast->primary.tok->type)
        {
        case TOKEN_TRUE: {
            AstValue value = {0};
            value.value = LLVMConstInt(llvm_type(l, ast->type_info), 1, false);
            if (out_value) *out_value = value;
            break;
        }
        case TOKEN_FALSE: {
            AstValue value = {0};
            value.value = LLVMConstInt(llvm_type(l, ast->type_info), 0, false);
            if (out_value) *out_value = value;
            break;
        }
        case TOKEN_NULL: {
            AstValue value = {0};
            value.value = LLVMConstPointerNull(llvm_type(l, ast->type_info));
            if (out_value) *out_value = value;
            break;
        }
        case TOKEN_INT_LIT: {
            switch (ast->type_info->kind)
            {
            case TYPE_INT: {
                AstValue value = {0};
                value.value = LLVMConstInt(
                    llvm_type(l, ast->type_info),
                    (unsigned long long)ast->primary.tok->i64,
                    true);
                if (out_value) *out_value = value;
                break;
            }
            case TYPE_FLOAT: {
                AstValue value = {0};
                value.value = LLVMConstReal(
                    llvm_type(l, ast->type_info),
                    (double)ast->primary.tok->i64);
                if (out_value) *out_value = value;
                break;
            }
            default: assert(0); break;
            }

            break;
        }
        case TOKEN_FLOAT_LIT: {
            switch (ast->type_info->kind)
            {
            case TYPE_FLOAT: {
                AstValue value = {0};
                value.value = LLVMConstReal(
                    llvm_type(l, ast->type_info),
                    (double)ast->primary.tok->f64);
                if (out_value) *out_value = value;
                break;
            }
            default: assert(0); break;
            }

            break;
        }
        case TOKEN_CSTRING_LIT: {
            LLVMValueRef glob = LLVMAddGlobal(
                mod->mod,
                LLVMArrayType(LLVMInt8Type(), ast->primary.tok->str.length),
                "");

            // set as internal linkage and constant
            LLVMSetLinkage(glob, LLVMInternalLinkage);
            LLVMSetGlobalConstant(glob, true);

            // Initialize with string:
            LLVMSetInitializer(
                glob,
                LLVMConstString(
                    ast->primary.tok->str.buf,
                    ast->primary.tok->str.length,
                    true));

            LLVMValueRef zero = LLVMConstInt(LLVMInt32Type(), 0, false);
            LLVMValueRef indices[2] = {zero, zero};

            AstValue value = {0};
            value.value = LLVMConstGEP(glob, indices, 2);
            if (out_value) *out_value = value;
            break;
        }
        case TOKEN_CHAR_LIT: {
            AstValue value = {0};
            value.value = LLVMConstInt(
                llvm_type(l, ast->type_info),
                (unsigned long long)ast->primary.tok->chr,
                true);
            if (out_value) *out_value = value;
            break;
        }
        case TOKEN_IDENT: {
            Ast *sym =
                get_symbol(*array_last(l->scope_stack), ast->primary.tok->str);
            assert(sym);

            switch (sym->type)
            {
            case AST_PROC_DECL: {
                assert(sym->proc.value.value);
                if (out_value) *out_value = sym->proc.value;
                break;
            }
            case AST_VAR_DECL:
            case AST_CONST_DECL: {
                assert(sym->decl.value.value);
                if (out_value) *out_value = sym->decl.value;
                break;
            }
            case AST_PROC_PARAM: {
                assert(sym->proc_param.value.value);
                if (out_value) *out_value = sym->proc_param.value;
                break;
            }
            case AST_STRUCT_FIELD: {
                llvm_codegen_ast(l, mod, sym, is_const, out_value);
                break;
            }
            default: assert(0); break;
            }

            break;
        }
        default: assert(0); break;
        }
        break;
    }
    case AST_PAREN_EXPR: {
        llvm_codegen_ast(l, mod, ast->expr, is_const, out_value);
        break;
    }
    case AST_PROC_CALL: {
        AstValue function_value = {0};
        llvm_codegen_ast(l, mod, ast->proc_call.expr, false, &function_value);
        LLVMValueRef fun = load_val(mod, &function_value);

        unsigned param_count = (unsigned)array_size(ast->proc_call.params);
        LLVMValueRef *params =
            bump_alloc(&l->compiler->bump, sizeof(LLVMValueRef) * param_count);

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;
        TypeInfo *proc_ty = proc_ptr_ty->ptr.sub;

        assert(array_size(l->operand_scope_stack) > 0);

        array_push(l->scope_stack, *array_last(l->operand_scope_stack));
        for (size_t i = 0; i < param_count; i++)
        {
            TypeInfo *param_expected_type = NULL;
            if (i < array_size(proc_ty->proc.params))
            {
                param_expected_type = &proc_ty->proc.params[i];
            }

            AstValue param_value = {0};
            llvm_codegen_ast(
                l, mod, &ast->proc_call.params[i], false, &param_value);
            params[i] = load_val(mod, &param_value);
            if (param_expected_type)
            {
                params[i] = autocast_value(
                    l,
                    mod,
                    ast->proc_call.params[i].type_info,
                    param_expected_type,
                    params[i]);
            }
            else if (proc_ty->proc.is_c_vararg)
            {
                // Promote float to double when passed as variadic argument
                // as per section 6.5.2.2 of the C standard
                if (ast->proc_call.params[i].type_info->kind == TYPE_FLOAT &&
                    ast->proc_call.params[i].type_info->floating.num_bits == 32)
                {
                    params[i] = LLVMBuildFPExt(
                        mod->builder, params[i], LLVMDoubleType(), "");
                }
            }
            assert(params[i]);
        }
        array_pop(l->scope_stack);

        AstValue result_value = {0};
        result_value.value =
            LLVMBuildCall(mod->builder, fun, params, param_count, "");
        if (out_value) *out_value = result_value;

        break;
    }
    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZEOF: {
            Ast *param = &ast->intrinsic_call.params[0];
            LLVMTypeRef llvm_ty = NULL;

            if (param->type_info->kind == TYPE_TYPE)
            {
                llvm_ty = llvm_type(l, param->as_type);
            }
            else
            {
                llvm_ty = llvm_type(l, param->type_info);
            }

            assert(llvm_ty);
            AstValue size_val = {0};
            size_val.value = LLVMSizeOf(llvm_ty);
            if (out_value) *out_value = size_val;

            break;
        }
        case INTRINSIC_ALIGNOF: {
            Ast *param = &ast->intrinsic_call.params[0];
            LLVMTypeRef llvm_ty = NULL;

            if (param->type_info->kind == TYPE_TYPE)
            {
                llvm_ty = llvm_type(l, param->as_type);
            }
            else
            {
                llvm_ty = llvm_type(l, param->type_info);
            }

            assert(llvm_ty);
            AstValue size_val = {0};
            size_val.value = LLVMAlignOf(llvm_ty);
            if (out_value) *out_value = size_val;

            break;
        }
        }

        break;
    }
    break;
    case AST_EXPR_STMT: {
        llvm_codegen_ast(l, mod, ast->expr, false, NULL);
        break;
    }
    case AST_CONST_DECL: {
        llvm_codegen_ast(l, mod, ast->decl.value_expr, true, &ast->decl.value);
        if (out_value) *out_value = ast->decl.value;
        break;
    }
    case AST_VAR_DECL: {
        Ast *proc = get_scope_procedure(*array_last(l->scope_stack));

        if (!proc)
        {
            assert(!ast->decl.value.value);
            LLVMTypeRef llvm_ty = llvm_type(l, ast->decl.type_expr->as_type);
            // Global variable
            ast->decl.value.is_lvalue = true;
            ast->decl.value.value = LLVMAddGlobal(mod->mod, llvm_ty, "");
            LLVMSetLinkage(ast->decl.value.value, LLVMInternalLinkage);
            LLVMSetExternallyInitialized(ast->decl.value.value, false);

            if (ast->decl.value_expr)
            {
                AstValue init_value = {0};
                llvm_codegen_ast(
                    l, mod, ast->decl.value_expr, false, &init_value);
                LLVMSetInitializer(
                    ast->decl.value.value, load_val(mod, &init_value));
            }
            else
            {
                LLVMSetInitializer(
                    ast->decl.value.value, LLVMConstNull(llvm_ty));
            }

            if (out_value) *out_value = ast->decl.value;
            break;
        }

        // Local variable
        ast->decl.value.is_lvalue = true;
        ast->decl.value.value =
            build_alloca(mod, llvm_type(l, ast->decl.type_expr->as_type));

        if (ast->decl.value_expr)
        {
            AstValue init_value = {0};
            llvm_codegen_ast(l, mod, ast->decl.value_expr, false, &init_value);

            LLVMValueRef to_store = load_val(mod, &init_value);
            to_store = autocast_value(
                l,
                mod,
                ast->decl.value_expr->type_info,
                ast->decl.type_expr->as_type,
                to_store);
            LLVMBuildStore(mod->builder, to_store, ast->decl.value.value);
        }

        if (out_value) *out_value = ast->decl.value;

        break;
    }
    case AST_VAR_ASSIGN: {
        AstValue assigned_value = {0};
        llvm_codegen_ast(
            l, mod, ast->assign.assigned_expr, false, &assigned_value);
        AstValue value = {0};
        llvm_codegen_ast(l, mod, ast->assign.value_expr, false, &value);

        LLVMValueRef to_store = load_val(mod, &value);
        to_store = autocast_value(
            l,
            mod,
            ast->assign.value_expr->type_info,
            ast->assign.assigned_expr->type_info,
            to_store);
        LLVMBuildStore(mod->builder, to_store, assigned_value.value);
        break;
    }
    case AST_RETURN: {
        Ast *proc = get_scope_procedure(*array_last(l->scope_stack));
        assert(proc);

        if (ast->expr)
        {
            AstValue return_value = {0};
            llvm_codegen_ast(l, mod, ast->expr, false, &return_value);

            LLVMValueRef ref = load_val(mod, &return_value);
            ref = autocast_value(
                l,
                mod,
                ast->expr->type_info,
                proc->proc.return_type->as_type,
                ref);
            LLVMBuildRet(mod->builder, ref);
        }
        else
        {
            LLVMBuildRetVoid(mod->builder);
        }

        break;
    }
    case AST_CAST: {
        // Check if type is castable
        TypeInfo *dest_ty = ast->cast.type_expr->as_type;
        TypeInfo *src_ty = ast->cast.value_expr->type_info;

        AstValue src_val = {0};
        llvm_codegen_ast(l, mod, ast->cast.value_expr, false, &src_val);
        LLVMValueRef src_llvm_val = load_val(mod, &src_val);

        LLVMTypeRef dest_llvm_ty = llvm_type(l, dest_ty);

        AstValue cast_val = {0};

        if (src_ty->kind == TYPE_POINTER && dest_ty->kind == TYPE_POINTER)
        {
            cast_val.value = LLVMBuildPointerCast(
                mod->builder, src_llvm_val, dest_llvm_ty, "");
        }
        else if (src_ty->kind == TYPE_INT && dest_ty->kind == TYPE_POINTER)
        {
            cast_val.value =
                LLVMBuildIntToPtr(mod->builder, src_llvm_val, dest_llvm_ty, "");
        }
        else if (src_ty->kind == TYPE_POINTER && dest_ty->kind == TYPE_INT)
        {
            cast_val.value =
                LLVMBuildPtrToInt(mod->builder, src_llvm_val, dest_llvm_ty, "");
        }
        else if (src_ty->kind == TYPE_INT && dest_ty->kind == TYPE_INT)
        {
            cast_val.value = LLVMBuildIntCast2(
                mod->builder,
                src_llvm_val,
                dest_llvm_ty,
                dest_ty->integer.is_signed,
                "");
        }
        else if (src_ty->kind == TYPE_FLOAT && dest_ty->kind == TYPE_INT)
        {
            if (dest_ty->integer.is_signed)
            {
                cast_val.value = LLVMBuildFPToSI(
                    mod->builder, src_llvm_val, dest_llvm_ty, "");
            }
            else
            {
                cast_val.value = LLVMBuildFPToUI(
                    mod->builder, src_llvm_val, dest_llvm_ty, "");
            }
        }
        else if (src_ty->kind == TYPE_INT && dest_ty->kind == TYPE_FLOAT)
        {
            if (src_ty->integer.is_signed)
            {
                cast_val.value = LLVMBuildSIToFP(
                    mod->builder, src_llvm_val, dest_llvm_ty, "");
            }
            else
            {
                cast_val.value = LLVMBuildUIToFP(
                    mod->builder, src_llvm_val, dest_llvm_ty, "");
            }
        }
        else if (src_ty->kind == TYPE_FLOAT && dest_ty->kind == TYPE_FLOAT)
        {
            cast_val.value =
                LLVMBuildFPCast(mod->builder, src_llvm_val, dest_llvm_ty, "");
        }
        else
        {
            assert(0);
        }

        if (out_value) *out_value = cast_val;

        break;
    }
    case AST_UNARY_EXPR: {
        AstValue sub_value = {0};
        llvm_codegen_ast(l, mod, ast->unop.sub, is_const, &sub_value);

        TypeInfo *op_type = ast->unop.sub->type_info;

        AstValue result_value = {0};

        switch (ast->unop.type)
        {
        case UNOP_ADDRESS: {
            if (!sub_value.is_lvalue)
            {
                result_value.value =
                    build_alloca(mod, llvm_type(l, ast->unop.sub->type_info));
                result_value.is_lvalue = false;

                LLVMBuildStore(
                    mod->builder, sub_value.value, result_value.value);
            }
            else
            {
                result_value = sub_value;
                result_value.is_lvalue = false;
            }
            break;
        }
        case UNOP_DEREFERENCE: {
            result_value.is_lvalue = true;
            result_value.value = load_val(mod, &sub_value);
            break;
        }
        case UNOP_NEG: {
            LLVMValueRef sub = load_val(mod, &sub_value);
            if (!is_const)
            {
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildNSWNeg(mod->builder, sub, "");
                    else
                        result_value.value =
                            LLVMBuildNeg(mod->builder, sub, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMBuildFNeg(mod->builder, sub, "");
                    break;
                default: assert(0); break;
                }
            }
            else
            {
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
                        result_value.value = LLVMConstNSWNeg(sub);
                    else
                        result_value.value = LLVMConstNeg(sub);
                    break;
                case TYPE_FLOAT: result_value.value = LLVMConstFNeg(sub); break;
                default: assert(0); break;
                }
            }

            break;
        }
        case UNOP_NOT: {
            LLVMValueRef sub = load_val(mod, &sub_value);
            LLVMValueRef bool_val = bool_value(l, mod, sub, op_type, is_const);

            if (!is_const)
            {
                result_value.value = LLVMBuildXor(
                    mod->builder,
                    bool_val,
                    LLVMConstInt(LLVMInt1Type(), 1, false),
                    "");
                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
            }
            else
            {
                result_value.value = LLVMConstXor(
                    bool_val, LLVMConstInt(LLVMInt1Type(), 1, false));
                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
            }

            break;
        }
        }

        if (out_value) *out_value = result_value;
        break;
    }
    case AST_SUBSCRIPT: {
        AstValue left_value = {0};
        llvm_codegen_ast(l, mod, ast->subscript.left, false, &left_value);
        AstValue right_value = {0};
        llvm_codegen_ast(l, mod, ast->subscript.right, false, &right_value);

        assert(left_value.value);
        assert(right_value.value);

        switch (ast->subscript.left->type_info->kind)
        {
        case TYPE_POINTER: {
            LLVMValueRef indices[1] = {
                load_val(mod, &right_value),
            };

            AstValue subscript_value = {0};
            subscript_value.is_lvalue = true;
            subscript_value.value = LLVMBuildGEP(
                mod->builder, load_val(mod, &left_value), indices, 1, "");
            if (out_value) *out_value = subscript_value;
            break;
        }
        case TYPE_ARRAY: {
            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt64Type(), 0, false),
                load_val(mod, &right_value),
            };

            AstValue subscript_value = {0};
            subscript_value.is_lvalue = true;
            subscript_value.value =
                LLVMBuildGEP(mod->builder, left_value.value, indices, 2, "");
            if (out_value) *out_value = subscript_value;
            break;
        }
        case TYPE_SLICE: {
            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 1; // Index for pointer field

            if (left_value.is_lvalue)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr = LLVMBuildGEP(
                    mod->builder, left_value.value, indices, 2, "");
            }
            else
            {
                LLVMValueRef indices[1] = {
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr = LLVMBuildGEP(
                    mod->builder, left_value.value, indices, 1, "");
            }

            LLVMValueRef indices[1] = {
                load_val(mod, &right_value),
            };

            AstValue subscript_value = {0};
            subscript_value.is_lvalue = true;
            subscript_value.value = LLVMBuildGEP(
                mod->builder,
                LLVMBuildLoad(mod->builder, field_ptr, ""),
                indices,
                1,
                "");

            if (out_value) *out_value = subscript_value;
            break;
        }
        default: assert(0); break;
        }

        break;
    }
    case AST_SUBSCRIPT_SLICE: {
        AstValue left_value = {0};
        llvm_codegen_ast(l, mod, ast->subscript_slice.left, false, &left_value);
        AstValue lower_value = {0};
        llvm_codegen_ast(
            l, mod, ast->subscript_slice.lower, false, &lower_value);
        AstValue upper_value = {0};
        llvm_codegen_ast(
            l, mod, ast->subscript_slice.upper, false, &upper_value);

        assert(left_value.value);
        assert(lower_value.value);
        assert(upper_value.value);

        assert(0 && "TODO");

        break;
    }
    case AST_STRUCT_FIELD: {
        AstValue struct_val = (*array_last(l->scope_stack))->value;

        LLVMValueRef indices[2] = {
            LLVMConstInt(LLVMInt32Type(), 0, false),
            LLVMConstInt(LLVMInt32Type(), ast->field.index, false),
        };

        AstValue field_value = {0};
        field_value.is_lvalue = true;
        field_value.value =
            LLVMBuildGEP(mod->builder, struct_val.value, indices, 2, "");
        if (out_value) *out_value = field_value;

        break;
    }
    case AST_ACCESS: {
        assert(array_size(l->scope_stack) > 0);

        switch (ast->access.left->type_info->kind)
        {
        case TYPE_SLICE: {
            AstValue slice_value = {0};
            llvm_codegen_ast(l, mod, ast->access.left, false, &slice_value);

            Ast *right = get_inner_expr(ast->access.right);
            assert(right->type == AST_PRIMARY);
            assert(right->primary.tok->type == TOKEN_IDENT);

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 0;
            if (string_equals(right->primary.tok->str, STR("len")))
            {
                field_index = 0;
            }
            else if (string_equals(right->primary.tok->str, STR("ptr")))
            {
                field_index = 1;
            }

            if (slice_value.is_lvalue)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr = LLVMBuildGEP(
                    mod->builder, slice_value.value, indices, 2, "");
            }
            else
            {
                LLVMValueRef indices[1] = {
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr = LLVMBuildGEP(
                    mod->builder, slice_value.value, indices, 1, "");
            }

            AstValue result_value = {0};
            result_value.is_lvalue = true;
            result_value.value = field_ptr;

            if (out_value) *out_value = result_value;

            break;
        }
        default: {
            Scope *accessed_scope = get_expr_scope(
                l->compiler, *array_last(l->scope_stack), ast->access.left);

            switch (accessed_scope->type)
            {
            case SCOPE_DEFAULT: {
                array_push(l->scope_stack, accessed_scope);
                llvm_codegen_ast(l, mod, ast->access.right, false, out_value);
                array_pop(l->scope_stack);
                break;
            }
            case SCOPE_STRUCT: {
                // Create a copy of the scope for this instance of the struct
                Scope instance_scope = *accessed_scope;

                AstValue accessed_value = {0};
                llvm_codegen_ast(
                    l, mod, ast->access.left, false, &accessed_value);

                if (ast->access.left->type_info->kind == TYPE_POINTER)
                {
                    accessed_value.value = load_val(mod, &accessed_value);
                }

                instance_scope.value = accessed_value;

                array_push(l->scope_stack, &instance_scope);
                llvm_codegen_ast(l, mod, ast->access.right, false, out_value);
                array_pop(l->scope_stack);
                break;
            }
            }
            break;
        }
        }

        break;
    }
    case AST_BINARY_EXPR: {
        AstValue left_val = {0};
        AstValue right_val = {0};
        llvm_codegen_ast(l, mod, ast->binop.left, is_const, &left_val);
        llvm_codegen_ast(l, mod, ast->binop.right, is_const, &right_val);

        TypeInfo *lhs_type = ast->binop.left->type_info;
        TypeInfo *rhs_type = ast->binop.right->type_info;

        AstValue result_value = {0};

        LLVMValueRef lhs_ptr = left_val.value;

        LLVMValueRef lhs = NULL;
        LLVMValueRef rhs = NULL;

        switch (ast->binop.type)
        {
        case BINOP_AND:
        case BINOP_OR: break;
        default:
            lhs = load_val(mod, &left_val);
            rhs = load_val(mod, &right_val);
            break;
        }

        if (!is_const)
        {
            switch (ast->binop.type)
            {
            case BINOP_ADD: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildNSWAdd(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildAdd(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_FLOAT: {
                    result_value.value =
                        LLVMBuildFAdd(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_SUB: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildNSWSub(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildSub(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_FLOAT: {
                    result_value.value =
                        LLVMBuildFSub(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_MUL: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildNSWMul(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildMul(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_FLOAT: {
                    result_value.value =
                        LLVMBuildFMul(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_DIV: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildSDiv(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildUDiv(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_FLOAT: {
                    result_value.value =
                        LLVMBuildFDiv(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_MOD: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildSRem(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildURem(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_FLOAT: {
                    result_value.value =
                        LLVMBuildFRem(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }

                break;
            }
            case BINOP_BITAND: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value =
                        LLVMBuildAnd(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_BITOR: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value =
                        LLVMBuildOr(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_BITXOR: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value =
                        LLVMBuildXor(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_LSHIFT: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value =
                        LLVMBuildShl(mod->builder, lhs, rhs, "");
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_RSHIFT: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMBuildAShr(mod->builder, lhs, rhs, "");
                    else
                        result_value.value =
                            LLVMBuildLShr(mod->builder, lhs, rhs, "");
                    break;
                }
                case TYPE_BOOL:
                    result_value.value =
                        LLVMBuildLShr(mod->builder, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_EQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntEQ, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntEQ, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealOEQ, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_NOTEQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntNE, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntNE, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealUNE, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_GREATER: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntSGT, lhs, rhs, "");
                    else
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntUGT, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntUGT, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealOGT, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_GREATEREQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntSGE, lhs, rhs, "");
                    else
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntUGE, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntUGE, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealOGE, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_LESS: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntSLT, lhs, rhs, "");
                    else
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntULT, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntULT, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealOLT, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_LESSEQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntSLE, lhs, rhs, "");
                    else
                        result_value.value = LLVMBuildICmp(
                            mod->builder, LLVMIntULE, lhs, rhs, "");
                    break;
                case TYPE_BOOL:
                case TYPE_POINTER:
                    result_value.value =
                        LLVMBuildICmp(mod->builder, LLVMIntULE, lhs, rhs, "");
                    break;
                case TYPE_FLOAT:
                    result_value.value =
                        LLVMBuildFCmp(mod->builder, LLVMRealOLE, lhs, rhs, "");
                    break;
                default: assert(0); break;
                }

                result_value.value = LLVMBuildZExt(
                    mod->builder, result_value.value, LLVMInt8Type(), "");
                break;
            }
            case BINOP_OR:
            case BINOP_AND: {
                lhs = load_val(mod, &left_val);
                LLVMValueRef lhs_bool =
                    bool_value(l, mod, lhs, lhs_type, is_const);

                LLVMValueRef fun =
                    LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
                assert(fun);

                LLVMBasicBlockRef prev_bb = LLVMGetInsertBlock(mod->builder);
                LLVMBasicBlockRef then_bb = LLVMAppendBasicBlock(fun, "");
                LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");

                switch (ast->binop.type)
                {
                case BINOP_AND:
                    LLVMBuildCondBr(mod->builder, lhs_bool, then_bb, merge_bb);
                    break;
                case BINOP_OR:
                    LLVMBuildCondBr(mod->builder, lhs_bool, merge_bb, then_bb);
                    break;
                default: assert(0); break;
                }

                // Then
                LLVMPositionBuilderAtEnd(mod->builder, then_bb);

                rhs = load_val(mod, &right_val);
                LLVMValueRef rhs_bool =
                    bool_value(l, mod, rhs, rhs_type, is_const);

                LLVMBuildBr(mod->builder, merge_bb);

                // Merge
                LLVMPositionBuilderAtEnd(mod->builder, merge_bb);
                LLVMValueRef phi =
                    LLVMBuildPhi(mod->builder, LLVMInt1Type(), "");

                LLVMValueRef phi_values[2];
                LLVMBasicBlockRef phi_blocks[2];

                switch (ast->binop.type)
                {
                case BINOP_AND:
                    phi_values[0] = LLVMConstInt(LLVMInt1Type(), 0, false);
                    phi_blocks[0] = prev_bb;
                    phi_values[1] = rhs_bool;
                    phi_blocks[1] = then_bb;
                    break;
                case BINOP_OR:
                    phi_values[0] = LLVMConstInt(LLVMInt1Type(), 1, false);
                    phi_blocks[0] = prev_bb;
                    phi_values[1] = rhs_bool;
                    phi_blocks[1] = then_bb;
                    break;
                default: assert(0); break;
                }

                LLVMAddIncoming(phi, phi_values, phi_blocks, 2);

                result_value.value =
                    LLVMBuildZExt(mod->builder, phi, LLVMInt8Type(), "");

                break;
            }
            }

            // For the assignment operators
            if (ast->binop.assign && left_val.is_lvalue)
            {
                LLVMBuildStore(mod->builder, result_value.value, lhs_ptr);
            }
        }
        else
        {
            switch (ast->binop.type)
            {
            case BINOP_ADD: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstNSWAdd(lhs, rhs);
                    else
                        result_value.value = LLVMConstAdd(lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFAdd(lhs, rhs);
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_SUB: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstNSWSub(lhs, rhs);
                    else
                        result_value.value = LLVMConstSub(lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFSub(lhs, rhs);
                    break;

                default: assert(0); break;
                }
                break;
            }
            case BINOP_MUL: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstNSWMul(lhs, rhs);
                    else
                        result_value.value = LLVMConstMul(lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFMul(lhs, rhs);
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_DIV: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstSDiv(lhs, rhs);
                    else
                        result_value.value = LLVMConstUDiv(lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFDiv(lhs, rhs);
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_MOD: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstSRem(lhs, rhs);
                    else
                        result_value.value = LLVMConstURem(lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFRem(lhs, rhs);
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_BITAND: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value = LLVMConstAnd(lhs, rhs);
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_BITOR: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value = LLVMConstOr(lhs, rhs);
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_BITXOR: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value = LLVMConstXor(lhs, rhs);
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_LSHIFT: {
                switch (lhs_type->kind)
                {
                case TYPE_BOOL:
                case TYPE_INT: {
                    result_value.value = LLVMConstShl(lhs, rhs);
                    break;
                }
                default: assert(0); break;
                }
                break;
            }
            case BINOP_RSHIFT: {
                switch (lhs_type->kind)
                {
                case TYPE_INT: {
                    if (lhs_type->integer.is_signed)
                        result_value.value = LLVMConstAShr(lhs, rhs);
                    else
                        result_value.value = LLVMConstLShr(lhs, rhs);
                    break;
                }
                case TYPE_BOOL:
                    result_value.value = LLVMConstLShr(lhs, rhs);
                    break;
                default: assert(0); break;
                }
                break;
            }
            case BINOP_EQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    result_value.value = LLVMConstICmp(LLVMIntEQ, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntEQ, lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFCmp(LLVMRealOEQ, lhs, rhs);
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_NOTEQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    result_value.value = LLVMConstICmp(LLVMIntNE, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntNE, lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFCmp(LLVMRealUNE, lhs, rhs);
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_GREATER: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMConstICmp(LLVMIntSGT, lhs, rhs);
                    else
                        result_value.value =
                            LLVMConstICmp(LLVMIntUGT, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntUGT, lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFCmp(LLVMRealOGT, lhs, rhs);
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_GREATEREQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMConstICmp(LLVMIntSGE, lhs, rhs);
                    else
                        result_value.value =
                            LLVMConstICmp(LLVMIntUGE, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntUGE, lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFCmp(LLVMRealOGE, lhs, rhs);
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_LESS: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMConstICmp(LLVMIntSLT, lhs, rhs);
                    else
                        result_value.value =
                            LLVMConstICmp(LLVMIntULT, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntULT, lhs, rhs);
                    break;
                case TYPE_FLOAT:
                    result_value.value = LLVMConstFCmp(LLVMRealOLT, lhs, rhs);
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_LESSEQ: {
                switch (lhs_type->kind)
                {
                case TYPE_INT:
                    if (lhs_type->integer.is_signed)
                        result_value.value =
                            LLVMConstICmp(LLVMIntSLE, lhs, rhs);
                    else
                        result_value.value =
                            LLVMConstICmp(LLVMIntULE, lhs, rhs);
                    break;
                case TYPE_BOOL:
                    result_value.value = LLVMConstICmp(LLVMIntULE, lhs, rhs);
                    break;
                    break;
                default: assert(0); break;
                }

                result_value.value =
                    LLVMConstZExt(result_value.value, LLVMInt8Type());
                break;
            }
            case BINOP_AND:
            case BINOP_OR: assert(0); break;
            }
        }

        if (out_value) *out_value = result_value;

        break;
    }
    case AST_IF: {
        AstValue cond_val = {0};
        llvm_codegen_ast(l, mod, ast->if_stmt.cond_expr, false, &cond_val);

        TypeInfo *cond_type = ast->if_stmt.cond_expr->type_info;
        LLVMValueRef cond = load_val(mod, &cond_val);
        LLVMValueRef bool_val = bool_value(l, mod, cond, cond_type, is_const);

        LLVMValueRef fun =
            LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
        assert(fun);

        LLVMBasicBlockRef then_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef else_bb = NULL;
        if (ast->if_stmt.else_stmt)
        {
            else_bb = LLVMAppendBasicBlock(fun, "");
        }
        LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");
        if (!else_bb) else_bb = merge_bb;

        LLVMBuildCondBr(mod->builder, bool_val, then_bb, else_bb);

        // Then
        {
            LLVMPositionBuilderAtEnd(mod->builder, then_bb);

            llvm_codegen_ast(l, mod, ast->if_stmt.cond_stmt, false, NULL);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
            {
                LLVMBuildBr(mod->builder, merge_bb);
            }
        }

        // Else
        if (ast->if_stmt.else_stmt)
        {
            LLVMPositionBuilderAtEnd(mod->builder, else_bb);

            llvm_codegen_ast(l, mod, ast->if_stmt.else_stmt, false, NULL);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, merge_bb);
        }

        // Merge
        LLVMPositionBuilderAtEnd(mod->builder, merge_bb);

        break;
    }
    case AST_WHILE: {
        LLVMValueRef fun =
            LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
        assert(fun);

        LLVMBasicBlockRef cond_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef stmts_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");

        LLVMBuildBr(mod->builder, cond_bb);

        // Cond
        {
            LLVMPositionBuilderAtEnd(mod->builder, cond_bb);

            AstValue cond_val = {0};
            llvm_codegen_ast(l, mod, ast->while_stmt.cond, false, &cond_val);

            TypeInfo *cond_type = ast->while_stmt.cond->type_info;

            LLVMValueRef bool_val = bool_value(
                l, mod, load_val(mod, &cond_val), cond_type, is_const);

            LLVMBuildCondBr(mod->builder, bool_val, stmts_bb, merge_bb);
        }

        // Stmts
        {
            LLVMPositionBuilderAtEnd(mod->builder, stmts_bb);

            array_push(l->break_block_stack, merge_bb);
            array_push(l->continue_block_stack, cond_bb);
            llvm_codegen_ast(l, mod, ast->while_stmt.stmt, false, NULL);
            array_pop(l->continue_block_stack);
            array_pop(l->break_block_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, cond_bb);
        }

        // Merge
        LLVMPositionBuilderAtEnd(mod->builder, merge_bb);

        break;
    }
    case AST_FOR: {
        array_push(l->scope_stack, ast->for_stmt.scope);
        array_push(l->operand_scope_stack, ast->for_stmt.scope);

        LLVMValueRef fun =
            LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
        assert(fun);

        if (ast->for_stmt.init)
            llvm_codegen_ast(l, mod, ast->for_stmt.init, false, NULL);

        LLVMBasicBlockRef cond_bb = NULL;
        if (ast->for_stmt.cond) cond_bb = LLVMAppendBasicBlock(fun, "");

        LLVMBasicBlockRef stmts_bb = LLVMAppendBasicBlock(fun, "");

        LLVMBasicBlockRef inc_bb = NULL;
        if (ast->for_stmt.inc) inc_bb = LLVMAppendBasicBlock(fun, "");

        LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");

        if (!cond_bb) cond_bb = stmts_bb;
        if (!inc_bb) inc_bb = stmts_bb;

        LLVMBuildBr(mod->builder, cond_bb);

        // Cond
        if (ast->for_stmt.cond)
        {
            LLVMPositionBuilderAtEnd(mod->builder, cond_bb);

            AstValue cond_val = {0};
            llvm_codegen_ast(l, mod, ast->for_stmt.cond, false, &cond_val);

            TypeInfo *cond_type = ast->for_stmt.cond->type_info;

            LLVMValueRef bool_val = bool_value(
                l, mod, load_val(mod, &cond_val), cond_type, is_const);

            LLVMBuildCondBr(mod->builder, bool_val, stmts_bb, merge_bb);
        }

        // Stmts
        {
            LLVMPositionBuilderAtEnd(mod->builder, stmts_bb);

            array_push(l->break_block_stack, merge_bb);
            array_push(l->continue_block_stack, inc_bb);
            llvm_codegen_ast(l, mod, ast->for_stmt.stmt, false, NULL);
            array_pop(l->continue_block_stack);
            array_pop(l->break_block_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, inc_bb);
        }

        // Inc
        if (ast->for_stmt.inc)
        {
            LLVMPositionBuilderAtEnd(mod->builder, inc_bb);

            if (ast->for_stmt.inc)
                llvm_codegen_ast(l, mod, ast->for_stmt.inc, false, NULL);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, cond_bb);
        }

        // Merge
        LLVMPositionBuilderAtEnd(mod->builder, merge_bb);

        array_pop(l->operand_scope_stack);
        array_pop(l->scope_stack);
        break;
    }
    case AST_BREAK: {
        LLVMBasicBlockRef *break_block = array_last(l->break_block_stack);
        assert(break_block);
        LLVMBuildBr(mod->builder, *break_block);
        break;
    }
    case AST_CONTINUE: {
        LLVMBasicBlockRef *continue_block = array_last(l->continue_block_stack);
        assert(continue_block);
        LLVMBuildBr(mod->builder, *continue_block);
        break;
    }
    case AST_PROC_TYPE: break;
    case AST_IMPORT: break;
    case AST_TYPEDEF: break;
    default: assert(0); break;
    }
}

void llvm_codegen_ast_children(
    LLContext *l, LLModule *mod, Ast *asts, size_t ast_count, bool is_const)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: llvm_add_proc(l, mod, ast); break;
        default: break;
        }
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_CONST_DECL:
        case AST_PROC_DECL:
        case AST_TYPEDEF: llvm_codegen_ast(l, mod, ast, is_const, NULL); break;
        case AST_VAR_DECL: {
            Ast *proc = get_scope_procedure(*array_last(l->scope_stack));
            if (!proc)
            {
                llvm_codegen_ast(l, mod, ast, is_const, NULL);
            }
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
        case AST_PROC_DECL:
        case AST_TYPEDEF: break;
        case AST_VAR_DECL: {
            Ast *proc = get_scope_procedure(*array_last(l->scope_stack));
            if (proc)
            {
                llvm_codegen_ast(l, mod, ast, is_const, NULL);
            }
            break;
        }
        default: llvm_codegen_ast(l, mod, ast, is_const, NULL); break;
        }

        if (ast->type == AST_RETURN || ast->type == AST_BREAK ||
            ast->type == AST_CONTINUE)
        {
            break;
        }
    }
}

void llvm_init(LLContext *l, Compiler *compiler)
{
    l->compiler = compiler;

    memset(&l->mod, 0, sizeof(l->mod));
    l->mod.mod = LLVMModuleCreateWithName("main");
    l->mod.builder = LLVMCreateBuilder();
    l->mod.data = LLVMGetModuleDataLayout(l->mod.mod);
}

void llvm_verify_module(LLContext *l)
{
    printf("%s\n", LLVMPrintModuleToString(l->mod.mod));

    char *error = NULL;
    if (LLVMVerifyModule(l->mod.mod, LLVMReturnStatusAction, &error))
    {
        printf("Failed to verify module:\n%s\n", error);
        abort();
    }
}

void llvm_run_module(LLContext *l)
{
    LLVMExecutionEngineRef engine;
    char *error = NULL;

    LLVMLinkInMCJIT();
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    if (LLVMCreateExecutionEngineForModule(&engine, l->mod.mod, &error) != 0)
    {
        fprintf(stderr, "failed to create execution engine\n");
        abort();
    }

    if (error)
    {
        fprintf(stderr, "error: %s\n", error);
        LLVMDisposeMessage(error);
        exit(EXIT_FAILURE);
    }

    void (*main_func)() = (void (*)())LLVMGetFunctionAddress(engine, "main");
    if (main_func)
    {
        main_func();
    }
}
// }}}

// File processing {{{
SourceFile *process_file(Compiler *compiler, String absolute_path);

void process_imports(Compiler *compiler, SourceFile *file, Ast *ast)
{
    switch (ast->type)
    {
    case AST_IMPORT: {
        char *c_imported = bump_c_str(&compiler->bump, ast->import.path);
        static char *core_prefix = "core:";

        String abs_path = {0};

        if (strncmp(c_imported, core_prefix, strlen(core_prefix)) == 0)
        {
            // Core import

            char *file_name_without_extension =
                c_imported + strlen(core_prefix);

            String import_file_name = bump_str_join(
                &compiler->bump,
                CSTR(file_name_without_extension),
                CSTR(LANG_FILE_EXTENSION));

            abs_path = bump_str_join(
                &compiler->bump, compiler->corelib_dir, import_file_name);
        }
        else
        {
            // Relative import
            char *c_dir = get_file_dir(bump_c_str(&compiler->bump, file->path));

            size_t new_path_size = strlen(c_dir) + 1 + strlen(c_imported) + 1;
            char *c_new_path = bump_alloc(&compiler->bump, new_path_size);
            snprintf(c_new_path, new_path_size, "%s/%s", c_dir, c_imported);

            // Normalize the path
            char *c_abs_path = get_absolute_path(c_new_path);
            abs_path = CSTR(c_abs_path);
        }

        ast->import.abs_path = abs_path;
        process_file(compiler, abs_path);
        break;
    }
    default: break;
    }

    // Analyze children ASTs
    switch (ast->type)
    {
    case AST_ROOT: {
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            process_imports(compiler, file, stmt);
        }
        break;
    }
    case AST_PROC_DECL: {
        for (Ast *stmt = ast->block.stmts;
             stmt != ast->block.stmts + array_size(ast->block.stmts);
             ++stmt)
        {
            process_imports(compiler, file, stmt);
        }
        break;
    }
    default: break;
    }
}

SourceFile *process_file(Compiler *compiler, String absolute_path)
{
    /* printf( */
    /*     "Processing file: '%.*s'\n", */
    /*     (int)absolute_path.length, */
    /*     absolute_path.buf); */

    SourceFile *file = hash_get(&compiler->files, absolute_path);
    if (file)
    {
        return file;
    }

    file = bump_alloc(&compiler->bump, sizeof(*file));
    source_file_init(file, compiler, absolute_path);

    hash_set(&compiler->files, absolute_path, file);

    Lexer *lexer = bump_alloc(&compiler->bump, sizeof(*lexer));
    lex_file(lexer, compiler, file);
    print_errors(compiler);

    Parser *parser = bump_alloc(&compiler->bump, sizeof(*parser));
    parse_file(parser, compiler, lexer);
    print_errors(compiler);
    file->root = parser->ast;

    process_imports(compiler, file, parser->ast);

    Analyzer *analyzer = bump_alloc(&compiler->bump, sizeof(*analyzer));
    memset(analyzer, 0, sizeof(*analyzer));
    analyzer->compiler = compiler;

    create_scopes_ast(analyzer, parser->ast);
    print_errors(compiler);

    register_symbol_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    symbol_check_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    type_check_asts(analyzer, parser->ast, 1);
    print_errors(compiler);

    llvm_codegen_ast(
        compiler->backend, &compiler->backend->mod, file->root, false, NULL);

    return file;
}
// }}}

void compile_file(Compiler *compiler, String filepath)
{
    LLContext *llvm_context =
        bump_alloc(&compiler->bump, sizeof(*llvm_context));
    memset(llvm_context, 0, sizeof(*llvm_context));
    llvm_init(llvm_context, compiler);
    compiler->backend = llvm_context;

    process_file(compiler, filepath);

    llvm_verify_module(llvm_context);
}

void link_module(Compiler *compiler, LLModule *mod, String out_file_path)
{
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmParsers();
    LLVMInitializeAllAsmPrinters();

    char *triple = LLVMGetDefaultTargetTriple();

    LLVMTargetRef target;
    char *error = NULL;
    if (LLVMGetTargetFromTriple(triple, &target, &error))
    {
        fprintf(stderr, "Failed to get target from triple: %s", error);
        exit(1);
    }

    char *cpu = "generic";
    char *features = "";
    LLVMTargetMachineRef target_machine = LLVMCreateTargetMachine(
        target,
        triple,
        cpu,
        features,
        LLVMCodeGenLevelNone,
        LLVMRelocDefault,
        LLVMCodeModelDefault);

    LLVMTargetDataRef data_layout = LLVMCreateTargetDataLayout(target_machine);
    char *data_layout_str = LLVMCopyStringRepOfTargetData(data_layout);

    LLVMSetDataLayout(mod->mod, data_layout_str);
    LLVMSetTarget(mod->mod, triple);

    if (LLVMTargetMachineEmitToFile(
            target_machine, mod->mod, TMP_OBJECT_NAME, LLVMObjectFile, &error))
    {
        remove(TMP_OBJECT_NAME);
        fprintf(stderr, "LLVM codegen error: %s", error);
        exit(1);
    }

    char *c_out_file_path = bump_c_str(&compiler->bump, out_file_path);

    pid_t pid = fork();
    if (pid == 0)
    {
        execlp("clang", "clang", TMP_OBJECT_NAME, "-o", c_out_file_path, NULL);
    }

    int status;
    waitpid(pid, &status, 0);
    if (status != 0)
    {
        remove(TMP_OBJECT_NAME);
        fprintf(stderr, "Linking failed!\n");
        exit(status);
    }

    remove(TMP_OBJECT_NAME);
}

static const char *COMPILER_USAGE[] = {
    "Usage:\n",
    "  %s <filename>        Compiles file.\n",
    "  %s run <filename>    Runs file.\n",
    NULL,
};

void print_usage(int argc, char **argv)
{
    const char **line = COMPILER_USAGE;
    while (*line)
    {
        fprintf(stderr, *line, argv[0]);
        line++;
    }
}

int main(int argc, char **argv)
{
    Compiler *compiler = malloc(sizeof(*compiler));
    compiler_init(compiler);

    if (argc <= 1)
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    if (argc == 2)
    {
        char *absolute_path = get_absolute_path(argv[1]);
        String filepath = CSTR(absolute_path);
        compile_file(compiler, filepath);
        link_module(compiler, &compiler->backend->mod, STR("a.out"));
    }
    else if (argc == 3)
    {
        if (strcmp(argv[1], "run") == 0)
        {
            char *absolute_path = get_absolute_path(argv[2]);
            String filepath = CSTR(absolute_path);
            compile_file(compiler, filepath);
            llvm_run_module(compiler->backend);
        }
    }
    else
    {
        print_usage(argc, argv);
        exit(EXIT_FAILURE);
    }

    compiler_destroy(compiler);
    free(compiler);
    return EXIT_SUCCESS;
}
