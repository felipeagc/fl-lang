typedef enum TokenKind {
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACK,
    TOKEN_RBRACK,
    TOKEN_LCURLY,
    TOKEN_RCURLY,

    TOKEN_HASH,
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

    TOKEN_ARROW, // ->

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
    TOKEN_STRING_LIT,
    TOKEN_CSTRING_LIT,
    TOKEN_CHAR_LIT,
    TOKEN_EXTERN,
    TOKEN_FN,
    TOKEN_MODULE,
    TOKEN_IN,
    TOKEN_CAST,
    TOKEN_IMPORT,
    TOKEN_TYPEDEF,
    TOKEN_STRUCT,
    TOKEN_UNION,
    TOKEN_ENUM,
    TOKEN_FOR,
    TOKEN_WHILE,
    TOKEN_SWITCH,
    TOKEN_CASE,
    TOKEN_DEFAULT,
    TOKEN_BREAK,
    TOKEN_CONTINUE,
    TOKEN_IF,
    TOKEN_ELSE,
    TOKEN_RETURN,
    TOKEN_CONST,
    TOKEN_VAR,
    TOKEN_DYN,
    TOKEN_STATIC,
    TOKEN_VERSION,
    TOKEN_PUB,
    TOKEN_USING,
    TOKEN_DEFER,
    TOKEN_STRING,
    TOKEN_ANY,

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

    TOKEN_INT,
    TOKEN_UINT,
} TokenKind;

static const char *token_strings[] = {
    [TOKEN_LPAREN] = "(",
    [TOKEN_RPAREN] = ")",
    [TOKEN_LBRACK] = "[",
    [TOKEN_RBRACK] = "]",
    [TOKEN_LCURLY] = "{",
    [TOKEN_RCURLY] = "}",

    [TOKEN_HASH] = "#",

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

    [TOKEN_ARROW] = "->",

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
    [TOKEN_STRING_LIT] = "string literal",
    [TOKEN_CSTRING_LIT] = "c-string literal",
    [TOKEN_CHAR_LIT] = "char literal",
    [TOKEN_FN] = "func",
    [TOKEN_MODULE] = "module",
    [TOKEN_IN] = "in",
    [TOKEN_EXTERN] = "extern",
    [TOKEN_CAST] = "cast",
    [TOKEN_IMPORT] = "import",
    [TOKEN_TYPEDEF] = "typedef",
    [TOKEN_STRUCT] = "struct",
    [TOKEN_UNION] = "union",
    [TOKEN_ENUM] = "enum",
    [TOKEN_FOR] = "for",
    [TOKEN_WHILE] = "while",
    [TOKEN_SWITCH] = "switch",
    [TOKEN_CASE] = "case",
    [TOKEN_DEFAULT] = "default",
    [TOKEN_BREAK] = "break",
    [TOKEN_CONTINUE] = "continue",
    [TOKEN_IF] = "if",
    [TOKEN_ELSE] = "else",
    [TOKEN_RETURN] = "return",
    [TOKEN_CONST] = "const",
    [TOKEN_VAR] = "var",
    [TOKEN_DYN] = "dyn",
    [TOKEN_STATIC] = "static",
    [TOKEN_VERSION] = "version",
    [TOKEN_PUB] = "pub",
    [TOKEN_USING] = "using",
    [TOKEN_DEFER] = "defer",
    [TOKEN_STRING] = "string",
    [TOKEN_ANY] = "any",

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

    [TOKEN_INT] = "int",
    [TOKEN_UINT] = "uint",
};

typedef struct Token
{
    TokenKind type;
    Location loc;
    union
    {
        double f64;
        int64_t i64;
        String str;
        char chr;
    };
} Token;

typedef ARRAY_OF(Token) ArrayOfToken;
