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
        else if (lex_peek(l, 0) == '>')
        {
            ++tok.loc.length;
            lex_next(l, 1);
            tok.type = TOKEN_ARROW;
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
    case '_': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_UNDERSCORE;
        break;
    }
    case '.': {
        tok.loc.length = 1;
        lex_next(l, 1);
        tok.type = TOKEN_DOT;
        if (lex_peek(l, 0) == '.')
        {
            lex_next(l, 1);
            tok.type = TOKEN_DOTDOT;
            tok.loc.length = 2;
            if (lex_peek(l, 0) == '.')
            {
                lex_next(l, 1);
                tok.type = TOKEN_ELLIPSIS;
                tok.loc.length = 3;
            }
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

            LEX_MATCH_STR("byte", TOKEN_U8);
            LEX_MATCH_STR("int", TOKEN_INT);
            LEX_MATCH_STR("uint", TOKEN_UINT);

            LEX_MATCH_STR("var", TOKEN_VAR);
            LEX_MATCH_STR("const", TOKEN_CONST);
            LEX_MATCH_STR("fn", TOKEN_FN);
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
            LEX_MATCH_STR("extern", TOKEN_EXTERN);
            LEX_MATCH_STR("distinct", TOKEN_DISTINCT);
            LEX_MATCH_STR("dynamic", TOKEN_DYNAMIC);
            LEX_MATCH_STR("static", TOKEN_STATIC);
            LEX_MATCH_STR("version", TOKEN_VERSION);
            LEX_MATCH_STR("pub", TOKEN_PUB);

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
            char *dot_ptr = NULL;

            while (is_numeric(tok.loc.buf[tok.loc.length]) ||
                   tok.loc.buf[tok.loc.length] == '.')
            {
                if (tok.loc.buf[tok.loc.length] == '.')
                {
                    if (!is_numeric(tok.loc.buf[tok.loc.length + 1])) break;
                    assert(!dot_ptr);
                    dot_ptr = &tok.loc.buf[tok.loc.length];
                }

                tok.loc.length++;
            }

            l->col += tok.loc.length;

            lex_next(l, tok.loc.length);

            char *str = bump_c_str(
                &l->compiler->bump,
                (String){.buf = tok.loc.buf, .length = tok.loc.length});

            if (dot_ptr)
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
