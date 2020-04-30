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

        PRINT_TOKEN_TYPE(TOKEN_HASH);

        PRINT_TOKEN_TYPE(TOKEN_SEMICOLON);
        PRINT_TOKEN_TYPE(TOKEN_COLON);
        PRINT_TOKEN_TYPE(TOKEN_UNDERSCORE);

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
        PRINT_TOKEN_TYPE(TOKEN_DOTDOT);
        PRINT_TOKEN_TYPE(TOKEN_ELLIPSIS);
        PRINT_TOKEN_TYPE(TOKEN_COMMA);

        PRINT_TOKEN_TYPE(TOKEN_ARROW);
        PRINT_TOKEN_TYPE(TOKEN_FAT_ARROW);

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
        PRINT_TOKEN_TYPE(TOKEN_FN);
        PRINT_TOKEN_TYPE(TOKEN_IN);
        PRINT_TOKEN_TYPE(TOKEN_EXTERN);
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
        PRINT_TOKEN_TYPE(TOKEN_DISTINCT);
        PRINT_TOKEN_TYPE(TOKEN_DYN);
        PRINT_TOKEN_TYPE(TOKEN_STATIC);
        PRINT_TOKEN_TYPE(TOKEN_VERSION);
        PRINT_TOKEN_TYPE(TOKEN_PUB);
        PRINT_TOKEN_TYPE(TOKEN_USING);
        PRINT_TOKEN_TYPE(TOKEN_DEFER);
        PRINT_TOKEN_TYPE(TOKEN_STRING);

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

        PRINT_TOKEN_TYPE(TOKEN_INT);
        PRINT_TOKEN_TYPE(TOKEN_UINT);

        PRINT_TOKEN_TYPE(TOKEN_STRING_LIT);
        PRINT_TOKEN_TYPE(TOKEN_CSTRING_LIT);
        PRINT_TOKEN_TYPE(TOKEN_CHAR_LIT);
    }

    printf(" \"%.*s\"\n", (int)tok->loc.length, tok->loc.buf);
}
