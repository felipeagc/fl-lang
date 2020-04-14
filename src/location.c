typedef struct SourceFile
{
    String path;
    String content;
    struct Ast *root;
    bool did_codegen;
} SourceFile;

typedef struct Location
{
    SourceFile *file;
    char *buf;
    uint32_t length;
    uint32_t line;
    uint32_t col;
} Location;

typedef struct Error
{
    Location loc;
    String message;
} Error;

