typedef struct SourceFile
{
    String path;
    String module_name;
    String content;
    struct Ast *root;
    struct Ast* main_function_ast;
    bool did_codegen;

    LLVMMetadataRef di_file;
    LLVMMetadataRef di_cu;
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

typedef ARRAY_OF(Error) ArrayOfError;
