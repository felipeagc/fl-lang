typedef struct LLModule LLModule;
typedef struct TypeInfo TypeInfo;
typedef ARRAY_OF(TypeInfo *) ArrayOfTypeInfoPtr;
typedef struct Ast Ast;
typedef struct Scope Scope;

typedef struct SourceFile
{
    String path;
    String module_name;
    String content;
    Ast *root;
    Ast* main_function_ast;
    bool did_codegen;

    LLVMMetadataRef di_file;
    LLVMMetadataRef di_cu;
} SourceFile;

typedef ARRAY_OF(SourceFile*) ArrayOfSourceFilePtr;

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

typedef struct Module
{
    HashMap symbol_names;
} Module;

typedef struct Compiler
{
    BumpAlloc bump;
    StringBuilder sb;

    ArrayOfError errors;
    HashMap files;
    HashMap versions;
    HashMap modules;
    HashMap types;
    HashMap extern_symbols;
    struct LLContext *backend;
    String compiler_path;
    String compiler_dir;
    String corelib_dir;

    Arguments args;

    Ast *runtime_module;

    ArrayOfTypeInfoPtr rtti_type_infos;

    struct TypeInfo *type_info_type;

    struct TypeInfo *u8_type;
    struct TypeInfo *u16_type;
    struct TypeInfo *u32_type;
    struct TypeInfo *u64_type;

    struct TypeInfo *i8_type;
    struct TypeInfo *i16_type;
    struct TypeInfo *i32_type;
    struct TypeInfo *i64_type;

    struct TypeInfo *int_type;
    struct TypeInfo *uint_type;

    struct TypeInfo *float_type;
    struct TypeInfo *double_type;

    struct TypeInfo *int_lit_type;
    struct TypeInfo *float_lit_type;

    struct TypeInfo *bool_type;
    struct TypeInfo *void_type;

    struct TypeInfo *null_ptr_type;
    struct TypeInfo *void_ptr_type;
    struct TypeInfo *bool_int_type;

    struct TypeInfo *string_type;
    struct TypeInfo *c_string_type;

    struct TypeInfo *any_type;
    struct TypeInfo *namespace_type;
    struct TypeInfo *template_type;
    struct TypeInfo *type_type;
} Compiler;

static void compiler_init(Compiler *compiler);

static void compiler_destroy(Compiler *compiler);

static void
compile_error(Compiler *compiler, Location loc, const char *fmt, ...);

static bool compiler_has_version(Compiler *compiler, String version);

static void compiler_print_errors(Compiler *compiler);

static void compile_file_to_object(Compiler *compiler, String filepath);

static Module *compiler_get_module(Compiler *compiler, String module_name);

static SourceFile *compiler_syntax_stage(Compiler *compiler, String absolute_path);

static void compiler_semantic_stage(Compiler *compiler, SourceFile *file, Ast *ast);

static void compiler_process_imports(
    Compiler *compiler, SourceFile *file, Scope *scope, Ast *ast);

static void
compiler_link_module(Compiler *compiler, LLModule *mod, String out_file_path);


/*
 * Compiler API
 */

typedef struct CompilerApiArguments CompilerApiArguments;

static void compiler_api_compile(CompilerApiArguments *args);
