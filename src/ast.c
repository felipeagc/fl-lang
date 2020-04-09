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
    INTRINSIC_SQRT,
    INTRINSIC_SIN,
    INTRINSIC_COS,
    INTRINSIC_VECTOR_TYPE,
} IntrinsicType;

typedef enum AstType {
    AST_UNINITIALIZED,
    AST_ROOT,
    AST_VERSION_BLOCK,
    AST_STRUCT,
    AST_ENUM,
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
    AST_SUBSCRIPT,
    AST_SUBSCRIPT_SLICE,
    AST_ARRAY_TYPE,
    AST_SLICE_TYPE,
    AST_EXPR_STMT,
    AST_ACCESS,
    AST_STRUCT_FIELD,
    AST_ENUM_FIELD,
    AST_PROC_PARAM,
    AST_CAST,
    AST_IF,
    AST_WHILE,
    AST_FOR,
    AST_BREAK,
    AST_CONTINUE,
    AST_COMPOUND_LIT,
    AST_DISTINCT_TYPE,
    AST_USING,

    AST_BUILTIN_LEN,
    AST_BUILTIN_PTR,
    AST_BUILTIN_CAP,
    AST_BUILTIN_MAX,
    AST_BUILTIN_MIN,

    AST_BUILTIN_VEC_ACCESS,
} AstType;

typedef struct AstValue
{
    LLVMValueRef value;
    bool is_lvalue;
} AstValue;

enum {
    PROC_FLAG_HAS_BODY = 1 << 0,
    PROC_FLAG_IS_C_VARARGS = 1 << 1,
};

typedef enum AstFlags {
    AST_FLAG_EXTERN = 1 << 0,
    AST_FLAG_STATIC = 1 << 1,
    AST_FLAG_PUBLIC = 1 << 2,
    AST_FLAG_USING = 1 << 3,
} AstFlags;

typedef struct AstAttribute
{
    String name;
} AstAttribute;

typedef struct Ast
{
    AstType type;
    uint32_t flags;
    Location loc;
    struct TypeInfo *type_info;
    struct TypeInfo *as_type;
    struct Scope *scope;     // Scope this symbol owns
    struct Scope *sym_scope; // Scope this symbol belongs to
    struct Ast *alias_to;
    /*array*/ AstAttribute *attributes;

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
            /*array*/ struct Ast *stmts;
        } block;
        struct
        {
            String name;
            uint32_t flags;
            struct Ast *return_type;
            /*array*/ struct Ast *params;
            /*array*/ struct Ast *stmts;
            AstValue value;

            bool returned; // helper
        } proc;
        struct
        {
            struct Ast *cond_expr;
            struct Ast *cond_stmt;
            struct Ast *else_stmt;
        } if_stmt;
        struct
        {
            String version;
            /*array*/ struct Ast *stmts;
        } version_block;
        struct
        {
            struct Ast *cond;
            struct Ast *stmt;
        } while_stmt;
        struct
        {
            struct Ast *init;
            struct Ast *cond;
            struct Ast *inc;

            struct Ast *stmt;
        } for_stmt;
        struct
        {
            /*array*/ struct Ast *fields;
        } structure;
        struct
        {
            struct Ast *type_expr;
            /*array*/ struct Ast *fields;
        } enumeration;
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
            struct Ast *type_expr;
            /*array*/ struct Ast *values;
        } compound;
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
        } struct_field;
        struct
        {
            struct Ast *value_expr;
            String name;
        } enum_field;
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
        struct
        {
            struct Ast *sub;
        } distinct;
        struct
        {
            size_t position;
        } vec_access;
    };
} Ast;
