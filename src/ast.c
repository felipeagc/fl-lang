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
    AST_COMPOUND_LIT,
    AST_DISTINCT_TYPE,
} AstType;

typedef struct AstValue
{
    LLVMValueRef value;
    bool is_lvalue;
} AstValue;

enum {
    PROC_FLAG_HAS_BODY = 1 << 0,
    PROC_FLAG_IS_C_VARARGS = 1 << 1,
    PROC_FLAG_IS_EXTERN = 1 << 2,
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
        struct
        {
            struct Ast *sub;
        } distinct;
    };
} Ast;
