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

    case TYPE_BOOL: type->ref = llvm_type(l, &BOOL_INT_TYPE); break;
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
            AstValue align_val = {0};
            align_val.value = LLVMAlignOf(llvm_ty);
            if (out_value) *out_value = align_val;

            break;
        }
        }

        break;
    }

    case AST_EXPR_STMT: {
        llvm_codegen_ast(l, mod, ast->expr, false, NULL);
        break;
    }

    case AST_CONST_DECL: {
        TypeInfo *const_type = ast->decl.type_expr->as_type;

        switch (const_type->kind)
        {
        case TYPE_SLICE:
        case TYPE_STRUCT:
        case TYPE_ARRAY: {
            LLVMValueRef glob =
                LLVMAddGlobal(mod->mod, llvm_type(l, const_type), "");
            LLVMSetLinkage(glob, LLVMInternalLinkage);
            LLVMSetGlobalConstant(glob, true);

            AstValue init_value = {0};

            llvm_codegen_ast(l, mod, ast->decl.value_expr, true, &init_value);

            assert(!init_value.is_lvalue);

            LLVMSetInitializer(glob, init_value.value);

            ast->decl.value.value = glob;
            ast->decl.value.is_lvalue = true;

            break;
        }

        default: {
            llvm_codegen_ast(
                l, mod, ast->decl.value_expr, true, &ast->decl.value);
            break;
        }
        }

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
            init_value.value = ast->decl.value.value;
            llvm_codegen_ast(l, mod, ast->decl.value_expr, false, &init_value);

            if (init_value.value != ast->decl.value.value)
            {
                LLVMValueRef to_store = load_val(mod, &init_value);
                to_store = autocast_value(
                    l,
                    mod,
                    ast->decl.value_expr->type_info,
                    ast->decl.type_expr->as_type,
                    to_store);
                LLVMBuildStore(mod->builder, to_store, ast->decl.value.value);
            }
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
            AstValue subscript_value = {0};

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt64Type(), 0, false),
                load_val(mod, &right_value),
            };

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
        AstValue upper_value = {0};
        if (ast->subscript_slice.lower && ast->subscript_slice.upper)
        {
            llvm_codegen_ast(
                l, mod, ast->subscript_slice.lower, false, &lower_value);
            llvm_codegen_ast(
                l, mod, ast->subscript_slice.upper, false, &upper_value);
        }

        assert(left_value.value);

        LLVMValueRef left = NULL;
        switch (ast->subscript_slice.left->type_info->kind)
        {
        case TYPE_ARRAY: {
            assert(left_value.is_lvalue);

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 0, false),
            };

            left = LLVMBuildGEP(mod->builder, left_value.value, indices, 2, "");

            if (!lower_value.value && !upper_value.value)
            {
                lower_value.value =
                    LLVMConstInt(llvm_type(l, &SIZE_INT_TYPE), 0, false);
                upper_value.value = LLVMConstInt(
                    llvm_type(l, &SIZE_INT_TYPE),
                    ast->subscript_slice.left->type_info->array.size,
                    false);
            }

            break;
        }

        case TYPE_SLICE: {
            assert(left_value.is_lvalue);

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 1, false),
            };

            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, left_value.value, indices, 2, "");
            left = LLVMBuildLoad(mod->builder, ptr_ptr, "");

            if (!lower_value.value && !upper_value.value)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                };

                LLVMValueRef len_ptr = LLVMBuildGEP(
                    mod->builder, left_value.value, indices, 2, "");

                lower_value.value =
                    LLVMConstInt(llvm_type(l, &SIZE_INT_TYPE), 0, false);
                upper_value.value = LLVMBuildLoad(mod->builder, len_ptr, "");
            }

            break;
        }

        case TYPE_POINTER: {
            left = load_val(mod, &left_value);

            if (!lower_value.value && !upper_value.value)
            {
                lower_value.value =
                    LLVMConstInt(llvm_type(l, &SIZE_INT_TYPE), 0, false);
                upper_value.value =
                    LLVMConstInt(llvm_type(l, &SIZE_INT_TYPE), 0, false);
            }
            break;
        }

        default: assert(0); break;
        }

        LLVMValueRef lower = load_val(mod, &lower_value);
        LLVMValueRef upper = load_val(mod, &upper_value);

        AstValue result_value = {0};
        result_value.is_lvalue = true;
        if (out_value && out_value->value)
        {
            result_value.value = out_value->value;
        }
        else
        {
            result_value.value =
                build_alloca(mod, llvm_type(l, ast->type_info));
        }

        {
            LLVMValueRef len = LLVMBuildSub(mod->builder, upper, lower, "");
            len = LLVMBuildIntCast2(
                mod->builder, len, llvm_type(l, &SIZE_INT_TYPE), false, "");

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 0, false),
            };

            LLVMValueRef len_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, len, len_ptr);
        }

        {
            LLVMValueRef ptr = LLVMBuildGEP(mod->builder, left, &lower, 1, "");

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 1, false),
            };

            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, ptr, ptr_ptr);
        }

        if (out_value)
        {
            *out_value = result_value;
        }

        break;
    }

    case AST_COMPOUND_LIT: {
        AstValue result_value = {0};

        if (!is_const)
        {
            switch (ast->type_info->kind)
            {
            case TYPE_ARRAY: {
                result_value.is_lvalue = true;
                if (out_value && out_value->value)
                {
                    result_value.value = out_value->value;
                }
                else
                {
                    result_value.value =
                        build_alloca(mod, llvm_type(l, ast->type_info));
                }

                for (Ast *value = ast->compound.values;
                     value !=
                     ast->compound.values + array_size(ast->compound.values);
                     ++value)
                {
                    size_t index = (size_t)(value - ast->compound.values);
                    AstValue val = {0};
                    llvm_codegen_ast(l, mod, value, is_const, &val);

                    LLVMValueRef indices[2] = {
                        LLVMConstInt(LLVMInt32Type(), 0, false),
                        LLVMConstInt(LLVMInt32Type(), index, false),
                    };

                    LLVMValueRef ptr = LLVMBuildGEP(
                        mod->builder, result_value.value, indices, 2, "");
                    LLVMBuildStore(mod->builder, load_val(mod, &val), ptr);
                }

                break;
            }

            default: assert(0); break;
            }
        }
        else
        {
            switch (ast->type_info->kind)
            {
            case TYPE_ARRAY: {
                LLVMValueRef *values = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * array_size(ast->compound.values));

                for (Ast *value = ast->compound.values;
                     value !=
                     ast->compound.values + array_size(ast->compound.values);
                     ++value)
                {
                    size_t index = (size_t)(value - ast->compound.values);
                    AstValue val = {0};
                    llvm_codegen_ast(l, mod, value, true, &val);
                    values[index] = val.value;
                }

                result_value.value = LLVMConstArray(
                    llvm_type(l, ast->type_info->array.sub),
                    values,
                    array_size(ast->compound.values));

                break;
            }

            default: assert(0); break;
            }
        }

        if (out_value)
        {
            *out_value = result_value;
        }
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

        case TYPE_ARRAY: {
            Ast *right = get_inner_expr(ast->access.right);
            assert(right->type == AST_PRIMARY);
            assert(right->primary.tok->type == TOKEN_IDENT);

            AstValue result_value = {0};

            if (string_equals(right->primary.tok->str, STR("len")))
            {
                result_value.is_lvalue = false;
                result_value.value = LLVMConstInt(
                    llvm_type(l, &SIZE_INT_TYPE),
                    ast->access.left->type_info->array.size,
                    false);
            }
            else if (string_equals(right->primary.tok->str, STR("ptr")))
            {
                AstValue array_value = {0};
                llvm_codegen_ast(l, mod, ast->access.left, false, &array_value);

                assert(array_value.is_lvalue);

                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                };

                result_value.is_lvalue = false;
                result_value.value = LLVMBuildGEP(
                    mod->builder, array_value.value, indices, 2, "");
            }

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
        case AST_PROC_DECL: {
            llvm_add_proc(l, mod, ast);
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
        case AST_TYPEDEF: {
            llvm_codegen_ast(l, mod, ast, is_const, NULL);
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

        default: {
            llvm_codegen_ast(l, mod, ast, is_const, NULL);
            break;
        }
        }

        if (ast->type == AST_RETURN || ast->type == AST_BREAK ||
            ast->type == AST_CONTINUE)
        {
            break;
        }
    }

    // Generate children
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: {
            if (ast->proc.flags & PROC_FLAG_HAS_BODY)
            {
                LLVMValueRef fun = ast->proc.value.value;
                assert(fun);

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
                    l,
                    mod,
                    ast->proc.stmts,
                    array_size(ast->proc.stmts),
                    is_const);
                array_pop(l->operand_scope_stack);
                array_pop(l->scope_stack);

                if (!LLVMGetBasicBlockTerminator(
                        LLVMGetInsertBlock(mod->builder)))
                {
                    LLVMBuildRetVoid(mod->builder); // Add void return
                }

                LLVMPositionBuilderAtEnd(mod->builder, prev_pos);
            }
            break;
        }

        default: break;
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
