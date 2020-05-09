typedef struct LLModule
{
    LLVMModuleRef mod;
    LLVMBuilderRef builder;
    LLVMTargetDataRef data;
    LLVMValueRef main_fun;
    LLVMValueRef main_wrapper_fun;
    LLVMValueRef runtime_statup_fun;
    LLVMValueRef rtti_type_infos;

    LLVMDIBuilderRef di_builder;
} LLModule;

enum {
    DW_ATE_address = 1,
    DW_ATE_boolean = 2,
    DW_ATE_float = 4,
    DW_ATE_signed = 5,
    DW_ATE_signed_char = 6,
    DW_ATE_unsigned = 7,
    DW_ATE_unsigned_char = 8,
};

typedef ARRAY_OF(LLVMBasicBlockRef) ArrayOfBasicBlock;
typedef ARRAY_OF(LLVMMetadataRef) ArrayOfMetadataRef;

typedef struct LLContext
{
    Compiler *compiler;
    LLModule mod;
    ArrayOfScopePtr scope_stack;
    ArrayOfScopePtr operand_scope_stack;
    ArrayOfBasicBlock break_block_stack;
    ArrayOfBasicBlock continue_block_stack;
    ArrayOfMetadataRef di_scope_stack;
    ArrayOfMetadataRef di_location_stack;
} LLContext;

static void llvm_codegen_ast(
    LLContext *l, LLModule *mod, Ast *ast, bool is_const, AstValue *out_value);
static void llvm_codegen_ast_children(
    LLContext *l, LLModule *mod, Ast *asts, size_t ast_count, bool is_const);

static String mangle_function_name(LLContext *l, Ast *ast)
{
    TypeInfo *proc_type = ast->type_info->ptr.sub;

    sb_reset(&l->compiler->sb);
    sb_append(&l->compiler->sb, STR("_F")); // mangled function prefix
    if (ast->loc.file->module_name.len > 0)
    {
        sb_append(&l->compiler->sb, ast->loc.file->module_name);
        sb_append_char(&l->compiler->sb, '.');
    }
    sb_append(&l->compiler->sb, ast->proc.name);

    if (ast->proc.template_params.len > 0)
    {
        for (size_t i = 0; i < proc_type->proc.params.len; ++i)
        {
            TypeInfo *param_type = proc_type->proc.params.ptr[i];
            sb_append(&l->compiler->sb, STR("$"));
            print_mangled_type(&l->compiler->sb, param_type);
        }
    }

    return sb_build(&l->compiler->sb, &l->compiler->bump);
}

static LLVMMetadataRef llvm_get_di_file(LLContext *l, SourceFile *file)
{
    if (file->di_file) return file->di_file;

    const char *c_file_path = bump_c_str(&l->compiler->bump, file->path);
    const char *c_dir = get_path_dir(c_file_path);
    const char *c_filename = get_path_filename(c_file_path);
    file->di_file = LLVMDIBuilderCreateFile(
        l->mod.di_builder,
        c_filename,
        strlen(c_filename),
        c_dir,
        strlen(c_dir));

    return file->di_file;
}

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

    case TYPE_BOOL: type->ref = llvm_type(l, l->compiler->bool_int_type); break;
    case TYPE_VOID: type->ref = LLVMVoidType(); break;

    case TYPE_POINTER: {
        type->ref = LLVMPointerType(llvm_type(l, type->ptr.sub), 0);
        break;
    }

    case TYPE_RAW_POINTER: {
        type->ref = LLVMPointerType(LLVMVoidType(), 0);
        break;
    }

    case TYPE_ARRAY: {
        type->ref =
            LLVMArrayType(llvm_type(l, type->array.sub), type->array.size);
        break;
    }

    case TYPE_VECTOR: {
        type->ref =
            LLVMVectorType(llvm_type(l, type->array.sub), type->array.size);
        break;
    }

    case TYPE_ANY: {
        LLVMTypeRef field_types[2] = {
            LLVMPointerType(LLVMVoidType(), 0), // ptr
            LLVMPointerType(
                llvm_type(l, l->compiler->type_info_type), 0), // type_info
        };

        type->ref = LLVMStructType(field_types, 2, false);
        break;
    }

    case TYPE_SLICE: {
        LLVMTypeRef field_types[2] = {
            LLVMPointerType(llvm_type(l, type->array.sub), 0), // ptr
            llvm_type(l, l->compiler->uint_type),              // len
        };

        type->ref = LLVMStructType(field_types, 2, false);
        break;
    }

    case TYPE_DYNAMIC_ARRAY: {
        LLVMTypeRef field_types[3] = {
            LLVMPointerType(llvm_type(l, type->array.sub), 0), // ptr
            llvm_type(l, l->compiler->uint_type),              // len
            llvm_type(l, l->compiler->uint_type),              // cap
        };

        type->ref = LLVMStructType(field_types, 3, false);
        break;
    }

    case TYPE_PROC: {
        size_t param_count = type->proc.params.len;
        LLVMTypeRef *param_types =
            bump_alloc(&l->compiler->bump, sizeof(LLVMTypeRef) * param_count);
        for (size_t i = 0; i < param_count; i++)
        {
            TypeInfo *param_type = type->proc.params.ptr[i];
            param_types[i] = llvm_type(l, param_type);
            if (is_type_compound(param_type))
            {
                param_types[i] = LLVMPointerType(param_types[i], 0);
            }
        }

        LLVMTypeRef return_type = llvm_type(l, type->proc.return_type);

        type->ref = LLVMFunctionType(
            return_type,
            param_types,
            param_count,
            (type->flags & TYPE_FLAG_C_VARARGS) == TYPE_FLAG_C_VARARGS);
        break;
    }

    case TYPE_STRUCT: {
        if (!type->structure.is_union)
        {
            char *struct_name = "";
            if (type->name.len > 0)
            {
                struct_name = bump_c_str(&l->compiler->bump, type->name);
            }
            type->ref =
                LLVMStructCreateNamed(LLVMGetGlobalContext(), struct_name);
            size_t field_count = type->structure.fields.len;
            LLVMTypeRef *field_types = bump_alloc(
                &l->compiler->bump, sizeof(LLVMTypeRef) * field_count);
            for (size_t i = 0; i < field_count; i++)
            {
                field_types[i] = llvm_type(l, type->structure.fields.ptr[i]);
            }
            LLVMStructSetBody(type->ref, field_types, field_count, false);
        }
        else
        {
            type->ref =
                LLVMArrayType(LLVMInt8Type(), size_of_type(l->compiler, type));
        }
        break;
    }

    case TYPE_TUPLE: {
        size_t field_count = type->tuple.fields.len;
        LLVMTypeRef *field_types =
            bump_alloc(&l->compiler->bump, sizeof(LLVMTypeRef) * field_count);
        for (size_t i = 0; i < field_count; i++)
        {
            field_types[i] = llvm_type(l, type->tuple.fields.ptr[i]);
        }

        type->ref = LLVMStructType(field_types, field_count, false);
        break;
    }

    case TYPE_ENUM: {
        type->ref = llvm_type(l, type->enumeration.underlying_type);
        break;
    }

    case TYPE_UNTYPED_INT:
    case TYPE_UNTYPED_FLOAT:
    case TYPE_NAMESPACE:
    case TYPE_TYPE:
    case TYPE_TEMPLATE:
    case TYPE_NAMED_PLACEHOLDER:
    case TYPE_UNINITIALIZED: assert(0); break;
    }

    return type->ref;
}

static LLVMMetadataRef llvm_debug_type(LLContext *l, TypeInfo *type)
{
    if (type->debug_ref) return type->debug_ref;

    switch (type->kind)
    {
    case TYPE_INT: {
        const char *name = "";
        LLVMDWARFTypeEncoding encoding = 0;
        if (type->integer.is_signed)
        {
            encoding = DW_ATE_signed;
            switch (type->integer.num_bits)
            {
            case 8: name = "i8"; break;
            case 16: name = "i16"; break;
            case 32: name = "i32"; break;
            case 64: name = "i64"; break;
            }
        }
        else
        {
            encoding = DW_ATE_unsigned;
            switch (type->integer.num_bits)
            {
            case 8: name = "u8"; break;
            case 16: name = "u16"; break;
            case 32: name = "u32"; break;
            case 64: name = "u64"; break;
            }
        }

        type->debug_ref = LLVMDIBuilderCreateBasicType(
            l->mod.di_builder,
            name,
            strlen(name),
            type->integer.num_bits,
            encoding,
            0);

        break;
    }

    case TYPE_FLOAT: {
        const char *name = "";
        LLVMDWARFTypeEncoding encoding = DW_ATE_float;

        switch (type->floating.num_bits)
        {
        case 32: name = "float"; break;
        case 64: name = "double"; break;
        default: assert(0); break;
        }

        type->debug_ref = LLVMDIBuilderCreateBasicType(
            l->mod.di_builder,
            name,
            strlen(name),
            type->floating.num_bits,
            encoding,
            0);

        break;
    }

    case TYPE_BOOL: {
        const char *name = "bool";
        type->debug_ref = LLVMDIBuilderCreateBasicType(
            l->mod.di_builder,
            name,
            strlen(name),
            l->compiler->bool_int_type->integer.num_bits,
            DW_ATE_boolean,
            0);
        break;
    }

    case TYPE_VOID: {
        assert(0);
        break;
    }

    case TYPE_RAW_POINTER: {
        type->debug_ref = LLVMDIBuilderCreateNullPtrType(l->mod.di_builder);
        break;
    }

    case TYPE_POINTER: {
        if (type->ptr.sub->kind == TYPE_VOID)
        {
            type->debug_ref = LLVMDIBuilderCreateNullPtrType(l->mod.di_builder);
            break;
        }

        String pretty_name = get_type_pretty_name(l->compiler, type);
        type->debug_ref = LLVMDIBuilderCreatePointerType(
            l->mod.di_builder,
            llvm_debug_type(l, type->ptr.sub),
            l->compiler->uint_type->integer.num_bits,
            align_of_type(l->compiler, type) * 8,
            0,
            pretty_name.ptr,
            pretty_name.len);
        break;
    }

    case TYPE_ARRAY: {
        type->debug_ref = LLVMDIBuilderCreateArrayType(
            l->mod.di_builder,
            type->array.size,
            align_of_type(l->compiler, type) * 8,
            llvm_debug_type(l, type->array.sub),
            NULL,
            0);
        break;
    }

    case TYPE_VECTOR: {
        const char *type_name = "@Vector";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_ANY: {
        const char *type_name = "@Any";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_SLICE: {
        const char *type_name = "@Slice";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_DYNAMIC_ARRAY: {
        const char *type_name = "@DynamicArray";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_PROC: {
        size_t param_count = type->proc.params.len;
        LLVMMetadataRef *param_types =
            bump_alloc(&l->compiler->bump, sizeof(LLVMTypeRef) * param_count);
        for (size_t i = 0; i < param_count; i++)
        {
            TypeInfo *param_type = type->proc.params.ptr[i];
            String pretty_name = get_type_pretty_name(l->compiler, param_type);
            param_types[i] = llvm_debug_type(l, param_type);
            if (is_type_compound(param_type))
            {
                param_types[i] = LLVMDIBuilderCreatePointerType(
                    l->mod.di_builder,
                    param_types[i],
                    l->compiler->uint_type->integer.num_bits,
                    align_of_type(l->compiler, l->compiler->uint_type) * 8,
                    0,
                    pretty_name.ptr,
                    pretty_name.len);
            }
        }

        assert(type->file);

        type->debug_ref = LLVMDIBuilderCreateSubroutineType(
            l->mod.di_builder,
            llvm_get_di_file(l, type->file),
            param_types,
            param_count,
            0);

        break;
    }

    case TYPE_STRUCT: {
        const char *type_name = "@Struct";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_TUPLE: {
        const char *type_name = "@Tuple";
        type->debug_ref = LLVMDIBuilderCreateUnspecifiedType(
            l->mod.di_builder, type_name, strlen(type_name));
        break;
    }

    case TYPE_ENUM: {
        type->debug_ref = llvm_debug_type(l, type->enumeration.underlying_type);
        break;
    }

    case TYPE_UNTYPED_INT:
    case TYPE_UNTYPED_FLOAT:
    case TYPE_NAMESPACE:
    case TYPE_TYPE:
    case TYPE_TEMPLATE:
    case TYPE_NAMED_PLACEHOLDER:
    case TYPE_UNINITIALIZED: assert(0); break;
    }

    return type->debug_ref;
}

enum {
    TYPEINFO_KIND_INDEX = 0,
    TYPEINFO_ALIGN_INDEX = 1,
    TYPEINFO_SIZE_INDEX = 2,
    TYPEINFO_FLAGS_INDEX = 3,
    TYPEINFO_NAME_INDEX = 4,
    TYPEINFO_INFO_INDEX = 5,
};

static LLVMValueRef llvm_get_malloc_fn(LLContext *l, LLModule *mod)
{
    LLVMValueRef malloc_fn = LLVMGetNamedFunction(mod->mod, "malloc");
    if (!malloc_fn)
    {
        LLVMTypeRef param_types[1] = {
            llvm_type(l, l->compiler->uint_type),
        };
        size_t param_count = 1;

        LLVMTypeRef fn_ty = LLVMFunctionType(
            LLVMPointerType(LLVMVoidType(), 0),
            param_types,
            param_count,
            false);
        malloc_fn = LLVMAddFunction(mod->mod, "malloc", fn_ty);
    }
    return malloc_fn;
}

static LLVMValueRef llvm_get_realloc_fn(LLContext *l, LLModule *mod)
{
    LLVMValueRef realloc_fn = LLVMGetNamedFunction(mod->mod, "realloc");
    if (!realloc_fn)
    {
        LLVMTypeRef param_types[2] = {
            LLVMPointerType(LLVMVoidType(), 0),
            llvm_type(l, l->compiler->uint_type),
        };
        size_t param_count = 2;

        LLVMTypeRef fn_ty = LLVMFunctionType(
            LLVMPointerType(LLVMVoidType(), 0),
            param_types,
            param_count,
            false);
        realloc_fn = LLVMAddFunction(mod->mod, "realloc", fn_ty);
    }
    return realloc_fn;
}

static LLVMValueRef llvm_get_free_fn(LLContext *l, LLModule *mod)
{
    LLVMValueRef free_fn = LLVMGetNamedFunction(mod->mod, "free");
    if (!free_fn)
    {
        LLVMTypeRef param_types[1] = {
            llvm_type(l, l->compiler->null_ptr_type),
        };
        size_t param_count = 1;

        LLVMTypeRef fn_ty =
            LLVMFunctionType(LLVMVoidType(), param_types, param_count, false);
        free_fn = LLVMAddFunction(mod->mod, "free", fn_ty);
    }
    return free_fn;
}

static void
generate_type_info_value(LLContext *l, LLModule *mod, size_t rtti_index)
{
    TypeInfo *type_info = l->compiler->rtti_type_infos.ptr[rtti_index];
    TypeInfo *type_info_type = l->compiler->type_info_type;

    LLVMValueRef indices[3] = {0};

    indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
    indices[1] = LLVMConstInt(LLVMInt32Type(), type_info->rtti_index, false);
    LLVMValueRef ptr =
        LLVMBuildGEP(mod->builder, mod->rtti_type_infos, indices, 2, "");

    LLVMValueRef kind_value = LLVMConstInt(
        llvm_type(l, type_info_type->structure.fields.ptr[0]),
        type_info->kind,
        false);
    indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_KIND_INDEX, false);
    LLVMBuildStore(
        mod->builder,
        kind_value,
        LLVMBuildGEP(mod->builder, ptr, indices, 2, ""));

    LLVMValueRef align_value = LLVMConstInt(
        llvm_type(l, type_info_type->structure.fields.ptr[1]),
        type_info->align,
        false);
    indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_ALIGN_INDEX, false);
    LLVMBuildStore(
        mod->builder,
        align_value,
        LLVMBuildGEP(mod->builder, ptr, indices, 2, ""));

    LLVMValueRef size_value = LLVMConstInt(
        llvm_type(l, type_info_type->structure.fields.ptr[2]),
        type_info->size,
        false);
    indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_SIZE_INDEX, false);
    LLVMBuildStore(
        mod->builder,
        size_value,
        LLVMBuildGEP(mod->builder, ptr, indices, 2, ""));

    LLVMValueRef flags_value = LLVMConstInt(
        llvm_type(l, type_info_type->structure.fields.ptr[3]),
        type_info->flags,
        false);
    indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_FLAGS_INDEX, false);
    LLVMBuildStore(
        mod->builder,
        flags_value,
        LLVMBuildGEP(mod->builder, ptr, indices, 2, ""));

    if (type_info->name.len > 0)
    {
        indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_NAME_INDEX, false);
        LLVMValueRef name_slice_ptr =
            LLVMBuildGEP(mod->builder, ptr, indices, 2, "");

        LLVMValueRef str_ptr = LLVMAddGlobal(
            mod->mod, LLVMArrayType(LLVMInt8Type(), type_info->name.len), "");
        LLVMSetLinkage(str_ptr, LLVMInternalLinkage);
        LLVMSetGlobalConstant(str_ptr, true);
        LLVMSetInitializer(
            str_ptr,
            LLVMConstString(type_info->name.ptr, type_info->name.len, true));

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        str_ptr = LLVMConstGEP(str_ptr, indices, 2);

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        LLVMValueRef ptr_ptr =
            LLVMBuildGEP(mod->builder, name_slice_ptr, indices, 2, "");
        LLVMBuildStore(mod->builder, str_ptr, ptr_ptr);

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
        LLVMValueRef len_ptr =
            LLVMBuildGEP(mod->builder, name_slice_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                type_info->name.len,
                false),
            len_ptr);
    }

    indices[1] = LLVMConstInt(LLVMInt32Type(), TYPEINFO_INFO_INDEX, false);
    LLVMValueRef union_ptr = LLVMBuildGEP(mod->builder, ptr, indices, 2, "");

    TypeInfo *info_union =
        type_info_type->structure.fields.ptr[TYPEINFO_INFO_INDEX];

    TypeInfo *field = NULL;
    LLVMValueRef value_ptr = NULL;

    switch (type_info->kind)
    {
    case TYPE_INT: {
        field = info_union->structure.fields.ptr[0];
        assert(field->structure.fields.len == 2);

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, field->structure.fields.ptr[0]),
                type_info->integer.num_bits,
                false),
            value_ptr);

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, field->structure.fields.ptr[1]),
                type_info->integer.is_signed,
                false),
            value_ptr);

        break;
    }

    case TYPE_FLOAT: {
        field = info_union->structure.fields.ptr[1];
        assert(field->structure.fields.len == 1);

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, field->structure.fields.ptr[0]),
                type_info->floating.num_bits,
                false),
            value_ptr);

        break;
    }

    case TYPE_POINTER: {
        field = info_union->structure.fields.ptr[2];
        assert(field->structure.fields.len == 1);

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(
            LLVMInt32Type(), type_info->ptr.sub->rtti_index, false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, mod->rtti_type_infos, indices, 2, ""),
            value_ptr);

        break;
    }

    case TYPE_SLICE:
    case TYPE_DYNAMIC_ARRAY:
    case TYPE_ARRAY: {
        field = info_union->structure.fields.ptr[3];
        assert(field->structure.fields.len == 2);

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(
            LLVMInt32Type(), type_info->array.sub->rtti_index, false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, mod->rtti_type_infos, indices, 2, ""),
            value_ptr);

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                type_info->array.size,
                false),
            value_ptr);

        break;
    }

    case TYPE_PROC: {
        field = info_union->structure.fields.ptr[4];
        assert(field->structure.fields.len == 2);

        LLVMTypeRef rtti_ptr_array_type = LLVMArrayType(
            LLVMPointerType(llvm_type(l, l->compiler->type_info_type), 0),
            type_info->proc.params.len);
        LLVMValueRef sub_ptrs =
            LLVMAddGlobal(mod->mod, rtti_ptr_array_type, "");
        LLVMSetLinkage(sub_ptrs, LLVMInternalLinkage);
        LLVMSetGlobalConstant(sub_ptrs, false);
        LLVMSetExternallyInitialized(sub_ptrs, false);
        LLVMSetInitializer(sub_ptrs, LLVMConstNull(rtti_ptr_array_type));

        for (size_t i = 0; i < type_info->proc.params.len; ++i)
        {
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), i, false);
            LLVMValueRef sub_ptr_ptr =
                LLVMBuildGEP(mod->builder, sub_ptrs, indices, 2, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(
                LLVMInt32Type(),
                type_info->proc.params.ptr[i]->rtti_index,
                false);
            LLVMBuildStore(
                mod->builder,
                LLVMBuildGEP(
                    mod->builder, mod->rtti_type_infos, indices, 2, ""),
                sub_ptr_ptr);
        }

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        // Paramteter slice pointer
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[2] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 3, "");
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, sub_ptrs, indices, 2, ""),
            value_ptr);

        // Paramteter slice length
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[2] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 3, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                type_info->proc.params.len,
                false),
            value_ptr);

        // Return type
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(
            LLVMInt32Type(), type_info->proc.return_type->rtti_index, false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, mod->rtti_type_infos, indices, 2, ""),
            value_ptr);

        break;
    }

    case TYPE_STRUCT: {
        field = info_union->structure.fields.ptr[5];

        assert(field->structure.fields.len == 2);

        LLVMTypeRef rtti_ptr_array_type = LLVMArrayType(
            LLVMPointerType(llvm_type(l, l->compiler->type_info_type), 0),
            type_info->structure.fields.len);
        LLVMValueRef sub_ptrs =
            LLVMAddGlobal(mod->mod, rtti_ptr_array_type, "");
        LLVMSetLinkage(sub_ptrs, LLVMInternalLinkage);
        LLVMSetGlobalConstant(sub_ptrs, false);
        LLVMSetExternallyInitialized(sub_ptrs, false);
        LLVMSetInitializer(sub_ptrs, LLVMConstNull(rtti_ptr_array_type));

        for (size_t i = 0; i < type_info->structure.fields.len; ++i)
        {
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), i, false);
            LLVMValueRef sub_ptr_ptr =
                LLVMBuildGEP(mod->builder, sub_ptrs, indices, 2, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(
                LLVMInt32Type(),
                type_info->structure.fields.ptr[i]->rtti_index,
                false);
            LLVMBuildStore(
                mod->builder,
                LLVMBuildGEP(
                    mod->builder, mod->rtti_type_infos, indices, 2, ""),
                sub_ptr_ptr);
        }

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        // Field slice pointer
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[2] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 3, "");
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, sub_ptrs, indices, 2, ""),
            value_ptr);

        // Field slice length
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[2] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 3, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                type_info->structure.fields.len,
                false),
            value_ptr);

        // is_union
        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");
        LLVMBuildStore(
            mod->builder,
            LLVMConstInt(
                llvm_type(l, field->structure.fields.ptr[1]),
                type_info->structure.is_union,
                false),
            value_ptr);

        break;
    }

    case TYPE_ENUM: {
        field = info_union->structure.fields.ptr[6];
        assert(field->structure.fields.len == 1);

        LLVMTypeRef info_type = llvm_type(l, field);
        union_ptr = LLVMBuildPointerCast(
            mod->builder, union_ptr, LLVMPointerType(info_type, 0), "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
        value_ptr = LLVMBuildGEP(mod->builder, union_ptr, indices, 2, "");

        indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
        indices[1] = LLVMConstInt(
            LLVMInt32Type(),
            type_info->enumeration.underlying_type->rtti_index,
            false);
        LLVMBuildStore(
            mod->builder,
            LLVMBuildGEP(mod->builder, mod->rtti_type_infos, indices, 2, ""),
            value_ptr);

        break;
    }

    default: break;
    }
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
        case TYPE_ENUM:
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

static inline LLVMValueRef
build_alloca(LLContext *l, LLModule *mod, TypeInfo *type)
{
    LLVMTypeRef llvm_ty = llvm_type(l, type);

    LLVMBasicBlockRef current_block = LLVMGetInsertBlock(mod->builder);

    LLVMValueRef fun = LLVMGetBasicBlockParent(current_block);

    LLVMBasicBlockRef entry_block = LLVMGetEntryBasicBlock(fun);
    LLVMPositionBuilder(
        mod->builder, entry_block, LLVMGetBasicBlockTerminator(entry_block));

    LLVMValueRef alloca = LLVMBuildAlloca(mod->builder, llvm_ty, "");
    LLVMSetAlignment(alloca, align_of_type(l->compiler, type));

    LLVMPositionBuilderAtEnd(mod->builder, current_block);

    return alloca;
}

static void
llvm_add_proc(LLContext *l, LLModule *mod, Ast *asts, size_t ast_count)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: {
            if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
            {
                // Generate instantiations
                for (Ast **instantiation =
                         (Ast **)ast->proc.template_cache->values.ptr;
                     instantiation !=
                     (Ast **)ast->proc.template_cache->values.ptr +
                         ast->proc.template_cache->values.len;
                     ++instantiation)
                {
                    llvm_add_proc(l, mod, *instantiation, 1);
                }
                break;
            }

            if ((ast->flags & AST_FLAG_WAS_USED) != AST_FLAG_WAS_USED)
            {
                break;
            }

            String mangled_name = ast->proc.name;
            if ((ast->flags & AST_FLAG_EXTERN) != AST_FLAG_EXTERN)
            {
                mangled_name = mangle_function_name(l, ast);
            }

            for (AstAttribute *attrib = ast->attributes.ptr;
                 attrib != ast->attributes.ptr + ast->attributes.len;
                 ++attrib)
            {
                if (string_equals(attrib->name, STR("link_name")))
                {
                    assert(attrib->value);
                    assert(attrib->value->type == AST_PRIMARY);
                    assert(
                        attrib->value->primary.tok->type == TOKEN_STRING_LIT);

                    mangled_name = attrib->value->primary.tok->str;
                }
            }

            TypeInfo *fun_type = ast->type_info->ptr.sub;
            LLVMTypeRef llvm_fun_type = llvm_type(l, fun_type);

            char *fun_name_c = bump_c_str(&l->compiler->bump, mangled_name);

            ast->value = LLVMAddFunction(mod->mod, fun_name_c, llvm_fun_type);

            if (ast->flags & AST_FLAG_FUNCTION_HAS_BODY)
            {
                sb_reset(&l->compiler->sb);
                sb_append(&l->compiler->sb, ast->loc.file->module_name);
                sb_append_char(&l->compiler->sb, '.');
                sb_append(&l->compiler->sb, ast->proc.name);
                String pretty_fun_name =
                    sb_build(&l->compiler->sb, &l->compiler->bump);

                ast->di_value = LLVMDIBuilderCreateFunction(
                    mod->di_builder,
                    llvm_get_di_file(l, ast->loc.file),
                    pretty_fun_name.ptr,
                    pretty_fun_name.len,
                    fun_name_c,
                    strlen(fun_name_c),
                    llvm_get_di_file(l, ast->loc.file),
                    ast->loc.line,
                    llvm_debug_type(l, fun_type),
                    false,
                    true,
                    ast->loc.line,
                    LLVMDIFlagZero,
                    false);
                LLVMSetSubprogram(ast->value, ast->di_value);
            }

            if (string_equals(ast->proc.name, STR("main")))
            {
                mod->main_fun = ast->value;
            }

            LLVMSetLinkage(ast->value, LLVMInternalLinkage);
            if ((ast->flags & AST_FLAG_EXTERN) == AST_FLAG_EXTERN)
            {
                LLVMSetLinkage(ast->value, LLVMExternalLinkage);
            }

            bool is_inline = false;
            for (AstAttribute *attrib = ast->attributes.ptr;
                 attrib != ast->attributes.ptr + ast->attributes.len;
                 ++attrib)
            {
                if (string_equals(attrib->name, STR("inline")))
                {
                    is_inline = true;
                    break;
                }
            }

            if (is_inline)
            {
                // Add alwaysinline attribute
                String attrib = STR("alwaysinline");
                LLVMAddAttributeAtIndex(
                    ast->value,
                    LLVMAttributeFunctionIndex,
                    LLVMCreateEnumAttribute(
                        LLVMGetGlobalContext(),
                        LLVMGetEnumAttributeKindForName(attrib.ptr, attrib.len),
                        0));
            }

            break;
        }

        default: break;
        }
    }
}

static void
llvm_codegen_deferred_stmts(LLContext *l, LLModule *mod, bool is_return)
{
    Scope *scope = *array_last(&l->scope_stack);

    while (scope)
    {
        for (size_t i = scope->deferred_stmts.len; i-- > 0;)
        {
            llvm_codegen_ast(l, mod, scope->deferred_stmts.ptr[i], false, NULL);
        }

        if (is_return)
        {
            scope = scope->parent;
            continue;
        }

        scope = NULL;
    }
}

static void llvm_codegen_ast(
    LLContext *l, LLModule *mod, Ast *ast, bool is_const, AstValue *out_value)
{
    if (l->di_scope_stack.len > 0)
    {
        LLVMMetadataRef di_location = LLVMDIBuilderCreateDebugLocation(
            LLVMGetGlobalContext(),
            ast->loc.line,
            ast->loc.col,
            *array_last(&l->di_scope_stack),
            NULL);
        assert(di_location);
        array_push(&l->di_location_stack, di_location);
    }

    if (l->di_location_stack.len > 0)
    {
        LLVMSetCurrentDebugLocation2(
            mod->builder, *array_last(&l->di_location_stack));
    }
    else
    {
        LLVMSetCurrentDebugLocation2(mod->builder, NULL);
    }

    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        array_push(&l->scope_stack, ast->scope);
        array_push(&l->operand_scope_stack, ast->scope);
        llvm_codegen_ast_children(
            l, mod, ast->block.stmts.ptr, ast->block.stmts.len, is_const);
        array_pop(&l->operand_scope_stack);
        array_pop(&l->scope_stack);
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(l->compiler, ast->version_block.version))
        {
            llvm_codegen_ast_children(
                l,
                mod,
                ast->version_block.stmts.ptr,
                ast->version_block.stmts.len,
                is_const);
        }
        else
        {
            llvm_codegen_ast_children(
                l,
                mod,
                ast->version_block.else_stmts.ptr,
                ast->version_block.else_stmts.len,
                is_const);
        }

        break;
    }

    case AST_PROC_DECL: {
        if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
        {
            // Generate instantiations
            for (Ast **instantiation =
                     (Ast **)ast->proc.template_cache->values.ptr;
                 instantiation != (Ast **)ast->proc.template_cache->values.ptr +
                                      ast->proc.template_cache->values.len;
                 ++instantiation)
            {
                llvm_codegen_ast(l, mod, *instantiation, false, NULL);
            }
            break;
        }

        if ((ast->flags & AST_FLAG_WAS_USED) != AST_FLAG_WAS_USED)
        {
            break;
        }

        assert(ast->type_info->kind == TYPE_POINTER);
        assert(ast->value);

        if (ast->flags & AST_FLAG_FUNCTION_HAS_BODY)
        {
            size_t param_count = ast->proc.params.len;
            for (size_t i = 0; i < param_count; i++)
            {
                Ast *param = &ast->proc.params.ptr[i];
                param->proc_param.value.is_lvalue = false;

                TypeInfo *param_type = param->proc_param.type_expr->as_type;
                if (is_type_compound(param_type))
                {
                    param->proc_param.value.is_lvalue = true;
                }
                param->proc_param.value.value = LLVMGetParam(ast->value, i);

                char *param_name =
                    bump_c_str(&l->compiler->bump, param->proc_param.name);
                LLVMSetValueName(param->proc_param.value.value, param_name);

                if (param->flags & AST_FLAG_USING)
                {
                    Scope *expr_scope = get_expr_scope(
                        l->compiler, *array_last(&l->scope_stack), param);
                    assert(expr_scope);

                    expr_scope->value = param->proc_param.value;
                }
            }
        }

        if (out_value)
        {
            out_value->is_lvalue = false;
            out_value->value = ast->value;
        }

        break;
    }

    case AST_PRIMARY: {
        TypeInfo *inner_type = get_inner_primitive_type(ast->type_info);
        assert(is_type_runtime(inner_type));

        switch (ast->primary.tok->type)
        {
        case TOKEN_TRUE: {
            AstValue value = {0};
            value.value = LLVMConstInt(llvm_type(l, inner_type), 1, false);
            if (out_value) *out_value = value;
            break;
        }

        case TOKEN_FALSE: {
            AstValue value = {0};
            value.value = LLVMConstInt(llvm_type(l, inner_type), 0, false);
            if (out_value) *out_value = value;
            break;
        }

        case TOKEN_NULL: {
            AstValue value = {0};
            value.value = LLVMConstPointerNull(llvm_type(l, inner_type));
            if (out_value) *out_value = value;
            break;
        }

        case TOKEN_INT_LIT: {
            switch (inner_type->kind)
            {
            case TYPE_INT: {
                AstValue value = {0};
                value.value = LLVMConstInt(
                    llvm_type(l, inner_type),
                    (unsigned long long)ast->primary.tok->i64,
                    true);
                if (out_value) *out_value = value;
                break;
            }

            case TYPE_FLOAT: {
                AstValue value = {0};
                value.value = LLVMConstReal(
                    llvm_type(l, inner_type), (double)ast->primary.tok->i64);
                if (out_value) *out_value = value;
                break;
            }

            default: assert(0); break;
            }

            break;
        }

        case TOKEN_FLOAT_LIT: {
            switch (inner_type->kind)
            {
            case TYPE_FLOAT: {
                AstValue value = {0};
                value.value = LLVMConstReal(
                    llvm_type(l, inner_type), (double)ast->primary.tok->f64);
                if (out_value) *out_value = value;
                break;
            }
            default: assert(0); break;
            }

            break;
        }

        case TOKEN_STRING_LIT: {
            LLVMValueRef glob = LLVMAddGlobal(
                mod->mod,
                LLVMArrayType(LLVMInt8Type(), ast->primary.tok->str.len),
                "");

            LLVMSetLinkage(glob, LLVMInternalLinkage);
            LLVMSetGlobalConstant(glob, true);

            LLVMSetInitializer(
                glob,
                LLVMConstString(
                    ast->primary.tok->str.ptr,
                    ast->primary.tok->str.len,
                    true));

            AstValue value = {0};
            value.is_lvalue = true;
            value.value = glob;

            if (out_value) *out_value = value;

            break;
        }

        case TOKEN_CSTRING_LIT: {
            LLVMValueRef glob = LLVMAddGlobal(
                mod->mod,
                LLVMArrayType(LLVMInt8Type(), ast->primary.tok->str.len),
                "");

            // set as internal linkage and constant
            LLVMSetLinkage(glob, LLVMInternalLinkage);
            LLVMSetGlobalConstant(glob, true);

            // Initialize with string:
            LLVMSetInitializer(
                glob,
                LLVMConstString(
                    ast->primary.tok->str.ptr,
                    ast->primary.tok->str.len,
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
                llvm_type(l, inner_type),
                (unsigned long long)ast->primary.tok->chr,
                true);
            if (out_value) *out_value = value;
            break;
        }

        case TOKEN_IDENT: {
            Ast *sym = get_symbol(
                *array_last(&l->scope_stack),
                ast->primary.tok->str,
                ast->loc.file);
            assert(sym);

            switch (sym->type)
            {
            case AST_PROC_DECL: {
                // TODO: shouldn't this be sym->flags? Is this bit even useful
                // past semantic analysis?
                if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
                {
                    break;
                }

                assert(sym->value);
                if (out_value)
                {
                    out_value->is_lvalue = false;
                    out_value->value = sym->value;
                }
                break;
            }

            case AST_VAR_DECL:
            case AST_CONST_DECL: {
                assert(sym->decl.value.value);
                if (out_value) *out_value = sym->decl.value;
                break;
            }

            case AST_FOREACH: {
                assert(sym->foreach_stmt.value.value);
                if (out_value) *out_value = sym->foreach_stmt.value;
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

            case AST_TUPLE_BINDING: {
                llvm_codegen_ast(l, mod, sym, is_const, out_value);
                break;
            }

            case AST_ENUM_FIELD: {
                llvm_codegen_ast(l, mod, sym, true, out_value);
                break;
            }

            case AST_BUILTIN_MAX:
            case AST_BUILTIN_MIN:
            case AST_BUILTIN_CAP:
            case AST_BUILTIN_PTR:
            case AST_BUILTIN_TYPE_INFO:
            case AST_BUILTIN_LEN:
            case AST_BUILTIN_VEC_ACCESS: {
                llvm_codegen_ast(l, mod, sym, is_const, out_value);
                break;
            }

            case AST_IMPORT: break;

            default: assert(0); break;
            }

            break;
        }
        default: assert(0); break;
        }
        break;
    }

    case AST_PROC_CALL: {
        if (ast->proc_call.is_template_inst)
        {
            assert(ast->proc_call.resolves_to);
            llvm_codegen_ast(
                l, mod, ast->proc_call.resolves_to, is_const, out_value);
            break;
        }

        AstValue function_value = {0};
        llvm_codegen_ast(l, mod, ast->proc_call.expr, false, &function_value);
        LLVMValueRef fun = load_val(mod, &function_value);

        unsigned param_count = (unsigned)(ast->proc_call.params.len);
        LLVMValueRef *params =
            bump_alloc(&l->compiler->bump, sizeof(LLVMValueRef) * param_count);

        TypeInfo *proc_ptr_ty = ast->proc_call.expr->type_info;
        TypeInfo *proc_ty = proc_ptr_ty->ptr.sub;

        assert(l->operand_scope_stack.len > 0);

        array_push(&l->scope_stack, *array_last(&l->operand_scope_stack));
        for (size_t i = 0; i < param_count; i++)
        {
            TypeInfo *param_expected_type = NULL;
            if (i < (proc_ty->proc.params.len))
            {
                param_expected_type = proc_ty->proc.params.ptr[i];
            }

            TypeInfo *param_type = ast->proc_call.params.ptr[i].type_info;

            AstValue param_value = {0};
            llvm_codegen_ast(
                l, mod, &ast->proc_call.params.ptr[i], false, &param_value);
            if (is_type_compound(param_type))
            {
                params[i] = param_value.value;
                if (!param_value.is_lvalue)
                {
                    params[i] = build_alloca(l, mod, param_type);
                    LLVMBuildStore(mod->builder, param_value.value, params[i]);
                }
            }
            else
            {
                params[i] = load_val(mod, &param_value);
            }

            if (param_expected_type)
            {
                params[i] = autocast_value(
                    l, mod, param_type, param_expected_type, params[i]);
            }
            else if (
                (proc_ty->flags & TYPE_FLAG_C_VARARGS) == TYPE_FLAG_C_VARARGS)
            {
                // Promote float to double when passed as variadic argument
                // as per section 6.5.2.2 of the C standard
                if (param_type->kind == TYPE_FLOAT &&
                    param_type->floating.num_bits == 32)
                {
                    params[i] = LLVMBuildFPExt(
                        mod->builder, params[i], LLVMDoubleType(), "");
                }
            }
            assert(params[i]);
        }
        array_pop(&l->scope_stack);

        // TODO: this is a workaround for the location not being set after
        // generating the parameters for some reason
        if (l->di_location_stack.len > 0)
        {
            LLVMSetCurrentDebugLocation2(
                mod->builder, *array_last(&l->di_location_stack));
        }
        else
        {
            LLVMSetCurrentDebugLocation2(mod->builder, NULL);
        }

        AstValue result_value = {0};
        result_value.value =
            LLVMBuildCall(mod->builder, fun, params, param_count, "");
        if (is_type_compound(ast->type_info))
        {
            result_value.is_lvalue = true;

            if (out_value && out_value->value)
            {
                LLVMValueRef alloca = out_value->value;
                LLVMBuildStore(mod->builder, result_value.value, alloca);
                result_value.value = alloca;
            }
            else
            {
                LLVMValueRef alloca = build_alloca(l, mod, ast->type_info);
                LLVMBuildStore(mod->builder, result_value.value, alloca);
                result_value.value = alloca;
            }
        }

        if (out_value) *out_value = result_value;

        break;
    }

    case AST_INTRINSIC_CALL: {
        switch (ast->intrinsic_call.type)
        {
        case INTRINSIC_SIZE_OF: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];
            TypeInfo *type = NULL;

            if (param->type_info->kind == TYPE_TYPE)
                type = param->as_type;
            else
                type = param->type_info;

            assert(type);

            AstValue size_val = {0};
            size_val.value = LLVMConstInt(
                llvm_type(l, ast->type_info),
                (unsigned long long)size_of_type(l->compiler, type),
                false);
            if (out_value) *out_value = size_val;

            break;
        }

        case INTRINSIC_ALIGN_OF: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            TypeInfo *type = NULL;

            if (param->type_info->kind == TYPE_TYPE)
                type = param->as_type;
            else
                type = param->type_info;

            assert(type);

            AstValue align_val = {0};
            align_val.value = LLVMConstInt(
                llvm_type(l, ast->type_info),
                (unsigned long long)align_of_type(l->compiler, type),
                false);
            if (out_value) *out_value = align_val;

            break;
        }

        case INTRINSIC_SQRT: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            AstValue param_val = {0};
            llvm_codegen_ast(l, mod, param, is_const, &param_val);
            LLVMValueRef param_ref = load_val(mod, &param_val);
            LLVMTypeRef param_type = llvm_type(l, param->type_info);

            String intrin_name = STR("llvm.sqrt");

            LLVMValueRef intrinsic = LLVMGetIntrinsicDeclaration(
                mod->mod,
                LLVMLookupIntrinsicID(intrin_name.ptr, intrin_name.len),
                &param_type,
                1);

            AstValue val = {0};
            val.value =
                LLVMBuildCall(mod->builder, intrinsic, &param_ref, 1, "");
            if (out_value) *out_value = val;
            break;
        }

        case INTRINSIC_COS: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            AstValue param_val = {0};
            llvm_codegen_ast(l, mod, param, is_const, &param_val);
            LLVMValueRef param_ref = load_val(mod, &param_val);
            LLVMTypeRef param_type = llvm_type(l, param->type_info);

            String intrin_name = STR("llvm.cos");

            LLVMValueRef intrinsic = LLVMGetIntrinsicDeclaration(
                mod->mod,
                LLVMLookupIntrinsicID(intrin_name.ptr, intrin_name.len),
                &param_type,
                1);

            AstValue val = {0};
            val.value =
                LLVMBuildCall(mod->builder, intrinsic, &param_ref, 1, "");
            if (out_value) *out_value = val;
            break;
        }

        case INTRINSIC_SIN: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            AstValue param_val = {0};
            llvm_codegen_ast(l, mod, param, is_const, &param_val);
            LLVMValueRef param_ref = load_val(mod, &param_val);
            LLVMTypeRef param_type = llvm_type(l, param->type_info);

            String intrin_name = STR("llvm.sin");

            LLVMValueRef intrinsic = LLVMGetIntrinsicDeclaration(
                mod->mod,
                LLVMLookupIntrinsicID(intrin_name.ptr, intrin_name.len),
                &param_type,
                1);

            AstValue val = {0};
            val.value =
                LLVMBuildCall(mod->builder, intrinsic, &param_ref, 1, "");
            if (out_value) *out_value = val;
            break;
        }

        case INTRINSIC_TYPE_INFO_OF: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            AstValue type_info_value = {0};
            type_info_value.is_lvalue = true;

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(
                    LLVMInt32Type(), param->as_type->rtti_index, false),
            };

            type_info_value.value = LLVMBuildGEP(
                mod->builder, mod->rtti_type_infos, indices, 2, "");

            if (out_value) *out_value = type_info_value;

            break;
        }

        case INTRINSIC_ALLOC: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            LLVMValueRef malloc_fn = llvm_get_malloc_fn(l, mod);
            assert(malloc_fn);

            AstValue param_val = {0};
            llvm_codegen_ast(l, mod, param, is_const, &param_val);

            AstValue result_value = {0};
            LLVMValueRef params[1] = {load_val(mod, &param_val)};
            result_value.value =
                LLVMBuildCall(mod->builder, malloc_fn, params, 1, "");
            if (out_value) *out_value = result_value;

            break;
        }

        case INTRINSIC_REALLOC: {
            Ast *ptr = &ast->intrinsic_call.params.ptr[0];
            Ast *size = &ast->intrinsic_call.params.ptr[1];

            LLVMValueRef realloc_fn = llvm_get_realloc_fn(l, mod);
            assert(realloc_fn);

            AstValue ptr_val = {0};
            llvm_codegen_ast(l, mod, ptr, is_const, &ptr_val);

            AstValue size_val = {0};
            llvm_codegen_ast(l, mod, size, is_const, &size_val);

            AstValue result_value = {0};
            LLVMValueRef params[2] = {
                LLVMBuildPointerCast(
                    mod->builder,
                    load_val(mod, &ptr_val),
                    LLVMPointerType(LLVMVoidType(), 0),
                    ""),
                load_val(mod, &size_val),
            };
            result_value.value =
                LLVMBuildCall(mod->builder, realloc_fn, params, 2, "");
            if (out_value) *out_value = result_value;

            break;
        }

        case INTRINSIC_FREE: {
            Ast *param = &ast->intrinsic_call.params.ptr[0];

            LLVMValueRef free_fn = llvm_get_free_fn(l, mod);
            assert(free_fn);

            AstValue param_val = {0};
            llvm_codegen_ast(l, mod, param, is_const, &param_val);

            LLVMValueRef params[1] = {
                LLVMBuildPointerCast(
                    mod->builder,
                    load_val(mod, &param_val),
                    LLVMPointerType(LLVMVoidType(), 0),
                    ""),
            };
            LLVMBuildCall(mod->builder, free_fn, params, 1, "");

            break;
        }

        case INTRINSIC_NEW: {
            Ast *type = &ast->intrinsic_call.params.ptr[0];

            LLVMValueRef malloc_fn = llvm_get_malloc_fn(l, mod);
            assert(malloc_fn);

            AstValue result_value = {0};
            LLVMValueRef params[1] = {
                LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type),
                    size_of_type(l->compiler, type->as_type),
                    0),
            };

            result_value.value = LLVMBuildPointerCast(
                mod->builder,
                LLVMBuildCall(mod->builder, malloc_fn, params, 1, ""),
                llvm_type(l, ast->type_info),
                "");

            if (out_value) *out_value = result_value;

            break;
        }

        case INTRINSIC_MAKE: {
            Ast *type = &ast->intrinsic_call.params.ptr[0];
            Ast *length = &ast->intrinsic_call.params.ptr[1];
            Ast *cap = length;
            if (ast->intrinsic_call.params.len == 3)
            {
                cap = &ast->intrinsic_call.params.ptr[2];
            }

            AstValue result_value = {0};
            result_value.is_lvalue = true;
            if (out_value && out_value->value)
            {
                result_value.value = out_value->value;
            }
            else
            {
                result_value.value = build_alloca(l, mod, ast->type_info);
            }

            LLVMValueRef malloc_fn = llvm_get_malloc_fn(l, mod);
            assert(malloc_fn);

            AstValue length_val = {0};
            llvm_codegen_ast(l, mod, length, is_const, &length_val);
            LLVMValueRef loaded_length_val = load_val(mod, &length_val);

            LLVMValueRef obj_size = LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                size_of_type(l->compiler, type->as_type),
                0);

            LLVMValueRef params[1] = {
                LLVMBuildMul(mod->builder, loaded_length_val, obj_size, ""),
            };

            LLVMValueRef ptr = LLVMBuildPointerCast(
                mod->builder,
                LLVMBuildCall(mod->builder, malloc_fn, params, 1, ""),
                LLVMPointerType(llvm_type(l, ast->type_info->array.sub), 0),
                "");

            LLVMValueRef indices[2] = {0};

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, ptr, ptr_ptr);

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef len_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, loaded_length_val, len_ptr);

            if (ast->type_info->kind == TYPE_DYNAMIC_ARRAY)
            {
                indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
                indices[1] = LLVMConstInt(LLVMInt32Type(), 2, false);
                LLVMValueRef cap_ptr = LLVMBuildGEP(
                    mod->builder, result_value.value, indices, 2, "");

                if (ast->intrinsic_call.params.len == 3)
                {
                    AstValue cap_val = {0};
                    llvm_codegen_ast(l, mod, cap, is_const, &cap_val);
                    LLVMValueRef loaded_cap_val = load_val(mod, &cap_val);
                    LLVMBuildStore(mod->builder, loaded_cap_val, cap_ptr);
                }
                else
                {
                    LLVMBuildStore(mod->builder, loaded_length_val, cap_ptr);
                }
            }

            if (out_value) *out_value = result_value;

            break;
        }

        case INTRINSIC_DELETE: {
            Ast *value = &ast->intrinsic_call.params.ptr[0];

            LLVMValueRef free_fn = llvm_get_free_fn(l, mod);
            assert(free_fn);

            AstValue value_val = {0};
            llvm_codegen_ast(l, mod, value, is_const, &value_val);

            LLVMValueRef indices[2] = {0};

            LLVMValueRef slice_ptr = load_val(mod, &value_val);

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, slice_ptr, indices, 2, "");

            LLVMValueRef ptr = LLVMBuildPointerCast(
                mod->builder,
                LLVMBuildLoad(mod->builder, ptr_ptr, ""),
                LLVMPointerType(LLVMVoidType(), 0),
                "");

            LLVMBuildCall(mod->builder, free_fn, &ptr, 1, "");
            LLVMBuildStore(
                mod->builder,
                LLVMConstNull(LLVMPointerType(
                    llvm_type(l, value->type_info->ptr.sub->array.sub), 0)),
                ptr_ptr);

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef len_ptr =
                LLVMBuildGEP(mod->builder, slice_ptr, indices, 2, "");
            LLVMBuildStore(
                mod->builder,
                LLVMConstNull(llvm_type(l, l->compiler->uint_type)),
                len_ptr);

            if (value->type_info->ptr.sub->kind == TYPE_DYNAMIC_ARRAY)
            {
                indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
                indices[1] = LLVMConstInt(LLVMInt32Type(), 2, false);
                LLVMValueRef cap_ptr =
                    LLVMBuildGEP(mod->builder, slice_ptr, indices, 2, "");
                LLVMBuildStore(
                    mod->builder,
                    LLVMConstNull(llvm_type(l, l->compiler->uint_type)),
                    cap_ptr);
            }

            break;
        }

        case INTRINSIC_APPEND: {
            Ast *array_ptr = &ast->intrinsic_call.params.ptr[0];
            Ast *value = &ast->intrinsic_call.params.ptr[1];

            LLVMValueRef realloc_fn = llvm_get_realloc_fn(l, mod);
            assert(realloc_fn);

            AstValue array_val = {0};
            llvm_codegen_ast(l, mod, array_ptr, is_const, &array_val);

            LLVMValueRef array_ptr_val = load_val(mod, &array_val);

            LLVMValueRef indices[2] = {0};

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, array_ptr_val, indices, 2, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef len_ptr =
                LLVMBuildGEP(mod->builder, array_ptr_val, indices, 2, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 2, false);
            LLVMValueRef cap_ptr =
                LLVMBuildGEP(mod->builder, array_ptr_val, indices, 2, "");

            LLVMValueRef ptr = LLVMBuildLoad(mod->builder, ptr_ptr, "");
            LLVMValueRef len = LLVMBuildLoad(mod->builder, len_ptr, "");
            LLVMValueRef cap = LLVMBuildLoad(mod->builder, cap_ptr, "");

            LLVMValueRef out_of_space =
                LLVMBuildICmp(mod->builder, LLVMIntUGE, len, cap, "");

            LLVMValueRef fun =
                LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
            assert(fun);

            LLVMBasicBlockRef begin_resize_bb = LLVMAppendBasicBlock(fun, "");
            LLVMBasicBlockRef init_cap_bb = LLVMAppendBasicBlock(fun, "");
            LLVMBasicBlockRef double_cap_bb = LLVMAppendBasicBlock(fun, "");
            LLVMBasicBlockRef end_resize_bb = LLVMAppendBasicBlock(fun, "");
            LLVMBasicBlockRef append_bb = LLVMAppendBasicBlock(fun, "");

            LLVMBuildCondBr(
                mod->builder, out_of_space, begin_resize_bb, append_bb);

            {
                LLVMPositionBuilderAtEnd(mod->builder, begin_resize_bb);

                LLVMValueRef is_cap_zero = LLVMBuildICmp(
                    mod->builder,
                    LLVMIntEQ,
                    cap,
                    LLVMConstInt(llvm_type(l, l->compiler->uint_type), 0, 0),
                    "");

                LLVMBuildCondBr(
                    mod->builder, is_cap_zero, init_cap_bb, double_cap_bb);
            }

            {
                LLVMPositionBuilderAtEnd(mod->builder, init_cap_bb);

                const size_t DEFAULT_DYNAMIC_ARRAY_CAP = 16;

                // Initialize the cap
                LLVMValueRef new_cap = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type),
                    DEFAULT_DYNAMIC_ARRAY_CAP,
                    0);
                LLVMBuildStore(mod->builder, new_cap, cap_ptr);

                LLVMBuildBr(mod->builder, end_resize_bb);
            }

            {
                LLVMPositionBuilderAtEnd(mod->builder, double_cap_bb);

                // Double the cap
                LLVMValueRef new_cap = LLVMBuildMul(
                    mod->builder,
                    LLVMConstInt(llvm_type(l, l->compiler->uint_type), 2, 0),
                    cap,
                    "");

                LLVMBuildStore(mod->builder, new_cap, cap_ptr);

                LLVMBuildBr(mod->builder, end_resize_bb);
            }

            {
                LLVMPositionBuilderAtEnd(mod->builder, end_resize_bb);

                LLVMValueRef obj_size = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type),
                    size_of_type(
                        l->compiler, array_ptr->type_info->ptr.sub->array.sub),
                    0);

                cap = LLVMBuildLoad(mod->builder, cap_ptr, "");
                LLVMValueRef params[2] = {
                    LLVMBuildPointerCast(
                        mod->builder,
                        ptr,
                        LLVMPointerType(LLVMVoidType(), 0),
                        ""),
                    LLVMBuildMul(mod->builder, obj_size, cap, ""),
                };

                LLVMValueRef new_ptr =
                    LLVMBuildCall(mod->builder, realloc_fn, params, 2, "");
                new_ptr = LLVMBuildPointerCast(
                    mod->builder,
                    new_ptr,
                    LLVMPointerType(
                        llvm_type(l, array_ptr->type_info->ptr.sub->array.sub),
                        0),
                    "");

                LLVMBuildStore(mod->builder, new_ptr, ptr_ptr);

                LLVMBuildBr(mod->builder, append_bb);
            }

            {
                LLVMPositionBuilderAtEnd(mod->builder, append_bb);

                AstValue value_val = {0};
                llvm_codegen_ast(l, mod, value, is_const, &value_val);

                LLVMValueRef loaded_value = load_val(mod, &value_val);

                ptr = LLVMBuildLoad(mod->builder, ptr_ptr, "");
                LLVMValueRef elem_ptr =
                    LLVMBuildGEP(mod->builder, ptr, &len, 1, "");

                LLVMBuildStore(mod->builder, loaded_value, elem_ptr);

                // Increment len by 1
                len = LLVMBuildAdd(
                    mod->builder,
                    len,
                    LLVMConstInt(llvm_type(l, l->compiler->uint_type), 1, 0),
                    "");
                LLVMBuildStore(mod->builder, len, len_ptr);
            }

            break;
        }

        case INTRINSIC_VECTOR_TYPE: break;
        }

        break;
    }

    case AST_EXPR_STMT: {
        llvm_codegen_ast(l, mod, ast->expr, false, NULL);
        break;
    }

    case AST_CONST_DECL: {
        if (ast->decl.value.value)
        {
            if (out_value) *out_value = ast->decl.value;
            break;
        }

        TypeInfo *const_type = ast->type_info;

        switch (const_type->kind)
        {
        case TYPE_SLICE:
        case TYPE_STRUCT:
        case TYPE_ARRAY:
        case TYPE_VECTOR: {
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
        if (ast->decl.value.value)
        {
            if (out_value) *out_value = ast->decl.value;
            break;
        }

        Ast *proc = get_scope_procedure(*array_last(&l->scope_stack));
        LLVMTypeRef llvm_ty = llvm_type(l, ast->type_info);

        if (ast->flags & AST_FLAG_EXTERN)
        {
            char *global_name = bump_c_str(&l->compiler->bump, ast->decl.name);

            // Global variable
            ast->decl.value.is_lvalue = true;
            ast->decl.value.value =
                LLVMAddGlobal(mod->mod, llvm_ty, global_name);
            LLVMSetLinkage(ast->decl.value.value, LLVMExternalLinkage);
            LLVMSetExternallyInitialized(ast->decl.value.value, false);

            if (out_value) *out_value = ast->decl.value;
            break;
        }

        if (ast->flags & AST_FLAG_STATIC)
        {
            char *global_name = bump_c_str(&l->compiler->bump, ast->decl.name);

            // Global variable
            ast->decl.value.is_lvalue = true;
            ast->decl.value.value =
                LLVMAddGlobal(mod->mod, llvm_ty, global_name);
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

        if (!proc)
        {
            char *global_name = bump_c_str(&l->compiler->bump, ast->decl.name);

            assert(!ast->decl.value.value);
            // Global variable
            ast->decl.value.is_lvalue = true;
            ast->decl.value.value =
                LLVMAddGlobal(mod->mod, llvm_ty, global_name);
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
        ast->decl.value.value = build_alloca(l, mod, ast->type_info);

        LLVMValueRef to_store = NULL;

        if (!ast->decl.uninitialized)
        {
            if (ast->decl.value_expr)
            {
                AstValue init_value = {0};
                init_value.value = ast->decl.value.value;
                llvm_codegen_ast(
                    l, mod, ast->decl.value_expr, false, &init_value);

                if (init_value.value != ast->decl.value.value)
                {
                    to_store = load_val(mod, &init_value);
                    to_store = autocast_value(
                        l,
                        mod,
                        ast->decl.value_expr->type_info,
                        ast->type_info,
                        to_store);
                }
            }
            else
            {
                to_store = LLVMConstNull(llvm_ty);
            }
        }

        if (to_store)
        {
            if (l->di_location_stack.len)
            {
                LLVMMetadataRef di_type = llvm_debug_type(l, ast->type_info);

                LLVMMetadataRef di_variable = LLVMDIBuilderCreateAutoVariable(
                    mod->di_builder,
                    *array_last(&l->di_scope_stack),
                    ast->decl.name.ptr,
                    ast->decl.name.len,
                    ast->loc.file->di_file,
                    ast->loc.line,
                    di_type,
                    true,
                    LLVMDIFlagZero,
                    align_of_type(l->compiler, ast->type_info) * 8);
                LLVMMetadataRef di_expr =
                    LLVMDIBuilderCreateExpression(mod->di_builder, NULL, 0);

                LLVMBasicBlockRef current_block =
                    LLVMGetInsertBlock(mod->builder);
                LLVMDIBuilderInsertDeclareAtEnd(
                    mod->di_builder,
                    ast->decl.value.value,
                    di_variable,
                    di_expr,
                    *array_last(&l->di_location_stack),
                    current_block);
            }

            LLVMBuildStore(mod->builder, to_store, ast->decl.value.value);
        }

        if (out_value) *out_value = ast->decl.value;

        break;
    }

    case AST_TUPLE_DECL: {
        ast->tuple_decl.value.is_lvalue = true;
        ast->tuple_decl.value.value = build_alloca(l, mod, ast->type_info);

        AstValue init_value = {0};
        init_value.value = ast->tuple_decl.value.value;
        llvm_codegen_ast(
            l, mod, ast->tuple_decl.value_expr, false, &init_value);

        LLVMValueRef to_store = NULL;
        if (init_value.value != ast->tuple_decl.value.value)
        {
            to_store = load_val(mod, &init_value);
        }

        if (to_store)
        {
            LLVMBuildStore(mod->builder, to_store, ast->tuple_decl.value.value);
        }

        for (size_t i = 0; i < ast->tuple_decl.bindings.len; ++i)
        {
            Ast *binding = &ast->tuple_decl.bindings.ptr[i];
            Ast *tuple_alias = binding->tuple_binding.alias;
            if (tuple_alias)
            {
                AstValue binding_val = {0};
                llvm_codegen_ast(l, mod, binding, is_const, &binding_val);
                assert(binding_val.value);
                assert(binding_val.is_lvalue);

                AstValue some_var = {0};
                llvm_codegen_ast(l, mod, tuple_alias, is_const, &some_var);

                assert(some_var.is_lvalue);
                assert(some_var.value);
                LLVMValueRef loaded = load_val(mod, &binding_val);
                LLVMBuildStore(mod->builder, loaded, some_var.value);
            }
        }

        if (out_value) *out_value = ast->tuple_decl.value;

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

        Ast *proc = get_scope_procedure(*array_last(&l->scope_stack));
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

            llvm_codegen_deferred_stmts(l, mod, true);
            LLVMBuildRet(mod->builder, ref);
        }
        else
        {
            llvm_codegen_deferred_stmts(l, mod, true);
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
                    build_alloca(l, mod, ast->unop.sub->type_info);
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

        array_push(&l->scope_stack, *array_last(&l->operand_scope_stack));
        AstValue right_value = {0};
        llvm_codegen_ast(l, mod, ast->subscript.right, false, &right_value);
        array_pop(&l->scope_stack);

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

        case TYPE_VECTOR:
        case TYPE_ARRAY: {
            AstValue subscript_value = {0};

            LLVMValueRef indices[2] = {
                LLVMConstInt(llvm_type(l, l->compiler->uint_type), 0, false),
                load_val(mod, &right_value),
            };

            subscript_value.is_lvalue = true;
            subscript_value.value =
                LLVMBuildGEP(mod->builder, left_value.value, indices, 2, "");

            if (out_value) *out_value = subscript_value;
            break;
        }

        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE: {
            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 0; // Index for pointer field

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

        array_push(&l->scope_stack, *array_last(&l->operand_scope_stack));
        AstValue lower_value = {0};
        AstValue upper_value = {0};
        if (ast->subscript_slice.lower && ast->subscript_slice.upper)
        {
            llvm_codegen_ast(
                l, mod, ast->subscript_slice.lower, false, &lower_value);
            llvm_codegen_ast(
                l, mod, ast->subscript_slice.upper, false, &upper_value);
        }
        array_pop(&l->scope_stack);

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
                lower_value.value = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type), 0, false);
                upper_value.value = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type),
                    ast->subscript_slice.left->type_info->array.size,
                    false);
            }

            break;
        }

        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE: {
            assert(left_value.is_lvalue);

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 0, false), // ptr index
            };

            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, left_value.value, indices, 2, "");
            left = LLVMBuildLoad(mod->builder, ptr_ptr, "");

            if (!lower_value.value && !upper_value.value)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), 1, false), // len index
                };

                LLVMValueRef len_ptr = LLVMBuildGEP(
                    mod->builder, left_value.value, indices, 2, "");

                lower_value.value = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type), 0, false);
                upper_value.value = LLVMBuildLoad(mod->builder, len_ptr, "");
            }

            break;
        }

        case TYPE_POINTER: {
            left = load_val(mod, &left_value);

            if (!lower_value.value && !upper_value.value)
            {
                lower_value.value = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type), 0, false);
                upper_value.value = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type), 0, false);
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
            result_value.value = build_alloca(l, mod, ast->type_info);
        }

        {
            LLVMValueRef ptr = LLVMBuildGEP(mod->builder, left, &lower, 1, "");

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 0, false),
            };

            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, ptr, ptr_ptr);
        }

        {
            LLVMValueRef len = LLVMBuildSub(mod->builder, upper, lower, "");
            len = LLVMBuildIntCast2(
                mod->builder,
                len,
                llvm_type(l, l->compiler->uint_type),
                false,
                "");

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 1, false),
            };

            LLVMValueRef len_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, len, len_ptr);
        }

        if (out_value)
        {
            *out_value = result_value;
        }

        break;
    }

    case AST_TO_ANY: {
        AstValue result_value = {0};
        assert(!is_const);
        assert(ast->expr->type_info->rtti_index > 0);

        result_value.is_lvalue = true;
        if (out_value && out_value->value)
        {
            result_value.value = out_value->value;
        }
        else
        {
            result_value.value = build_alloca(l, mod, ast->type_info);
        }

        AstValue val = {0};
        llvm_codegen_ast(l, mod, ast->expr, false, &val);
        LLVMValueRef ptr_val = val.value;
        if (!val.is_lvalue)
        {
            ptr_val = build_alloca(l, mod, ast->expr->type_info);
            LLVMBuildStore(mod->builder, val.value, ptr_val);
        }
        ptr_val = LLVMBuildPointerCast(
            mod->builder, ptr_val, LLVMPointerType(LLVMVoidType(), 0), "");

        LLVMValueRef indices[2];

        // Store pointer
        {
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
            LLVMValueRef ptr_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, ptr_val, ptr_ptr);
        }

        // Store type info pointer
        {
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(
                LLVMInt32Type(), ast->expr->type_info->rtti_index, false);
            LLVMValueRef type_info_ptr = LLVMBuildGEP(
                mod->builder, mod->rtti_type_infos, indices, 2, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef type_info_ptr_ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, type_info_ptr, type_info_ptr_ptr);
        }

        if (out_value)
        {
            *out_value = result_value;
        }

        break;
    }

    case AST_TUPLE_LIT: {
        AstValue result_value = {0};
        result_value.is_lvalue = true;
        if (out_value && out_value->value)
        {
            result_value.value = out_value->value;
        }
        else
        {
            result_value.value = build_alloca(l, mod, ast->type_info);
        }

        assert(
            (ast->tuple_lit.values.len) == (ast->type_info->tuple.fields.len));

        for (Ast *value = ast->tuple_lit.values.ptr;
             value != ast->tuple_lit.values.ptr + ast->tuple_lit.values.len;
             ++value)
        {
            size_t index = (size_t)(value - ast->tuple_lit.values.ptr);
            AstValue val = {0};
            llvm_codegen_ast(l, mod, value, is_const, &val);

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), index, false),
            };

            LLVMValueRef ptr =
                LLVMBuildGEP(mod->builder, result_value.value, indices, 2, "");
            LLVMBuildStore(mod->builder, load_val(mod, &val), ptr);
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
            result_value.is_lvalue = true;
            if (out_value && out_value->value)
            {
                result_value.value = out_value->value;
            }
            else
            {
                result_value.value = build_alloca(l, mod, ast->type_info);
            }

            switch (ast->type_info->kind)
            {
            case TYPE_VECTOR:
            case TYPE_ARRAY: {
                if (ast->compound.values.len != ast->type_info->array.size &&
                    ast->compound.values.len == 1)
                {
                    // Only got one value, replicate it
                    AstValue val = {0};
                    llvm_codegen_ast(
                        l, mod, &ast->compound.values.ptr[0], is_const, &val);

                    for (size_t i = 0; i < ast->type_info->array.size; ++i)
                    {
                        LLVMValueRef indices[2] = {
                            LLVMConstInt(LLVMInt32Type(), 0, false),
                            LLVMConstInt(LLVMInt32Type(), i, false),
                        };

                        LLVMValueRef ptr = LLVMBuildGEP(
                            mod->builder, result_value.value, indices, 2, "");
                        LLVMBuildStore(mod->builder, load_val(mod, &val), ptr);
                    }
                }
                else if (ast->compound.values.len == 0)
                {
                    LLVMBuildStore(
                        mod->builder,
                        LLVMConstNull(llvm_type(l, ast->type_info)),
                        result_value.value);
                }
                else
                {
                    assert(
                        ast->compound.values.len == ast->type_info->array.size);

                    for (Ast *value = ast->compound.values.ptr;
                         value !=
                         ast->compound.values.ptr + ast->compound.values.len;
                         ++value)
                    {
                        size_t index =
                            (size_t)(value - ast->compound.values.ptr);
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
                }

                break;
            }

            case TYPE_STRUCT: {
                if (ast->compound.values.len == 0)
                {
                    LLVMBuildStore(
                        mod->builder,
                        LLVMConstNull(llvm_type(l, ast->type_info)),
                        result_value.value);
                }
                else
                {
                    if (ast->compound.is_named)
                    {
                        // Zero-initialize it first
                        LLVMBuildStore(
                            mod->builder,
                            LLVMConstNull(llvm_type(l, ast->type_info)),
                            result_value.value);

                        assert(ast->type_info->scope);
                        assert(
                            ast->compound.values.len ==
                            ast->compound.names.len);
                        for (size_t i = 0; i < ast->compound.values.len; ++i)
                        {
                            Ast *field = get_symbol(
                                ast->type_info->scope,
                                ast->compound.names.ptr[i],
                                ast->loc.file);
                            assert(field->type == AST_STRUCT_FIELD);

                            AstValue val = {0};
                            llvm_codegen_ast(
                                l,
                                mod,
                                &ast->compound.values.ptr[i],
                                is_const,
                                &val);

                            LLVMValueRef indices[2] = {
                                LLVMConstInt(LLVMInt32Type(), 0, false),
                                LLVMConstInt(
                                    LLVMInt32Type(),
                                    field->struct_field.index,
                                    false),
                            };

                            LLVMValueRef ptr = LLVMBuildGEP(
                                mod->builder,
                                result_value.value,
                                indices,
                                2,
                                "");
                            LLVMBuildStore(
                                mod->builder, load_val(mod, &val), ptr);
                        }
                    }
                    else
                    {
                        assert(
                            (ast->compound.values.len) ==
                            (ast->type_info->structure.fields.len));

                        for (Ast *value = ast->compound.values.ptr;
                             value != ast->compound.values.ptr +
                                          ast->compound.values.len;
                             ++value)
                        {
                            size_t index =
                                (size_t)(value - ast->compound.values.ptr);
                            AstValue val = {0};
                            llvm_codegen_ast(l, mod, value, is_const, &val);

                            LLVMValueRef indices[2] = {
                                LLVMConstInt(LLVMInt32Type(), 0, false),
                                LLVMConstInt(LLVMInt32Type(), index, false),
                            };

                            LLVMValueRef ptr = LLVMBuildGEP(
                                mod->builder,
                                result_value.value,
                                indices,
                                2,
                                "");
                            LLVMBuildStore(
                                mod->builder, load_val(mod, &val), ptr);
                        }
                    }
                }

                break;
            }

            default: {
                assert(ast->compound.values.len == 1);
                llvm_codegen_ast(
                    l,
                    mod,
                    &ast->compound.values.ptr[0],
                    is_const,
                    &result_value);
                break;
            }
            }
        }
        else
        {
            switch (ast->type_info->kind)
            {
            case TYPE_VECTOR: {
                LLVMValueRef *values = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * ast->compound.values.len);

                if ((ast->compound.values.len) != ast->type_info->array.size &&
                    (ast->compound.values.len) == 1)
                {
                    // Only got one value, replicate it
                    AstValue val = {0};
                    llvm_codegen_ast(
                        l, mod, &ast->compound.values.ptr[0], is_const, &val);

                    for (size_t i = 0; i < ast->type_info->array.size; ++i)
                    {
                        values[i] = val.value;
                    }
                }
                else
                {
                    for (Ast *value = ast->compound.values.ptr;
                         value !=
                         ast->compound.values.ptr + ast->compound.values.len;
                         ++value)
                    {
                        size_t index =
                            (size_t)(value - ast->compound.values.ptr);
                        AstValue val = {0};
                        llvm_codegen_ast(l, mod, value, true, &val);
                        values[index] = val.value;
                    }
                }

                result_value.value =
                    LLVMConstVector(values, ast->type_info->array.size);

                break;
            }

            case TYPE_ARRAY: {
                LLVMValueRef *values = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * ast->compound.values.len);

                if ((ast->compound.values.len) != ast->type_info->array.size &&
                    (ast->compound.values.len) == 1)
                {
                    // Only got one value, replicate it
                    AstValue val = {0};
                    llvm_codegen_ast(
                        l, mod, &ast->compound.values.ptr[0], is_const, &val);

                    for (size_t i = 0; i < ast->type_info->array.size; ++i)
                    {
                        values[i] = val.value;
                    }
                }
                else
                {
                    for (Ast *value = ast->compound.values.ptr;
                         value !=
                         ast->compound.values.ptr + ast->compound.values.len;
                         ++value)
                    {
                        size_t index =
                            (size_t)(value - ast->compound.values.ptr);
                        AstValue val = {0};
                        llvm_codegen_ast(l, mod, value, true, &val);
                        values[index] = val.value;
                    }
                }

                result_value.value = LLVMConstArray(
                    llvm_type(l, ast->type_info->array.sub),
                    values,
                    ast->type_info->array.size);

                break;
            }

            case TYPE_STRUCT: {
                LLVMValueRef *values = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * ast->compound.values.len);

                for (Ast *value = ast->compound.values.ptr;
                     value !=
                     ast->compound.values.ptr + ast->compound.values.len;
                     ++value)
                {
                    size_t index = (size_t)(value - ast->compound.values.ptr);
                    AstValue val = {0};
                    llvm_codegen_ast(l, mod, value, true, &val);
                    values[index] = val.value;
                }

                result_value.value = LLVMConstNamedStruct(
                    llvm_type(l, ast->type_info),
                    values,
                    ast->compound.values.len);

                break;
            }

            default: {
                assert(ast->compound.values.len == 1);
                llvm_codegen_ast(
                    l,
                    mod,
                    &ast->compound.values.ptr[0],
                    is_const,
                    &result_value);
                break;
            }
            }
        }

        if (out_value)
        {
            *out_value = result_value;
        }
        break;
    }

    case AST_STRUCT_FIELD: {
        Ast *left_expr = ast->sym_scope->ast;
        assert(left_expr);
        assert(left_expr->type_info);
        assert(left_expr->type_info->kind == TYPE_STRUCT);

        AstValue struct_val = ast->sym_scope->value;
        assert(struct_val.value);
        assert(struct_val.is_lvalue);

        AstValue field_value = {0};
        field_value.is_lvalue = true;

        if (!left_expr->type_info->structure.is_union)
        {
            field_value.value = LLVMBuildStructGEP(
                mod->builder, struct_val.value, ast->struct_field.index, "");
        }
        else
        {
            field_value.value = LLVMBuildBitCast(
                mod->builder,
                struct_val.value,
                LLVMPointerType(llvm_type(l, ast->type_info), 0),
                "");
        }

        if (out_value) *out_value = field_value;

        break;
    }

    case AST_ENUM_FIELD: {
        AstValue field_val = {0};
        llvm_codegen_ast(l, mod, ast->enum_field.value_expr, true, &field_val);

        if (out_value) *out_value = field_val;

        break;
    }

    case AST_BUILTIN_VEC_ACCESS: {
        Scope *scope = *array_last(&l->scope_stack);
        assert(scope->type_info);

        AstValue vec_value = (*array_last(&l->scope_stack))->value;

        AstValue subscript_value = {0};

        LLVMValueRef indices[2] = {
            LLVMConstInt(LLVMInt32Type(), 0, false),
            LLVMConstInt(LLVMInt32Type(), ast->vec_access.position, false),
        };

        subscript_value.is_lvalue = true;
        subscript_value.value =
            LLVMBuildGEP(mod->builder, vec_value.value, indices, 2, "");

        if (out_value) *out_value = subscript_value;

        break;
    }

    case AST_BUILTIN_PTR: {
        Scope *scope = *array_last(&l->scope_stack);
        assert(scope->type_info);

        TypeInfo *type = scope->type_info;

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE: {
            AstValue slice_value = (*array_last(&l->scope_stack))->value;
            assert(slice_value.value);

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 0; // ptr index

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
            AstValue array_value = (*array_last(&l->scope_stack))->value;
            assert(array_value.value);
            assert(array_value.is_lvalue);

            LLVMValueRef indices[2] = {
                LLVMConstInt(LLVMInt32Type(), 0, false),
                LLVMConstInt(LLVMInt32Type(), 0, false),
            };

            AstValue result_value = {0};
            result_value.is_lvalue = false;
            result_value.value =
                LLVMBuildGEP(mod->builder, array_value.value, indices, 2, "");

            if (out_value) *out_value = result_value;
            break;
        }

        case TYPE_ANY: {
            AstValue any_value = (*array_last(&l->scope_stack))->value;
            assert(any_value.value);

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 0; // ptr index

            if (any_value.is_lvalue)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, any_value.value, indices, 2, "");
            }
            else
            {
                LLVMValueRef indices[1] = {
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, any_value.value, indices, 1, "");
            }

            AstValue result_value = {0};
            result_value.is_lvalue = true;
            result_value.value = field_ptr;

            if (out_value) *out_value = result_value;

            break;
        }

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_TYPE_INFO: {
        Scope *scope = *array_last(&l->scope_stack);
        assert(scope->type_info);

        TypeInfo *type = scope->type_info;

        switch (type->kind)
        {
        case TYPE_ANY: {
            AstValue any_value = (*array_last(&l->scope_stack))->value;

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 1; // type_info index

            if (any_value.is_lvalue)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, any_value.value, indices, 2, "");
            }
            else
            {
                LLVMValueRef indices[1] = {
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, any_value.value, indices, 1, "");
            }

            AstValue result_value = {0};
            result_value.is_lvalue = true;
            result_value.value = field_ptr;

            if (out_value) *out_value = result_value;

            break;
        }

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_LEN: {
        Scope *scope = *array_last(&l->scope_stack);
        assert(scope->type_info);

        TypeInfo *type = scope->type_info;

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE: {
            AstValue slice_value = (*array_last(&l->scope_stack))->value;

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 1; // len index

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

        case TYPE_VECTOR:
        case TYPE_ARRAY: {
            AstValue result_value = {0};
            result_value.is_lvalue = false;
            result_value.value = LLVMConstInt(
                llvm_type(l, l->compiler->uint_type), type->array.size, false);

            if (out_value) *out_value = result_value;
            break;
        }

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_CAP: {
        Scope *scope = *array_last(&l->scope_stack);
        assert(scope->type_info);

        TypeInfo *type = scope->type_info;

        switch (type->kind)
        {
        case TYPE_DYNAMIC_ARRAY: {
            AstValue arr_value = (*array_last(&l->scope_stack))->value;

            LLVMValueRef field_ptr = NULL;
            uint32_t field_index = 2; // cap index

            if (arr_value.is_lvalue)
            {
                LLVMValueRef indices[2] = {
                    LLVMConstInt(LLVMInt32Type(), 0, false),
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, arr_value.value, indices, 2, "");
            }
            else
            {
                LLVMValueRef indices[1] = {
                    LLVMConstInt(LLVMInt32Type(), field_index, false),
                };

                field_ptr =
                    LLVMBuildGEP(mod->builder, arr_value.value, indices, 1, "");
            }

            AstValue result_value = {0};
            result_value.is_lvalue = true;
            result_value.value = field_ptr;

            if (out_value) *out_value = result_value;

            break;
        }

        default: assert(0); break;
        }

        break;
    }

    case AST_BUILTIN_MAX: {
        Scope *scope = *array_last(&l->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        AstValue result_value = {0};

        switch (type->kind)
        {
        case TYPE_INT: {
            uint64_t max_val;

            if (type->integer.is_signed)
            {
                switch (type->integer.num_bits)
                {
                case 8: max_val = INT8_MAX; break;
                case 16: max_val = INT16_MAX; break;
                case 32: max_val = INT32_MAX; break;
                case 64: max_val = INT64_MAX; break;
                default: assert(0); break;
                }
            }
            else
            {
                switch (type->integer.num_bits)
                {
                case 8: max_val = UINT8_MAX; break;
                case 16: max_val = UINT16_MAX; break;
                case 32: max_val = UINT32_MAX; break;
                case 64: max_val = UINT64_MAX; break;
                default: assert(0); break;
                }
            }

            result_value.value =
                LLVMConstInt(llvm_type(l, type), max_val, false);

            break;
        }

        case TYPE_FLOAT: {
            double max_val;

            switch (type->floating.num_bits)
            {
            case 32: max_val = FLT_MAX; break;
            case 64: max_val = DBL_MAX; break;
            default: assert(0); break;
            }

            result_value.value = LLVMConstReal(llvm_type(l, type), max_val);

            break;
        }

        default: assert(0); break;
        }

        if (out_value) *out_value = result_value;

        break;
    }

    case AST_BUILTIN_MIN: {
        Scope *scope = *array_last(&l->scope_stack);
        TypeInfo *type = scope->type_info;
        assert(type);

        AstValue result_value = {0};

        switch (type->kind)
        {
        case TYPE_INT: {
            uint64_t min_val;

            if (type->integer.is_signed)
            {
                switch (type->integer.num_bits)
                {
                case 8: min_val = INT8_MIN; break;
                case 16: min_val = INT16_MIN; break;
                case 32: min_val = INT32_MIN; break;
                case 64: min_val = INT64_MIN; break;
                default: assert(0); break;
                }
            }
            else
            {
                min_val = 0;
            }

            result_value.value =
                LLVMConstInt(llvm_type(l, type), min_val, false);

            break;
        }

        case TYPE_FLOAT: {
            double min_val;

            switch (type->floating.num_bits)
            {
            case 32: min_val = FLT_MIN; break;
            case 64: min_val = DBL_MIN; break;
            default: assert(0); break;
            }

            result_value.value = LLVMConstReal(llvm_type(l, type), min_val);

            break;
        }

        default: assert(0); break;
        }

        if (out_value) *out_value = result_value;

        break;
    }

    case AST_USING: {
        if (ast->expr->type_info->kind != TYPE_NAMESPACE)
        {
            AstValue value = {0};
            llvm_codegen_ast(l, mod, ast->expr, is_const, &value);

            Scope *expr_scope = get_expr_scope(
                l->compiler, *array_last(&l->scope_stack), ast->expr);

            assert(value.value);
            expr_scope->value = value;
        }
        break;
    }

    case AST_ACCESS: {
        assert(l->scope_stack.len > 0);

        Scope *accessed_scope = get_expr_scope(
            l->compiler, *array_last(&l->scope_stack), ast->access.left);
        assert(accessed_scope);

        if (accessed_scope->type == SCOPE_INSTANCED)
        {
            AstValue accessed_value = {0};
            llvm_codegen_ast(
                l, mod, ast->access.left, is_const, &accessed_value);

            if (ast->access.left->type_info->kind == TYPE_POINTER)
            {
                accessed_value.value = load_val(mod, &accessed_value);
            }

            accessed_scope->value = accessed_value;
        }

        array_push(&l->scope_stack, accessed_scope);
        llvm_codegen_ast(l, mod, ast->access.right, false, out_value);
        array_pop(&l->scope_stack);

        break;
    }

    case AST_BINARY_EXPR: {
        AstValue left_val = {0};
        AstValue right_val = {0};
        llvm_codegen_ast(l, mod, ast->binop.left, is_const, &left_val);
        llvm_codegen_ast(l, mod, ast->binop.right, is_const, &right_val);

        TypeInfo *lhs_type =
            get_inner_primitive_type(ast->binop.left->type_info);
        TypeInfo *rhs_type =
            get_inner_primitive_type(ast->binop.right->type_info);

        AstValue result_value = {0};

        LLVMValueRef lhs_ptr = left_val.value;

        LLVMValueRef lhs = NULL;
        LLVMValueRef rhs = NULL;

        TypeInfo *op_type = lhs_type;
        if (lhs_type->kind == TYPE_VECTOR)
        {
            op_type = lhs_type->array.sub;
        }
        else if (rhs_type->kind == TYPE_VECTOR)
        {
            op_type = rhs_type->array.sub;
        }

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
            if (lhs_type->kind == TYPE_VECTOR && rhs_type->kind != TYPE_VECTOR)
            {
                LLVMValueRef vector = build_alloca(l, mod, lhs_type);
                for (unsigned i = 0; i < lhs_type->array.size; ++i)
                {
                    LLVMValueRef indices[2] = {
                        LLVMConstInt(LLVMInt32Type(), 0, false),
                        LLVMConstInt(LLVMInt32Type(), i, false),
                    };

                    LLVMValueRef ptr =
                        LLVMBuildGEP(mod->builder, vector, indices, 2, "");
                    LLVMBuildStore(mod->builder, rhs, ptr);
                }
                rhs = LLVMBuildLoad(mod->builder, vector, "");
            }

            if (rhs_type->kind == TYPE_VECTOR && lhs_type->kind != TYPE_VECTOR)
            {
                LLVMValueRef vector = build_alloca(l, mod, rhs_type);
                for (unsigned i = 0; i < rhs_type->array.size; ++i)
                {
                    LLVMValueRef indices[2] = {
                        LLVMConstInt(LLVMInt32Type(), 0, false),
                        LLVMConstInt(LLVMInt32Type(), i, false),
                    };

                    LLVMValueRef ptr =
                        LLVMBuildGEP(mod->builder, vector, indices, 2, "");
                    LLVMBuildStore(mod->builder, lhs, ptr);
                }
                lhs = LLVMBuildLoad(mod->builder, vector, "");
            }
        }
        else
        {
            // Constant vectors

            if (lhs_type->kind == TYPE_VECTOR && rhs_type->kind != TYPE_VECTOR)
            {
                LLVMValueRef *vals = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * lhs_type->array.size);
                for (unsigned i = 0; i < lhs_type->array.size; ++i)
                {
                    vals[i] = rhs;
                }
                rhs = LLVMConstVector(vals, (unsigned)lhs_type->array.size);
            }

            if (rhs_type->kind == TYPE_VECTOR && lhs_type->kind != TYPE_VECTOR)
            {
                LLVMValueRef *vals = bump_alloc(
                    &l->compiler->bump,
                    sizeof(LLVMValueRef) * rhs_type->array.size);
                for (unsigned i = 0; i < rhs_type->array.size; ++i)
                {
                    vals[i] = lhs;
                }
                lhs = LLVMConstVector(vals, (unsigned)rhs_type->array.size);
            }
        }

        if (!is_const)
        {
            switch (ast->binop.type)
            {
            case BINOP_ADD: {
                switch (op_type->kind)
                {
                case TYPE_INT: {
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT: {
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT: {
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT: {
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT: {
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
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
                switch (op_type->kind)
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
                switch (op_type->kind)
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
                    if (op_type->integer.is_signed)
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
                    if (op_type->integer.is_signed)
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
                    if (op_type->integer.is_signed)
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
                    if (op_type->integer.is_signed)
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
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
                {
                case TYPE_INT:
                    if (op_type->integer.is_signed)
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
                switch (op_type->kind)
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
                switch (op_type->kind)
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
                switch (op_type->kind)
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

    case AST_SWITCH: {
        AstValue expr_val = {0};
        llvm_codegen_ast(l, mod, ast->switch_stmt.expr, false, &expr_val);

        LLVMValueRef fun =
            LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
        assert(fun);

        size_t case_count = ast->switch_stmt.vals.len;

        LLVMBasicBlockRef *case_bbs = bump_alloc(
            &l->compiler->bump, sizeof(LLVMBasicBlockRef) * case_count);
        LLVMBasicBlockRef default_bb = NULL;
        for (size_t i = 0; i < case_count; ++i)
        {
            case_bbs[i] = LLVMAppendBasicBlock(fun, "");
            if (ast->switch_stmt.vals.ptr[i].type == AST_UNINITIALIZED)
            {
                default_bb = case_bbs[i];
            }
        }

        LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");
        if (!default_bb) default_bb = merge_bb;

        LLVMValueRef switch_val = LLVMBuildSwitch(
            mod->builder,
            load_val(mod, &expr_val),
            default_bb,
            (unsigned)case_count);

        for (size_t i = 0; i < case_count; ++i)
        {
            Ast *case_val = &ast->switch_stmt.vals.ptr[i];
            if (case_val->type == AST_NOTHING) continue;

            AstValue cond_val;
            llvm_codegen_ast(l, mod, case_val, true, &cond_val);
            LLVMAddCase(switch_val, cond_val.value, case_bbs[i]);
        }

        for (size_t i = 0; i < case_count; ++i)
        {
            LLVMPositionBuilderAtEnd(mod->builder, case_bbs[i]);

            LLVMBasicBlockRef continue_bb = case_bbs[i + 1];
            if (i == (case_count - 1)) continue_bb = merge_bb;

            array_push(&l->continue_block_stack, continue_bb);
            array_push(&l->break_block_stack, merge_bb);
            llvm_codegen_ast(
                l, mod, &ast->switch_stmt.stmts.ptr[i], false, NULL);
            array_pop(&l->continue_block_stack);
            array_pop(&l->break_block_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
            {
                LLVMBuildBr(mod->builder, merge_bb);
            }
        }

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

            array_push(&l->break_block_stack, merge_bb);
            array_push(&l->continue_block_stack, cond_bb);
            llvm_codegen_ast(l, mod, ast->while_stmt.stmt, false, NULL);
            array_pop(&l->continue_block_stack);
            array_pop(&l->break_block_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, cond_bb);
        }

        // Merge
        LLVMPositionBuilderAtEnd(mod->builder, merge_bb);

        break;
    }

    case AST_FOR: {
        array_push(&l->scope_stack, ast->scope);
        array_push(&l->operand_scope_stack, ast->scope);

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

            array_push(&l->break_block_stack, merge_bb);
            array_push(&l->continue_block_stack, inc_bb);
            llvm_codegen_ast(l, mod, ast->for_stmt.stmt, false, NULL);
            array_pop(&l->continue_block_stack);
            array_pop(&l->break_block_stack);

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

        array_pop(&l->operand_scope_stack);
        array_pop(&l->scope_stack);
        break;
    }

    case AST_FOREACH: {
        array_push(&l->scope_stack, ast->scope);
        array_push(&l->operand_scope_stack, ast->scope);

        LLVMValueRef current_ptr_ptr = NULL;
        if (ast->flags & AST_FLAG_FOREACH_PTR)
        {
            assert(ast->type_info->kind == TYPE_POINTER);
            current_ptr_ptr = build_alloca(l, mod, ast->type_info);
            ast->foreach_stmt.value.is_lvalue = true;
            ast->foreach_stmt.value.value = current_ptr_ptr;
        }
        else
        {
            current_ptr_ptr = build_alloca(
                l, mod, create_pointer_type(l->compiler, ast->type_info));
            ast->foreach_stmt.value.is_lvalue = true;
            ast->foreach_stmt.value.value =
                build_alloca(l, mod, ast->type_info);
        }

        AstValue iterator_value = {0};
        llvm_codegen_ast(
            l, mod, ast->foreach_stmt.iterator, false, &iterator_value);

        LLVMValueRef first = NULL;
        LLVMValueRef last = NULL;

        LLVMValueRef fun =
            LLVMGetBasicBlockParent(LLVMGetInsertBlock(mod->builder));
        assert(fun);

        Ast *iterator = ast->foreach_stmt.iterator;

        LLVMValueRef indices[2];

        switch (iterator->type_info->kind)
        {
        case TYPE_ARRAY: {
            unsigned index_count = 0;
            if (iterator_value.is_lvalue)
            {
                index_count++;
                indices[index_count - 1] = LLVMConstInt(
                    llvm_type(l, l->compiler->uint_type), 0, false);
            }

            index_count++;

            indices[index_count - 1] =
                LLVMConstInt(llvm_type(l, l->compiler->uint_type), 0, false);
            first = LLVMBuildGEP(
                mod->builder, iterator_value.value, indices, index_count, "");

            indices[index_count - 1] = LLVMConstInt(
                llvm_type(l, l->compiler->uint_type),
                iterator->type_info->array.size,
                false);
            last = LLVMBuildGEP(
                mod->builder, iterator_value.value, indices, index_count, "");

            break;
        }

        case TYPE_DYNAMIC_ARRAY:
        case TYPE_SLICE: {
            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 0, false);
            first = LLVMBuildLoad(
                mod->builder,
                LLVMBuildGEP(
                    mod->builder, iterator_value.value, indices, 2, ""),
                "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 0, false);
            indices[1] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef len = LLVMBuildLoad(
                mod->builder,
                LLVMBuildGEP(
                    mod->builder, iterator_value.value, indices, 2, ""),
                "");

            indices[0] = len;
            last = LLVMBuildGEP(mod->builder, first, indices, 1, "");
            break;
        }

        default: assert(0); break;
        }

        LLVMBuildStore(mod->builder, first, current_ptr_ptr);

        LLVMBasicBlockRef cond_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef stmts_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef inc_bb = LLVMAppendBasicBlock(fun, "");
        LLVMBasicBlockRef merge_bb = LLVMAppendBasicBlock(fun, "");

        LLVMBuildBr(mod->builder, cond_bb);

        // Cond
        {
            LLVMPositionBuilderAtEnd(mod->builder, cond_bb);

            LLVMValueRef current_ptr =
                LLVMBuildLoad(mod->builder, current_ptr_ptr, "");

            LLVMValueRef cond =
                LLVMBuildICmp(mod->builder, LLVMIntNE, current_ptr, last, "");

            LLVMBuildCondBr(mod->builder, cond, stmts_bb, merge_bb);
        }

        // Stmts
        {
            LLVMPositionBuilderAtEnd(mod->builder, stmts_bb);

            if ((ast->flags & AST_FLAG_FOREACH_PTR) != AST_FLAG_FOREACH_PTR)
            {
                // Copy based for
                LLVMValueRef current_ptr =
                    LLVMBuildLoad(mod->builder, current_ptr_ptr, "");
                LLVMBuildStore(
                    mod->builder,
                    LLVMBuildLoad(mod->builder, current_ptr, ""),
                    ast->foreach_stmt.value.value);
            }

            array_push(&l->break_block_stack, merge_bb);
            array_push(&l->continue_block_stack, inc_bb);
            llvm_codegen_ast(l, mod, ast->for_stmt.stmt, false, NULL);
            array_pop(&l->continue_block_stack);
            array_pop(&l->break_block_stack);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, inc_bb);
        }

        // Increment
        {
            LLVMPositionBuilderAtEnd(mod->builder, inc_bb);

            LLVMValueRef current_ptr =
                LLVMBuildLoad(mod->builder, current_ptr_ptr, "");

            indices[0] = LLVMConstInt(LLVMInt32Type(), 1, false);
            LLVMValueRef next =
                LLVMBuildGEP(mod->builder, current_ptr, indices, 1, "");

            LLVMBuildStore(mod->builder, next, current_ptr_ptr);

            if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
                LLVMBuildBr(mod->builder, cond_bb);
        }

        // Merge
        LLVMPositionBuilderAtEnd(mod->builder, merge_bb);

        array_pop(&l->operand_scope_stack);
        array_pop(&l->scope_stack);
        break;
    }

    case AST_BREAK: {
        llvm_codegen_deferred_stmts(l, mod, false);

        LLVMBasicBlockRef *break_block = array_last(&l->break_block_stack);
        assert(break_block);
        LLVMBuildBr(mod->builder, *break_block);
        break;
    }

    case AST_CONTINUE: {
        llvm_codegen_deferred_stmts(l, mod, false);

        LLVMBasicBlockRef *continue_block =
            array_last(&l->continue_block_stack);
        assert(continue_block);
        LLVMBuildBr(mod->builder, *continue_block);
        break;
    }

    case AST_IMPORT: {
        SourceFile *file = NULL;
        if (!hash_get(
                &l->compiler->files, ast->import.abs_path, (void **)&file))
        {
            assert(0);
        }

        assert(file);
        if (!file->did_codegen)
        {
            file->did_codegen = true;
            llvm_codegen_ast(l, mod, file->root, false, out_value);
        }

        break;
    }

    case AST_DEFER: {
        Scope *last_scope = *array_last(&l->scope_stack);
        array_push(&last_scope->deferred_stmts, ast->stmt);
        break;
    }

    case AST_TUPLE_BINDING: {
        Ast *tuple_decl = ast->tuple_binding.decl;
        assert(tuple_decl);
        assert(tuple_decl->type_info);
        assert(tuple_decl->type_info->kind == TYPE_TUPLE);

        AstValue tuple_val = tuple_decl->tuple_decl.value;
        assert(tuple_val.value);
        assert(tuple_val.is_lvalue);

        AstValue field_value = {0};
        field_value.is_lvalue = true;
        field_value.value = LLVMBuildStructGEP(
            mod->builder, tuple_val.value, ast->tuple_binding.index, "");

        if (out_value) *out_value = field_value;

        break;
    }

    case AST_NOTHING:
    case AST_PROC_TYPE:
    case AST_TYPEDEF: break;

    default: assert(0); break;
    }

    if (l->di_scope_stack.len > 0)
    {
        array_pop(&l->di_location_stack);
    }

    if (l->di_location_stack.len > 0)
    {
        LLVMSetCurrentDebugLocation2(
            mod->builder, *array_last(&l->di_location_stack));
    }
    else
    {
        LLVMSetCurrentDebugLocation2(mod->builder, NULL);
    }
}

static void llvm_codegen_proc_stmts(LLContext *l, LLModule *mod, Ast *ast)
{
    assert(ast->type == AST_PROC_DECL);

    if ((ast->flags & AST_FLAG_IS_TEMPLATE) == AST_FLAG_IS_TEMPLATE)
    {
        // Generate instantiations
        for (Ast **instantiation = (Ast **)ast->proc.template_cache->values.ptr;
             instantiation != (Ast **)ast->proc.template_cache->values.ptr +
                                  ast->proc.template_cache->values.len;
             ++instantiation)
        {
            llvm_codegen_proc_stmts(l, mod, *instantiation);
        }

        return;
    }

    if ((ast->flags & AST_FLAG_WAS_USED) != AST_FLAG_WAS_USED)
    {
        return;
    }

    if ((ast->flags & AST_FLAG_FUNCTION_HAS_BODY) != AST_FLAG_FUNCTION_HAS_BODY)
    {
        return;
    }

    LLVMValueRef fun = ast->value;
    assert(fun);

    LLVMBasicBlockRef alloca_block = LLVMAppendBasicBlock(fun, "allocas");
    LLVMBasicBlockRef entry = LLVMAppendBasicBlock(fun, "entry");
    LLVMBasicBlockRef prev_pos = LLVMGetInsertBlock(mod->builder);

    LLVMPositionBuilderAtEnd(mod->builder, alloca_block);
    LLVMBuildBr(mod->builder, entry);

    LLVMPositionBuilderAtEnd(mod->builder, entry);

    array_push(&l->scope_stack, ast->scope);
    array_push(&l->operand_scope_stack, ast->scope);
    array_push(&l->di_scope_stack, ast->di_value);
    llvm_codegen_ast_children(
        l, mod, ast->proc.stmts.ptr, ast->proc.stmts.len, false);
    array_pop(&l->di_scope_stack);
    array_pop(&l->operand_scope_stack);
    array_pop(&l->scope_stack);

    if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
    {
        LLVMBuildRetVoid(mod->builder); // Add void return
    }

    LLVMPositionBuilderAtEnd(mod->builder, prev_pos);
}

static void llvm_codegen_ast_children(
    LLContext *l, LLModule *mod, Ast *asts, size_t ast_count, bool is_const)
{
    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_IMPORT: {
            llvm_codegen_ast(l, mod, ast, is_const, NULL);
            break;
        }

        default: break;
        }
    }

    llvm_add_proc(l, mod, asts, ast_count);

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

    bool returned = false;

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_IMPORT:
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
            returned = true;
            break;
        }
    }

    // Generate deferred stmts
    if (!returned)
    {
        llvm_codegen_deferred_stmts(l, mod, false);
    }

    for (Ast *ast = asts; ast != asts + ast_count; ++ast)
    {
        switch (ast->type)
        {
        case AST_PROC_DECL: {
            llvm_codegen_proc_stmts(l, mod, ast);
            break;
        }

        default: break;
        }
    }
}

static void llvm_generate_runtime_variables(LLContext *l, LLModule *mod)
{
    LLVMTypeRef rtti_array_type = LLVMArrayType(
        llvm_type(l, l->compiler->type_info_type),
        l->compiler->rtti_type_infos.len);
    mod->rtti_type_infos =
        LLVMAddGlobal(mod->mod, rtti_array_type, "__type_infos");
    LLVMSetLinkage(mod->rtti_type_infos, LLVMInternalLinkage);
    LLVMSetGlobalConstant(mod->rtti_type_infos, false);
    LLVMSetExternallyInitialized(mod->rtti_type_infos, false);
    LLVMSetInitializer(mod->rtti_type_infos, LLVMConstNull(rtti_array_type));
}

static void llvm_generate_runtime_functions(LLContext *l, LLModule *mod)
{
    {
        LLVMTypeRef llvm_fun_type =
            LLVMFunctionType(LLVMVoidType(), NULL, 0, false);

        mod->runtime_statup_fun =
            LLVMAddFunction(mod->mod, "__startup_runtime", llvm_fun_type);
        LLVMSetLinkage(mod->runtime_statup_fun, LLVMInternalLinkage);

        LLVMBasicBlockRef entry =
            LLVMAppendBasicBlock(mod->runtime_statup_fun, "entry");
        LLVMPositionBuilderAtEnd(mod->builder, entry);

        // Important to start from 1
        for (size_t i = 1; i < l->compiler->rtti_type_infos.len; ++i)
        {
            generate_type_info_value(l, mod, i);
        }

        if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
        {
            LLVMBuildRetVoid(mod->builder); // Add void return
        }
    }

    {
        LLVMTypeRef arg_types[2] = {
            LLVMInt32Type(),
            LLVMPointerType(LLVMPointerType(LLVMInt8Type(), 0), 0)};

        LLVMTypeRef llvm_fun_type =
            LLVMFunctionType(LLVMInt32Type(), arg_types, 2, false);

        mod->main_wrapper_fun =
            LLVMAddFunction(mod->mod, "main", llvm_fun_type);
        LLVMSetLinkage(mod->main_wrapper_fun, LLVMExternalLinkage);

        LLVMBasicBlockRef entry =
            LLVMAppendBasicBlock(mod->main_wrapper_fun, "entry");
        LLVMPositionBuilderAtEnd(mod->builder, entry);

        LLVMBuildCall(mod->builder, mod->runtime_statup_fun, NULL, 0, "");
        if (mod->main_fun)
        {
            LLVMBuildCall(mod->builder, mod->main_fun, NULL, 0, "");
        }

        if (!LLVMGetBasicBlockTerminator(LLVMGetInsertBlock(mod->builder)))
        {
            LLVMBuildRet(mod->builder, LLVMConstInt(LLVMInt32Type(), 0, false));
        }
    }
}

static void llvm_codegen_file(LLContext *l, SourceFile *file)
{
    const char *producer = "Felipe's compiler";
    bool is_optimized = l->compiler->args.opt_level > 0;
    file->di_cu = LLVMDIBuilderCreateCompileUnit(
        l->mod.di_builder,
        LLVMDWARFSourceLanguageC,
        llvm_get_di_file(l, file),
        producer,
        strlen(producer),
        is_optimized,
        "",
        0,
        0,
        "",
        0,
        LLVMDWARFEmissionFull,
        0,
        true,
        false);

    file->did_codegen = true;
    llvm_codegen_ast(l, &l->mod, file->root, false, NULL);
}

static void llvm_init(LLContext *l, Compiler *compiler)
{
    l->compiler = compiler;

    memset(&l->mod, 0, sizeof(l->mod));
    l->mod.mod = LLVMModuleCreateWithName("main");
    l->mod.builder = LLVMCreateBuilder();
    l->mod.di_builder = LLVMCreateDIBuilder(l->mod.mod);
    l->mod.data = LLVMGetModuleDataLayout(l->mod.mod);
}

static void llvm_finalize_module(LLContext *l)
{
    LLVMDIBuilderFinalize(l->mod.di_builder);
}

static void llvm_verify_module(LLContext *l)
{
    char *error = NULL;
    if (LLVMVerifyModule(l->mod.mod, LLVMReturnStatusAction, &error))
    {
        fprintf(stderr, "%s\n", LLVMPrintModuleToString(l->mod.mod));

        fprintf(stderr, "Failed to verify module:\n%s\n", error);
        exit(EXIT_FAILURE);
    }
}

static void llvm_run_module(LLContext *l)
{
    LLVMExecutionEngineRef engine;
    char *error = NULL;

    LLVMLinkInMCJIT();
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
    if (LLVMCreateExecutionEngineForModule(&engine, l->mod.mod, &error) != 0)
    {
        fprintf(stderr, "failed to create execution engine\n");
        exit(EXIT_FAILURE);
    }

    if (error)
    {
        fprintf(stderr, "error: %s\n", error);
        LLVMDisposeMessage(error);
        exit(EXIT_FAILURE);
    }

    Ast *found = NULL;
    if (hash_get(
            &l->compiler->extern_symbols,
            STR("compiler_api_compile"),
            (void **)&found))
    {
        if (found->value)
        {
            LLVMAddGlobalMapping(engine, found->value, compiler_api_compile);
        }
    }

    void (*main_func)() = (void (*)())LLVMGetFunctionAddress(engine, "main");
    if (main_func)
    {
        main_func();
    }
}

static void llvm_optimize_module(LLContext *l)
{
    if (l->compiler->args.opt_level > 0)
    {
        LLVMPassManagerRef pm = LLVMCreatePassManager();

        LLVMPassManagerBuilderRef pmb = LLVMPassManagerBuilderCreate();
        LLVMPassManagerBuilderSetOptLevel(pmb, l->compiler->args.opt_level);
        LLVMPassManagerBuilderSetDisableSimplifyLibCalls(pmb, false);
        LLVMPassManagerBuilderSetDisableUnrollLoops(pmb, false);

        switch (l->compiler->args.opt_level)
        {
        case 3: {
            LLVMPassManagerBuilderUseInlinerWithThreshold(pmb, 250);
            break;
        }

        default: break;
        }

        LLVMPassManagerBuilderPopulateModulePassManager(pmb, pm);

        LLVMRunPassManager(pm, l->mod.mod);
    }
}
