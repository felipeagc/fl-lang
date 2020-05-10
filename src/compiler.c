static void compiler_init(Compiler *compiler)
{
    memset(compiler, 0, sizeof(*compiler));
    bump_init(&compiler->bump, 1 << 16);
    sb_init(&compiler->sb);
    hash_init(&compiler->files, 512);
    hash_init(&compiler->versions, 16);
    hash_init(&compiler->modules, 16);
    hash_init(&compiler->types, 64);
    hash_init(&compiler->extern_symbols, 16);

    compiler->backend = bump_alloc(&compiler->bump, sizeof(*compiler->backend));
    memset(compiler->backend, 0, sizeof(*compiler->backend));
    llvm_init(compiler->backend, compiler);

    static TypeInfo blank_type_info = {0};
    array_push(
        &compiler->rtti_type_infos, &blank_type_info); // Reserve the 0 index

    char *c_compiler_path = get_exe_path();
    char *c_compiler_dir = get_path_dir(c_compiler_path);
    compiler->compiler_path = CSTR(c_compiler_path);
    compiler->compiler_dir = CSTR(c_compiler_dir);
    compiler->corelib_dir =
        bump_str_join(&compiler->bump, compiler->compiler_dir, STR("core/"));

    // Initialize runtime scopes
    {
        compiler->u8_type = create_int_type(compiler, 8, false);
        compiler->u16_type = create_int_type(compiler, 16, false);
        compiler->u32_type = create_int_type(compiler, 32, false);
        compiler->u64_type = create_int_type(compiler, 64, false);

        compiler->i8_type = create_int_type(compiler, 8, true);
        compiler->i16_type = create_int_type(compiler, 16, true);
        compiler->i32_type = create_int_type(compiler, 32, true);
        compiler->i64_type = create_int_type(compiler, 64, true);

        compiler->uint_type = compiler->u64_type;
        compiler->int_type = compiler->i64_type;

        compiler->float_type = create_float_type(compiler, 32);
        compiler->double_type = create_float_type(compiler, 64);

        compiler->int_lit_type = create_simple_type(compiler, TYPE_UNTYPED_INT);
        compiler->float_lit_type =
            create_simple_type(compiler, TYPE_UNTYPED_FLOAT);

        compiler->bool_type = create_simple_type(compiler, TYPE_BOOL);
        compiler->void_type = create_simple_type(compiler, TYPE_VOID);
        compiler->bool_int_type = compiler->u8_type;

        compiler->null_ptr_type =
            create_simple_type(compiler, TYPE_RAW_POINTER);
        compiler->void_ptr_type =
            create_pointer_type(compiler, compiler->void_type);

        compiler->string_type = create_slice_type(compiler, compiler->i8_type);
        compiler->c_string_type =
            create_pointer_type(compiler, compiler->i8_type);

        compiler->any_type = create_any_type(compiler);
        compiler->namespace_type = create_simple_type(compiler, TYPE_NAMESPACE);
        compiler->template_type = create_simple_type(compiler, TYPE_TEMPLATE);
        compiler->type_type = create_simple_type(compiler, TYPE_TYPE);
    }

#if defined(__linux__)
    hash_set(&compiler->versions, STR("linux"), NULL);
    hash_set(&compiler->versions, STR("glibc"), NULL);
    hash_set(&compiler->versions, STR("posix"), NULL);
#elif defined(__APPLE__)
    hash_set(&compiler->versions, STR("apple"), NULL);
    hash_set(&compiler->versions, STR("darwin"), NULL);
    hash_set(&compiler->versions, STR("posix"), NULL);
#elif defined(_WIN32)
    hash_set(&compiler->versions, STR("windows"), NULL);
#else
#error OS not supported
#endif

    hash_set(&compiler->versions, STR("x86"), NULL);
    hash_set(&compiler->versions, STR("x86_64"), NULL);
    hash_set(&compiler->versions, STR("x86_any"), NULL);
    hash_set(&compiler->versions, STR("debug"), NULL);

    // Initialize runtime module
    String runtime_abs_path = bump_str_join(
        &compiler->bump,
        compiler->corelib_dir,
        STR("runtime" LANG_FILE_EXTENSION));
    SourceFile *runtime_file =
        compiler_syntax_stage(compiler, runtime_abs_path);
    compiler->runtime_module = runtime_file->root;

    Ast *type_info_structure = get_symbol(
        compiler->runtime_module->scope, STR("TypeInfo"), runtime_file);
    assert(type_info_structure);
    compiler->type_info_type = type_info_structure->as_type;
    assert(compiler->type_info_type);
}

static void compiler_destroy(Compiler *compiler)
{
    hash_destroy(&compiler->extern_symbols);
    hash_destroy(&compiler->types);
    hash_destroy(&compiler->modules);
    hash_destroy(&compiler->versions);
    hash_destroy(&compiler->files);
    sb_destroy(&compiler->sb);
    bump_destroy(&compiler->bump);
}

static Module *compiler_get_module(Compiler *compiler, String module_name)
{
    Module *module = NULL;
    if (hash_get(&compiler->modules, module_name, (void **)&module))
    {
        return module;
    }

    module = bump_alloc(&compiler->bump, sizeof(Module));
    memset(module, 0, sizeof(Module));

    hash_init(&module->symbol_names, 64);

    hash_set(&compiler->modules, module_name, module);
    return module;
}

static void
compile_error(Compiler *compiler, Location loc, const char *fmt, ...)
{
    char buf[2048];
    assert(loc.file);

    va_list vl;
    va_start(vl, fmt);
    vsnprintf(buf, sizeof(buf), fmt, vl);
    va_end(vl);

    String message = bump_strdup(&compiler->bump, CSTR(buf));

    Error err = {.loc = loc, .message = message};
    array_push(&compiler->errors, err);
}

static bool compiler_has_version(Compiler *compiler, String version)
{
    return hash_get(&compiler->versions, version, NULL);
}

static void compiler_print_errors(Compiler *compiler)
{
    if (compiler->errors.len > 0)
    {
        for (Error *err = compiler->errors.ptr;
             err != compiler->errors.ptr + compiler->errors.len;
             ++err)
        {
            fprintf(
                stderr,
                "%.*s:%u:%u: error: %.*s\n",
                PRINT_STR(err->loc.file->path),
                err->loc.line,
                err->loc.col,
                PRINT_STR(err->message));
        }
        exit(1);
    }
}

static void
compiler_semantic_stage(Compiler *compiler, SourceFile *file, Ast *ast)
{
    Analyzer *analyzer = bump_alloc(&compiler->bump, sizeof(*analyzer));
    memset(analyzer, 0, sizeof(*analyzer));
    analyzer->compiler = compiler;

    create_scopes_ast(analyzer, ast);
    compiler_print_errors(compiler);

    compiler_process_imports(compiler, file, NULL, ast);

    register_symbol_asts(analyzer, ast, 1);
    compiler_print_errors(compiler);

    analyze_asts(analyzer, ast, 1);
    compiler_print_errors(compiler);

    if (file->main_function_ast)
    {
        check_used_asts(analyzer, file->main_function_ast);
    }
}

static SourceFile *
compiler_syntax_stage(Compiler *compiler, String absolute_path)
{
    SourceFile *file = NULL;
    if (hash_get(&compiler->files, absolute_path, (void **)&file))
    {
        assert(file);
        return file;
    }

    file = bump_alloc(&compiler->bump, sizeof(*file));
    source_file_init(file, compiler, absolute_path);

    hash_set(&compiler->files, absolute_path, file);

    Lexer *lexer = bump_alloc(&compiler->bump, sizeof(*lexer));
    lex_file(lexer, compiler, file);
    compiler_print_errors(compiler);

    Parser *parser = bump_alloc(&compiler->bump, sizeof(*parser));
    parse_file(parser, compiler, lexer);
    compiler_print_errors(compiler);
    file->root = parser->ast;

    compiler_semantic_stage(compiler, file, parser->ast);

    return file;
}

static void compiler_process_imports(
    Compiler *compiler, SourceFile *file, Scope *scope, Ast *ast)
{
    switch (ast->type)
    {
    case AST_IMPORT: {
        bool import_exists = true;

        char *c_imported = bump_c_str(&compiler->bump, ast->import.path);
        static char *core_prefix = "core:";

        if (strncmp(c_imported, core_prefix, strlen(core_prefix)) == 0)
        {
            // Core import

            char *file_name_without_extension =
                c_imported + strlen(core_prefix);

            String import_file_name = bump_str_join(
                &compiler->bump,
                CSTR(file_name_without_extension),
                CSTR(LANG_FILE_EXTENSION));

            ast->import.abs_path = bump_str_join(
                &compiler->bump, compiler->corelib_dir, import_file_name);

            char *abs_path_c =
                bump_c_str(&compiler->bump, ast->import.abs_path);
            if (!file_exists(abs_path_c))
            {
                import_exists = false;
            }
        }
        else
        {
            // Relative import
            char *c_dir = get_path_dir(bump_c_str(&compiler->bump, file->path));

            size_t new_path_size = strlen(c_dir) + 1 + strlen(c_imported) + 1;
            char *c_new_path = bump_alloc(&compiler->bump, new_path_size);
            snprintf(c_new_path, new_path_size, "%s/%s", c_dir, c_imported);

            // Normalize the path
            char *abs_path_c = get_absolute_path(c_new_path);
            if (abs_path_c)
            {
                ast->import.abs_path = CSTR(abs_path_c);
            }
            else
            {
                import_exists = false;
            }
        }

        if (!import_exists)
        {
            compile_error(
                compiler,
                ast->loc,
                "imported file does not exist: '%.*s'",
                PRINT_STR(ast->import.path));
            break;
        }

        SourceFile *imported_file =
            compiler_syntax_stage(compiler, ast->import.abs_path);

        if (ast->import.name.ptr == NULL)
        {
            array_push(&scope->siblings, imported_file->root->scope);
        }

        break;
    }
    default: break;
    }

    // Analyze children ASTs
    switch (ast->type)
    {
    case AST_BLOCK:
    case AST_ROOT: {
        for (Ast *stmt = ast->block.stmts.ptr;
             stmt != ast->block.stmts.ptr + ast->block.stmts.len;
             ++stmt)
        {
            compiler_process_imports(compiler, file, ast->scope, stmt);
        }
        break;
    }

    case AST_VERSION_BLOCK: {
        if (compiler_has_version(compiler, ast->version_block.version))
        {
            for (Ast *stmt = ast->version_block.stmts.ptr;
                 stmt !=
                 ast->version_block.stmts.ptr + ast->version_block.stmts.len;
                 ++stmt)
            {
                compiler_process_imports(compiler, file, scope, stmt);
            }
        }

        break;
    }

    case AST_PROC_DECL: {
        for (Ast *stmt = ast->proc.stmts.ptr;
             stmt != ast->proc.stmts.ptr + ast->proc.stmts.len;
             ++stmt)
        {
            compiler_process_imports(compiler, file, ast->scope, stmt);
        }
        break;
    }
    default: break;
    }
}

static void compile_file_to_object(Compiler *compiler, String filepath)
{
    SourceFile *file = compiler_syntax_stage(compiler, filepath);

    llvm_generate_runtime_variables(compiler->backend, &compiler->backend->mod);

    llvm_codegen_file(compiler->backend, file);

    llvm_generate_runtime_functions(compiler->backend, &compiler->backend->mod);

    llvm_finalize_module(compiler->backend);
    llvm_verify_module(compiler->backend);
    llvm_optimize_module(compiler->backend);

    if (compiler->args.print_llvm)
    {
        fprintf(
            stderr,
            "%s\n",
            LLVMPrintModuleToString(compiler->backend->mod.mod));
    }
}

static void
compiler_link_module(Compiler *compiler, LLModule *mod, String out_file_path)
{
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmParsers();
    LLVMInitializeAllAsmPrinters();

    char *triple = LLVMGetDefaultTargetTriple();

    LLVMTargetRef target;
    char *error = NULL;
    if (LLVMGetTargetFromTriple(triple, &target, &error))
    {
        fprintf(stderr, "Failed to get target from triple: %s", error);
        exit(1);
    }

    char *cpu = "generic";
    char *features = "";
    LLVMTargetMachineRef target_machine = LLVMCreateTargetMachine(
        target,
        triple,
        cpu,
        features,
        LLVMCodeGenLevelNone,
        LLVMRelocDefault,
        LLVMCodeModelDefault);

    LLVMTargetDataRef data_layout = LLVMCreateTargetDataLayout(target_machine);
    char *data_layout_str = LLVMCopyStringRepOfTargetData(data_layout);

    LLVMSetDataLayout(mod->mod, data_layout_str);
    LLVMSetTarget(mod->mod, triple);

    if (LLVMTargetMachineEmitToFile(
            target_machine, mod->mod, TMP_OBJECT_NAME, LLVMObjectFile, &error))
    {
        remove(TMP_OBJECT_NAME);
        fprintf(stderr, "LLVM codegen error: %s", error);
        exit(1);
    }

#if defined(__linux__) || defined(__APPLE__)
#define LINKER_PATH "clang"
    char *c_out_file_path = bump_c_str(&compiler->bump, out_file_path);

    ArrayOfCharPtr args = {0};
    array_push(&args, LINKER_PATH);
    array_push(&args, TMP_OBJECT_NAME);
    array_push(&args, "-lm");
    array_push(&args, "-o");
    array_push(&args, c_out_file_path);

    for (size_t i = 0; i < compiler->args.library_paths.len; ++i)
    {
        char arg[256] = {0};
        sprintf(arg, "-L%s", compiler->args.library_paths.ptr[i]);
        array_push(&args, strdup(arg));
    }

    for (size_t i = 0; i < compiler->args.link_libraries.len; ++i)
    {
        char arg[256] = {0};
        sprintf(arg, "-l%s", compiler->args.link_libraries.ptr[i]);
        array_push(&args, strdup(arg));
    }

    array_push(&args, NULL);

    pid_t pid;
    int status = posix_spawnp(&pid, LINKER_PATH, NULL, NULL, args.ptr, environ);
    if (status == 0)
    {
        if (waitpid(pid, &status, 0) == -1)
        {
            remove(TMP_OBJECT_NAME);
            fprintf(stderr, "Linking failed 1!\n");
            exit(status);
        }

        if (status != 0)
        {
            remove(TMP_OBJECT_NAME);
            fprintf(stderr, "Linking failed 2!\n");
            exit(status);
        }
    }
    else
    {
        fprintf(stderr, "Linking failed 3!\n");
        exit(status);
    }

    remove(TMP_OBJECT_NAME);
#elif defined(_WIN32)
    sb_reset(&compiler->sb);

    VSFindResult find_result = find_visual_studio_and_windows_sdk();
    char *link_exe_path = utf16_to_utf8(find_result.vs_exe_path);
    char *vs_lib_path = utf16_to_utf8(find_result.vs_library_path);
    char *win_crt_lib_path =
        utf16_to_utf8(find_result.windows_sdk_ucrt_library_path);
    char *win_um_lib_path =
        utf16_to_utf8(find_result.windows_sdk_um_library_path);

    sb_sprintf(&compiler->sb, "\"%s\\link.exe\"", link_exe_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", vs_lib_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", win_crt_lib_path);
    sb_sprintf(&compiler->sb, " /LIBPATH:\"%s\"", win_um_lib_path);
    sb_append(
        &compiler->sb,
        STR(" /nologo /defaultlib:libcmt /ENTRY:mainCRTStartup"));
    sb_append(&compiler->sb, STR(" -OUT:\""));
    sb_append(&compiler->sb, out_file_path);
    sb_append(&compiler->sb, STR("\" "));
    sb_append(&compiler->sb, STR(TMP_OBJECT_NAME));
    for (size_t i = 0; i < array_size(compiler->args.library_paths); ++i)
    {
        sb_sprintf(
            &compiler->sb,
            " /LIBPATH:\"%s\"",
            compiler->args.link_libraries[i]);
    }
    for (size_t i = 0; i < array_size(compiler->args.link_libraries); ++i)
    {
        sb_sprintf(&compiler->sb, " \"%s\"", compiler->args.link_libraries[i]);
    }

    String cmd_line = sb_build(&compiler->sb, &compiler->bump);
    char *cmd_line_c = bump_c_str(&compiler->bump, cmd_line);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL result = CreateProcessA(
        NULL, cmd_line_c, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (!result)
    {
        fprintf(stderr, "Failed to start linker!\n");
        exit(1);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!DeleteFileA(TMP_OBJECT_NAME))
    {
        fprintf(stderr, "Failed to delete temporary object\n");
    }

#else
#error OS not supported
#endif
}
