static void source_file_init(SourceFile *file, Compiler *compiler, String path)
{
    memset(file, 0, sizeof(*file));

    file->path = bump_strdup(&compiler->bump, path);

    FILE *f = fopen(bump_c_str(&compiler->bump, file->path), "rb");
    if (!f)
    {
        fprintf(stderr, "Failed to open file: %.*s", PRINT_STR(file->path));
        abort();
    }

    fseek(f, 0, SEEK_END);
    file->content.len = (uint32_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    file->content.ptr = malloc(file->content.len);
    fread(file->content.ptr, 1, file->content.len, f);
    fclose(f);
}

