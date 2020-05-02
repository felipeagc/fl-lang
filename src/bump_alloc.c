typedef struct BumpBlock
{
    unsigned char *data;
    size_t size;
    size_t pos;
    struct BumpBlock *next;
} BumpBlock;

static void block_init(BumpBlock *block, size_t size)
{
    block->data = malloc(size);
    block->size = size;
    block->pos = 0;
    block->next = NULL;
}

static void block_destroy(BumpBlock *block)
{
    if (block->next != NULL)
    {
        block_destroy(block->next);
        free(block->next);
        block->next = NULL;
    }

    free(block->data);
}

static void *block_alloc(BumpBlock *block, size_t size)
{
    assert((block->size - block->pos) >= size);
    void *data = block->data + block->pos;
    block->pos += size;
    return data;
}

typedef struct BumpAlloc
{
    size_t block_size;
    size_t last_block_size;
    BumpBlock base_block;
    BumpBlock *last_block;
} BumpAlloc;

static void bump_init(BumpAlloc *alloc, size_t block_size)
{
    alloc->block_size = block_size;
    alloc->last_block_size = alloc->block_size;
    block_init(&alloc->base_block, block_size);
    alloc->last_block = &alloc->base_block;
}

static void *bump_alloc(BumpAlloc *alloc, size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    size_t space = alloc->last_block->size - alloc->last_block->pos;
    if (space < size)
    {
        // Append new block
        alloc->last_block->next = malloc(sizeof(BumpBlock));
        alloc->last_block_size *= 2;
        alloc->last_block_size += size;
        block_init(alloc->last_block->next, alloc->last_block_size);
        alloc->last_block = alloc->last_block->next;
    }

    return block_alloc(alloc->last_block, size);
}

static String bump_strdup(BumpAlloc *alloc, String str)
{
    String s;
    s.len = str.len;
    s.ptr = bump_alloc(alloc, s.len);
    memcpy(s.ptr, str.ptr, str.len);
    return s;
}

static String bump_str_join(BumpAlloc *alloc, String a, String b)
{
    String s;
    s.len = a.len + b.len;
    s.ptr = bump_alloc(alloc, s.len);
    memcpy(s.ptr, a.ptr, a.len);
    memcpy(s.ptr + a.len, b.ptr, b.len);
    return s;
}

static char *bump_c_str(BumpAlloc *alloc, String str)
{
    char *s;
    s = bump_alloc(alloc, str.len + 1);
    for (size_t i = 0; i < str.len; i++)
    {
        s[i] = str.ptr[i];
    }
    s[str.len] = '\0';
    return s;
}

#if 0
static size_t bump_usage(BumpAlloc *alloc)
{
    size_t usage = 0;

    BumpBlock *block = &alloc->base_block;
    while (block)
    {
        usage += block->pos;
        block = block->next;
    }

    return usage;
}
#endif

static void bump_destroy(BumpAlloc *alloc)
{
    block_destroy(&alloc->base_block);
}
