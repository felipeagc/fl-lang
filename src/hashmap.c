#define DEFAULT_HASHMAP_SIZE 32

typedef struct HashMap
{
    String *keys;
    uint64_t *hashes;
    void **values;
    uint64_t size;
} HashMap;

static void hash_grow(HashMap *map);

static uint64_t hash_str(String str)
{
    uint64_t hash = 5381;

    for (uint64_t i = 0; i < str.length; ++i)
    {
        hash = ((hash << 5) + hash) + str.buf[i]; /* hash * 33 + c */
    }

    return hash;
}

static void hash_init(HashMap *map, uint64_t size)
{
    memset(map, 0, sizeof(*map));

    map->size = size;
    if (map->size == 0)
    {
        map->size = DEFAULT_HASHMAP_SIZE;
    }

    // Round up to nearnest power of two
    map->size -= 1;
    map->size |= map->size >> 1;
    map->size |= map->size >> 2;
    map->size |= map->size >> 4;
    map->size |= map->size >> 8;
    map->size |= map->size >> 16;
    map->size |= map->size >> 32;
    map->size += 1;

    // Init memory
    map->keys = malloc(sizeof(*map->keys) * map->size);
    map->hashes = malloc(sizeof(*map->hashes) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);

    memset(map->keys, 0, sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
}

#if 0
static void hash_clear(HashMap *map)
{
    memset(map->keys, 0, sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
}
#endif

static void *hash_set(HashMap *map, String key, void *value)
{
    uint64_t hash = hash_str(key);
    uint64_t i = hash & (map->size - 1);
    uint64_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) & (map->size - 1);
        iters++;
    }

    if (iters >= map->size)
    {
        hash_grow(map);
        return hash_set(map, key, value);
    }

    map->keys[i] = key;
    map->hashes[i] = hash;
    map->values[i] = value;

    return value;
}

static bool hash_get(HashMap *map, String key, void **result)
{
    uint64_t hash = hash_str(key);
    uint64_t i = hash & (map->size - 1);
    uint64_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) & (map->size - 1);
        iters++;
    }
    if (iters >= map->size)
    {
        return false;
    }

    if (map->hashes[i] != 0)
    {
        if (result) *result = map->values[i];
        return true;
    }

    return false;
}

#if 0
static void hash_remove(HashMap *map, String key)
{
    uint64_t hash = hash_str(key);
    uint64_t i = hash & (map->size - 1);
    uint64_t iters = 0;
    while ((map->hashes[i] != hash || !string_equals(map->keys[i], key)) &&
           map->hashes[i] != 0 && iters < map->size)
    {
        i = (i + 1) & (map->size - 1);
        iters++;
    }

    if (iters >= map->size)
    {
        return;
    }

    map->hashes[i] = 0;

    return;
}
#endif

static void hash_grow(HashMap *map)
{
    uint64_t old_size = map->size;
    String *old_keys = map->keys;
    uint64_t *old_hashes = map->hashes;
    void **old_values = map->values;

    map->size = old_size * 2;
    map->hashes = malloc(sizeof(*map->hashes) * map->size);
    map->values = malloc(sizeof(*map->values) * map->size);
    map->keys = malloc(sizeof(*map->keys) * map->size);
    memset(map->hashes, 0, sizeof(*map->hashes) * map->size);
    memset(map->keys, 0, sizeof(*map->keys) * map->size);

    for (uint64_t i = 0; i < old_size; i++)
    {
        if (old_hashes[i] != 0)
        {
            hash_set(map, old_keys[i], old_values[i]);
        }
    }

    free(old_hashes);
    free(old_values);
    free(old_keys);
}

static void hash_destroy(HashMap *map)
{
    free(map->hashes);
    free(map->values);
    free(map->keys);
}
