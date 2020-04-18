#define ARRAY_OF(TYPE)                                                         \
    struct                                                                     \
    {                                                                          \
        TYPE *ptr;                                                             \
        size_t len;                                                            \
        size_t cap;                                                            \
    }

#define ARRAY_INITIAL_CAPACITY 16

#define array_full(a) ((a)->ptr ? ((a)->len >= (a)->cap) : 1)

#define array_last(a) (&(a)->ptr[(a)->len - 1])

#define array_push(a, item)                                                    \
    (array_full(a)                                                             \
         ? (a)->ptr = array_grow((a)->ptr, &(a)->cap, 0, sizeof(*((a)->ptr)))  \
         : 0,                                                                  \
     (a)->ptr[(a)->len++] = (item))

#define array_pop(a) ((a)->len > 0 ? ((a)->len--, &(a)->ptr[(a)->len]) : NULL)

#define array_reserve(a, capacity)                                             \
    (array_full(a) ? (a)->ptr = array_grow(                                    \
                         (a)->ptr, &(a)->cap, capacity, sizeof(*((a)->ptr)))   \
                   : 0)

#define array_add(a, count)                                                    \
    do                                                                         \
    {                                                                          \
        array_reserve((a), (a)->len + count);                                  \
        (a)->len += count;                                                     \
    } while (0)

#define array_free(a)                                                          \
    do                                                                         \
    {                                                                          \
        if ((a)->ptr) free((a)->ptr);                                          \
        (a)->ptr = NULL;                                                       \
    } while (0)

static void *
array_grow(void *ptr, size_t *cap, size_t wanted_cap, size_t item_size)
{
    if (!ptr)
    {
        size_t desired_cap =
            ((wanted_cap == 0) ? ARRAY_INITIAL_CAPACITY : wanted_cap);
        *cap = desired_cap;
        return malloc(item_size * desired_cap);
    }

    size_t desired_cap = ((wanted_cap == 0) ? ((*cap) * 2) : wanted_cap);
    *cap = desired_cap;
    return realloc(ptr, (desired_cap * item_size));
}
