#if defined(__unix__) || defined(__APPLE__)
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif
