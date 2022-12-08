#include "platform.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

int64_t clocks_per_sec = -1;
void start_clock(void)
{
    LARGE_INTEGER freq = {0};
    QueryPerformanceFrequency(&freq);
    clocks_per_sec = freq.QuadPart;
}

int64_t get_clock(void)
{
    LARGE_INTEGER counter = {0};
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
}
#else
#include <time.h>

int64_t clocks_per_sec = -1;
void start_clock(void)
{
    clocks_per_sec = CLOCKS_PER_SEC;
}

int64_t get_clock(void)
{
    return clock();
}
#endif
