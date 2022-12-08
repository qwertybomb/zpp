#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

void start_clock(void);
int64_t get_clock(void);
extern int64_t clocks_per_sec;

#endif // PLATFORM_H

