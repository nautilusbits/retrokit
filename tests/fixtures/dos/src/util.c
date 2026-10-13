#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "engine.h"

int g_verbose = 1;

/* @noreturn @varargs */
void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("FATAL: ", stderr);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(3);
}

/* @varargs */
void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    if (level > g_verbose)
        return;
    va_start(ap, fmt);
    printf("[%d] ", level);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

unsigned int rng_next(unsigned int *seed)
{
    *seed = *seed * 1103515245u + 12345u;
    return (*seed >> 16) & 0x7fff;
}

int rng_range(unsigned int *seed, int lo, int hi)
{
    if (hi <= lo)
        return lo;
    return lo + (int)(rng_next(seed) % (unsigned)(hi - lo + 1));
}

int clamp(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

int fixed_mul(int a, int b)
{
    return (int)(((long long)a * b) >> 16);
}

long long mul64(int a, int b)
{
    return (long long)a * (long long)b;
}

int checksum(const unsigned char *p, int len, int seed, int rounds, int mask, int shift)
{
    int r, i, h = seed;
    for (r = 0; r < rounds; r++)
        for (i = 0; i < len; i++)
            h = ((h << shift) | ((unsigned)h >> (32 - shift))) ^ (p[i] & mask);
    return h;
}
