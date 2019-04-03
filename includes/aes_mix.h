#ifndef AES_MIX_H
#define AES_MIX_H

#include <stdio.h>
#include <math.h>


#ifndef BLOCK_SIZE
#define BLOCK_SIZE                                 16
#endif
#ifndef MINI_SIZE
#define MINI_SIZE                                   4
#endif
#ifndef MINI_PER_MACRO
#define MINI_PER_MACRO                           1024
#endif

#define MINI_PER_BLOCK       (BLOCK_SIZE / MINI_SIZE)
#define MACRO_SIZE       (MINI_SIZE * MINI_PER_MACRO)
#define DIGITS           ((int) log2(MINI_PER_MACRO))
#define DOF              ((int) log2(MINI_PER_BLOCK))

#ifdef DEBUG
#define D
#else
#define D if(0)
#endif

#define MAX(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define MIN(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })
#define LOG(x,base) (log(x) / log(base))
#define ISPOWEROF(x,base) (x == pow(base, (int) LOG(x, base)))

void mixencrypt (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

void mixdecrypt (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

/* mixfn and process definitions are used to extend Mix&Slice to other types
 * of mixes, shuffles and encryption methods */

typedef void (*mixfn) (
    const unsigned char* macro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
);

void mixprocess (
    mixfn fn, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

/* utility functions */

void* memxor (
    void* dst, const void* src, size_t n
);

#endif // AES_MIX_H
