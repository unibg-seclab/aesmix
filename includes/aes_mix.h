#ifndef AES_MIX_H
#define AES_MIX_H

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

void mixencrypt(const unsigned char* data, unsigned char* out,
                const unsigned long size, const unsigned char* key,
                const unsigned char* iv);

void mixdecrypt(const unsigned char* data, unsigned char* out,
                const unsigned long size, const unsigned char* key,
                const unsigned char* iv);

#endif // AES_MIX_H
