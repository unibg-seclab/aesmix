#ifndef AES_LCK_H
#define AES_LCK_H

#define BLOCK_SIZE                                 16
#define MINI_SIZE                                   4
#define MINI_PER_MACRO                           1024
#define MINI_PER_BLOCK       (BLOCK_SIZE / MINI_SIZE)
#define MACRO_SIZE       (MINI_SIZE * MINI_PER_MACRO)
#define DIGITS           ((int) log2(MINI_PER_MACRO))
#define DOF              ((int) log2(MINI_PER_BLOCK))

#ifdef DEBUG
#define D
#else
#define D if(0)
#endif

void encrypt(unsigned char* data, unsigned char* out, unsigned long size,
             unsigned char* key, unsigned char* iv);

void decrypt(unsigned char* data, unsigned char* out, unsigned long size,
             unsigned char* key, unsigned char* iv);

#endif // AES_LCK_H
