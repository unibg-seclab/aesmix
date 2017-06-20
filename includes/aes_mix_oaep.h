#ifndef AES_MIX_OAEP_H
#define AES_MIX_OAEP_H

#include "aes_mix.h"

#ifndef BIBLOCK_SIZE
#define BIBLOCK_SIZE                               64
#endif

#define BIMINI_PER_BLOCK   (BIBLOCK_SIZE / MINI_SIZE)
#define BIMACRO_SIZE                 (2 * MACRO_SIZE)
#define BIDOF          ((int) log2(BIMINI_PER_BLOCK))

void mixencrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

void mixdecrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_OAEP_H
