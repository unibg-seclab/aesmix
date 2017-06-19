#ifndef AES_MIX_OAEP_H
#define AES_MIX_OAEP_H

#include "aes_mix.h"

#define BIMACRO_SIZE (2*MACRO_SIZE)

void mixencrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

void mixdecrypt_oaep (
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_OAEP_H
