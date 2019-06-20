#ifndef AES_MIX_MULTI_OAEP_RECURSIVE_H
#define AES_MIX_MULTI_OAEP_RECURSIVE_H

#include "aes_mix_multi_oaep.h"
#include "aes_mix_oaep_recursive.h"

void t_mixencrypt_oaep_recursive (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

void t_mixdecrypt_oaep_recursive (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_MULTI_OAEP_RECURSIVE_H
