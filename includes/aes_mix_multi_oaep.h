#ifndef AES_MIX_MULTI_OAEP_H
#define AES_MIX_MULTI_OAEP_H

#include <aes_mix_oaep.h>

void t_mixencrypt_oaep (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

void t_mixdecrypt_oaep (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_MULTI_OAEP_H
