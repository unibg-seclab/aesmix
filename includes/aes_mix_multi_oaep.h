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

/* for internal usage */

typedef struct aesmix_args_s {
    const unsigned char* data;
    unsigned char* out;
    unsigned long size;
    const unsigned char* key;
    const unsigned char* iv;
} aesmix_args;

typedef void* (*w_fn) (void* data);

void t_mixprocess_oaep (
    w_fn fn, unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
);

#endif // AES_MIX_MULTI_OAEP_H
