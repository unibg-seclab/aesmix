#ifndef AES_MIX_MULTI_H
#define AES_MIX_MULTI_H

#include <aes_mix.h>

void t_mixencrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv);

void t_mixdecrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv);

#endif // AES_MIX_MULTI_H
