#ifndef AES_MIXSLICE_H
#define AES_MIXSLICE_H

#include <aes_mix.h>

void mixslice(unsigned int thr, const unsigned char* data, unsigned char* fragdata,
    const unsigned long size, const unsigned char* key, const unsigned char* iv);

void unsliceunmix(unsigned int thr, const unsigned char* fragdata, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv);

#endif // AES_MIXSLICE_H
