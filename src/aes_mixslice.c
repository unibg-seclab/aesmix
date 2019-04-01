#include <string.h>
#include <stdlib.h>
#include "aes_mix_multi.h"
#include "aes_mixslice.h"

void mixslice(unsigned int thr, const unsigned char* data, unsigned char* fragdata,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    unsigned int fragoffset, readoffset, writeoffset;
    unsigned char* temp = malloc(size);
    t_mixencrypt(thr, data, temp, size, key, iv);

    writeoffset = 0;
    for (fragoffset=0; fragoffset < MACRO_SIZE; fragoffset += MINI_SIZE) {
        for (readoffset=fragoffset; readoffset < size; readoffset += MACRO_SIZE) {
            memcpy(fragdata + writeoffset, temp + readoffset, MINI_SIZE);
            writeoffset += MINI_SIZE;
        }
    }

    free(temp);
}

void unsliceunmix(unsigned int thr, const unsigned char* fragdata, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    unsigned int fragoffset, readoffset, writeoffset;
    unsigned char* temp = malloc(size);

    readoffset = 0;
    for (fragoffset=0; fragoffset < MACRO_SIZE; fragoffset += MINI_SIZE) {
        for (writeoffset=fragoffset; writeoffset < size; writeoffset += MACRO_SIZE) {
            memcpy(temp + writeoffset, fragdata + readoffset, MINI_SIZE);
            readoffset += MINI_SIZE;
        }
    }

    t_mixdecrypt(thr, temp, out, size, key, iv);
    free(temp);
}
