#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "lck.h"


static inline void do_step_encrypt(
    unsigned char* macro,
    unsigned char* out,
    unsigned int step,
    unsigned char* key,
    unsigned char* iv
){
    unsigned int i, j, off, mask, start, dist;
    unsigned char temp[MACRO_SIZE];
    int outl1 = 0, outl2 = 0;
    EVP_CIPHER_CTX ctx;

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = 1 << (step * DOF);

    D fprintf(stderr, "\n== STEP %d (dist %d) ==\n== PACKING ==\n", step, dist);
    for (i=0, start=0; start < (1<<DIGITS); ++i, start=((start|mask)+1)&~mask) {
        for (j=0, off=start; j < MINI_PER_BLOCK; ++j, off+=dist) {
            D fprintf(stderr, "%d->%d\n", off, i*BLOCK_SIZE/MINI_SIZE + j);
            memcpy(&temp[i*BLOCK_SIZE + j*MINI_SIZE],
                   &macro[off*MINI_SIZE], MINI_SIZE);
        }
    }

    EVP_EncryptInit(&ctx, STEPi_CIPHER, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding
    EVP_EncryptUpdate(&ctx, out, &outl1, temp, MACRO_SIZE);
    EVP_EncryptFinal(&ctx, &out[outl1], &outl2);
    D assert(outl1 + outl2 == MACRO_SIZE);
}

static inline void do_step_decrypt(
    unsigned char* macro,
    unsigned char* out,
    unsigned int step,
    unsigned char* key,
    unsigned char* iv
){
    unsigned int i, j, off, mask, start, dist;
    unsigned char temp[MACRO_SIZE];
    int outl1 = 0, outl2 = 0;
    EVP_CIPHER_CTX ctx;

    EVP_DecryptInit(&ctx, STEPi_CIPHER, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding
    EVP_DecryptUpdate(&ctx, temp, &outl1, macro, MACRO_SIZE);
    EVP_DecryptFinal(&ctx, &temp[outl1], &outl2);
    D assert(outl1 + outl2 == MACRO_SIZE);

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = 1 << (step * DOF);

    D fprintf(stderr, "\n== STEP %d (dist %d) ==\n", step, dist);
    for (i=0, start=0; start < (1<<DIGITS); ++i, start=((start|mask)+1)&~mask) {
        for (j=0, off=start; j < MINI_PER_BLOCK; ++j, off+=dist) {
            D fprintf(stderr, "%d->%d\n", off, i*BLOCK_SIZE/MINI_SIZE + j);
            memcpy(&out[off*MINI_SIZE],
                   &temp[i*BLOCK_SIZE + j*MINI_SIZE], MINI_SIZE);
        }
    }
}

void encrypt_macroblock(
    unsigned char* macro,
    unsigned char* out,
    unsigned char* key,
    unsigned char* iv
){
    int outl1, outl2;
    unsigned int step;
    EVP_CIPHER_CTX ctx;

    // Step 0
    EVP_EncryptInit(&ctx, STEP0_CIPHER, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding
    EVP_EncryptUpdate(&ctx, out, &outl1, macro, MACRO_SIZE);
    EVP_EncryptFinal(&ctx, &out[outl1], &outl2);
    D assert(outl1 + outl2 == MACRO_SIZE);

    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(out, out, step, key, iv);
    }
}

void decrypt_macroblock(
    unsigned char* macro,
    unsigned char* out,
    unsigned char* key,
    unsigned char* iv
){
    int outl1, outl2;
    unsigned int step;
    EVP_CIPHER_CTX ctx;

    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(macro, out, step, key, iv);
        macro = out;
    }

    // Step 0
    EVP_DecryptInit(&ctx, STEP0_CIPHER, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding
    EVP_DecryptUpdate(&ctx, out, &outl1, out, MACRO_SIZE);
    EVP_DecryptFinal(&ctx, &out[outl1], &outl2);
    D assert(outl1 + outl2 == MACRO_SIZE);
}

void encrypt(
    unsigned char* data,
    unsigned char* out,
    unsigned long size,
    unsigned char* key,
    unsigned char* iv
){
    unsigned long offset;
    D assert(size % MACRO_SIZE == 0);
    for (offset=0; offset < size; offset+=MACRO_SIZE) {
        D fprintf(stderr, "\n== ENCRYPT BLOCK with offset: %lu ==\n", offset);
        encrypt_macroblock(&data[offset], &out[offset], key, iv);
    }
}

void decrypt(
    unsigned char* data,
    unsigned char* out,
    unsigned long size,
    unsigned char* key,
    unsigned char* iv
){
    unsigned long offset;
    D assert(size % MACRO_SIZE == 0);
    for (offset=0; offset < size; offset+=MACRO_SIZE) {
        D fprintf(stderr, "\n== DECRYPT BLOCK with offset: %lu ==\n", offset);
        decrypt_macroblock(&data[offset], &out[offset], key, iv);
    }
}
