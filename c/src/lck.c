#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "lck.h"


static inline void do_step_encrypt(
    EVP_CIPHER_CTX* ctx,
    unsigned char* macro,
    unsigned char* out,
    unsigned int step,
    unsigned char* key,
    unsigned char* iv
){
    unsigned int i, j, off, mask, start, dist;
    unsigned char temp[MACRO_SIZE];
    int outl1;

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = 1 << (step * DOF);
    D fprintf(stderr, "\n== STEP %d (dist %d) ==\n", step, dist);
    for (i=0, start=0; start < (1<<DIGITS); ++i, start=((start|mask)+1)&~mask) {
        for (j=0, off=start; j < MINI_PER_BLOCK; ++j, off+=dist) {
            D fprintf(stderr, "%d<->%d\n", off, i*BLOCK_SIZE/MINI_SIZE + j);
            memcpy(&temp[i*BLOCK_SIZE + j*MINI_SIZE],
                   &macro[off*MINI_SIZE], MINI_SIZE);
        }
    }

    EVP_EncryptUpdate(ctx, out, &outl1, temp, MACRO_SIZE);
    D assert(outl1 == MACRO_SIZE);
}

static inline void do_step_decrypt(
    EVP_CIPHER_CTX* ctx,
    unsigned char* macro,
    unsigned char* out,
    unsigned int step,
    unsigned char* key,
    unsigned char* iv
){
    unsigned int i, j, off, mask, start, dist;
    unsigned char temp[MACRO_SIZE];
    int outl1;

    EVP_DecryptUpdate(ctx, temp, &outl1, macro, MACRO_SIZE);
    D assert(outl1 == MACRO_SIZE);

    mask = ((1 << DOF) - 1) << (step * DOF);
    dist = 1 << (step * DOF);
    D fprintf(stderr, "\n== STEP %d (dist %d) ==\n", step, dist);
    for (i=0, start=0; start < (1<<DIGITS); ++i, start=((start|mask)+1)&~mask) {
        for (j=0, off=start; j < MINI_PER_BLOCK; ++j, off+=dist) {
            D fprintf(stderr, "%d<->%d\n", off, i*BLOCK_SIZE/MINI_SIZE + j);
            memcpy(&out[off*MINI_SIZE],
                   &temp[i*BLOCK_SIZE + j*MINI_SIZE], MINI_SIZE);
        }
    }
}

static inline void memxor(
    void* dst,
    const void* src,
    size_t n
){
    char *d = dst;
    char const *s = src;
    for (; n>0; --n) {
        *d++ ^= *s++;
    }
}

void encrypt_macroblock(
    unsigned char* macro,
    unsigned char* out,
    unsigned char* key,
    unsigned char* iv
){
    int outl1;
    unsigned int step;
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    // Step 0
    memxor(macro, iv, BLOCK_SIZE);       // add IV to input
    EVP_EncryptUpdate(&ctx, out, &outl1, macro, MACRO_SIZE);
    memxor(macro, iv, BLOCK_SIZE);       // remove IV from input
    D assert(outl1 == MACRO_SIZE);

    // Steps 1 -> N
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(&ctx, out, out, step, key, iv);
    }

    EVP_EncryptFinal(&ctx, &out[outl1], &outl1);
    D assert(0 == outl1);
}

void decrypt_macroblock(
    unsigned char* macro,
    unsigned char* out,
    unsigned char* key,
    unsigned char* iv
){
    int outl1;
    unsigned int step;
    EVP_CIPHER_CTX ctx;
    EVP_DecryptInit(&ctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

    // Steps N -> 1
    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(&ctx, macro, out, step, key, iv);
        macro = out;   // this is needed to avoid a starting memcpy
    }

    // Step 0
    EVP_DecryptUpdate(&ctx, out, &outl1, out, MACRO_SIZE);
    memxor(out, iv, BLOCK_SIZE);         // remove IV from output
    D assert(outl1 == MACRO_SIZE);
    EVP_DecryptFinal(&ctx, &out[outl1], &outl1);
    D assert(0 == outl1);
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
        // TODO mix IV with offset
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
        // TODO mix IV with offset
        decrypt_macroblock(&data[offset], &out[offset], key, iv);
    }
}
