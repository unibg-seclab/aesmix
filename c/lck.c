#include <openssl/evp.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "lck.h"

#define do_step_encrypt(...) do_step(1, __VA_ARGS__)
#define do_step_decrypt(...) do_step(0, __VA_ARGS__)

static inline void do_step(
    short encrypt,
    unsigned char* macro,
    unsigned int step,
    unsigned char* key
){
    unsigned int i, j, off, mask, start, dist;
    unsigned char temp[MACRO_SIZE];
    int outlen1;
    EVP_CIPHER_CTX ctx;

    if (encrypt) { EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, NULL); }
    else         { EVP_DecryptInit(&ctx, EVP_aes_128_ecb(), key, NULL); }
    EVP_CIPHER_CTX_set_padding(&ctx, 0); // disable padding

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

    if (encrypt) { EVP_EncryptUpdate(&ctx, temp, &outlen1, temp, MACRO_SIZE); }
    else         { EVP_DecryptUpdate(&ctx, temp, &outlen1, temp, MACRO_SIZE); }
    assert(outlen1 == MACRO_SIZE);

    D fprintf(stderr, "\n== UNPACKING ==\n");
    for (i=0, start=0; start < (1<<DIGITS); ++i, start=((start|mask)+1)&~mask) {
        for (j=0, off=start; j < MINI_PER_BLOCK; ++j, off+=dist) {
            D fprintf(stderr, "%d<-%d\n", off, i*BLOCK_SIZE/MINI_SIZE + j);
            memcpy(&macro[off*MINI_SIZE],
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
    int outlen1, outlen2;
    unsigned int step;
    EVP_CIPHER_CTX ctx;

    // Step 0 is always a CTR encryption
    EVP_EncryptInit(&ctx, EVP_aes_128_ctr(), key, iv);
    EVP_EncryptUpdate(&ctx, out, &outlen1, macro, MACRO_SIZE);
    EVP_EncryptFinal(&ctx, &out[outlen1], &outlen2);
    assert(outlen1 + outlen2 == MACRO_SIZE);

    // Step 1-N are always ECB encryptions
    for (step=1; step < DIGITS/DOF; ++step) {
        do_step_encrypt(out, step, key);
    }
}

void decrypt_macroblock(
    unsigned char* macro,
    unsigned char* out,
    unsigned char* key,
    unsigned char* iv
){
    int outlen1, outlen2;
    unsigned int step;
    EVP_CIPHER_CTX ctx;

    // Step 1-N are always ECB encryptions
    memcpy(out, macro, MACRO_SIZE);
    for (step = DIGITS/DOF - 1; step >= 1; --step) {
        do_step_decrypt(out, step, key);
    }

    // Step 0 is always a CTR encryption
    EVP_DecryptInit(&ctx, EVP_aes_128_ctr(), key, iv);
    EVP_DecryptUpdate(&ctx, out, &outlen1, out, MACRO_SIZE);
    EVP_DecryptFinal(&ctx, &out[outlen1], &outlen2);
    assert(outlen1 + outlen2 == MACRO_SIZE);
}

void encrypt(
    unsigned char* data,
    unsigned char* out,
    unsigned long size,
    unsigned char* key,
    unsigned char* iv
){
    unsigned long offset;
    assert(size % MACRO_SIZE == 0);
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
    assert(size % MACRO_SIZE == 0);
    for (offset=0; offset < size; offset+=MACRO_SIZE) {
        D fprintf(stderr, "\n== DECRYPT BLOCK with offset: %lu ==\n", offset);
        decrypt_macroblock(&data[offset], &out[offset], key, iv);
    }
}
