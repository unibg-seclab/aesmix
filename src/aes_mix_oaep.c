#include <openssl/evp.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_oaep.h"

static void do_step_encrypt_oaep(
    EVP_CIPHER_CTX* ctx, unsigned char* buffer, const unsigned char* macro,
    unsigned char* out, const unsigned long size
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char *left = out;
    unsigned char *right = out + partsize;
    memcpy(out, macro, size);

    if (partsize == BLOCK_SIZE) {
        EVP_EncryptUpdate(ctx, buffer, &outl, left, partsize);
        memxor(right, buffer, partsize);
        EVP_EncryptUpdate(ctx, buffer, &outl, right, partsize);
        memxor(left, buffer, partsize);
        EVP_EncryptUpdate(ctx, buffer, &outl, left, partsize);
        memxor(right, buffer, partsize);

    } else if (partsize > BLOCK_SIZE) {
        do_step_encrypt_oaep(ctx, buffer + partsize, left, buffer, partsize);
        memxor(right, buffer, partsize);
        do_step_encrypt_oaep(ctx, buffer + partsize, right, buffer, partsize);
        memxor(left, buffer, partsize);
        do_step_encrypt_oaep(ctx, buffer + partsize, left, buffer, partsize);
        memxor(right, buffer, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }

}

static void do_step_decrypt_oaep(
    EVP_CIPHER_CTX* ctx, unsigned char* buffer, const unsigned char* macro,
    unsigned char* out, const unsigned long size
){
    int outl;
    unsigned long partsize = size / 2;
    unsigned char *left = out;
    unsigned char *right = out + partsize;
    memcpy(out, macro, size);

    if (partsize == BLOCK_SIZE) {
        EVP_DecryptUpdate(ctx, buffer, &outl, left, partsize);
        memxor(right, buffer, partsize);
        EVP_DecryptUpdate(ctx, buffer, &outl, right, partsize);
        memxor(left, buffer, partsize);
        EVP_DecryptUpdate(ctx, buffer, &outl, left, partsize);
        memxor(right, buffer, partsize);

    } else if (partsize > BLOCK_SIZE) {
        do_step_encrypt_oaep(ctx, buffer + partsize, left, buffer, partsize);
        memxor(right, buffer, partsize);
        do_step_encrypt_oaep(ctx, buffer + partsize, right, buffer, partsize);
        memxor(left, buffer, partsize);
        do_step_encrypt_oaep(ctx, buffer + partsize, left, buffer, partsize);
        memxor(right, buffer, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }
}

static inline void mixencrypt_oaep_macroblock (
    const unsigned char* macro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv); // init encryption context
    EVP_CIPHER_CTX_set_padding(ctx, 0);                       // disable padding

    memxor((unsigned char*) macro, iv, BLOCK_SIZE);           // add IV to input
    do_step_encrypt_oaep(ctx, buffer, macro, out, MACRO_SIZE);   // oaep shuffle
    memxor((unsigned char*) macro, iv, BLOCK_SIZE);      // remove IV from input

    EVP_EncryptUpdate(ctx, out, &outl, out, MACRO_SIZE); // post-shuffle encrypt
    D assert(MACRO_SIZE == outl);

    EVP_CIPHER_CTX_cleanup(ctx);                              // cleanup context
    EVP_CIPHER_CTX_free(ctx);
}

static inline void mixdecrypt_oaep_macroblock(
    const unsigned char* macro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv); // init decryption context
    EVP_CIPHER_CTX_set_padding(ctx, 0);                       // disable padding

    EVP_DecryptUpdate(ctx, out, &outl, macro, MACRO_SIZE); // preshuffle decrypt
    D assert(MACRO_SIZE == outl);

    do_step_decrypt_oaep(ctx, buffer, macro, out, MACRO_SIZE); // oaep unshuffle
    memxor(out, iv, BLOCK_SIZE);                        // remove IV from output

    EVP_CIPHER_CTX_cleanup(ctx);                              // cleanup context
    EVP_CIPHER_CTX_free(ctx);
}

void mixencrypt_oaep(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixprocess(mixencrypt_oaep_macroblock, data, out, size, key, iv);
}

void mixdecrypt_oaep(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixprocess(mixdecrypt_oaep_macroblock, data, out, size, key, iv);
}
