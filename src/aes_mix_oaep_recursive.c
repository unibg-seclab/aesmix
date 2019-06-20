#include <openssl/evp.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_oaep_recursive.h"

// avoid using AES specific defines
#define AES_BLOCK_SIZE BLOCK_SIZE
#define AES_MINI_PER_MACRO MINI_PER_MACRO
#define AES_MINI_SIZE MINI_SIZE
#undef MINI_PER_BLOCK
#undef MACRO_SIZE
#undef DIGITS
#undef DOF

#ifndef RECURSIVE_SHA512
#ifndef RECURSIVE_AES
#define RECURSIVE_AES
#endif
#endif

#ifdef RECURSIVE_SHA512
#define RECURSIVE_BLOCK_SIZE OAEP_BLOCK_SIZE
#define RECURSIVE_MINI_PER_MACRO OAEP_MINI_PER_MACRO
#define RECURSIVE_MINI_SIZE OAEP_MINI_SIZE
#define OUTLTYPE unsigned int
#define GCTX EVP_MD_CTX
#define G(CTX, OUTPUT, INPUT, OUTL)                     \
    EVP_DigestInit_ex(CTX, EVP_sha512(), NULL);         \
    EVP_DigestUpdate(CTX, INPUT, RECURSIVE_BLOCK_SIZE); \
    EVP_DigestFinal_ex(CTX, OUTPUT, &OUTL);             \
    D assert(RECURSIVE_BLOCK_SIZE == OUTL);
#endif

#ifdef RECURSIVE_AES
#define RECURSIVE_BLOCK_SIZE AES_BLOCK_SIZE
#define RECURSIVE_MINI_SIZE AES_MINI_SIZE
#define RECURSIVE_MINI_PER_MACRO (OAEP_MACRO_SIZE / RECURSIVE_MINI_SIZE)
#define OUTLTYPE int
#define GCTX EVP_CIPHER_CTX
#define G(CTX, OUTPUT, INPUT, OUTL)                                    \
    EVP_EncryptUpdate(CTX, OUTPUT, &OUTL, INPUT, RECURSIVE_BLOCK_SIZE); \
    D assert(RECURSIVE_BLOCK_SIZE == OUTL);
#endif



static inline void mixoaep_pad(
    GCTX* gctx, unsigned char* data, unsigned char* buffer,
    const unsigned long size
){

    OUTLTYPE outl;
    unsigned long partsize = size / 2;
    unsigned char *left = data;
    unsigned char *right = data + partsize;
    unsigned char *gout = buffer;

    D printf("%lu ", partsize);

    if (partsize == RECURSIVE_BLOCK_SIZE) {
        D printf("G\n ");
        G(gctx, gout, left, outl)
        memxor(right, gout, RECURSIVE_BLOCK_SIZE);

        G(gctx, gout, right, outl)
        memxor(left, gout, RECURSIVE_BLOCK_SIZE);

        G(gctx, gout, left, outl)
        memxor(right, gout, RECURSIVE_BLOCK_SIZE);

    } else if (partsize > BLOCK_SIZE) {
        D printf("RECURSIVE\n ");
        memcpy(gout, left, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(right, gout, partsize);

        memcpy(gout, right, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(left, gout, partsize);

        memcpy(gout, left, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(right, gout, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }
}

// the function below is identical to mixoaep_pad for odd number of
// OAEP steps, but must be changed in case of even steps.
static inline void mixoaep_unpad(
    GCTX* gctx, unsigned char* data, unsigned char* buffer,
    const unsigned long size
){

    OUTLTYPE outl;
    unsigned long partsize = size / 2;
    unsigned char *left = data;
    unsigned char *right = data + partsize;
    unsigned char *gout = buffer;

    if (partsize == RECURSIVE_BLOCK_SIZE) {
        G(gctx, gout, left, outl)
        memxor(right, gout, RECURSIVE_BLOCK_SIZE);

        G(gctx, gout, right, outl)
        memxor(left, gout, RECURSIVE_BLOCK_SIZE);

        G(gctx, gout, left, outl)
        memxor(right, gout, RECURSIVE_BLOCK_SIZE);

    } else if (partsize > BLOCK_SIZE) {
        memcpy(gout, left, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(right, gout, partsize);

        memcpy(gout, right, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(left, gout, partsize);

        memcpy(gout, left, partsize);
        mixoaep_pad(gctx, gout, buffer + partsize, partsize);
        memxor(right, gout, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }
}


static inline void mixencrypt_bimacroblock_oaep_recursive(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){

#ifdef RECURSIVE_SHA512
#if OPENSSL_VERSION_NUMBER < 0x10100000
    GCTX* gctx = EVP_MD_CTX_create();
#else
    GCTX* gctx = EVP_MD_CTX_new();
#endif
#endif
#ifdef RECURSIVE_AES
    GCTX *gctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(gctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(gctx, 0); // disable padding
#endif

    // add IV
    memcpy(out, bimacro, OAEP_BIMACRO_SIZE);
    memxor(out, iv, AES_BLOCK_SIZE);

    // OAEP pad
    mixoaep_pad(gctx, out, buffer, OAEP_BIMACRO_SIZE);

#ifdef RECURSIVE_SHA512
#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX_destroy(gctx);
#else
    EVP_MD_CTX_free(gctx);
#endif
#endif
#ifdef RECURSIVE_AES
    EVP_CIPHER_CTX_cleanup(gctx);
    EVP_CIPHER_CTX_free(gctx);
#endif

// encrypt
#ifndef RECURSIVE_AES
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_EncryptUpdate(ctx, out, &outl, out, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
#endif

}

static inline void mixdecrypt_bimacroblock_oaep_recursive(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){

#ifdef RECURSIVE_SHA512
#if OPENSSL_VERSION_NUMBER < 0x10100000
    GCTX* gctx = EVP_MD_CTX_create();
#else
    GCTX* gctx = EVP_MD_CTX_new();
#endif
#endif
#ifdef RECURSIVE_AES
    GCTX *gctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(gctx, EVP_aes_128_ecb(), key, iv);
    EVP_CIPHER_CTX_set_padding(gctx, 0); // disable padding
#endif

#ifndef RECURSIVE_AES
    // decrypt
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_DecryptUpdate(ctx, out, &outl, bimacro, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
#else
    memcpy(out, bimacro, OAEP_BIMACRO_SIZE);
#endif

    // OAEP unpad
    mixoaep_unpad(gctx, out, buffer, OAEP_BIMACRO_SIZE);

    // remove IV
    memxor(out, iv, AES_BLOCK_SIZE);

#ifdef RECURSIVE_SHA512
#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX_destroy(gctx);
#else
    EVP_MD_CTX_free(gctx);
#endif
#endif
#ifdef RECURSIVE_AES
    EVP_CIPHER_CTX_cleanup(gctx);
    EVP_CIPHER_CTX_free(gctx);
#endif
}

inline void mixbiprocess(
    mixfn fn, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    D assert(1 == ISPOWEROF(RECURSIVE_MINI_PER_MACRO, RECURSIVE_BLOCK_SIZE / RECURSIVE_MINI_SIZE)
             && "RECURSIVE_MINI_PER_MACRO must be a power of (RECURSIVE_BLOCK_SIZE / RECURSIVE_MINI_SIZE)");
    const unsigned char* last = data + size;
    unsigned __int128 miv;
    unsigned char* buffer = malloc(OAEP_BIMACRO_SIZE);

    if ( !buffer ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    assert(0 == size % OAEP_BIMACRO_SIZE);
    memcpy(&miv, iv, sizeof(miv));

    for ( ; data < last; data+=OAEP_BIMACRO_SIZE, out+=OAEP_BIMACRO_SIZE, miv++) {
        fn(data, out, buffer, key, (unsigned char*) &miv);
    }

    free(buffer);
}

void mixencrypt_oaep_recursive(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixbiprocess(mixencrypt_bimacroblock_oaep_recursive, data, out, size, key, iv);
}

void mixdecrypt_oaep_recursive(const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    mixbiprocess(mixdecrypt_bimacroblock_oaep_recursive, data, out, size, key, iv);
}
