#include <openssl/evp.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_oaep_recursive.h"

// avoid using AES specific defines
#define AES_BLOCK_SIZE BLOCK_SIZE
#undef MINI_SIZE
#undef MINI_PER_MACRO
#undef MINI_PER_BLOCK
#undef MACRO_SIZE
#undef DIGITS
#undef DOF


static inline void mixoaep_pad(
    EVP_MD_CTX* mdctx, unsigned char* data, unsigned char* buffer,
    const unsigned long size
){

    unsigned int outl;
    unsigned long partsize = size / 2;
    unsigned char *left = data;
    unsigned char *right = data + partsize;

    unsigned char *gout = malloc(OAEP_MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }
    /* printf("%lu ", partsize); */

    if (partsize == OAEP_BLOCK_SIZE) {
        /* printf("SHA\n "); */
        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, left, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(right, gout, OAEP_BLOCK_SIZE);

        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, right, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(left, gout, OAEP_BLOCK_SIZE);

        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, left, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(right, gout, OAEP_BLOCK_SIZE);

    } else if (partsize > BLOCK_SIZE) {
        /* printf("RECURSIVE\n "); */
        memcpy(gout, left, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(right, gout, partsize);

        memcpy(gout, right, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(left, gout, partsize);

        memcpy(gout, left, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(right, gout, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }

    free(gout);
}

// the function below is identical to mixoaep_pad for odd number of
// OAEP steps, but must be changed in case of even steps.
static inline void mixoaep_unpad(
    EVP_MD_CTX* mdctx, unsigned char* data, unsigned char* buffer,
    const unsigned long size
){

    unsigned int outl;
    unsigned long partsize = size / 2;
    unsigned char *left = data;
    unsigned char *right = data + partsize;

    unsigned char *gout = malloc(OAEP_MACRO_SIZE);

    if ( !gout ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    if (partsize == OAEP_BLOCK_SIZE) {
        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, left, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(right, gout, OAEP_BLOCK_SIZE);

        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, right, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(left, gout, OAEP_BLOCK_SIZE);

        EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL);
        EVP_DigestUpdate(mdctx, left, OAEP_BLOCK_SIZE);
        EVP_DigestFinal_ex(mdctx, gout, &outl);
        D assert(OAEP_BLOCK_SIZE == outl);
        memxor(right, gout, OAEP_BLOCK_SIZE);

    } else if (partsize > BLOCK_SIZE) {
        memcpy(gout, left, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(right, gout, partsize);

        memcpy(gout, right, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(left, gout, partsize);

        memcpy(gout, left, partsize);
        mixoaep_pad(mdctx, gout, buffer, partsize);
        memxor(right, gout, partsize);

    } else {  // partsize < BLOCK_SIZE
        printf("plaintext length must be 2*n*16 Bytes (n>0, int)");
        exit(EXIT_FAILURE);
    }

    free(gout);
}


static inline void mixencrypt_bimacroblock_oaep_recursive(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
#else
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
#endif

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // add IV
    memcpy(out, bimacro, OAEP_BIMACRO_SIZE);
    memxor(out, iv, AES_BLOCK_SIZE);

    // OAEP pad
    mixoaep_pad(mdctx, out, buffer, OAEP_BIMACRO_SIZE);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX_destroy(mdctx);
#else
    EVP_MD_CTX_free(mdctx);
#endif

    // encrypt
    EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_EncryptUpdate(ctx, out, &outl, out, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);


}

static inline void mixdecrypt_bimacroblock_oaep_recursive(
    const unsigned char* bimacro, unsigned char* out, unsigned char* buffer,
    const unsigned char* key, const unsigned char* iv
){
    int outl;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
#else
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
#endif

    if ( !ctx ) {
        printf("Cannot allocate needed memory\n");
        exit(EXIT_FAILURE);
    }

    // decrypt
    EVP_DecryptInit(ctx, EVP_aes_128_ctr(), key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // disable padding
    EVP_DecryptUpdate(ctx, out, &outl, bimacro, OAEP_BIMACRO_SIZE);
    D assert(OAEP_BIMACRO_SIZE == outl);
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    // OAEP unpad
    mixoaep_unpad(mdctx, out, buffer, OAEP_BIMACRO_SIZE);

    // remove IV
    memxor(out, iv, AES_BLOCK_SIZE);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    EVP_MD_CTX_destroy(mdctx);
#else
    EVP_MD_CTX_free(mdctx);
#endif

}

inline void mixbiprocess(
    mixfn fn, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    D assert(1 == ISPOWEROF(OAEP_MINI_PER_MACRO, OAEP_BLOCK_SIZE / OAEP_MINI_SIZE)
             && "OAEP_MINI_PER_MACRO must be a power of (OAEP_BLOCK_SIZE / OAEP_MINI_SIZE)");
    const unsigned char* last = data + size;
    unsigned __int128 miv;
    unsigned char* buffer = malloc(OAEP_MACRO_SIZE);

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
