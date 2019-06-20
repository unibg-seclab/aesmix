#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_multi_oaep_recursive.h"


// avoid using AES specific defines
#define AES_BLOCK_SIZE BLOCK_SIZE
#undef MINI_SIZE
#undef MINI_PER_MACRO
#undef MINI_PER_BLOCK
#undef MACRO_SIZE
#undef DIGITS
#undef DOF


static void *w_mixencrypt_oaep_recursive(void *data){
    aesmix_args *args = data;
    mixencrypt_oaep_recursive(args->data, args->out, args->size, args->key, args->iv);
    return NULL;
}

static void *w_mixdecrypt_oaep_recursive(void *data){
    aesmix_args *args = data;
    mixdecrypt_oaep_recursive(args->data, args->out, args->size, args->key, args->iv);
    return NULL;
}

void t_mixencrypt_oaep_recursive (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess_oaep(w_mixencrypt_oaep_recursive, thr, data, out, size, key, iv);
}


void t_mixdecrypt_oaep_recursive (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess_oaep(w_mixdecrypt_oaep_recursive, thr, data, out, size, key, iv);
}
