#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_multi_oaep.h"

typedef struct aesmix_args_s {
    const unsigned char* data;
    unsigned char* out;
    unsigned long size;
    const unsigned char* key;
    const unsigned char* iv;
} aesmix_args;

typedef void* (*w_fn) (void* data);

static void *w_mixencrypt_oaep(void *data){
    aesmix_args *args = data;
    mixencrypt_oaep(args->data, args->out, args->size, args->key, args->iv);
    return NULL;
}

static void *w_mixdecrypt_oaep(void *data){
    aesmix_args *args = data;
    mixdecrypt_oaep(args->data, args->out, args->size, args->key, args->iv);
    return NULL;
}

static inline void t_mixprocess_oaep (
    w_fn fn, unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    pthread_t thread[thr];
    aesmix_args args[thr];
    unsigned char tiv[thr][BLOCK_SIZE];
    unsigned long remaining_bimacro;
    unsigned int t;
    unsigned __int128 miv;

    assert(0 == size % BIMACRO_SIZE);
    remaining_bimacro = size / BIMACRO_SIZE;
    memcpy(&miv, iv, BLOCK_SIZE);


    for (t=0; t < thr; ++t) {
        //compute optimal number of bimacroblocks per thread
        unsigned long tbimacro = remaining_bimacro / (thr - t);
        unsigned long tsize = tbimacro * BIMACRO_SIZE;
        remaining_bimacro -= tbimacro;

        aesmix_args* a = &args[t];
        memcpy(tiv[t], &miv, BLOCK_SIZE);
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = tiv[t];
        pthread_create(&thread[t], NULL, fn, a);
        data += tsize; out += tsize; miv += tbimacro;
    }

    assert(!remaining_bimacro);
    for (t=0; t < thr; ++t) {
        pthread_join(thread[t], NULL);
    }
}

void t_mixencrypt_oaep (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess_oaep(w_mixencrypt_oaep, thr, data, out, size, key, iv);
}


void t_mixdecrypt_oaep (
    unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess_oaep(w_mixdecrypt_oaep, thr, data, out, size, key, iv);
}
