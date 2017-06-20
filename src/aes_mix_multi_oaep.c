#include <pthread.h>
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
    unsigned long tsize = size / thr;
    aesmix_args* a;
    unsigned int t;

    assert(0 == size % BIMACRO_SIZE);

    for (t=0; t < thr; ++t) {
        a = &args[t];
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = iv;
        pthread_create(&thread[t], NULL, fn, a);
        data += tsize; out += tsize;
    }

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
