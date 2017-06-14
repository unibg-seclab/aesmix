#include <pthread.h>
#include <assert.h>

#include "aes_mix_multi.h"

typedef struct aesmix_args_s {
    const unsigned char* data;
    unsigned char* out;
    unsigned long size;
    const unsigned char* key;
    const unsigned char* iv;
} aesmix_args;

static void *w_mixencrypt(void *data){
    aesmix_args *args = data;
    mixencrypt(args->data, args->out, args->size, args->key, args->iv);
    return NULL;  // TODO return something meaningful
}

static void *w_mixdecrypt(void *data){
    aesmix_args *args = data;
    mixdecrypt(args->data, args->out, args->size, args->key, args->iv);
    return NULL;  // TODO return something meaningful
}

static inline void process(const short enc, unsigned int thr,
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    pthread_t thread[thr];
    aesmix_args args[thr];
    unsigned long tsize = size / thr;
    aesmix_args* a;
    unsigned int t;

    assert(0 == size % MACRO_SIZE);

    for (t=0; t < thr; ++t) {
        a = &args[t];
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = iv;
        pthread_create(&thread[t], NULL, enc ? w_mixencrypt : w_mixdecrypt, a);
        data += tsize; out += tsize;
    }

    for (t=0; t<thr; ++t) {
        pthread_join(thread[t], NULL);
    }
}

void t_mixencrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(1, thr, data, out, size, key, iv);
}


void t_mixdecrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(0, thr, data, out, size, key, iv);
}
