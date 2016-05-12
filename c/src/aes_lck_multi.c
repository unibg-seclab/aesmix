#include <pthread.h>
#include <assert.h>

#include "aes_lck_multi.h"

typedef struct aeslck_args_s {
    const unsigned char* data;
    unsigned char* out;
    unsigned long size;
    const unsigned char* key;
    const unsigned char* iv;
} aeslck_args;

static void *w_encrypt(void *data){
    aeslck_args *args = data;
    encrypt(args->data, args->out, args->size, args->key, args->iv);
    return NULL;  // TODO return something meaningful
}

static void *w_decrypt(void *data){
    aeslck_args *args = data;
    decrypt(args->data, args->out, args->size, args->key, args->iv);
    return NULL;  // TODO return something meaningful
}

static inline void process(const short enc, unsigned int thr,
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    pthread_t thread[thr];
    aeslck_args args[thr];
    unsigned long tsize = size / thr;
    aeslck_args* a;
    unsigned int t;

    assert(0 == size % MACRO_SIZE);

    for (t=0; t < thr; ++t) {
        a = &args[t];
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = iv;
        pthread_create(&thread[t], NULL, enc ? w_encrypt : w_decrypt, a);
        data += tsize; out += tsize;
    }

    for (t=0; t<thr; ++t) {
        pthread_join(thread[t], NULL);
    }
}

void t_encrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(1, thr, data, out, size, key, iv);
}


void t_decrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    process(0, thr, data, out, size, key, iv);
}
