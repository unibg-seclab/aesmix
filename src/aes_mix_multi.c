#include <pthread.h>
#include <string.h>
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

static inline void t_mixprocess(const short enc, unsigned int thr,
    const unsigned char* data, unsigned char* out, const unsigned long size,
    const unsigned char* key, const unsigned char* iv
){
    pthread_t thread[thr];
    aesmix_args args[thr];
    unsigned char tiv[thr][BLOCK_SIZE];
    unsigned long remaining_macro;
    unsigned int t, started_thr = 0;
    unsigned __int128 miv;

    assert(0 == size % MACRO_SIZE);
    remaining_macro = size / MACRO_SIZE;
    memcpy(&miv, iv, BLOCK_SIZE);

    for (t=0; t < thr; ++t) {
        if (!remaining_macro) break;

        // compute optimal number of macroblocks per thread
        unsigned long tmacro = MAX(1UL, remaining_macro / (thr - t));
        unsigned long tsize = tmacro * MACRO_SIZE;
        remaining_macro -= tmacro;
        D printf("%lu macroblocks assigned to thread %d\n", tmacro, t);

        aesmix_args* a = &args[t];
        memcpy(tiv[t], &miv, BLOCK_SIZE);
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = tiv[t];
        pthread_create(&thread[t], NULL, enc ? w_mixencrypt : w_mixdecrypt, a);
        data += tsize; out += tsize; miv += tmacro; started_thr++;
    }

    assert(!remaining_macro);
    for (t=0; t<started_thr; ++t) {
        pthread_join(thread[t], NULL);
    }
}

void t_mixencrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess(1, thr, data, out, size, key, iv);
}


void t_mixdecrypt(unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    t_mixprocess(0, thr, data, out, size, key, iv);
}
