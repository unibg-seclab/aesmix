#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "aes_mix_multi_oaep.h"


// avoid using AES specific defines
#define AES_BLOCK_SIZE BLOCK_SIZE
#undef MINI_SIZE
#undef MINI_PER_MACRO
#undef MINI_PER_BLOCK
#undef MACRO_SIZE
#undef DIGITS
#undef DOF


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

inline void t_mixprocess_oaep (
    w_fn fn, unsigned int thr, const unsigned char* data, unsigned char* out,
    const unsigned long size, const unsigned char* key, const unsigned char* iv
){
    pthread_t thread[thr];
    aesmix_args args[thr];
    unsigned char tiv[thr][AES_BLOCK_SIZE];
    unsigned long remaining_bimacro;
    unsigned int t, started_thr = 0;
    unsigned __int128 miv;

    assert(0 == size % OAEP_BIMACRO_SIZE);
    remaining_bimacro = size / OAEP_BIMACRO_SIZE;
    memcpy(&miv, iv, AES_BLOCK_SIZE);


    for (t=0; t < thr; ++t) {
        if (!remaining_bimacro) break;

        //compute optimal number of bimacroblocks per thread
        unsigned long tbimacro = MAX(1UL, remaining_bimacro / (thr - t));
        unsigned long tsize = tbimacro * OAEP_BIMACRO_SIZE;
        remaining_bimacro -= tbimacro;
        D printf("%lu bimacroblocks assigned to thread %d\n", tbimacro, t);

        aesmix_args* a = &args[t];
        memcpy(tiv[t], &miv, AES_BLOCK_SIZE);
        a->data = data; a->out = out; a->size = tsize; a->key = key; a->iv = tiv[t];
        pthread_create(&thread[t], NULL, fn, a);
        data += tsize; out += tsize; miv += tbimacro; started_thr++;
    }

    assert(!remaining_bimacro);
    for (t=0; t < started_thr; ++t) {
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
