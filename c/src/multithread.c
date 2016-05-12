#include <openssl/rand.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "aes_lck.h"

#define MACROS               4
#define THREADS              2
#define TIMES             1024

typedef struct aeslck_args_s {
    const unsigned char* data;
    unsigned char* out;
    unsigned long size;
    const unsigned char* key;
    const unsigned char* iv;
} aeslck_args;

static void *w_encrypt(void *data){
    aeslck_args *args = data;
    D printf("Started working thread with size: %lu\n", args->size);
    encrypt(args->data, args->out, args->size, args->key, args->iv);
    return NULL;  // TODO return something meaningful
}

static void *w_decrypt(void *data){
    aeslck_args *args = data;
    D printf("Started working thread with size: %lu\n", args->size);
    encrypt(args->data, args->out, args->size, args->key, args->iv);
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

int main(int argc, char *argv[]) {
    unsigned long i, threads, size, times;

    threads = argc > 1 ? atoi(argv[1]) : THREADS;
    size = MACRO_SIZE * (argc > 2 ? atoi(argv[2]) : MACROS);
    times = argc > 3 ? atoi(argv[3]) : TIMES;

    unsigned char  in[size];
    unsigned char out[size];
    unsigned char dec[size];
    unsigned char key[BLOCK_SIZE];
    unsigned char  iv[BLOCK_SIZE];

    RAND_pseudo_bytes(key, BLOCK_SIZE);
    RAND_pseudo_bytes(iv, BLOCK_SIZE);

    printf("%lu ENCRYPTIONS + %lu DECRYPTIONS \n", times, times);
    for (i=0; i < times; ++i) {
        t_encrypt(threads,  in, out, size, key, iv);
        t_decrypt(threads, out, dec, size, key, iv);
        D assert(memcmp(in, dec, size));
    }
    printf("DONE\n");

}
