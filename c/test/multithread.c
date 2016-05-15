#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "aes_mix_multi.h"

#define MACROS               4
#define THREADS              2
#define TIMES             1024


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
        assert(0 == memcmp(in, dec, size));
    }
    printf("DONE\n");

}
