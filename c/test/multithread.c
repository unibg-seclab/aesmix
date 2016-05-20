#include <openssl/rand.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "aes_mix_multi.h"

#define MACROS               4
#define THREADS              2
#define TIMES             1024

int main(int argc, char *argv[]) {
    unsigned long i, threads, size, times;
    unsigned char key[BLOCK_SIZE];
    unsigned char  iv[BLOCK_SIZE];
    unsigned char *in;
    unsigned char *dec;
    unsigned char *out;
    struct timespec start, finish;
    double elapsed = 0;
    //FILE *fp;

    threads = argc > 1 ? atoi(argv[1]) : THREADS;
    size = MACRO_SIZE * (argc > 2 ? atoi(argv[2]) : MACROS);
    times = argc > 3 ? atoi(argv[3]) : TIMES;

    in = malloc(size);
    dec = malloc(size);
    out = malloc(size);

    //fp = fopen("test/data/video_10mb.mp4", "rb");
    //fread(in, 1, size, fp);
    //fclose(fp);
    RAND_pseudo_bytes(in, size);

    RAND_pseudo_bytes(key, BLOCK_SIZE);
    RAND_pseudo_bytes(iv, BLOCK_SIZE);

    for (i=0; i < times; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        D printf("ENCRYPTION (size %lu)\n", size);
        t_encrypt(threads, in, out, size, key, iv);

        D printf("DECRYPTION (size %lu)\n", size);
        t_decrypt(threads, out, dec, size, key, iv);
        clock_gettime(CLOCK_MONOTONIC, &finish);
        elapsed += (finish.tv_sec - start.tv_sec);
        elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;

        assert(0 == memcmp(in, dec, size));
    }

    //fp = fopen("test/data/video_10mb.mp4.out", "wb");
    //fwrite(dec, 1, size, fp);
    //fclose(fp);

    free(in);
    free(out);
    free(dec);

    printf("DONE in %f seconds.\n", elapsed);
}
