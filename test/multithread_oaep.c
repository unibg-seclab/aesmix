#include <openssl/rand.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "aes_mix_multi_oaep.h"

#define THREADS              4
#define TIMES             1024

double test(
    char *filename,
    char *output,
    unsigned long size,
    unsigned int threads,
    unsigned int times
) {
    unsigned char key[BLOCK_SIZE];
    unsigned char  iv[BLOCK_SIZE];
    unsigned char *in;
    unsigned char *dec;
    unsigned char *out;
    unsigned long bytes;
    unsigned int i;
    struct timespec start, finish;
    double elapsed = 0;
    FILE *fp;

    in = malloc(size);
    dec = malloc(size);
    out = malloc(size);

    fp = fopen(filename, "rb");
    bytes = fread(in, 1, size, fp);
    fclose(fp);

    if (bytes != size) {
        printf("Can read only %lu Bytes from file\n", bytes);
        return EXIT_FAILURE;
    }

    RAND_bytes(key, BLOCK_SIZE);
    RAND_bytes(iv, BLOCK_SIZE);

    for (i=0; i < times; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        D printf("ENCRYPTION (size %lu)\n", size);
        t_mixencrypt_oaep(threads, in, out, size, key, iv);

        D printf("DECRYPTION (size %lu)\n", size);
        D t_mixdecrypt_oaep(threads, out, dec, size, key, iv);
        clock_gettime(CLOCK_MONOTONIC, &finish);
        elapsed += (finish.tv_sec - start.tv_sec);
        elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;

        D assert(0 == memcmp(in, dec, size));
    }

    fp = fopen(output, "wb");
    bytes = fwrite(dec, 1, size, fp);
    fclose(fp);

    if (bytes != size) {
        printf("Can write only %lu Bytes from file\n", bytes);
        return EXIT_FAILURE;
    }

    free(in);
    free(out);
    free(dec);

    return elapsed;
}

int main(int argc, char *argv[]) {
    unsigned int t, threads, times;
    unsigned long size;
    char *filename, *output;
    double elapsed;
    struct stat st;

    if (argc < 3) {
        printf("Usage: ./%s FILE OUTPUT THREADS TIMES\n", argv[0]);
        return EXIT_FAILURE;
    }

    filename = argv[1];
    stat(filename, &st);
    size = st.st_size;

    output = argv[2];
    threads = argc > 3 ? atoi(argv[3]) : THREADS;
    times = argc > 4 ? atoi(argv[4]) : TIMES;

    for (t=1; t<=threads; t*=2) {
        printf("AESMIX-ing with OAEP %s (%luB) with %d threads %d times\n",
               filename, size, t, times);
        elapsed = test(filename, output, size, t, times);
        printf("DONE in %f seconds.\n", elapsed);
    }

    return EXIT_SUCCESS;
}
