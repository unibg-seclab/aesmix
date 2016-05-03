#define BLOCK_SIZE                                 16
#define MINI_SIZE                                   4
#define MINI_PER_MACRO                           1024
#define MINI_PER_BLOCK       (BLOCK_SIZE / MINI_SIZE)
#define MACRO_SIZE       (MINI_SIZE * MINI_PER_MACRO)
#define DIGITS           ((int) log2(MINI_PER_MACRO))
#define DOF              ((int) log2(MINI_PER_BLOCK))

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define debug_print(...) \
    do { if (DEBUG_TEST) fprintf(stderr, __VA_ARGS__); } while (0)

void encrypt(unsigned char* data, unsigned char* out, unsigned long size,
             unsigned char* key, unsigned char* iv);

void decrypt(unsigned char* data, unsigned char* out, unsigned long size,
             unsigned char* key, unsigned char* iv);
