#include <stdio.h>
#include "debug.h"
#include "lck.h"

void print_hex(const unsigned char *s, unsigned int l)
{
    int i;
    for (i = 0; i < l; ++i) {
        if (i && (i % MINI_SIZE == 0)) printf("-");
        printf("%02x", (unsigned int) s[i]);
    }
    printf("\n");
}
