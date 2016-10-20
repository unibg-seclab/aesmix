#include <stdio.h>
#include "debug.h"

void print_hex(const unsigned char *s, unsigned int l, unsigned int split)
{
    unsigned int i;
    for (i = 0; i < l; ++i) {
        if (i && split && (i % split == 0)) printf("-");
        printf("%02x", (unsigned int) s[i]);
    }
    printf("\n");
}
