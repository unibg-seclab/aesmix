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

void print_diff(const unsigned char *s1, const unsigned char *s2, unsigned long size)
{
    unsigned int i;
    for (i = 0; i < size; i++) {
        printf("%02x", (unsigned char) s1[i]);
        printf((s1[i] == s2[i]) ? ANSI_COLOR_GREEN : ANSI_COLOR_RED);
        printf("%02x", (unsigned char) s2[i]);
        printf(ANSI_COLOR_RESET);
    }
    printf("\n");
}
