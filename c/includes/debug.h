#ifndef DEBUG_H
#define DEBUG_H

#define printx(str, data, size, split) \
    do { printf(str); print_hex(data, size, split); } while (0);

void print_hex(const unsigned char *s, unsigned int l, unsigned int split);

#endif // DEBUG_H
