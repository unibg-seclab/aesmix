#ifndef DEBUG_H
#define DEBUG_H

#define printx(str, data, size) \
    do { printf(str); print_hex(data, size); } while (0);

void print_hex(const unsigned char *s, unsigned int l);

#endif // DEBUG_H
