#ifndef DEBUG_H
#define DEBUG_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define printx(str, data, size, split) \
    do { printf(str); print_hex(data, size, split); } while (0);

void print_hex(const unsigned char *s, unsigned int l, unsigned int split);

void print_diff(const unsigned char *s1, const unsigned char *s2, unsigned long size);

#endif // DEBUG_H
