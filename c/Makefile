TARGET   = main

SRCS     = lck.c
OBJS    := $(SRCS:%.c=%.o)

CC       = gcc
CFLAGS   = -Wall
LFLAGS   = -lcrypto

$(TARGET) all: $(OBJS)
	$(CC) -o $(TARGET) $(LFLAGS) $(OBJS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	@rm -f $(OBJS) $(TARGET)
