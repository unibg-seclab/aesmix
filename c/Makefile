TARGET   = main

SRCS     = lck.c main.c
OBJS    := $(SRCS:%.c=%.o)

CC       = gcc
CFLAGS   = -Wall
LFLAGS   = -lcrypto

$(TARGET) all: $(OBJS)
	$(CC) -o $(TARGET) $(LFLAGS) $(OBJS)

%.o: %.c
	$(CC) -c -O6 -o $@ $< $(CFLAGS)

clean:
	@rm -f $(OBJS) $(TARGET)
