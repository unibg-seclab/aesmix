.PHONY:    all clean debug

TARGET   = main

SRCS     = lck.c main.c
OBJS    := $(SRCS:%.c=%.o)

CFLAGS += -O6 -Wall
LDLIBS  += -lcrypto

debug: CFLAGS += -DDEBUG -g
debug: all

$(TARGET) all: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -f $(OBJS) $(TARGET)
