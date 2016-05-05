.PHONY:    all clean debug

TARGET   = main

SRCS     = lck.c main.c
OBJS    := $(SRCS:%.c=%.o)

CFLAGS += -O6 -Wall
LDLIBS  += -lcrypto

$(TARGET) all: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $(TARGET)

debug: CFLAGS += -DDEBUG -g -pg
debug: LDFLAGS += -pg
debug: all

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -f $(OBJS) $(TARGET) *.out
