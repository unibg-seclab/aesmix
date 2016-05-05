.PHONY:    all clean debug

TARGETS  = main blackbox

CFLAGS  += -O6 -Wall
INC     += -Iincludes
LDLIBS  += -lcrypto

all: $(TARGETS)

debug: CFLAGS += -DDEBUG -g -pg
debug: LDFLAGS += -pg
debug: all

main: lck.o debug.o main.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox: lck.o debug.o blackbox.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	@rm -f *.o *.out $(TARGETS)
