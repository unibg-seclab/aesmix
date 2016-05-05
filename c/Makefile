.PHONY:    all clean debug

TARGETS  = main blackbox

SRCDIR   = src
CFLAGS  += -O6 -Wall
INC     += -Iincludes
LDLIBS  += -lcrypto

all: $(TARGETS)

debug: CFLAGS += -DDEBUG -g
debug: all

main: lck.o debug.o main.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox: lck.o debug.o blackbox.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

test: | clean debug
	@ echo -e "\nRUNNING TESTS ..."
	@ ./main 1 &> /dev/null || ./main 1
	@ ./blackbox &> /dev/null || ./blackbox
	@ echo -e "\033[0;32mALL OK\033[0m"

clean:
	@ rm -f $(TARGETS) *.o *.out
