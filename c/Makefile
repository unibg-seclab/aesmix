.PHONY:    all callgrind clean debug fresh test time

TARGETS  = main blackbox multithread

SRCDIR   = src
TESTDIR  = test
CFLAGS  += -O6 -Wall -Wextra
INC     += -Iincludes
LDLIBS  += -lcrypto

vpath %.c $(SRCDIR) $(TESTDIR)

all: $(TARGETS)

fresh: | clean all

debug: CFLAGS += -DDEBUG -g
debug: all

callgrind: CFLAGS += -g
callgrind: | clean main
	valgrind --tool=callgrind --callgrind-out-file=callgrind.out ./main 1024

main: aes_mix.o debug.o main.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox: aes_mix.o debug.o blackbox.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

multithread: aes_mix.o aes_mix_multi.o multithread.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

test: | clean debug
	@ echo -e "\nRUNNING TESTS ..."
	@ ./main 1 &> /dev/null || ./main 1
	@ ./blackbox &> /dev/null || ./blackbox
	@ echo -e "\033[0;32mALL OK\033[0m"

time: | clean main
	@ echo -e "\nENCRYPTING 1GiB ..."
	@ time ./main 262144

clean:
	@ rm -f $(TARGETS) *.o *.out
