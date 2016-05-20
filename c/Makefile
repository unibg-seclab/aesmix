.PHONY:    all callgrind clean cleanall debug fresh multitest test time

# DEFINES
MINI_SIZE      =    4
BLOCK_SIZE     =   16
MINI_PER_MACRO = 1024

# TEST
TESTDIR   = test
DUMMYFILE = $(TESTDIR)/data/file.dummy
DUMMYSIZE = $$(( 1024 * 1024 * 1024 ))
THREADS   = 128
TIMES     = 1

# DO NOT TOUCH
TARGETS   = main blackbox multithread
SRCDIR    = src
CFLAGS   += -O6 -Wall -Wextra
CFLAGS   += -DMINI_SIZE=$(MINI_SIZE)
CFLAGS   += -DBLOCK_SIZE=$(BLOCK_SIZE)
CFLAGS   += -DMINI_PER_MACRO=$(MINI_PER_MACRO)
INC      += -Iincludes
LDLIBS   += -lcrypto
AESNI     = 1

ifneq ($(AESNI),1)
export OPENSSL_ia32cap = "~0x200000200000000"
endif

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

$(TESTDIR)/data:
	mkdir -p $@

$(DUMMYFILE): $(TESTDIR)/data
	openssl rand -out $@ $(DUMMYSIZE)

test: | clean debug
	@ echo -e "\nRUNNING TESTS ..."
	@ $(ENV) ./main 1 &> /dev/null || ./main 1
	@ $(ENV) ./blackbox &> /dev/null || ./blackbox
	@ echo -e "\033[0;32mALL OK\033[0m"

time: | clean main
	@ echo -e "\nENCRYPTING 1GiB ..."
	@ $(ENV) time ./main $$((1024*1024*1024 / ($(MINI_SIZE)*$(MINI_PER_MACRO))))

multitest: multithread $(DUMMYFILE)
	$(ENV) ./multithread $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

clean:
	@ rm -f $(TARGETS) *.o *.out

cleanall: clean
	@ rm -f $(DUMMYFILE) $(DUMMYFILE).out
