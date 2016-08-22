.PHONY:	all callgrind clean cleanall debug fresh multitest printvars \
		supertest test time

# DEFINES
MINI_SIZE      =    4
BLOCK_SIZE     =   16
MINI_PER_MACRO = 1024

# TEST
TESTDIR   = test
DUMMYFILE = $(TESTDIR)/data/file.dummy
DUMMYSIZE = $$(( 1024 * 1024 * 1024 ))
THREADS   = 8
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

ifeq ($(shell uname), Darwin)  # OSX
    LDFLAGS  += -L/usr/local/opt/openssl/lib
    CFLAGS   += -I/usr/local/opt/openssl/include
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

printvars:
	@ printf "\nAESNI=%d MINI=%d MPM=%d\n" \
		$(AESNI) $(MINI_SIZE) $(MINI_PER_MACRO)

test: | clean debug printvars
	@ echo -e "\nRUNNING TESTS ..."
	@ ./main 1 &> /dev/null || ./main 1
	@ ./blackbox &> /dev/null || ./blackbox
	@ echo -e "\033[0;32mALL OK\033[0m"

time: | clean main printvars
	@ echo -e "\nENCRYPTING 1GiB ..."
	@ time ./main $$((1024*1024*1024 / ($(MINI_SIZE)*$(MINI_PER_MACRO))))

supertest: clean
	@ for aesni in 1 0; do \
		for mini in 2 4 8; do \
			for mpm in 16 64 256 1024 4096; do \
				$(MAKE) -s multitest \
					AESNI=$$aesni \
					MINI_SIZE=$$mini \
					MINI_PER_MACRO=$$mpm; \
			done \
		done \
	done

multitest: | clean multithread $(DUMMYFILE) printvars
	./multithread $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

clean:
	@ rm -f $(TARGETS) *.o *.out

cleanall: clean
	@ rm -f $(DUMMYFILE) $(DUMMYFILE).out
