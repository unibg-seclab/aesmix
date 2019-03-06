.PHONY:	all callgrind clean cleanall debug fresh multitest printvars \
		supertest test test_oaep time time_oaep \
		multidiff multidiff_oaep

# DEFINES
include config.properties

# TEST
TESTDIR   = test
DUMMYFILE = $(TESTDIR)/data/file.dummy
DUMMYSIZE = $$(( 1024 * 1024 * 1024 ))
THREADS   = 32
TIMES     = 1

# DO NOT TOUCH
TARGETS   = main main_oaep blackbox blackbox_oaep multithread multithread_oaep multidiff multidiff_oaep
SRCDIR    = src
CFLAGS   += -fPIC -O6 -Wall -Wextra
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

libaesmix.so: aes_mix.o aes_mix_oaep.o aes_mix_multi.o aes_mix_multi_oaep.o
	$(CC) $(LDFLAGS) -shared -o $@ $^

main: aes_mix.o debug.o main.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

main_oaep: aes_mix.o debug.o main_oaep.o aes_mix_oaep.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox: aes_mix.o debug.o blackbox.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox_oaep: aes_mix.o debug.o blackbox_oaep.o aes_mix_oaep.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

multithread: aes_mix.o debug.o aes_mix_multi.o multithread.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multithread_oaep: aes_mix.o debug.o aes_mix_multi_oaep.o multithread_oaep.o aes_mix_oaep.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multidiff: aes_mix.o debug.o aes_mix_multi.o multidiff.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multidiff_oaep: aes_mix.o debug.o aes_mix_multi_oaep.o multidiff_oaep.o aes_mix_oaep.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(DUMMYFILE):
	@ mkdir -p $(TESTDIR)/data
	openssl rand -out $@ $(DUMMYSIZE)

printvars:
	@ printf "\nAESNI=%d MINI=%d MPM=%d\n" \
		$(AESNI) $(MINI_SIZE) $(MINI_PER_MACRO)

test: | clean debug printvars
	@ echo -e "\nRUNNING TESTS ..."
	./main 1 &> /dev/null || ./main 1
	./blackbox &> /dev/null || ./blackbox
	./multidiff &> /dev/null || ./multidiff
	@ echo -e "\033[0;32mALL OK\033[0m"

test_oaep: | clean debug printvars
	@ echo -e "\nRUNNING OAEP TESTS ..."
	./main_oaep 1 &> /dev/null || ./main_oaep 1
	./blackbox_oaep &> /dev/null || ./blackbox_oaep
	./multidiff_oaep &> /dev/null || ./multidiff_oaep
	@ echo -e "\033[0;32mALL OK\033[0m"

time: | clean main printvars
	@ echo -e "\nENCRYPTING 1GiB ..."
	time ./main $$((1024*1024*1024 / ($(MINI_SIZE)*$(MINI_PER_MACRO))))

time_oaep: | clean main_oaep printvars
	@ echo -e "\nENCRYPTING 1GiB with OAEP ..."
	time ./main_oaep $$((1024*1024*1024 / ($(MINI_SIZE)*$(MINI_PER_MACRO))))

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

multitest_oaep: | clean multithread_oaep $(DUMMYFILE) printvars
	./multithread_oaep $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

clean:
	@ rm -f $(TARGETS) *.o *.out *.so _*.c

cleanall: clean
	@ rm -f $(DUMMYFILE) $(DUMMYFILE).out
