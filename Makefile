.PHONY:	all callgrind clean cleanall debug fresh freshdebug multitest multitest_oaep multitest_oaep_recursive printvars \
		supertest test test_oaep test_oaep_recursive time time_oaep install

# DEFINES
include Makefile.properties

# TEST
TESTDIR   = test
DUMMYFILE = $(TESTDIR)/data/file.dummy
DUMMYSIZE = $$(( 1024 * 1024 * 1024 ))
THREADS   = 32
TIMES     = 1

# DO NOT TOUCH
TARGETS   = main main_oaep main_oaep_recursive blackbox blackbox_oaep blackbox_oaep_recursive multithread multithread_oaep multithread_oaep_recursive multidiff multidiff_oaep
LIBS      = libaesmix.la
SRCDIR    = src
CFLAGS   += -fPIC -O6 -Wall -Wextra
CFLAGS   += -DMINI_SIZE=$(MINI_SIZE)
CFLAGS   += -DBLOCK_SIZE=$(BLOCK_SIZE)
CFLAGS   += -DMINI_PER_MACRO=$(MINI_PER_MACRO)
CFLAGS   += -DOAEP_MINI_SIZE=$(OAEP_MINI_SIZE)
CFLAGS   += -DOAEP_BLOCK_SIZE=$(OAEP_BLOCK_SIZE)
CFLAGS   += -DOAEP_MINI_PER_MACRO=$(OAEP_MINI_PER_MACRO)
INC      += -Iincludes
LDLIBS   += -lcrypto -lm
LIBTOOL   = libtool --tag=CC
LIBDIR    = /usr/lib
AESNI     = 1

ifeq ($(RECURSIVE_SHA512),1)
    CFLAGS += -DRECURSIVE_SHA512
else
    CFLAGS += -DRECURSIVE_AES
endif

ifeq ($(NO_NAOR),1)
    CFLAGS += -DNO_NAOR
endif

# check_params,MINI_SIZE,BLOCK_SIZE,MINI_PER_MACRO
define check_params
    $(eval miniperblock=$(shell echo "$(2) / $(1)" | bc))
    $(eval exp=$(shell echo "l($(3)) / l($(miniperblock))" | bc -l))
    $(shell printf "%d==%d^%.0f\n" $(3) $(miniperblock) $(exp) | bc)
endef

ifneq (1,$(strip $(call check_params,$(MINI_SIZE),$(BLOCK_SIZE),$(MINI_PER_MACRO))))
    $(error "MINI_PER_MACRO ($(MINI_PER_MACRO)) is not a power of BLOCK_SIZE ($(BLOCK_SIZE)) / MINI_SIZE ($(MINI_SIZE))")
endif

ifneq (1,$(strip $(call check_params,$(OAEP_MINI_SIZE),$(OAEP_BLOCK_SIZE),$(OAEP_MINI_PER_MACRO))))
    $(error "OAEP_MINI_PER_MACRO ($(OAEP_MINI_PER_MACRO)) is not a power of OAEP_BLOCK_SIZE ($(OAEP_BLOCK_SIZE)) / OAEP_MINI_SIZE ($(OAEP_MINI_SIZE))")
endif


ifneq ($(AESNI),1)
export OPENSSL_ia32cap = "~0x200000200000000"
endif

ifeq ($(shell uname), Darwin)  # OSX
    LDFLAGS  += -L/usr/local/opt/openssl/lib
    CFLAGS   += -I/usr/local/opt/openssl/include
    LIBTOOL   = glibtool --tag=CC
    CFLAGS   += -O3
endif

ifeq ($(shell uname -s), Linux)
    MAKEFLAGS += "-j $(shell nproc) "
endif

vpath %.c $(SRCDIR) $(TESTDIR)
BASE        = aes_mix.lo hctx.lo debug.lo

all: $(TARGETS) $(LIBS)

fresh:
	$(MAKE) clean
	$(MAKE) all

debug: CFLAGS += -DDEBUG -g
debug: all

callgrind: CFLAGS += -g
callgrind: clean
	$(MAKE) main
	valgrind --tool=callgrind --callgrind-out-file=callgrind.out ./main 1024

main: $(BASE) main.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

main_oaep: $(BASE) main_oaep.lo aes_mix_oaep.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

main_oaep_recursive: $(BASE) main_oaep_recursive.lo aes_mix_oaep_recursive.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox: $(BASE) blackbox.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox_oaep: $(BASE) blackbox_oaep.lo aes_mix_oaep.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

blackbox_oaep_recursive: $(BASE) blackbox_oaep_recursive.lo aes_mix_oaep_recursive.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

multithread: $(BASE) aes_mix_multi.lo multithread.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multithread_oaep: $(BASE) aes_mix_multi_oaep.lo multithread_oaep.lo aes_mix_oaep.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multithread_oaep_recursive: $(BASE) aes_mix_multi_oaep.lo aes_mix_multi_oaep_recursive.lo multithread_oaep_recursive.lo aes_mix_oaep.lo aes_mix_oaep_recursive.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multidiff: $(BASE) aes_mix_multi.lo multidiff.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

multidiff_oaep: $(BASE) aes_mix_multi_oaep.lo multidiff_oaep.lo aes_mix_oaep.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) $^ $(LDLIBS) -lpthread -o $@

%.lo: %.c Makefile.properties
	$(LIBTOOL) --mode=compile $(CC) $(CFLAGS) $(INC) -c -o $@ $<

libaesmix.la: aes_mix.lo hctx.lo aes_mix_oaep.lo aes_mix_multi.lo aes_mix_multi_oaep.lo aes_mixslice.lo
	$(LIBTOOL) --mode=link $(CC) $(LDFLAGS) -o $@ $^ -rpath $(LIBDIR) $(LDLIBS)

install: libaesmix.la
	$(LIBTOOL) --mode=install install -c $< $(LIBDIR)/$<
	$(LIBTOOL) --mode=finish $(LIBDIR)

uninstall: libaesmix.la
	$(LIBTOOL) --mode=uninstall $(RM) $(LIBDIR)/$<

$(DUMMYFILE):
	@ mkdir -p $(TESTDIR)/data
	openssl rand -out $@ $(DUMMYSIZE)

printvars:
	@ printf "\nAESNI: %d\nAES: MINI=%d MPM=%d\nOAEP: MINI=%d MPM=%d" \
		$(AESNI) $(MINI_SIZE) $(MINI_PER_MACRO) $(OAEP_MINI_SIZE) $(OAEP_MINI_PER_MACRO)

freshdebug:
	@ $(MAKE) clean
	@ $(MAKE) debug

test: freshdebug printvars
	@ echo -e "\nRUNNING TESTS ..."
	./main 1 > /dev/null || ./main 1
	./blackbox > /dev/null || ./blackbox
	./multidiff > /dev/null || ./multidiff
	@ echo -e "\033[0;32mALL OK\033[0m"

test_oaep: freshdebug printvars
	@ echo -e "\nRUNNING OAEP TESTS ..."
	./main_oaep 1 > /dev/null || ./main_oaep 1
	./blackbox_oaep > /dev/null || ./blackbox_oaep
	./multidiff_oaep > /dev/null || ./multidiff_oaep
	@ echo -e "\033[0;32mALL OK\033[0m"

test_oaep_recursive: freshdebug printvars
	@ echo -e "\nRUNNING OAEP RECURSIVE TESTS ..."
	./main_oaep_recursive 1 > /dev/null || ./main_oaep_recursive 1
	./blackbox_oaep_recursive > /dev/null || ./blackbox_oaep_recursive
	@ echo -e "\033[0;32mALL OK\033[0m"

time: clean printvars
	@ $(MAKE) main
	@ echo -e "\nENCRYPTING 64MiB ..."
	time ./main $$((1024*1024*64 / ($(MINI_SIZE)*$(MINI_PER_MACRO))))

time_oaep: clean printvars
	@ $(MAKE) main_oaep
	@ echo -e "\nENCRYPTING 64MiB with OAEP ..."
	time ./main_oaep $$((1024*1024*64 / ($(OAEP_MINI_SIZE)*$(OAEP_MINI_PER_MACRO))))

time_oaep_recursive: clean printvars
	@ $(MAKE) main_oaep_recursive
	@ echo -e "\nENCRYPTING 64MiB with OAEP RECURSIVE ..."
	time ./main_oaep_recursive $$((1024*1024*64 / ($(OAEP_MINI_SIZE)*$(OAEP_MINI_PER_MACRO))))

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

multitest: clean $(DUMMYFILE) printvars
	@ $(MAKE) multithread
	./multithread $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

multitest_oaep: clean $(DUMMYFILE) printvars
	@ $(MAKE) multithread_oaep
	./multithread_oaep $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

multitest_oaep_recursive: clean $(DUMMYFILE) printvars
	@ $(MAKE) multithread_oaep_recursive
	./multithread_oaep_recursive $(DUMMYFILE) $(DUMMYFILE).out $(THREADS) $(TIMES)

clean:
	@ rm -f $(TARGETS)
	@ rm -rf .libs
	@ find . \( -iname '*.o' -or -iname '*.lo' -or -iname '*.la' -or -iname '*.out' -or -iname '*.so' -or -iname '_*.c' \) -type f -delete

cleanall: clean
	@ rm -f $(DUMMYFILE) $(DUMMYFILE).out
