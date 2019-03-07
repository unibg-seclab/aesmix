.PHONY:	all cffi clean

all: cffi

libaesmix.so: ..
	$(MAKE) -C .. $@
	cp ../libaesmix.so .

cffi: _aesmix_cffi.so

_aesmix_cffi%: libaesmix.so build_aesmix_cffi.py
	python build_aesmix_cffi.py

clean:
	@ find . \( -iname '*.o' -or -iname '*.out' -or -iname '*.so' -or -iname '_*.c' \) -type f -delete
