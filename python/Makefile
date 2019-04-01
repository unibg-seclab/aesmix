.PHONY:	all clean shell install run _aesmix

SHELL   := /bin/bash
VENV    := venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
APP     := example.py


all: $(VENV)

run: $(VENV) $(APP) _aesmix
	$(PYTHON) $(APP)

$(VENV): requirements.txt
	test -d $@ || virtualenv $@
	$(PIP) install -r $<
	$(PYTHON) setup.py install

shell: $(VENV) _aesmix
	$(PIP) install ipython
	- $(VENV)/bin/ipython

install: _aesmix
	python setup.py install

_aesmix: build_aesmix.py
ifeq ("","$(wildcard aesmix/_aesmix*.so)")
	@ echo "building aesmix/_aesmix.so"
	@ python $<
else
	@ if [[ "$<" -nt "$(wildcard aesmix/_aesmix*.so)" ]]; then \
		echo "building aesmix/_aesmix.so" ; \
		python $< ; \
	fi
endif

clean:
	@ rm -rf $(VENV)
	@ rm -rf *.egg-info build dist
	@ rm -f *.out *.private *.public
	@ find . \( -iname '*.o' -or -iname '*.out' -or -iname '*.so' -or -iname '_*.c' \) -type f -delete
