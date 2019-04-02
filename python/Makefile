.PHONY:	all clean install run

SHELL   := /bin/bash
VENV    := venv
PYTHON  := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip
APP     := example/example.py


all: build

build: aesmix setup.py
	python setup.py build sdist egg_info

install:
	python setup.py install

run: $(VENV) $(APP)
	cd example; ../$(PYTHON) ../$(APP)

$(VENV):
	test -d $@ || virtualenv $@
	$(PYTHON) setup.py install

shell: $(VENV)
	$(PIP) install ipython
	- $(VENV)/bin/ipython

clean:
	@ rm -rf $(VENV)
	@ rm -rf *.egg-info .eggs build dist
	@ find . \( -iname '*.public' -or -iname '*.private' \) -type f -delete
	@ find . \( -path '*.enc/*' \) -type f -delete
	@ find . \( -name '*.enc' \) -type d -delete
	@ find . \( -path '*/__pycache__/*' \) -type f -delete
	@ find . \( -name '__pycache__' \) -type d -delete
	@ find . \( -iname '*.o' -or -iname '*.out' -or -iname '*.so' -or -iname '_*.c' \) -type f -delete
