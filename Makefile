# Authors: 
#   Trevor Perrin
#   Hubert Kario - test and test-dev
#
PYTHON2 := $(shell which python2 2>/dev/null)
PYTHON3 := $(shell which python3 2>/dev/null)
COVERAGE := $(shell which coverage 2>/dev/null)
COVERAGE2 := $(shell which coverage2 2>/dev/null)
COVERAGE3 := $(shell which coverage3 2>/dev/null)

.PHONY : default
default:
	@echo To install tlslite run \"./setup.py install\" or \"make install\"

.PHONY: install
install:
	./setup.py install

.PHONY : clean
clean:
	rm -rf tlslite/__pycache__
	rm -rf tlslite/integration/__pycache__
	rm -rf tlslite/utils/__pycache__
	rm -rf tlslite/*.pyc
	rm -rf tlslite/utils/*.pyc
	rm -rf tlslite/integration/*.pyc
	rm -rf unit_tests/*.pyc
	rm -rf unit_tests/__pycache__
	rm -rf dist
	rm -rf docs
	rm -rf build
	rm -f MANIFEST

docs:
	epydoc --html -v --introspect-only -o docs --graph all tlslite

dist: docs
	./setup.py sdist

test:
	cd tests/ && python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && python ./tlstest.py client localhost:4433 .

test-local:
	cd tests/ && PYTHONPATH=.. python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python ./tlstest.py client localhost:4433 .

test-dev:
ifdef PYTHON2
	@echo "Running test suite with Python 2"
	python2 -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python2 ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python2 ./tlstest.py client localhost:4433 .
endif
ifdef PYTHON3
	@echo "Running test suite with Python 3"
	python3 -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python3 ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python3 ./tlstest.py client localhost:4433 .
endif
ifndef PYTHON2
ifndef PYTHON3
	@echo "Running test suite with default Python"
	python -m unittest discover -v
	cd tests/ && PYTHONPATH=.. python ./tlstest.py server localhost:4433 . & sleep 1
	cd tests/ && PYTHONPATH=.. python ./tlstest.py client localhost:4433 .
endif
endif
	epydoc --check --fail-on-error -v tlslite
	pylint --msg-template="{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}" tlslite > pylint_report.txt || :
	diff-quality --violations=pylint --fail-under=90 pylint_report.txt
ifdef COVERAGE2
	coverage2 run --branch --source tlslite -m unittest discover
	coverage2 report -m
	coverage2 xml
	diff-cover --fail-under=90 coverage.xml
endif
ifdef COVERAGE3
	coverage3 run --branch --source tlslite -m unittest discover
	coverage3 report -m
	coverage3 xml
	diff-cover --fail-under=90 coverage.xml
endif
ifndef COVERAGE2
ifndef COVERAGE3
ifdef COVERAGE
	coverage run --branch --source tlslite -m unittest discover
	coverage report -m
	coverage xml
	diff-cover --fail-under=90 coverage.xml
endif
endif
endif

tests/TACK_Key1.pem:
	tack genkey -x -p test -o tests/TACK_Key1.pem

tests/TACK_Key2.pem:
	tack genkey -x -p test -o tests/TACK_Key2.pem

# the following needs to be used only when the server certificate gets recreated
gen-tacks: tests/TACK_Key1.pem tests/TACK_Key2.pem
	tack sign -x -k tests/TACK_Key1.pem -p test -c tests/serverX509Cert.pem -o tests/TACK1.pem
	tack sign -x -k tests/TACK_Key2.pem -p test -c tests/serverX509Cert.pem -o tests/TACK2.pem
