# The major work is building group.so, for which we hijack the Python
# distutils stuff. Originally we used the following CFLAGS and link
# lines:
#CFLAGS=-O2 -I/usr/include/python2.3 -fPIC
#	gcc -shared -o group.so group/group.o

all:	group.so

# We use the Python distutils stuff to build our extension module the
# (relatively) easy way. The arguments are painfully researched. We
# must use the right python to invoke this; it should be the version
# of python that the programs will run under.
PYTHON=python
group.so: group/group.c group/setup-group.py
	$(PYTHON) group/setup-group.py build_ext -t . -i

lint pychecker: group.so
	pychecker *.py

# MODORDER is the order that modules must be tested in in order to stop
# as soon as we have a failure, and not cause cascades.
MODORDER=util ranges netblock conntrack contread lexr rdparse hinfo matchers rules msgs actions cfloader log
tests:
	for i in ${MODORDER}; do echo $$i; python test_$$i.py || exit 1; done
# ... just in case I haven't updated MODORDER yet.
alltests:
	for i in test_*.py; do echo $$i; python $$i; done

sizes:
	wc -l test*.py
	wc -l `/bin/ls -1 *.py | grep -v '^test'`

clean:
	rm -f *.pyc *~ *.so group/*.o
