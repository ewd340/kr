.POSIX:
CC      = cc
CFLAGS  = -pedantic -Wall -Wextra -O3 -march=native
LDFLAGS = -flto
LDLIBS  =
PREFIX = /usr/local

sources = src/kr.c src/monocypher.c src/platform.c
test_sources = tests/tests.c tests/platform.c tests/utils.c src/monocypher.c

all: kr test.out

kr: $(sources)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(sources) $(LDLIBS)

test.out: $(test_sources)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(test_sources) $(LDLIBS)

test: test.out
	./test.out -n5

install: kr kr.1
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 755 kr $(DESTDIR)$(PREFIX)/bin
	gzip < kr.1 > $(DESTDIR)$(PREFIX)/share/man/man1/kr.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/kr
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/kr.1.gz

clean:
	rm -f kr test.out *.o
