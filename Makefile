.POSIX:
CC      = cc
CFLAGS  = -pedantic -Wall -Wextra -O3 -march=native
LDFLAGS = -flto
LDLIBS  =
PREFIX = /usr/local

sources = src/kr.c src/monocypher.c src/platform.c

kr: $(sources)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(sources) $(LDLIBS)

install: kr kr.1
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 755 kr $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	gzip < kr.1 > $(DESTDIR)$(PREFIX)/share/man/man1/kr.1.gz

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/kr
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/kr.1.gz

clean:
	rm -f kr *.o
