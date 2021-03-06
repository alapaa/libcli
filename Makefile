UNAME = $(shell sh -c 'uname -s 2>/dev/null || echo not')
DESTDIR =
PREFIX = /usr/local

#BUILD_NB_ST = 1 # non-blocking and single-threaded

MAJOR = 1
MINOR = 9
REVISION = 5
LIB = libcli.so

CC = gcc
DEBUG = -g
#OPTIM = -O3
CFLAGS += $(DEBUG) $(OPTIM) -Wall -Wformat-security -Wno-format-zero-length

ifdef BUILD_NB_ST
CFLAGS += -D CLI_NB_ST
endif

LDFLAGS += -shared
LIBPATH += -L.

ifeq ($(UNAME),Darwin)
LDFLAGS += -Wl,-install_name,$(LIB).$(MAJOR).$(MINOR)
else
LDFLAGS += -Wl,-soname,$(LIB).$(MAJOR).$(MINOR)
LIBS = -lcrypt
endif

all: $(LIB) clitest libcli.a
ifdef BUILD_NB_ST
$(LIB): libcli.o elog.o libcli_wrapper.o iputils.o sysutils.o cli_cmd.o
	$(CC) -o $(LIB).$(MAJOR).$(MINOR).$(REVISION) $^ $(LDFLAGS) $(LIBS)
	-rm -f $(LIB) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR).$(REVISION) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR) $(LIB)
else
$(LIB): libcli.o
	$(CC) -o $(LIB).$(MAJOR).$(MINOR).$(REVISION) $^ $(LDFLAGS) $(LIBS)
	-rm -f $(LIB) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR).$(REVISION) $(LIB).$(MAJOR).$(MINOR)
	ln -s $(LIB).$(MAJOR).$(MINOR) $(LIB)
endif
libcli.a: elog.o libcli.o libcli_wrapper.o iputils.o sysutils.o cli_cmd.o
	ar r $@ $^

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ -c $<

libcli.o: libcli.h

ifdef BUILD_NB_ST
clitest:  clitest_nbst.o libcli.a libcli.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. libcli.a -lev -lcrypt
else
clitest: clitest.o $(LIB) libcli.a libcli.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<  -L. -lcli -lcrypt
endif

clitest.exe: clitest.c libcli.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< libcli.o -lws2_32

clean:
	rm -f *.o $(LIB)* clitest *.a core

install: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib
	install -m 0644 libcli.h $(DESTDIR)$(PREFIX)/include
	install -m 0755 $(LIB).$(MAJOR).$(MINOR).$(REVISION) $(DESTDIR)$(PREFIX)/lib
	cd $(DESTDIR)$(PREFIX)/lib && \
	    ln -s $(LIB).$(MAJOR).$(MINOR).$(REVISION) $(LIB).$(MAJOR).$(MINOR) && \
	    ln -s $(LIB).$(MAJOR).$(MINOR) $(LIB)

rpm:
	mkdir libcli-$(MAJOR).$(MINOR).$(REVISION)
	cp -R *.c *.h Makefile Doc README *.spec libcli-$(MAJOR).$(MINOR).$(REVISION)
	tar zcvf libcli-$(MAJOR).$(MINOR).$(REVISION).tar.gz --exclude CVS --exclude *.tar.gz libcli-$(MAJOR).$(MINOR).$(REVISION)
	rm -rf libcli-$(MAJOR).$(MINOR).$(REVISION)
	rpm -ta libcli-$(MAJOR).$(MINOR).$(REVISION).tar.gz --clean

vg:
	valgrind --leak-check=full --track-origins=yes --show-reachable=yes ./clitest