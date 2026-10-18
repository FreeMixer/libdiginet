# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# libdiginet: the DigiNet protocol (frame grammar, codecs, personalities) as libdiginet.a,
# and the wire under it (packet socket, session) as libdiginet-transport.a. See BUILDING.md.
#
# `make shared` and `make install-shared` are what the packages build: the same objects as
# shared libraries, and diginet-probe linked against them.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
LDFLAGS ?=
# -fPIC always: the same objects go into the archives and the shared libraries.
WARN    := -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE -fPIC
INC     := -Iinclude
PREFIX  ?= /usr/local
LIBDIR  ?= $(PREFIX)/lib
INCDIR  ?= $(PREFIX)/include
BINDIR  ?= $(PREFIX)/bin
PCDIR   ?= $(LIBDIR)/pkgconfig
DATADIR ?= $(PREFIX)/share
MANDIR  ?= $(DATADIR)/man
DESTDIR ?=

# The version is the VERSION file; the sonames' majors are in diginet.h. The header's version
# string and the packaging copies are held to them by tests/conformance-packaging.sh.
VERSION := $(shell cat VERSION)
ABI     := $(shell sed -n 's/^\#define DIGINET_ABI  *\([0-9]*\)$$/\1/p' include/diginet/diginet.h)
TABI    := $(shell sed -n 's/^\#define DIGINET_TRANSPORT_ABI  *\([0-9]*\)$$/\1/p' include/diginet/diginet.h)

OBJS := src/diginet_frame.o src/diginet_msg.o src/diginet_codec.o src/diginet_decode.o

TOBJS := transport/src/diginet_io.o transport/src/diginet_session.o

TESTS := tests/test_frame tests/test_codec tests/test_transport tests/test_fdio tests/test_packet

GOLDEN := tests/golden/frames.txt
RUN_TEST := tests/run-test.sh

PROBE := tools/diginet-probe

all: libdiginet.a libdiginet-transport.a $(PROBE)

# -MMD -MP: a header edit rebuilds every object that includes it.
src/%.o: src/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

transport/src/%.o: transport/src/%.c
	$(CC) $(CFLAGS) $(WARN) -MMD -MP $(INC) -c $< -o $@

-include $(OBJS:.o=.d) $(TOBJS:.o=.d)

libdiginet.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

libdiginet-transport.a: $(TOBJS)
	$(AR) rcs $@ $(TOBJS)

tests/test_frame: tests/test_frame.c tests/golden.h libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet.a -o $@

tests/test_codec: tests/test_codec.c tests/golden.h libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet.a -o $@

tests/test_transport: tests/test_transport.c tests/desk_emu.c tests/desk_emu.h tests/golden.h libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< tests/desk_emu.c libdiginet-transport.a libdiginet.a -o $@

tests/test_fdio tests/test_packet: tests/%: tests/%.c tests/desk_emu.c tests/desk_emu.h tests/emu_pump.h tests/golden.h libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< tests/desk_emu.c libdiginet-transport.a libdiginet.a -o $@

$(PROBE): tools/diginet-probe.c libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< libdiginet-transport.a libdiginet.a $(LDFLAGS) -o $@

# ---- shared libraries (the packages) -------------------------------------------------------
# --no-undefined: a symbol nothing defines fails here, not at a consumer's link.
SO  := libdiginet.so.$(VERSION)
TSO := libdiginet-transport.so.$(VERSION)

$(SO): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libdiginet.so.$(ABI) -Wl,--no-undefined -o $@ $(OBJS)
	ln -sf $@ libdiginet.so.$(ABI)
	ln -sf libdiginet.so.$(ABI) libdiginet.so

$(TSO): $(TOBJS) $(SO)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,libdiginet-transport.so.$(TABI) -Wl,--no-undefined \
	    -o $@ $(TOBJS) -L. -ldiginet
	ln -sf $@ libdiginet-transport.so.$(TABI)
	ln -sf libdiginet-transport.so.$(TABI) libdiginet-transport.so

build/diginet-probe: tools/diginet-probe.c $(TSO) $(SO)
	@mkdir -p build
	$(CC) $(CFLAGS) $(WARN) $(INC) $< $(LDFLAGS) -L. -ldiginet-transport -ldiginet -o $@

shared: $(SO) $(TSO) build/diginet-probe libdiginet.pc libdiginet-transport.pc

tests/test_probe: tests/test_probe.c tests/desk_emu.c tests/desk_emu.h tests/emu_pump.h tests/golden.h libdiginet-transport.a libdiginet.a
	$(CC) $(CFLAGS) $(WARN) $(INC) $< tests/desk_emu.c libdiginet-transport.a libdiginet.a -o $@

test: $(TESTS) tests/test_probe $(PROBE)
	$(RUN_TEST) tests/test_frame $(GOLDEN)
	$(RUN_TEST) tests/test_codec $(GOLDEN)
	$(RUN_TEST) tests/test_transport
	$(RUN_TEST) tests/test_fdio
	$(RUN_TEST) tests/test_packet
	$(RUN_TEST) tests/test_probe $(PROBE)
	$(RUN_TEST) tests/test_install.sh
	$(RUN_TEST) tests/test_workflows.sh
	$(RUN_TEST) tests/public-sources-check.sh
	$(RUN_TEST) tests/test_public_sources.sh

# The Kaitai grammar compiles, and the parser it generates reads the golden frames with
# the values the C suite asserts. Needs kaitai-struct-compiler 0.11 and the Python runtime.
KSY_OUT := build/ksy
ksy-check:
	@mkdir -p $(KSY_OUT)
	kaitai-struct-compiler -t python --outdir $(KSY_OUT) protocol/diginet.ksy
	python3 tests/ksy/check_golden.py $(KSY_OUT) $(GOLDEN)

%.pc: packaging/%.pc.in VERSION
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@LIBDIR@|$(LIBDIR)|' -e 's|@INCDIR@|$(INCDIR)|' \
	    -e 's|@VERSION@|$(VERSION)|' $< > $@

# What both installs carry: headers, pkg-config files, the grammar, the manual page.
install-common: libdiginet.pc libdiginet-transport.pc
	install -d $(DESTDIR)$(INCDIR)/diginet/transport $(DESTDIR)$(PCDIR) $(DESTDIR)$(BINDIR) \
	    $(DESTDIR)$(DATADIR)/diginet $(DESTDIR)$(MANDIR)/man1
	install -m 644 include/diginet/*.h $(DESTDIR)$(INCDIR)/diginet/
	install -m 644 include/diginet/transport/*.h $(DESTDIR)$(INCDIR)/diginet/transport/
	install -m 644 libdiginet.pc libdiginet-transport.pc $(DESTDIR)$(PCDIR)/
	install -m 644 protocol/diginet.ksy $(DESTDIR)$(DATADIR)/diginet/
	install -m 644 docs/diginet-probe.1 $(DESTDIR)$(MANDIR)/man1/

install: libdiginet.a libdiginet-transport.a $(PROBE) install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 644 libdiginet.a libdiginet-transport.a $(DESTDIR)$(LIBDIR)/
	install -m 755 $(PROBE) $(DESTDIR)$(BINDIR)/

# The packages: shared libraries with their soname links, the probe linked against them.
install-shared: shared install-common
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 $(SO) $(TSO) $(DESTDIR)$(LIBDIR)/
	ln -sf $(SO) $(DESTDIR)$(LIBDIR)/libdiginet.so.$(ABI)
	ln -sf libdiginet.so.$(ABI) $(DESTDIR)$(LIBDIR)/libdiginet.so
	ln -sf $(TSO) $(DESTDIR)$(LIBDIR)/libdiginet-transport.so.$(TABI)
	ln -sf libdiginet-transport.so.$(TABI) $(DESTDIR)$(LIBDIR)/libdiginet-transport.so
	install -m 755 build/diginet-probe $(DESTDIR)$(BINDIR)/

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TOBJS) $(TOBJS:.o=.d) libdiginet.a libdiginet-transport.a *.pc $(TESTS) tests/test_probe $(PROBE)
	rm -f libdiginet.so* libdiginet-transport.so*
	rm -rf build

.PHONY: all test ksy-check shared install install-common install-shared clean
