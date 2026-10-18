# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# libdiginet: the DigiNet protocol (frame grammar, codecs, personalities) as libdiginet.a,
# and the wire under it (packet socket, session) as libdiginet-transport.a. See BUILDING.md.

CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2 -g
WARN    := -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE
INC     := -Iinclude
PREFIX  ?= /usr/local
LIBDIR  ?= $(PREFIX)/lib
INCDIR  ?= $(PREFIX)/include
BINDIR  ?= $(PREFIX)/bin
PCDIR   ?= $(LIBDIR)/pkgconfig
DESTDIR ?=

VERSION := $(shell sed -n 's/^\#define DIGINET_VERSION_STRING "\(.*\)"/\1/p' include/diginet/diginet.h)

OBJS := src/diginet_frame.o src/diginet_msg.o src/diginet_codec.o src/diginet_decode.o

TOBJS := transport/src/diginet_io.o transport/src/diginet_session.o

TESTS := tests/test_frame tests/test_codec tests/test_transport tests/test_fdio tests/test_packet

GOLDEN := tests/golden/frames.txt
RUN_TEST := tests/run-test.sh

all: libdiginet.a libdiginet-transport.a

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

test: $(TESTS)
	$(RUN_TEST) tests/test_frame $(GOLDEN)
	$(RUN_TEST) tests/test_codec $(GOLDEN)
	$(RUN_TEST) tests/test_transport
	$(RUN_TEST) tests/test_fdio
	$(RUN_TEST) tests/test_packet
	$(RUN_TEST) tests/public-sources-check.sh
	$(RUN_TEST) tests/test_public_sources.sh

# The Kaitai grammar compiles, and the parser it generates reads the golden frames with
# the values the C suite asserts. Needs kaitai-struct-compiler 0.11 and the Python runtime.
KSY_OUT := build/ksy
ksy-check:
	@mkdir -p $(KSY_OUT)
	kaitai-struct-compiler -t python --outdir $(KSY_OUT) protocol/diginet.ksy
	python3 tests/ksy/check_golden.py $(KSY_OUT) $(GOLDEN)

%.pc: packaging/%.pc.in include/diginet/diginet.h
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@LIBDIR@|$(LIBDIR)|' -e 's|@INCDIR@|$(INCDIR)|' \
	    -e 's|@VERSION@|$(VERSION)|' $< > $@

install: libdiginet.a libdiginet-transport.a libdiginet.pc libdiginet-transport.pc
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR)/diginet/transport $(DESTDIR)$(PCDIR)
	install -m 644 libdiginet.a libdiginet-transport.a $(DESTDIR)$(LIBDIR)/
	install -m 644 include/diginet/*.h $(DESTDIR)$(INCDIR)/diginet/
	install -m 644 include/diginet/transport/*.h $(DESTDIR)$(INCDIR)/diginet/transport/
	install -m 644 libdiginet.pc libdiginet-transport.pc $(DESTDIR)$(PCDIR)/

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TOBJS) $(TOBJS:.o=.d) libdiginet.a libdiginet-transport.a *.pc $(TESTS)
	rm -rf build

.PHONY: all test ksy-check install clean
