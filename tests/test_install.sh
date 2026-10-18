#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# `make install` into a scratch root, then build and run a consumer against that root
# through pkg-config alone: every installed header, archive and .pc file has to be there.
set -u
command -v pkg-config >/dev/null 2>&1 || { echo "no pkg-config: nothing tested"; exit 77; }
top=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
make -s -C "$top" install PREFIX=/usr DESTDIR="$tmp/root" >/dev/null || { echo "FAIL: make install"; exit 1; }
cat > "$tmp/consumer.c" <<'C'
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_session.h>
int main(void)
{
	struct diginet_session_config c;
	struct diginet_cmd cmd;
	diginet_session_config_default(&c);
	if (diginet_fader_encode(diginet_personality_of(DIGINET_DESK_CONTROL24), 0, 512, &cmd) || cmd.len != 5)
		return 1;
	return c.keepalive_ms == 10000 && diginet_sum16(cmd.bytes, cmd.len) == 0x110 ? 0 : 1;
}
C
PKG_CONFIG_SYSROOT_DIR="$tmp/root" PKG_CONFIG_LIBDIR="$tmp/root/usr/lib/pkgconfig" \
	sh -c "${CC:-cc} '$tmp/consumer.c' \$(pkg-config --cflags --libs libdiginet-transport) -o '$tmp/consumer'" ||
	{ echo "FAIL: a consumer does not build against the installed tree"; exit 1; }
"$tmp/consumer" || { echo "FAIL: the consumer gave the wrong answer"; exit 1; }
echo "test_install: ok"
