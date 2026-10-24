// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* Writes the seed corpus of every harness in fuzz/ (`make fuzz-corpus`).
 *
 * Every seed is built from what the repository already holds: the golden frames of
 * tests/golden/frames.txt and the commands the library's own encoders make. Beside the
 * well-formed frames it writes one input per refusal a reader makes (a short frame, a wrong
 * EtherType, a length past the buffer, a status byte where a data byte is due, a sysex with
 * no F7, an F0 13 xx 70 whole or cut short, a value past an encoder's range ...), and the
 * sessions that reach every state. Nothing is fetched and nothing is random, so the corpus
 * regenerates byte for byte on any machine.
 *
 * Each seed is shaped the way its harness reads its input; the harness's header comment is
 * the grammar. Usage: fuzz-gen-corpus <tests/golden/frames.txt> <corpus dir>. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <sys/stat.h>

#include "golden.h"

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>   /* DIGINET_QUEUE_MAX */

/* ---- a growable byte buffer, one seed at a time ---- */
struct seed {
	uint8_t *p;
	size_t n, cap;
};

static struct seed S;

static void put(const void *p, size_t n)
{
	if (S.n + n > S.cap) {
		S.cap = (S.n + n) * 2 + 64;
		S.p = realloc(S.p, S.cap);
		if (!S.p) {
			perror("realloc");
			exit(1);
		}
	}
	if (n)
		memcpy(S.p + S.n, p, n);
	S.n += n;
}

static const char *g_root;

static void mkdir_p(const char *path)
{
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		perror(path);
		exit(1);
	}
}

static void emit(const char *harness, const char *name)
{
	char dir[512], path[640];
	snprintf(dir, sizeof dir, "%s/%s", g_root, harness);
	mkdir_p(dir);
	snprintf(path, sizeof path, "%s/%s", dir, name);
	FILE *f = fopen(path, "wb");
	if (!f || fwrite(S.p, 1, S.n, f) != S.n || fclose(f) != 0) {
		perror(path);
		exit(1);
	}
	S.n = 0;
}

static void set16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

/* ---- fuzz_frame: one frame ---- */

static void frame_seeds(void)
{
	uint8_t f[DIGINET_MAX_FRAME_LEN + 64];
	const struct golden *g;

	for (int i = 0; i < golden_count; i++) {
		put(golden_set[i].bytes, golden_set[i].len);
		emit("frame", golden_set[i].name);
	}

	g = golden("keepalive");
	put(g->bytes, 29);
	emit("frame", "short");
	memcpy(f, g->bytes, g->len);
	set16(f + 12, 0x0800);
	put(f, g->len);
	emit("frame", "wrong-ethertype");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, 15);
	put(f, g->len);
	emit("frame", "numbytes-under-16");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, 47);   /* 14 + 47 = 61 > 60 */
	put(f, g->len);
	emit("frame", "numbytes-past-buffer");
	put(g->bytes, DIGINET_BODY_OFFSET + 1);
	emit("frame", "unpadded");

	g = golden("fader_move");
	memcpy(f, g->bytes, g->len);
	f[DIGINET_ETH_HDR_LEN + 3] ^= 1;
	put(f, g->len);
	emit("frame", "sum-mismatch");

	/* announces cut short, at the edge, and with fields that fill their 9 bytes */
	g = golden("announce_cntrl24");
	memcpy(f, g->bytes, g->len);
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + 32);
	put(f, g->len);
	emit("frame", "announce-body-32");
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + 33);
	put(f, g->len);
	emit("frame", "announce-body-33");
	memcpy(f, g->bytes, g->len);
	memset(f + DIGINET_BODY_OFFSET + 15, 'v', 9);
	memset(f + DIGINET_BODY_OFFSET + 24, 'n', 9);
	put(f, g->len);
	emit("frame", "announce-unterminated");

	/* a data frame holding the system family, which the builder refuses */
	g = golden("meter");
	memcpy(f, g->bytes, g->len);
	f[DIGINET_BODY_OFFSET + 3] = DIGINET_FN_SYSTEM;
	put(f, g->len);
	emit("frame", "system-body");

	/* a body longer than any Ethernet frame carries */
	memset(f, 0, sizeof f);
	memcpy(f, golden("keepalive")->bytes, DIGINET_BODY_OFFSET);
	set16(f + DIGINET_ETH_HDR_LEN, DIGINET_HDR_LEN + DIGINET_MAX_BODY_LEN + 1);
	put(f, DIGINET_BODY_OFFSET + DIGINET_MAX_BODY_LEN + 1);
	emit("frame", "body-past-max");
}

int main(int argc, char **argv)
{
	(void)fails;
	if (argc != 3) {
		fprintf(stderr, "usage: %s <golden frames> <corpus dir>\n", argv[0]);
		return 2;
	}
	golden_load(argv[1]);
	g_root = argv[2];
	mkdir_p(g_root);
	frame_seeds();
	free(S.p);
	return 0;
}
