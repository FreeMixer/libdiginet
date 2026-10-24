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

static void put8(unsigned v)
{
	uint8_t b = (uint8_t)v;
	put(&b, 1);
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

/* ---- fuzz_decode: [sel] then a body or a frame ---- */

static void body_seed(unsigned sel, const uint8_t *b, size_t n, const char *name)
{
	put8(sel);
	put(b, n);
	emit("decode", name);
}

#define BODY(name, ...) do { \
	static const uint8_t b_[] = { __VA_ARGS__ }; \
	body_seed(1, b_, sizeof b_, name); \
} while (0)

static void decode_seeds(void)
{
	static const char *const DATA[] = {
		"keepalive", "fader_move", "button_mute", "scribble_write", "meter", "clock_init",
		"running_status", "desk_retry", "counter_write",
	};
	char name[96];
	struct diginet_cmd c;
	const struct diginet_personality *c24 = diginet_personality_of(DIGINET_DESK_CONTROL24);
	const struct diginet_personality *pc = diginet_personality_of(DIGINET_DESK_PROCONTROL);

	for (size_t i = 0; i < sizeof DATA / sizeof DATA[0]; i++) {
		const struct golden *g = golden(DATA[i]);
		struct diginet_frame f;
		if (diginet_frame_parse(g->bytes, g->len, &f) != DIGINET_OK) {
			fprintf(stderr, "golden frame %s does not parse\n", DATA[i]);
			exit(1);
		}
		body_seed(1, f.body, f.body_len, DATA[i]);
		snprintf(name, sizeof name, "%s-procontrol", DATA[i]);
		body_seed(2, f.body, f.body_len, name);
		snprintf(name, sizeof name, "%s-frame", DATA[i]);
		body_seed(0x80, g->bytes, g->len, name);
	}
	body_seed(0x80, golden("keepalive")->bytes, 20, "frame-refused");

	/* the cursor's refusals */
	BODY("status-for-data", 0x90, 0x90, 0x40);
	BODY("status-for-second-data", 0x90, 0x08, 0xc0, 0x05);
	BODY("no-status", 0x07, 0x41, 0x90, 0x08, 0x40);
	BODY("status-f1", 0xf1, 0x90, 0x08, 0x40, 0xff);
	BODY("channel-cut-short", 0x90, 0x08);
	BODY("sysex-no-f7", 0xf0, 0x13, 0x01, 0x40, 0x00);
	BODY("one-data-byte", 0xc0, 0x05, 0xd0, 0x7f, 0x10);
	BODY("aftertouch", 0xa0, 0x10, 0x20);

	/* the decoder's kinds */
	BODY("fader-msb-only", 0xb0, 0x03, 0x40, 0x90, 0x08, 0x40);
	BODY("fader-lsb-explicit", 0xb0, 0x03, 0x40, 0xb0, 0x23, 0x70);
	BODY("fader-lsb-other-strip", 0xb0, 0x03, 0x40, 0x24, 0x70);
	BODY("fader-last", 0xb0, 0x1f, 0x7f);
	BODY("jog-vpot", 0xb0, 0x5c, 0x41, 0xb0, 0x45, 0x3f, 0x58, 0x10);
	BODY("cc-other", 0xb0, 0x60, 0x10);
	BODY("zone-key", 0x90, 0x05, 0x58, 0x90, 0x05, 0x1d);
	BODY("touch", 0x90, 0x09, 0x45);
	BODY("sysex-short", 0xf0, 0x13, 0x01, 0xf7);
	BODY("sysex-other-maker", 0xf0, 0x12, 0x01, 0x10, 0xf7);
	BODY("sysex-other-fn", 0xf0, 0x13, 0x01, 0x55, 0x00, 0xf7);
	BODY("sysex-wrong-sizes", 0xf0, 0x13, 0x01, 0x00, 0x01, 0xf7, 0xf0, 0x13, 0x01, 0x10, 0x00, 0xf7,
	     0xf0, 0x13, 0x01, 0x20, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0xf7, 0xf0, 0x13, 0x01, 0x30,
	     0x19, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	     0x48, 0x49, 0xf7);

	/* the system family: whole, cut short, inside another sysex */
	BODY("system-whole", 0xf0, 0x13, 0x01, 0x70, 0x00, 0xf7);
	BODY("system-cut-short", 0xf0, 0x13, 0x01, 0x70);
	BODY("system-in-sysex", 0xf0, 0x01, 0xf0, 0x13, 0x01, 0x70, 0xf7);
	BODY("system-after-message", 0x90, 0x08, 0x40, 0xf0, 0x13, 0x00, 0x70, 0x01, 0x02);

	/* what the encoders make, read by both personalities */
	if (diginet_ring_encode(c24, 5, diginet_ring_fill(9) | 1, &c) == DIGINET_OK)
		body_seed(1, c.bytes, c.len, "ring");
	if (diginet_strip_leds_encode(c24, 2, DIGINET_AUTO_WRITE | DIGINET_AUTO_READ, &c) == DIGINET_OK)
		body_seed(1, c.bytes, c.len, "strip-leds");
	if (diginet_meter_encode(pc, 3, 1, 14, &c) == DIGINET_OK)
		body_seed(2, c.bytes, c.len, "meter-right");
	if (diginet_scribble_encode(pc, 0x10, (const uint8_t *)"ProCtrl8", &c) == DIGINET_OK)
		body_seed(2, c.bytes, c.len, "scribble-procontrol");
	body_seed(0, golden("running_status")->bytes + DIGINET_BODY_OFFSET, 14, "no-personality");
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
	decode_seeds();
	free(S.p);
	return 0;
}
