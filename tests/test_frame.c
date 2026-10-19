// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The frame grammar against the golden frames (tests/golden/frames.txt).
 *
 * 1. VALUES. Every golden frame decodes to the header, body and messages docs/protocol.md
 *    gives: the 50-byte announce with "CNTRL|24" and "1.37", the 16-byte ack and the
 *    17-byte keepalive, the fader at 512, the MUTE press, the scribble "OMX1", the meter,
 *    and the clock frame whose body sum is the 0x0244 ReaControl24 sends.
 * 2. ONE BYTE. Changing any one byte of a golden frame before the padding makes it decode
 *    to something else, or not at all. Changing a padding byte changes nothing.
 * 3. BUILD. Building each frame back from its decoded values gives the golden bytes.
 * 4. CURSOR. Running status, a stale byte past the body, and the malformed streams: a data
 *    byte with no status, a cut-short message, an unterminated system exclusive.
 */
#include "golden.h"

#include <diginet/diginet.h>

struct exp_msg {
	uint8_t status, running, d1, d2;
	const char *sysex; /* hex of the bytes between F0 and F7, or NULL */
};

struct expect {
	const char *name;
	const char *dst, *src;     /* hex */
	uint16_t numbytes, sum;
	uint32_t send_counter, ack_counter;
	uint16_t retry;
	uint8_t cmd, ncmds;
	const char *body;          /* hex */
	int sum_matches;
	struct exp_msg msgs[8];
	int nmsgs;
};

#define DESK "00a07e240001"
#define HOST "020000000001"
#define BCST "ffffffffffff"
/* An announce body: 15 unknown bytes, a 9-byte version, a 9-byte name, one more byte. */
#define ZERO15 "000000000000000000000000000000"
#define V137   "312e33370000000000"
#define V210   "322e31300000000000"
#define C24    "434e54524c7c323400"
#define MAIN   "4d41494e554e495400"

static const struct expect expects[] = {
	{ "announce_cntrl24", BCST, DESK, 50, 0x032e, 0, 0, 0, 0xe0, 0,
	  ZERO15 V137 C24 "00", 1, {{0}}, 0 },
	{ "announce_session_cntrl24", BCST, DESK, 50, 0x0331, 0, 0, 0, 0xe1, 0,
	  HOST "000000000000000000" V137 C24 "00", 1, {{0}}, 0 },
	{ "announce_mainunit", BCST, "00a07e080001", 50, 0x0326, 0, 0, 0, 0xe0, 0,
	  ZERO15 V210 MAIN "00", 1, {{0}}, 0 },
	{ "wake", DESK, HOST, 16, 0, 0, 0, 0, 0xe2, 0, "", 1, {{0}}, 0 },
	{ "disconnect", DESK, HOST, 16, 0, 0, 0, 0, 0xe3, 0, "", 1, {{0}}, 0 },
	{ "keepalive", DESK, HOST, 17, 0, 0x2a, 0, 0, 0x00, 1, "00", 1,
	  {{0}}, 0 },
	{ "ack", DESK, HOST, 16, 0, 0x2a, 0x105, 0, 0xa0, 0, "", 1, {{0}}, 0 },
	{ "fader_move", HOST, DESK, 21, 0x0110, 0x105, 0, 0, 0x00, 1, "b000402000", 1,
	  { { 0xb0, 0, 0x00, 0x40, NULL }, { 0xb0, 1, 0x20, 0x00, NULL } }, 2 },
	{ "button_mute", HOST, DESK, 19, 0x00d8, 0x106, 0, 0, 0x00, 1, "900840", 1,
	  { { 0x90, 0, 0x08, 0x40, NULL } }, 1 },
	{ "scribble_write", DESK, HOST, 27, 0x0360, 0x2b, 0, 0, 0x00, 1, "f013014000004f4d5831f7", 1,
	  { { 0xf0, 0, 0, 0, "1301400000" "4f4d5831" } }, 1 },
	{ "meter", DESK, HOST, 24, 0x0291, 0x2c, 0, 0, 0x00, 1, "f0130110 00077ff7", 1,
	  { { 0xf0, 0, 0, 0, "130110" "00077f" } }, 1 },
	{ "clock_init", DESK, HOST, 30, 0x0244, 1, 0, 0, 0x00, 1, "f0130130190000000000000000f7", 1,
	  { { 0xf0, 0, 0, 0, "1301301900000000000000" "00" } }, 1 },
	{ "running_status", HOST, DESK, 30, 0x03fd, 0x107, 0, 0, 0x00, 5,
	  "9008400741b0017f217040415c3f", 1,
	  { { 0x90, 0, 0x08, 0x40, NULL }, { 0x90, 1, 0x07, 0x41, NULL },
	    { 0xb0, 0, 0x01, 0x7f, NULL }, { 0xb0, 1, 0x21, 0x70, NULL },
	    { 0xb0, 1, 0x40, 0x41, NULL }, { 0xb0, 1, 0x5c, 0x3f, NULL } }, 6 },
	{ "desk_retry", HOST, DESK, 19, 0x0098, 0x108, 0, 1, 0x00, 1, "900800", 1,
	  { { 0x90, 0, 0x08, 0x00, NULL } }, 1 },
	{ "counter_write", DESK, HOST, 31, 0x037c, 0x2d, 0, 0, 0x00, 1, "f013013019405b6d300000000000f7", 1,
	  { { 0xf0, 0, 0, 0, "1301301940" "5b6d300000000000" } }, 1 },
};
#define NEXPECTS (sizeof expects / sizeof expects[0])

/* hex with optional spaces -> bytes; returns the count. */
static size_t unhex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = 0;
	while (*s && n < cap) {
		if (*s == ' ') { s++; continue; }
		out[n++] = (uint8_t)(hexval(s[0]) << 4 | hexval(s[1]));
		s += 2;
	}
	return n;
}

/* 1 when buf decodes to exactly what e says. Quiet: the callers decide what is a failure. */
static int decodes_to(const uint8_t *buf, size_t len, const struct expect *e)
{
	struct diginet_frame f;
	uint8_t want[1514];
	if (diginet_frame_parse(buf, len, &f) != DIGINET_OK)
		return 0;
	if (memcmp(f.dst, want, unhex(e->dst, want, 6)) || memcmp(f.src, want, unhex(e->src, want, 6)))
		return 0;
	if (f.ethertype != DIGINET_ETHERTYPE || f.h.numbytes != e->numbytes || f.h.sum != e->sum ||
	    f.h.send_counter != e->send_counter || f.h.ack_counter != e->ack_counter ||
	    f.h.retry != e->retry || f.h.cmd != e->cmd || f.h.num_commands != e->ncmds)
		return 0;
	size_t bl = unhex(e->body, want, sizeof want);
	if (f.body_len != bl || memcmp(f.body, want, bl) || f.sum_matches != e->sum_matches)
		return 0;
	if (f.h.cmd == DIGINET_CMD_DATA && e->nmsgs == 0)
		return diginet_frame_is_keepalive(&f);
	if (f.h.cmd == DIGINET_CMD_DATA) {
		struct diginet_cursor c;
		struct diginet_msg m;
		int i = 0, r;
		diginet_cursor_init(&c, f.body, f.body_len);
		while ((r = diginet_msg_next(&c, &m)) == 1) {
			if (i >= e->nmsgs)
				return 0;
			const struct exp_msg *x = &e->msgs[i++];
			if (m.status != x->status || m.running != x->running)
				return 0;
			if (x->sysex) {
				uint8_t sx[256];
				size_t sn = unhex(x->sysex, sx, sizeof sx);
				if (m.sysex_len != sn || memcmp(m.sysex, sx, sn))
					return 0;
			} else if (m.d1 != x->d1 || m.d2 != x->d2) {
				return 0;
			}
		}
		if (r != 0 || i != e->nmsgs)
			return 0;
	}
	return 1;
}

static void test_values(void)
{
	for (size_t k = 0; k < NEXPECTS; k++) {
		const struct golden *g = golden(expects[k].name);
		int ok = decodes_to(g->bytes, g->len, &expects[k]);
		if (!ok)
			fprintf(stderr, "golden frame %s does not decode to its documented values\n", g->name);
		CHK(ok);
	}
	if (fails)
		return;

	/* The facts docs/protocol.md states, asserted once more by name. */
	struct diginet_frame f;
	struct diginet_announce a;
	const struct golden *g = golden("announce_cntrl24");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(f.h.numbytes == 50 && f.body_len == DIGINET_ANNOUNCE_BODY_LEN);
	CHK(diginet_mac_is_digidesign(f.src));
	CHK(diginet_announce_parse(&f, &a) == DIGINET_OK);
	CHK(!strcmp(a.name, "CNTRL|24"));
	CHK(!strcmp(a.version, "1.37"));
	CHK(a.unknown_len == 15);

	g = golden("announce_mainunit");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(diginet_announce_parse(&f, &a) == DIGINET_OK);
	CHK(!strcmp(a.name, "MAINUNIT"));

	g = golden("ack");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(diginet_announce_parse(&f, &a) == DIGINET_E_NOT_ANNOUNCE);
	CHK(f.h.numbytes == 16 && f.body_len == 0 && f.pad_len == 30);
	CHK(!diginet_mac_is_digidesign(f.src));

	g = golden("keepalive");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(f.h.numbytes == 17 && f.body_len == 1 && f.body[0] == 0 && f.h.num_commands == 1);
	CHK(diginet_frame_is_keepalive(&f));
	g = golden("button_mute");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK && !diginet_frame_is_keepalive(&f));

	/* The one non-zero sum ReaControl24 ever sends is the byte sum of the clock body. */
	g = golden("clock_init");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(f.h.sum == 0x0244 && f.body_sum == 0x0244 && f.sum_matches);

	/* Fader 1 at 512 is B0 00 40 20 00: MSB 0x40 = 512 >> 3, LSB 0x00 = (512 & 7) << 4. */
	g = golden("fader_move");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(f.body_len == 5 && ((f.body[2] << 3) | (f.body[4] >> 4)) == 512);

	/* Stale bytes after the body are padding, never commands. */
	g = golden("running_status");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
	CHK(f.body_len == 14 && f.pad_len == 16 && g->bytes[DIGINET_BODY_OFFSET + 14] == 0x5a);
}

static void test_one_byte(void)
{
	for (size_t k = 0; k < NEXPECTS; k++) {
		const struct golden *g = golden(expects[k].name);
		uint8_t buf[1514];
		size_t logical = DIGINET_BODY_OFFSET + expects[k].numbytes - DIGINET_HDR_LEN;
		for (size_t i = 0; i < g->len; i++) {
			for (int bit = 0; bit < 8; bit += 7) {
				memcpy(buf, g->bytes, g->len);
				buf[i] ^= (uint8_t)(1u << bit);
				int same = decodes_to(buf, g->len, &expects[k]);
				if (i < logical && same)
					fprintf(stderr, "%s: byte %zu bit %d changed and nothing noticed\n",
						g->name, i, bit);
				if (i >= logical && !same)
					fprintf(stderr, "%s: padding byte %zu changed the decode\n", g->name, i);
				CHK(i < logical ? !same : same);
			}
		}
	}
}

static void test_build(void)
{
	for (size_t k = 0; k < NEXPECTS; k++) {
		const struct golden *g = golden(expects[k].name);
		struct diginet_frame f;
		uint8_t out[1514];
		CHK(diginet_frame_parse(g->bytes, g->len, &f) == DIGINET_OK);
		enum diginet_sum_mode mode = f.h.sum == f.body_sum ? DIGINET_SUM_BODY : DIGINET_SUM_ZERO;
		int n = diginet_frame_build(out, sizeof out, f.dst, f.src, &f.h, f.body, f.body_len, mode);
		CHK(n == (int)g->len);
		size_t logical = DIGINET_BODY_OFFSET + f.body_len;
		CHK(n > 0 && !memcmp(out, g->bytes, logical));
		/* Built padding is zero, whatever stale bytes a desk leaves there. */
		for (int i = (int)logical; i < n; i++)
			CHK(out[i] == 0);
	}

	/* The keepalive with the body sum would carry 0, the same bytes as SUM_ZERO. */
	uint8_t a[64], b[64], ka = 0x00, body[3] = { 0x90, 0x08, 0x40 };
	struct diginet_header h = { .send_counter = 7, .cmd = DIGINET_CMD_DATA, .num_commands = 1 };
	uint8_t d[6] = { 0x00, 0xa0, 0x7e, 1, 2, 3 }, s[6] = { 2, 0, 0, 0, 0, 1 };
	CHK(diginet_frame_build(a, sizeof a, d, s, &h, &ka, 1, DIGINET_SUM_BODY) == 60);
	CHK(a[16] == 0 && a[17] == 0 && a[15] == 17);
	CHK(diginet_frame_build(a, sizeof a, d, s, &h, body, 3, DIGINET_SUM_BODY) == 60);
	CHK(diginet_frame_build(b, sizeof b, d, s, &h, body, 3, DIGINET_SUM_ZERO) == 60);
	CHK(a[16] == 0x00 && a[17] == 0xd8 && b[16] == 0 && b[17] == 0);
	CHK(!memcmp(a, b, 16) && !memcmp(a + 18, b + 18, 42));

	/* Refusals. */
	CHK(diginet_frame_build(a, 59, d, s, &h, body, 3, DIGINET_SUM_BODY) == DIGINET_E_SPACE);
	CHK(diginet_frame_build(a, sizeof a, d, s, &h, NULL, 3, DIGINET_SUM_BODY) == DIGINET_E_ARG);
	CHK(diginet_frame_build(a, sizeof a, d, s, &h, body, 3, (enum diginet_sum_mode)7) == DIGINET_E_ARG);
	CHK(diginet_frame_build(a, 4096, d, s, &h, body, DIGINET_MAX_BODY_LEN + 1, DIGINET_SUM_BODY) ==
	    DIGINET_E_LENGTH);
}

static void test_parse_refusals(void)
{
	struct diginet_frame f;
	const struct golden *g = golden("button_mute");
	uint8_t buf[1514];

	CHK(diginet_frame_parse(g->bytes, 29, &f) == DIGINET_E_SHORT);
	memcpy(buf, g->bytes, g->len);
	buf[13] = 0x60;
	CHK(diginet_frame_parse(buf, g->len, &f) == DIGINET_E_ETHERTYPE);
	memcpy(buf, g->bytes, g->len);
	buf[14] = 0; buf[15] = 15;                       /* numbytes 15 < 16 */
	CHK(diginet_frame_parse(buf, g->len, &f) == DIGINET_E_LENGTH);
	buf[15] = 47;                                    /* 14 + 47 = 61 > 60 bytes held */
	CHK(diginet_frame_parse(buf, g->len, &f) == DIGINET_E_LENGTH);
	buf[15] = 46;                                    /* exactly the whole buffer */
	CHK(diginet_frame_parse(buf, g->len, &f) == DIGINET_OK && f.body_len == 30 && f.pad_len == 0);
	CHK(diginet_frame_parse(NULL, 60, &f) == DIGINET_E_ARG);

	/* A sum that does not match is reported, not refused. */
	memcpy(buf, g->bytes, g->len);
	buf[17] = 0;
	CHK(diginet_frame_parse(buf, g->len, &f) == DIGINET_OK && !f.sum_matches && f.body_sum == 0xd8);
}

static int next(struct diginet_cursor *c, struct diginet_msg *m) { return diginet_msg_next(c, m); }

static void test_cursor(void)
{
	struct diginet_cursor c;
	struct diginet_msg m;

	/* A data byte before any status. */
	const uint8_t a[] = { 0x08, 0x40, 0x90, 0x08, 0x40 };
	diginet_cursor_init(&c, a, sizeof a);
	CHK(next(&c, &m) == DIGINET_E_NO_STATUS && c.pos == 1);
	CHK(next(&c, &m) == DIGINET_E_NO_STATUS && c.pos == 2);
	CHK(next(&c, &m) == 1 && m.status == 0x90 && m.d1 == 0x08 && m.d2 == 0x40 && m.offset == 2);
	CHK(next(&c, &m) == 0);

	/* A message cut short by the end of the body, and by a status byte. */
	const uint8_t b[] = { 0xb0, 0x00 };
	diginet_cursor_init(&c, b, sizeof b);
	CHK(next(&c, &m) == DIGINET_E_TRUNCATED && c.pos == 2);
	CHK(next(&c, &m) == 0);
	const uint8_t b2[] = { 0xb0, 0x00, 0x90, 0x08, 0x40 };
	diginet_cursor_init(&c, b2, sizeof b2);
	CHK(next(&c, &m) == DIGINET_E_TRUNCATED && c.pos == 2);
	CHK(next(&c, &m) == 1 && m.status == 0x90 && m.running == 0 && m.d1 == 8);

	/* An unterminated system exclusive, and running status cancelled by one. */
	const uint8_t s[] = { 0xf0, 0x13, 0x01, 0x40 };
	diginet_cursor_init(&c, s, sizeof s);
	CHK(next(&c, &m) == DIGINET_E_TRUNCATED && c.pos == 4);
	const uint8_t s2[] = { 0x90, 0x08, 0x40, 0xf0, 0x13, 0xf7, 0x07, 0x41 };
	diginet_cursor_init(&c, s2, sizeof s2);
	CHK(next(&c, &m) == 1 && m.status == 0x90);
	CHK(next(&c, &m) == 1 && m.status == 0xf0 && m.sysex_len == 1 && m.sysex[0] == 0x13 && m.len == 3);
	CHK(next(&c, &m) == DIGINET_E_NO_STATUS);

	/* A stray F7 and the one-data-byte statuses. */
	const uint8_t t[] = { 0xf7, 0xc0, 0x05, 0x06, 0xd1, 0x7f };
	diginet_cursor_init(&c, t, sizeof t);
	CHK(next(&c, &m) == DIGINET_E_STATUS && c.pos == 1);
	CHK(next(&c, &m) == 1 && m.status == 0xc0 && m.d1 == 5 && m.d2 == 0 && m.len == 2);
	CHK(next(&c, &m) == 1 && m.status == 0xc0 && m.running && m.d1 == 6 && m.len == 1);
	CHK(next(&c, &m) == 1 && m.status == 0xd1 && m.d1 == 0x7f);
	CHK(next(&c, &m) == 0);

	diginet_cursor_init(&c, NULL, 4);
	CHK(next(&c, &m) == 0);
	CHK(diginet_msg_next(NULL, &m) == DIGINET_E_ARG);
}

int main(int argc, char **argv)
{
	golden_load(argc > 1 ? argv[1] : "tests/golden/frames.txt");
	CHK(golden_count == (int)NEXPECTS);
	test_values();
	test_one_byte();
	test_build();
	test_parse_refusals();
	test_cursor();
	if (fails) {
		fprintf(stderr, "test_frame: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_frame: ok (%d golden frames)\n", golden_count);
	return 0;
}
