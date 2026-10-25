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

/* little-endian, as fuzz_u16() reads it */
static void put16(unsigned v)
{
	put8(v & 0xff);
	put8(v >> 8 & 0xff);
}

/* a length-prefixed record, as fuzz_record() reads it */
static void put_rec(const uint8_t *p, size_t n)
{
	put16((unsigned)n);
	put(p, n);
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

static const uint8_t HOST[DIGINET_MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t DESK[DIGINET_MAC_LEN] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };

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
	/* a message that runs past the body, its one byte left a status byte */
	BODY("status-at-end", 0x90, 0xc0);
	BODY("sysex-no-f7", 0xf0, 0x13, 0x01, 0x40, 0x00);
	BODY("one-data-byte", 0xc0, 0x05, 0xd0, 0x7f, 0x10);
	BODY("aftertouch", 0xa0, 0x10, 0x20);
	/* a system exclusive between a message and data bytes that running status would take */
	BODY("status-cancelled", 0x90, 0x08, 0x40, 0xf0, 0x13, 0x01, 0x20, 0x01, 0x40, 0xf7, 0x08, 0x40);

	/* the decoder's kinds */
	BODY("fader-msb-only", 0xb0, 0x03, 0x40, 0x90, 0x08, 0x40);
	BODY("fader-lsb-explicit", 0xb0, 0x03, 0x40, 0xb0, 0x23, 0x70);
	BODY("fader-lsb-other-strip", 0xb0, 0x03, 0x40, 0x24, 0x70);
	BODY("fader-last", 0xb0, 0x1f, 0x7f);
	BODY("jog-vpot", 0xb0, 0x5c, 0x41, 0xb0, 0x45, 0x3f, 0x58, 0x10);
	BODY("cc-other", 0xb0, 0x60, 0x10);
	BODY("zone-key", 0x90, 0x05, 0x58, 0x90, 0x05, 0x1d);
	/* each edge of the zones and of the control changes, from both sides: strip 23, zone 18,
	 * zone 1D, id 1E; CC 20 alone, 3F, the first and the last V-Pot, 58, the jog; a fader MSB
	 * followed by a key on 20 + tt, which is no LSB */
	BODY("key-edges", 0x90, 0x05, 0x57, 0x90, 0x05, 0x58, 0x90, 0x05, 0x5d, 0x90, 0x05, 0x1e);
	BODY("cc-edges", 0xb0, 0x20, 0x10, 0xb0, 0x3f, 0x10, 0xb0, 0x40, 0x41, 0xb0, 0x57, 0x3f, 0xb0, 0x58,
	     0x41, 0xb0, 0x5b, 0x41, 0xb0, 0x5c, 0x40, 0xb0, 0x03, 0x40, 0x90, 0x23, 0x40);
	BODY("touch", 0x90, 0x09, 0x45);
	BODY("sysex-short", 0xf0, 0x13, 0x01, 0xf7);
	BODY("sysex-other-maker", 0xf0, 0x12, 0x01, 0x10, 0xf7);
	BODY("sysex-other-fn", 0xf0, 0x13, 0x01, 0x55, 0x00, 0xf7);
	BODY("meter-not-thermometer", 0xf0, 0x13, 0x01, 0x10, 0x00, 0x00, 0x05, 0xf7);
	BODY("sysex-wrong-sizes", 0xf0, 0x13, 0x01, 0x00, 0x01, 0xf7, 0xf0, 0x13, 0x01, 0x10, 0x00, 0xf7,
	     0xf0, 0x13, 0x01, 0x20, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0xf7, 0xf0, 0x13, 0x01, 0x30,
	     0x19, 0xf7, 0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	     0x48, 0x49, 0xf7);

	/* the system family: whole, cut short, inside another sysex */
	BODY("system-whole", 0xf0, 0x13, 0x01, 0x70, 0x00, 0xf7);
	BODY("system-cut-short", 0xf0, 0x13, 0x01, 0x70);
	BODY("system-in-sysex", 0xf0, 0x01, 0xf0, 0x13, 0x01, 0x70, 0xf7);
	BODY("system-after-message", 0x90, 0x08, 0x40, 0xf0, 0x13, 0x00, 0x70, 0x01, 0x02);
	/* function 70 of another maker is not the family */
	BODY("system-other-maker", 0xf0, 0x12, 0x01, 0x70, 0xf7);

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

/* ---- fuzz_codec: operations ---- */

enum { NONE = 0, C24 = 1, PC = 2 };
static void op(unsigned kind, unsigned desk) { put8(desk * 15 + kind); }

static void codec_seeds(void)
{
	static const uint8_t seg[8] = { 0x7e, 0x30, 0x6d, 0x79, 0x33, 0x5b, 0x5f, 0x70 };
	static const uint8_t pl[3] = { 0x01, 0x02, 0x03 };

	/* every encoder, in range, for both desks */
	for (unsigned desk = C24; desk <= PC; desk++) {
		op(0, desk); put8(1); put16(700);
		op(1, desk); put8(DIGINET_BTN_MUTE); put8(2); put8(1);
		op(1, desk); put8(DIGINET_BTN_TOUCH); put8(3); put8(0);
		op(1, desk); put8(0x10); put8(DIGINET_ZONE_FIRST); put8(1);
		op(2, desk); put8(4); put8(1);
		op(3, desk); put8(5); put16((uint16_t)-3);
		op(4, desk); put16(7);
		op(5, desk); put8(6); put16(0x7fff);
		op(6, desk); put8(7); put8(1); put8(10);
		op(6, desk); put8(24); put8(0); put8(0);
		op(7, desk); put8(1); put8(DIGINET_AUTO_TOUCH);
		op(8, desk); put8(0x7f);
		op(9, desk); put8(0x20); put("OMX1Mix8", 8);
		op(10, desk); put8(0x05); put(seg, 8);
		op(11, desk); put8(0x01); put8(DIGINET_FN_METER); put8(3); put(pl, 3);
		emit("codec", desk == C24 ? "encoders-control24" : "encoders-procontrol");
	}

	/* every encoder out of range, and without a personality */
	op(0, C24); put8(0); put16(DIGINET_FADER_MAX + 1);
	op(1, C24); put8(0x80); put8(0); put8(0);
	op(1, C24); put8(0); put8(0x40); put8(0);
	op(2, C24); put8(24); put8(1);
	op(3, C24); put8(0); put16(64);
	op(3, C24); put8(24); put16(0);
	op(4, C24); put16((uint16_t)-65);
	op(5, C24); put8(0); put16(0x8000);
	op(5, C24); put8(24); put16(1);
	op(6, C24); put8(0x20); put8(0); put8(1);
	op(6, C24); put8(0); put8(0); put8(15);
	op(7, C24); put8(0); put8(0x80);
	op(7, C24); put8(24); put8(0);
	op(8, C24); put8(0x80);
	op(9, C24); put8(0x80); put("abcdefgh", 8);
	op(9, C24); put8(0x01); put("ab\x80" "defgh", 8);
	op(10, C24); put8(0x80); put(seg, 8);
	op(10, C24); put8(0); put8(0x80); put(seg + 1, 7);
	op(11, C24); put8(0x80); put8(0x10); put8(0);
	op(11, C24); put8(0x01); put8(0x80); put8(0);
	op(11, C24); put8(0x01); put8(0x10); put8(20); put("01234567890123456789", 20);
	op(11, C24); put8(0x01); put8(0x10); put8(1); put8(0x80);
	for (unsigned k = 0; k <= 10; k++) {
		op(k, NONE);
		put("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", 10);
	}
	emit("codec", "out-of-range");

	/* every range at its last accepted value, for both desks: out-of-range holds the first
	 * refused one, so a bound moved by one either way shows on one of the two */
	for (unsigned desk = C24; desk <= PC; desk++) {
		unsigned last = desk == C24 ? 23 : 7;
		static const uint8_t pl19[19] = { 0x7f };
		op(0, desk); put8(last); put16(DIGINET_FADER_MAX);
		op(1, desk); put8(0x7f); put8(0x3f); put8(1);
		op(2, desk); put8(last); put8(1);
		op(3, desk); put8(last); put16((uint16_t)-64);
		op(3, desk); put8(0); put16(63);
		op(4, desk); put16((uint16_t)-64);
		op(4, desk); put16(63);
		op(5, desk); put8(last); put16(0x7fff);
		op(6, desk); put8(0x1f); put8(1); put8(14);
		op(7, desk); put8(last); put8(0x7f);
		op(8, desk); put8(0x7f);
		op(9, desk); put8(0x7f); put("\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f", 8);
		op(10, desk); put8(0x7f); put("\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f", 8);
		op(11, desk); put8(0x7f); put8(0x7f); put8(19); put(pl19, 19);
	}
	emit("codec", "edges");

	/* the mutants' seeds */
	op(0, C24); put8(24); put16(0);
	emit("codec", "fader-past-last-strip");
	op(0, C24); put8(0); put16(DIGINET_FADER_MAX);
	emit("codec", "fader-full");
	op(11, C24); put8(0x01); put8(DIGINET_FN_SYSTEM); put8(2); put("\x00\x00", 2);
	op(11, C24); put8(0x80); put8(DIGINET_FN_SYSTEM); put8(0);
	emit("codec", "sysex-system");
	op(13, C24); put16(9); put("12345678.", 9);
	emit("codec", "counter-text-last-dot");

	/* the text helpers */
	static const char *const TEXT[] = {
		"Kick", "Vox.2", "a.1.9", "\xc3\xa9t\xc3\xa9", "", "longer than eight",
	};
	for (size_t i = 0; i < sizeof TEXT / sizeof TEXT[0]; i++) {
		op(12, i & 1 ? PC : C24); put8(0x10 + i); put16(strlen(TEXT[i])); put(TEXT[i], strlen(TEXT[i]));
	}
	op(12, NONE); put8(0x01); put16(3); put("abc", 3);
	emit("codec", "scribble-text");
	static const char *const COUNTER[] = {
		"12.5", "1.2.3.4.5.6.7.8", "123456789", "0:00", "-HELLO-", "..", "", "1..2",
		/* every character the display shows */
		"01234567", "89AaBbCc", "DdEeFfHh", "JjLlOoPp", "RrSsUuYy", "Zz- ",
	};
	for (size_t i = 0; i < sizeof COUNTER / sizeof COUNTER[0]; i++) {
		op(13, C24); put16(strlen(COUNTER[i])); put(COUNTER[i], strlen(COUNTER[i]));
	}
	emit("codec", "counter-text");
	op(14, NONE); put8(0); put16(0);
	op(14, NONE); put8(10); put16(0x3ff);
	op(14, NONE); put8(14); put16(0x3fff);
	op(14, NONE); put8(15); put16(0x7fff);
	op(14, NONE); put8(200); put16(0x0005);
	emit("codec", "masks");
}

/* ---- fuzz_transport: a session ---- */

enum { F_AUTO = 1, F_ZERO = 2, F_DESKSET = 4, F_RAW = 8 };

/* the config, in the harness's units: each argument is the value the session gets */
static void config(unsigned flags, unsigned retries, unsigned ack_ms, unsigned ka_ms, unsigned backoff_ms,
		   unsigned offline_ms, unsigned wake_ms, unsigned gap_us, unsigned max_cmds, unsigned max_body)
{
	put8(flags);
	put8(retries);
	put8(ack_ms - 1);
	put16(ka_ms - 1);
	put8(backoff_ms);
	put16(offline_ms - 1);
	put16(wake_ms - 1);
	put16(gap_us);
	put8(max_cmds - 1);
	put16(max_body - DIGINET_CMD_MAX_LEN);
}

/* the default config, as diginet_session_config_default() gives it, scaled to fit u16 ms */
static void config_default(unsigned flags)
{
	config(flags, 5, 100, 10000, 255, 25000, 3000, 2000, 48, 314);
}

enum { T_RAW = 0, T_FRAME, T_ANNOUNCE, T_TIME, T_SUBMIT, T_WAKE, T_CLOSE, T_FAIL, T_POLL };
enum { C_DATA = 0, C_ACK, C_E0, C_E1, C_E2, C_E3, C_UNKNOWN };
enum { FROM_DESK = 0, FROM_DESK2 = 1 << 3, FROM_HOST = 2 << 3, FROM_NOTDD = 3 << 3 };
enum { TO_HOST = 0, TO_BCAST = 1 << 5, TO_OTHER = 2 << 5 };
#define ACK_LAST 0x80

static void t_frame(unsigned sel, unsigned send, unsigned ack, unsigned retry, const uint8_t *b, size_t n)
{
	put8(T_FRAME);
	put8(sel);
	put16(send);
	put16(ack);
	put8(retry);
	put_rec(b, n);
}

/* mac: < 10 the host's MAC at that offset, 10..12 another host's, else none */
static void t_announce(int e1, unsigned mac, unsigned name)
{
	put8(T_ANNOUNCE);
	put8(e1);
	put8(mac);
	put8(name);
}

static void t_time(unsigned scale, unsigned n)
{
	put8(T_TIME);
	put8(scale);
	put16(n);
}

enum { US = 0, MSEC = 1, DECI = 2, SEC = 3 };

static void t_tagged(unsigned kind, unsigned addr, unsigned display, unsigned len, const char *fill)
{
	put8(T_SUBMIT);
	put8(kind - 1);
	put8(addr);
	put8(display);
	put8(len - 3);
	put(fill, len - 3);
}

static void t_rawcmd(unsigned kind, unsigned addr, unsigned display, const uint8_t *b, size_t n)
{
	put8(T_SUBMIT);
	put8(kind - 1);
	put8(addr);
	put8(display);
	put_rec(b, n);
}

/* e0, our e2, its a0, an e1 naming us: online */
static void online(void)
{
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
}

static const uint8_t MUTE[3] = { 0x90, 0x08, 0x40 };

static void transport_seeds(void)
{
	uint8_t f[DIGINET_MAX_FRAME_LEN];
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .send_counter = 0x200 };
	struct diginet_cmd c;
	const struct diginet_personality *c24 = diginet_personality_of(DIGINET_DESK_CONTROL24);

	config_default(F_AUTO);
	put8(T_POLL); put8(0); put_rec(NULL, 0);   /* idle: nothing due */
	online();
	emit("transport", "online");

	/* data from the desk, ACKed with its send counter, a retry ACKed again */
	config_default(F_AUTO);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0x22, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_BCAST, 0x106, 0x22, 1, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x106, 0x22, 1, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x107, 0x22, 0, (const uint8_t *)"\0", 1);
	t_time(DECI, 4);
	emit("transport", "data-acked");

	/* data before any session, from a desk the config names, then closed */
	config_default(F_DESKSET);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x10, 0x01, 0, MUTE, sizeof MUTE);
	put8(T_CLOSE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x11, 0x01, 0, MUTE, sizeof MUTE);
	put8(T_WAKE);
	emit("transport", "data-before-session");

	/* frames the session does not take: from us, for another host, from another desk, from
	 * a MAC that is not Digidesign's, of a command it does not know, a desk's e2, an ACK of a
	 * frame not in flight */
	config_default(F_AUTO);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 1, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_E0 | FROM_NOTDD | TO_BCAST, 1, 0, 0, NULL, 0);
	online();
	t_frame(C_DATA | FROM_HOST | TO_HOST, 2, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_OTHER, 3, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK2 | TO_HOST, 4, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_UNKNOWN | FROM_DESK | TO_HOST, 5, 0, 0, NULL, 0);
	t_frame(C_E2 | FROM_DESK | TO_HOST, 6, 0, 0, NULL, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST, 7, 0x999, 0, NULL, 0);
	t_frame(C_E1 | FROM_DESK | TO_BCAST, 8, 0, 0, MUTE, sizeof MUTE);   /* an announce too short */
	put8(T_RAW); put_rec(golden("fader_move")->bytes, 20);
	emit("transport", "filters");

	/* an e2 nobody answers: retried until max_retries, dropped, then the wake times out */
	config(F_AUTO, 3, 1, 60000, 0, 60000, 50, 0, 48, 314);
	t_announce(0, 13, 1);
	for (int i = 0; i < 5; i++)
		t_time(MSEC, 1);
	t_time(MSEC, 60);
	emit("transport", "wake-unanswered");

	/* a retransmission whose send fails still counts */
	config(F_AUTO, 2, 1, 60000, 0, 60000, 50, 0, 48, 314);
	t_announce(0, 13, 1);
	put8(T_FAIL);
	for (int i = 0; i < 4; i++)
		t_time(MSEC, 1);
	emit("transport", "retransmit-fails");

	/* a frame in flight, a wake whose send fails, then the retransmission of that frame */
	config(F_AUTO, 3, 1, 1, 0, 60000, 3000, 0, 48, 314);
	online();
	t_time(MSEC, 2);
	put8(T_FAIL);
	put8(T_WAKE);
	t_time(DECI, 5);
	emit("transport", "wake-fails-in-flight");

	/* keepalives on their own clock, a desk retry holding them back, then silence */
	config(F_AUTO, 1, 1, 10, 30, 1000, 3000, 0, 48, 314);
	online();
	for (int i = 0; i < 3; i++) {
		t_time(MSEC, 11);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	}
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x30, 0, 1, MUTE, sizeof MUTE);
	t_time(MSEC, 11);
	t_time(MSEC, 40);
	t_time(SEC, 2);
	emit("transport", "keepalive-silence");

	/* the ways a session ends: e0, a desk e3, another host's e1, close */
	config_default(F_AUTO);
	online();
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 3, 1);
	t_frame(C_E3 | FROM_DESK | TO_HOST, 1, 0, 0, NULL, 0);
	t_announce(0, 13, 2);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 10, 0);
	put8(T_WAKE);
	t_announce(0, 13, 0);
	put8(T_CLOSE);
	put8(T_CLOSE);
	t_announce(0, 13, 0);
	emit("transport", "session-ends");

	/* a wake asked for while another host holds the desk */
	config_default(0);
	t_announce(1, 11, 0);
	put8(T_WAKE);
	emit("transport", "wake-foreign");

	/* a close while another host holds the desk: no e3 */
	config_default(0);
	t_announce(1, 11, 0);
	put8(T_CLOSE);
	emit("transport", "close-foreign");

	/* without auto_wake: woken by hand, online, then the desk's e0 ends it */
	config_default(0);
	t_announce(0, 13, 0);
	put8(T_WAKE);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 0, 0);
	t_announce(0, 13, 0);
	emit("transport", "offline-e0");

	/* online, then nothing from the desk for longer than offline_ms */
	config(F_AUTO, 5, 100, 60000, 0, 1000, 3000, 0, 48, 314);
	online();
	t_time(SEC, 2);
	emit("transport", "silence");

	/* the e1 naming the host before the a0 of the e2: online only with both */
	config_default(F_AUTO);
	t_announce(0, 13, 0);
	t_announce(1, 0, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	emit("transport", "e1-before-ack");

	/* the host's MAC at the last offset of the 15 leading bytes it fits */
	config_default(F_AUTO);
	t_announce(0, 13, 0);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 1, 0, 0, NULL, 0);
	t_announce(1, 9, 0);
	emit("transport", "e1-mac-at-9");

	/* an e2 unanswered, with time passing in steps of 6 and 5 ms against a 10 ms ack timeout */
	config(F_AUTO, 3, 10, 60000, 0, 60000, 3000, 0, 48, 314);
	t_announce(0, 13, 0);
	t_time(MSEC, 6);
	t_time(MSEC, 5);
	t_time(MSEC, 6);
	t_time(MSEC, 5);
	emit("transport", "retry-timing");

	/* a 10 ms keepalive, time passing in steps of 5 ms, each keepalive ACKed */
	config(F_AUTO, 5, 100, 10, 0, 60000, 3000, 0, 48, 314);
	online();
	for (int i = 0; i < 6; i++) {
		t_time(MSEC, 5);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	}
	emit("transport", "keepalive-clock");

	/* two display writes, one a frame, against a 2000 us gap: the second goes exactly when
	 * the gap has passed */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 2000, 1, 314);
	online();
	t_tagged(DIGINET_KEY_SCRIBBLE, 1, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	t_tagged(DIGINET_KEY_SCRIBBLE, 2, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	t_time(US, 1000);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	t_time(US, 2000);
	emit("transport", "display-gap-exact");

	/* a desk retry holds the host back 10 ms; a command waits, then goes exactly as the
	 * back-off ends */
	config(F_AUTO, 5, 100, 60000, 10, 60000, 3000, 0, 48, 314);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x40, 0, 1, MUTE, sizeof MUTE);
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	t_time(MSEC, 5);
	t_time(MSEC, 5);
	emit("transport", "backoff-exact");

	/* the wake timeout and the silence, each reached exactly */
	config(F_AUTO, 0, 100, 60000, 0, 60000, 5, 0, 48, 314);
	t_announce(0, 13, 0);
	t_time(MSEC, 5);
	emit("transport", "wake-timeout-exact");
	config(F_AUTO, 5, 100, 60000, 0, 7, 3000, 0, 48, 314);
	online();
	t_time(MSEC, 7);
	emit("transport", "silence-exact");

	/* the same desk counter twice, with no retry: two frames, both delivered */
	config_default(F_AUTO);
	online();
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0, 0, MUTE, sizeof MUTE);
	t_frame(C_DATA | FROM_DESK | TO_HOST, 0x105, 0, 0, MUTE, sizeof MUTE);
	emit("transport", "data-repeat");

	/* a manual wake, in the zero-sum mode, through poll */
	config_default(F_ZERO);
	put8(T_WAKE);
	t_announce(0, 13, 0);
	put8(T_WAKE);
	h.cmd = DIGINET_CMD_ACK;
	h.ack_counter = 0;
	int n = diginet_frame_build(f, sizeof f, HOST, DESK, &h, NULL, 0, DIGINET_SUM_BODY);
	put8(T_POLL); put8(0); put_rec(f, (size_t)n);
	h.cmd = DIGINET_CMD_DATA;
	n = diginet_frame_build(f, sizeof f, HOST, DESK, &h, MUTE, sizeof MUTE, DIGINET_SUM_BODY);
	put8(T_POLL); put8(0); put_rec(f, (size_t)n);
	t_announce(1, 4, 0);
	put8(T_POLL); put8(1); put_rec(f, (size_t)n);   /* and its retransmission behind it */
	put8(T_POLL); put8(2); put_rec(f, (size_t)n);   /* recv fails */
	put8(T_POLL); put8(0); put_rec(NULL, 0);
	emit("transport", "wake-poll");

	/* latest wins: two values for one fader, then sent; one value for an input key, twice */
	config_default(F_AUTO);
	online();
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x10\x20");
	t_tagged(DIGINET_KEY_FADER, 1, 0, 5, "\x11\x21");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_time(MSEC, 1);
	t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
	emit("transport", "coalesce");

	/* frames full by count, by bytes, and display writes paced */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 2000, 3, 30);
	online();
	for (unsigned i = 0; i < 8; i++)
		t_tagged(DIGINET_KEY_RING, i, 0, 10, "\x01\x02\x03\x04\x05\x06\x07");
	for (unsigned i = 0; i < 4; i++)
		t_tagged(DIGINET_KEY_SCRIBBLE, i, 1, 12, "\x41\x42\x43\x44\x45\x46\x47\x48\x49");
	for (int i = 0; i < 8; i++) {
		t_time(US, 700);
		t_frame(C_ACK | FROM_DESK | TO_HOST | ACK_LAST, 9, 0, 0, NULL, 0);
		put8(T_POLL); put8(0); put_rec(NULL, 0);   /* the deadline of a paced queue */
	}
	emit("transport", "batches");

	/* two commands each whole alone that are F0 13 xx 70 together: the first ends F0 13, and
	 * the second is serial 112, so its A0 70 follows */
	config(F_AUTO, 5, 100, 60000, 0, 60000, 3000, 0, 255, DIGINET_MAX_BODY_LEN);
	for (unsigned i = 0; i < 111; i++)
		t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 5, "\xf0\x13");
	t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	online();
	t_time(MSEC, 1);
	emit("transport", "split-system");

	/* the queue filled while no session lives */
	config_default(F_AUTO);
	for (unsigned i = 0; i < DIGINET_QUEUE_MAX + 1; i++)
		t_tagged(DIGINET_KEY_INPUT, 0, 0, 3, "");
	t_tagged(DIGINET_KEY_METER, 1, 0, 3, "");
	emit("transport", "queue-full");

	/* raw commands: the system family refused whole and cut short, others queued and sent */
	static const uint8_t SYS[6] = { 0xf0, 0x13, 0x01, 0x70, 0x00, 0xf7 };
	config_default(F_AUTO | F_RAW);
	online();
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, SYS, 6);
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, NULL, 0);
	if (diginet_fader_encode(c24, 2, 300, &c) == DIGINET_OK)
		t_rawcmd(DIGINET_KEY_FADER, 2, 0, c.bytes, c.len);
	t_time(MSEC, 1);
	emit("transport", "submit-system");
	config_default(F_AUTO | F_RAW);
	t_rawcmd(DIGINET_KEY_LEDS, 1, 0, SYS, 4);
	emit("transport", "submit-system-cut-short");
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
	codec_seeds();
	transport_seeds();
	free(S.p);
	return 0;
}
