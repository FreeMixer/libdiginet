// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The codecs, both ways, against the bytes docs/protocol.md gives.
 *
 * 1. EXACT BYTES. Each encoder makes the documented command: fader 1 at 512 is
 *    B0 00 40 20 00, strip-1 MUTE is 90 08 40, "OMX1" at 0x00 is F0 13 01 40 00 00 4F 4D 58
 *    31 F7, ten meter segments are 07 7F, and so on.
 * 2. ROUND TRIP. Every value an encoder accepts decodes back to itself: all 1024 fader
 *    positions on every strip, all 32768 ring masks, 0..14 meter segments, every delta.
 * 3. RUNNING STATUS. The golden running-status frame decodes to five controls.
 * 4. PERSONALITIES. The golden announces select the Control|24 and the ProControl, and the
 *    ProControl's device byte, width and counter address reach the bytes.
 * 5. REFUSALS. The 0x70 family is refused by the sysex encoder, by the body check and by
 *    the frame builder; values the wire cannot carry are refused.
 */
#include "golden.h"

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

static const struct diginet_personality *C24, *PRO;

static int bytes_are(const struct diginet_cmd *c, const char *hex)
{
	uint8_t want[64];
	size_t n = 0;
	for (const char *s = hex; *s; ) {
		if (*s == ' ') { s++; continue; }
		want[n++] = (uint8_t)(hexval(s[0]) << 4 | hexval(s[1]));
		s += 2;
	}
	if (c->len != n || memcmp(c->bytes, want, n)) {
		fprintf(stderr, "  got:");
		for (int i = 0; i < c->len; i++)
			fprintf(stderr, " %02x", c->bytes[i]);
		fprintf(stderr, "\n want: %s\n", hex);
		return 0;
	}
	return 1;
}

/* Decode one command; returns its single event (fails the test if there is not exactly one). */
static struct diginet_event one_event(const struct diginet_personality *p, const struct diginet_cmd *c)
{
	struct diginet_decoder d;
	struct diginet_event ev, extra;
	memset(&ev, 0, sizeof ev);
	diginet_decoder_init(&d, p, c->bytes, c->len);
	CHK(diginet_decoder_next(&d, &ev) == 1);
	CHK(diginet_decoder_next(&d, &extra) == 0);
	return ev;
}

static void test_personalities(void)
{
	struct diginet_frame f;
	struct diginet_announce a;
	CHK(diginet_frame_parse(golden("announce_cntrl24")->bytes, golden("announce_cntrl24")->len, &f) == 0);
	CHK(diginet_announce_parse(&f, &a) == 0);
	C24 = diginet_personality_from_name(a.name);
	CHK(C24 && C24->desk == DIGINET_DESK_CONTROL24 && C24->device == 0x01 && C24->strips == 24 &&
	    C24->scribble_chars == 4 && C24->counter_addr == 0x19);
	CHK(diginet_frame_parse(golden("announce_mainunit")->bytes, golden("announce_mainunit")->len, &f) == 0);
	CHK(diginet_announce_parse(&f, &a) == 0);
	PRO = diginet_personality_from_name(a.name);
	CHK(PRO && PRO->desk == DIGINET_DESK_PROCONTROL && PRO->device == 0x00 && PRO->strips == 8 &&
	    PRO->scribble_chars == 8 && PRO->counter_addr == 0x09);
	CHK(diginet_personality_from_name("C|24") == NULL);
	CHK(diginet_personality_from_name(NULL) == NULL);
	CHK(diginet_personality_of(DIGINET_DESK_CONTROL24) == C24);
	CHK(diginet_personality_of(DIGINET_DESK_UNKNOWN) == NULL);
	if (!C24 || !PRO) {
		fprintf(stderr, "NOT A RESULT: no personalities\n");
		exit(2);
	}
}

static void test_fader(void)
{
	struct diginet_cmd c;
	CHK(diginet_fader_encode(C24, 0, 512, &c) == 0 && bytes_are(&c, "b0 00 40 20 00"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_FADER, 0) && !c.display);
	CHK(diginet_fader_encode(C24, 23, 1023, &c) == 0 && bytes_are(&c, "b0 17 7f 37 70"));
	CHK(diginet_fader_encode(C24, 1, 256, &c) == 0 && bytes_are(&c, "b0 01 20 21 00"));
	CHK(diginet_fader_encode(C24, 0, 7, &c) == 0 && bytes_are(&c, "b0 00 00 20 70"));
	for (unsigned s = 0; s < C24->strips; s++)
		for (unsigned v = 0; v <= DIGINET_FADER_MAX; v++) {
			CHK(diginet_fader_encode(C24, s, v, &c) == 0);
			struct diginet_event ev = one_event(C24, &c);
			if (ev.kind != DIGINET_EV_FADER || ev.strip != s || ev.value != v || ev.lsb_missing) {
				CHK(!"fader round trip");
				return;
			}
		}
	CHK(diginet_fader_encode(C24, 0, 1024, &c) == DIGINET_E_RANGE);
	CHK(diginet_fader_encode(C24, 24, 0, &c) == DIGINET_E_RANGE);
	CHK(diginet_fader_encode(PRO, 8, 0, &c) == DIGINET_E_RANGE);
	CHK(diginet_fader_encode(PRO, 7, 0, &c) == 0);

	/* An MSB with no LSB after it still moves the fader, flagged. */
	struct diginet_cmd m = { .bytes = { 0xb0, 0x02, 0x40, 0x90, 0x08, 0x40 }, .len = 6 };
	struct diginet_decoder d;
	struct diginet_event ev;
	diginet_decoder_init(&d, C24, m.bytes, m.len);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_FADER && ev.strip == 2 &&
	    ev.value == 512 && ev.lsb_missing);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_STRIP_BUTTON && ev.button == 8);
	/* The LSB under the explicit status, not only under running status. */
	struct diginet_cmd m2 = { .bytes = { 0xb0, 0x03, 0x7f, 0xb0, 0x23, 0x70 }, .len = 6 };
	diginet_decoder_init(&d, C24, m2.bytes, m2.len);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.value == 1023 && !ev.lsb_missing);
	CHK(diginet_decoder_next(&d, &ev) == 0);
}

static void test_buttons(void)
{
	struct diginet_cmd c;
	struct diginet_event ev;
	CHK(diginet_button_encode(DIGINET_BTN_MUTE, 0, 1, &c) == 0 && bytes_are(&c, "90 08 40"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_LED, 0x0800));
	CHK(diginet_button_encode(DIGINET_BTN_MUTE, 0, 0, &c) == 0 && bytes_are(&c, "90 08 00"));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_STRIP_BUTTON && ev.button == 8 && ev.strip == 0 && !ev.on);
	/* Every strip button on every strip, pressed and released. */
	for (unsigned b = 0; b <= DIGINET_BTN_ROLL_OFF; b++)
		for (unsigned s = 0; s < 24; s++)
			for (int on = 0; on < 2; on++) {
				CHK(diginet_button_encode(b, s, on, &c) == 0);
				ev = one_event(C24, &c);
				int want = b == DIGINET_BTN_TOUCH ? DIGINET_EV_TOUCH : DIGINET_EV_STRIP_BUTTON;
				CHK((int)ev.kind == want && ev.strip == s && ev.on == on && ev.button == b);
			}
	/* Section zones 0x18..0x1D: e.g. a transport key in 0x1C. */
	for (unsigned z = DIGINET_ZONE_FIRST; z <= DIGINET_ZONE_LAST; z++) {
		CHK(diginet_button_encode(0x12, z, 1, &c) == 0);
		ev = one_event(C24, &c);
		CHK(ev.kind == DIGINET_EV_SECTION_BUTTON && ev.zone == z && ev.button == 0x12 && ev.on);
	}
	CHK(diginet_button_encode(0x0c, 0x1c, 1, &c) == 0 && bytes_are(&c, "90 0c 5c"));

	CHK(diginet_touch_encode(C24, 4, 1, &c) == 0 && bytes_are(&c, "90 09 44"));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_TOUCH && ev.strip == 4 && ev.on);
	CHK(diginet_touch_encode(C24, 4, 0, &c) == 0 && bytes_are(&c, "90 09 04"));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_TOUCH && ev.strip == 4 && !ev.on);
	CHK(diginet_touch_encode(PRO, 8, 1, &c) == DIGINET_E_RANGE);
	CHK(diginet_button_encode(0x80, 0, 1, &c) == DIGINET_E_RANGE);
	CHK(diginet_button_encode(0, 0x40, 1, &c) == DIGINET_E_RANGE);
}

static void test_vpot_jog(void)
{
	struct diginet_cmd c;
	struct diginet_event ev;
	CHK(diginet_vpot_encode(C24, 0, 1, &c) == 0 && bytes_are(&c, "b0 40 41"));
	CHK(diginet_vpot_encode(C24, 23, -3, &c) == 0 && bytes_are(&c, "b0 57 3d"));
	CHK(diginet_jog_encode(-1, &c) == 0 && bytes_are(&c, "b0 5c 3f"));
	for (int dlt = -64; dlt <= 63; dlt++) {
		CHK(diginet_vpot_encode(C24, 5, dlt, &c) == 0);
		ev = one_event(C24, &c);
		CHK(ev.kind == DIGINET_EV_VPOT && ev.strip == 5 && ev.delta == dlt);
		CHK(diginet_jog_encode(dlt, &c) == 0);
		ev = one_event(C24, &c);
		CHK(ev.kind == DIGINET_EV_JOG && ev.delta == dlt);
	}
	CHK(diginet_vpot_encode(C24, 0, 64, &c) == DIGINET_E_RANGE);
	CHK(diginet_jog_encode(-65, &c) == DIGINET_E_RANGE);

	/* The ProControl logs show a stale 4th byte after a V-Pot turn: past the body it is
	 * padding and never read. */
	const struct golden *g = golden("running_status");
	struct diginet_frame f;
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == 0 && f.pad_len > 0);
}

static void test_running_status(void)
{
	const struct golden *g = golden("running_status");
	struct diginet_frame f;
	struct diginet_decoder d;
	struct diginet_event ev;
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == 0);
	diginet_decoder_init(&d, C24, f.body, f.body_len);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_STRIP_BUTTON &&
	    ev.button == DIGINET_BTN_MUTE && ev.strip == 0 && ev.on && !ev.msg.running);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_STRIP_BUTTON &&
	    ev.button == DIGINET_BTN_SOLO && ev.strip == 1 && ev.on && ev.msg.running);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_FADER && ev.strip == 1 &&
	    ev.value == 1023 && !ev.lsb_missing);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_VPOT && ev.strip == 0 && ev.delta == 1);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_JOG && ev.delta == -1);
	CHK(diginet_decoder_next(&d, &ev) == 0);

	g = golden("fader_move");
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == 0);
	diginet_decoder_init(&d, C24, f.body, f.body_len);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_FADER && ev.strip == 0 && ev.value == 512);
	CHK(diginet_decoder_next(&d, &ev) == 0);
}

static void test_ring(void)
{
	struct diginet_cmd c;
	CHK(diginet_ring_encode(C24, 0, diginet_ring_dot(0), &c) == 0 && bytes_are(&c, "f0 13 01 00 40 00 00 f7"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_RING, 0) && !c.display);
	CHK(diginet_ring_encode(C24, 2, diginet_ring_dot(1), &c) == 0 && bytes_are(&c, "f0 13 01 00 02 40 00 f7"));
	CHK(diginet_ring_encode(C24, 2, diginet_ring_dot(7), &c) == 0 && bytes_are(&c, "f0 13 01 00 02 01 00 f7"));
	CHK(diginet_ring_encode(C24, 2, diginet_ring_dot(8), &c) == 0 && bytes_are(&c, "f0 13 01 00 02 00 40 f7"));
	CHK(diginet_ring_encode(C24, 2, diginet_ring_dot(14), &c) == 0 && bytes_are(&c, "f0 13 01 00 02 00 01 f7"));
	CHK(diginet_ring_encode(C24, 3, diginet_ring_fill(15), &c) == 0 && bytes_are(&c, "f0 13 01 00 43 7f 7f f7"));
	CHK(diginet_ring_encode(C24, 3, diginet_ring_fill(8), &c) == 0 && bytes_are(&c, "f0 13 01 00 43 7f 00 f7"));
	CHK(diginet_ring_encode(C24, 3, diginet_ring_fill(0), &c) == 0 && bytes_are(&c, "f0 13 01 00 03 00 00 f7"));
	CHK(diginet_ring_fill(16) == 0 && diginet_ring_dot(15) == 0 && diginet_ring_fill(3) == 0x7);
	for (unsigned m = 0; m < (1u << DIGINET_RING_LEDS); m++) {
		CHK(diginet_ring_encode(C24, 9, (uint16_t)m, &c) == 0);
		struct diginet_event ev = one_event(C24, &c);
		if (ev.kind != DIGINET_EV_RING || ev.strip != 9 || ev.mask != m || ev.device != 1) {
			CHK(!"ring round trip");
			return;
		}
	}
	CHK(diginet_ring_encode(C24, 0, 0x8000, &c) == DIGINET_E_RANGE);
	CHK(diginet_ring_encode(PRO, 1, 1, &c) == 0 && bytes_are(&c, "f0 13 00 00 41 00 00 f7"));
}

static void test_meter(void)
{
	struct diginet_cmd c;
	CHK(diginet_meter_encode(C24, 0, 0, 10, &c) == 0 && bytes_are(&c, "f0 13 01 10 00 07 7f f7"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_METER, 0x00));
	CHK(diginet_meter_encode(C24, 0, 1, 10, &c) == 0 && bytes_are(&c, "f0 13 01 10 20 07 7f f7"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_METER, 0x20));
	CHK(diginet_meter_encode(C24, 24, 0, 14, &c) == 0 && bytes_are(&c, "f0 13 01 10 18 7f 7f f7"));
	CHK(diginet_meter_encode(C24, 5, 0, 0, &c) == 0 && bytes_are(&c, "f0 13 01 10 05 00 00 f7"));
	CHK(diginet_meter_encode(C24, 5, 0, 7, &c) == 0 && bytes_are(&c, "f0 13 01 10 05 00 7f f7"));
	for (unsigned s = 0; s <= DIGINET_METER_SEGMENTS; s++)
		for (int right = 0; right < 2; right++) {
			CHK(diginet_meter_encode(C24, 7, right, s, &c) == 0);
			struct diginet_event ev = one_event(C24, &c);
			CHK(ev.kind == DIGINET_EV_METER && ev.strip == 7 && ev.right == right &&
			    ev.segments == (int)s && ev.mask == diginet_meter_mask(s));
		}
	CHK(diginet_meter_segments(0x5) == -1);
	CHK(diginet_meter_encode(C24, 0, 0, 15, &c) == DIGINET_E_RANGE);
	CHK(diginet_meter_encode(C24, 0x20, 0, 1, &c) == DIGINET_E_RANGE);

	/* The golden meter frame decodes to the same. */
	const struct golden *g = golden("meter");
	struct diginet_frame f;
	struct diginet_decoder d;
	struct diginet_event ev;
	CHK(diginet_frame_parse(g->bytes, g->len, &f) == 0);
	diginet_decoder_init(&d, C24, f.body, f.body_len);
	CHK(diginet_decoder_next(&d, &ev) == 1 && ev.kind == DIGINET_EV_METER && ev.strip == 0 &&
	    !ev.right && ev.segments == 10);
}

static void test_leds(void)
{
	struct diginet_cmd c;
	struct diginet_event ev;
	CHK(diginet_strip_leds_encode(C24, 3, DIGINET_AUTO_WRITE | DIGINET_AUTO_READ, &c) == 0 &&
	    bytes_are(&c, "f0 13 01 20 03 44 f7"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_LEDS, 3));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_STRIP_LEDS && ev.addr == 3 && ev.mask == 0x44);
	CHK(diginet_counter_leds_encode(C24, 0x01, &c) == 0 && bytes_are(&c, "f0 13 01 20 19 01 f7"));
	CHK(diginet_counter_leds_encode(PRO, 0x01, &c) == 0 && bytes_are(&c, "f0 13 00 20 09 01 f7"));
	CHK(diginet_strip_leds_encode(C24, 3, 0x80, &c) == DIGINET_E_RANGE);
	CHK(diginet_strip_leds_encode(C24, 24, 0, &c) == DIGINET_E_RANGE);
}

static void test_scribble(void)
{
	struct diginet_cmd c;
	struct diginet_event ev;
	uint8_t t[8];
	CHK(diginet_scribble_text("OMX1", t, 4) == 4);
	CHK(diginet_scribble_encode(C24, 0x00, t, &c) == 0 &&
	    bytes_are(&c, "f0 13 01 40 00 00 4f 4d 58 31 f7"));
	CHK(c.display && c.key == DIGINET_KEY(DIGINET_KEY_SCRIBBLE, 0x00));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_SCRIBBLE && ev.addr == 0 && ev.len == 4 && !strcmp(ev.text, "OMX1"));
	CHK(diginet_scribble_encode(C24, 0x20, t, &c) == 0 &&
	    bytes_are(&c, "f0 13 01 40 20 00 4f 4d 58 31 f7"));
	CHK(c.key == DIGINET_KEY(DIGINET_KEY_SCRIBBLE, 0x20));

	/* Padding, cutting, and the dot plus small digit glyphs 0x17..0x1F. */
	diginet_scribble_text("Ab", t, 4);
	CHK(!memcmp(t, "Ab  ", 4));
	diginet_scribble_text("Kick drum", t, 4);
	CHK(!memcmp(t, "Kick", 4));
	diginet_scribble_text("Vx.1", t, 4);
	CHK(t[0] == 'V' && t[1] == 'x' && t[2] == 0x17 && t[3] == ' ');
	diginet_scribble_text(".9.5", t, 4);
	CHK(t[0] == 0x1f && t[1] == 0x1b && t[2] == ' ');
	diginet_scribble_text("a.0", t, 4);
	CHK(!memcmp(t, "a.0 ", 4));
	diginet_scribble_text("\xc3\xa9", t, 4);
	CHK(t[0] == '?' && t[1] == '?');
	diginet_scribble_text(NULL, t, 4);
	CHK(!memcmp(t, "    ", 4));

	/* The ProControl: device byte 00, 8 characters, rows at 00 and 20. */
	diginet_scribble_text("Overhead", t, 8);
	CHK(diginet_scribble_encode(PRO, 0x20, t, &c) == 0 &&
	    bytes_are(&c, "f0 13 00 40 20 00 4f 76 65 72 68 65 61 64 f7"));
	ev = one_event(PRO, &c);
	CHK(ev.kind == DIGINET_EV_SCRIBBLE && ev.len == 8 && !strcmp(ev.text, "Overhead") && ev.device == 0);

	uint8_t bad[4] = { 'a', 0x80, 'b', 'c' };
	CHK(diginet_scribble_encode(C24, 0, bad, &c) == DIGINET_E_RANGE);
	CHK(diginet_scribble_encode(C24, 0x80, t, &c) == DIGINET_E_RANGE);
}

static void test_counter(void)
{
	struct diginet_cmd c;
	struct diginet_event ev;
	uint8_t seg[8], dots;

	CHK(diginet_seg7('0') == 0x3f && diginet_seg7('8') == 0x7f && diginet_seg7('-') == 0x40);
	CHK(diginet_seg7('1') == 0x06 && diginet_seg7('7') == 0x07 && diginet_seg7(' ') == 0);
	CHK(diginet_seg7('X') == -1 && diginet_seg7('M') == -1);
	const char *letters = "AbCdEFHhJLoPrSUYZ-";
	for (const char *l = letters; *l; l++)
		CHK(diginet_seg7(*l) > 0);

	/* Shown left to right as 1 2 3 4 5 6 7 8; on the wire 8 first. */
	CHK(diginet_counter_text("12345678", seg, &dots) == 0 && dots == 0);
	CHK(seg[0] == 0x06 && seg[7] == 0x7f);
	CHK(diginet_counter_encode(C24, seg, dots, &c) == 0 &&
	    bytes_are(&c, "f0 13 01 30 19 00 7f 07 7d 6d 66 4f 5b 06 f7"));
	CHK(c.display && c.key == DIGINET_KEY(DIGINET_KEY_COUNTER, 0x19));
	ev = one_event(C24, &c);
	CHK(ev.kind == DIGINET_EV_COUNTER && ev.addr == 0x19 && !memcmp(ev.seg, seg, 8) && ev.dots == 0);

	/* Dots: bit k is the k-th digit on the wire, so the rightmost digit is bit 0. */
	CHK(diginet_counter_text("1.2.3.4", seg, &dots) == 0);
	CHK(seg[0] == 0 && seg[4] == 0x06 && seg[7] == 0x66);
	CHK(dots == (DIGINET_COUNTER_DOT(4) | DIGINET_COUNTER_DOT(5) | DIGINET_COUNTER_DOT(6)));
	CHK(dots == 0x0e);
	CHK(diginet_counter_text("12345678.", seg, &dots) == 0 && dots == 0x01);
	CHK(diginet_counter_encode(C24, seg, dots, &c) == 0);
	ev = one_event(C24, &c);
	CHK(ev.dots == 0x01 && ev.seg[7] == 0x7f);
	CHK(diginet_counter_text("1.2345678", seg, &dots) == DIGINET_E_RANGE);  /* leftmost dot */
	CHK(diginet_counter_text("123456789", seg, &dots) == DIGINET_E_RANGE);
	CHK(diginet_counter_text("12M", seg, &dots) == DIGINET_E_RANGE);
	CHK(diginet_counter_text("", seg, &dots) == 0 && seg[0] == 0 && seg[7] == 0);

	/* The ProControl: device 00, address 09. */
	CHK(diginet_counter_text("-", seg, &dots) == 0);
	CHK(diginet_counter_encode(PRO, seg, dots, &c) == 0 &&
	    bytes_are(&c, "f0 13 00 30 09 00 40 00 00 00 00 00 00 00 f7"));

	/* A dot byte of 0x80 cannot ride a data byte. */
	CHK(diginet_counter_encode(C24, seg, 0x80, &c) == DIGINET_E_RANGE);
	uint8_t s8[8] = { 0x80 };
	CHK(diginet_counter_encode(C24, s8, 0, &c) == DIGINET_E_RANGE);
}

static void test_refusals(void)
{
	struct diginet_cmd c;
	memset(&c, 0xaa, sizeof c);
	const uint8_t name[] = { 0x00, 0x6e, 'C', 'N', 'T', 'R', 'L', '|', '2', '4' };
	CHK(diginet_sysex_encode(0x01, DIGINET_FN_SYSTEM, name, sizeof name, &c) == DIGINET_E_REFUSED);
	CHK(c.len == 0xaa);  /* untouched */
	CHK(diginet_sysex_encode(0x00, 0x70, NULL, 0, &c) == DIGINET_E_REFUSED);
	CHK(diginet_sysex_encode(0x01, 0x40, name, sizeof name, &c) == 0);
	CHK(diginet_sysex_encode(0x01, 0x40, (const uint8_t *)"\x80", 1, &c) == DIGINET_E_RANGE);
	CHK(diginet_sysex_encode(0x80, 0x40, name, 1, &c) == DIGINET_E_ARG);

	/* The body check and the frame builder refuse it however it got into the body. */
	const uint8_t body[] = { 0x90, 0x08, 0x40, 0xf0, 0x13, 0x01, 0x70, 0x00, 0x6e,
				 'C', 'N', 'T', 'R', 'L', '|', '2', '4', 0xf7 };
	const uint8_t cut[] = { 0xf0, 0x13, 0x00, 0x70, 0x01 };
	const uint8_t fine[] = { 0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 'p', 0x70, 'q', 'r', 0xf7 };
	CHK(diginet_body_check(body, sizeof body) == DIGINET_E_REFUSED);
	CHK(diginet_body_check(cut, sizeof cut) == DIGINET_E_REFUSED);
	CHK(diginet_body_check(fine, sizeof fine) == DIGINET_OK);   /* 0x70 as a character is fine */
	uint8_t frame[128];
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .num_commands = 2 };
	uint8_t d[6] = { 0x00, 0xa0, 0x7e, 0, 0, 1 }, s[6] = { 2, 0, 0, 0, 0, 1 };
	CHK(diginet_frame_build(frame, sizeof frame, d, s, &h, body, sizeof body, DIGINET_SUM_BODY) ==
	    DIGINET_E_REFUSED);
	CHK(diginet_frame_build(frame, sizeof frame, d, s, &h, cut, sizeof cut, DIGINET_SUM_ZERO) ==
	    DIGINET_E_REFUSED);
	CHK(diginet_frame_build(frame, sizeof frame, d, s, &h, fine, sizeof fine, DIGINET_SUM_BODY) == 60);

	/* What a desk might send in that family decodes as SYSTEM, never as something else. */
	struct diginet_decoder dec;
	struct diginet_event ev;
	diginet_decoder_init(&dec, C24, body, sizeof body);
	CHK(diginet_decoder_next(&dec, &ev) == 1 && ev.kind == DIGINET_EV_STRIP_BUTTON);
	CHK(diginet_decoder_next(&dec, &ev) == 1 && ev.kind == DIGINET_EV_SYSTEM);
}

int main(int argc, char **argv)
{
	golden_load(argc > 1 ? argv[1] : "tests/golden/frames.txt");
	test_personalities();
	test_fader();
	test_buttons();
	test_vpot_jog();
	test_running_status();
	test_ring();
	test_meter();
	test_leds();
	test_scribble();
	test_counter();
	test_refusals();
	if (fails) {
		fprintf(stderr, "test_codec: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_codec: ok\n");
	return 0;
}
