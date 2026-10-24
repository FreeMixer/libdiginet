// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE CONTROLS (src/diginet_codec.c), every encoder diginet_codec.h
 * declares, the text helpers of the scribble strip and the counter, and the decoder of
 * src/diginet_decode.c reading back what each encoder made.
 *
 * Input: up to OPS_MAX operations, each [op] and its arguments. op % 15 is the call, and
 * op / 15 % 3 the personality it is given: none (NULL), Control|24, ProControl.
 *    0 strip u16 value          diginet_fader_encode
 *    1 button id on             diginet_button_encode
 *    2 strip on                 diginet_touch_encode
 *    3 strip u16 delta          diginet_vpot_encode (delta as int16)
 *    4 u16 delta                diginet_jog_encode (delta as int16)
 *    5 strip u16 mask           diginet_ring_encode
 *    6 channel right segments   diginet_meter_encode
 *    7 strip bits               diginet_strip_leds_encode
 *    8 bits                     diginet_counter_leds_encode
 *    9 addr c1..c8              diginet_scribble_encode
 *   10 dots s1..s8              diginet_counter_encode (s1 the leftmost digit)
 *   11 device fn n p1..pn       diginet_sysex_encode (n % 25 payload bytes)
 *   12 addr u16-len text        diginet_scribble_text, then diginet_scribble_encode
 *   13 u16-len text             diginet_counter_text, then diginet_counter_encode
 *   14 n u16 mask               diginet_meter_mask, diginet_meter_segments, ring_dot/fill
 * Every byte argument is a u8; text is cut at its first NUL and at 64 bytes. The text
 * operations use Control|24 when the personality is none.
 *
 * Properties, each an abort(), checked in this order after each encoder call:
 *   - refusal: the system family is never encoded: diginet_sysex_encode() never makes
 *     function 0x70 and leaves the command untouched, refusing it with DIGINET_E_REFUSED
 *     whenever the device byte is one the wire carries (a device past 0x7f is DIGINET_E_ARG
 *     first), and every command an encoder makes passes diginet_body_check().
 *     Mutant: fuzz/mutants/codec-refusal.patch, only an empty 0x70 message is refused; seed
 *     sysex-system.
 *   - range: an encoder succeeds exactly for the values its comment in diginet_codec.h
 *     accepts (a strip below the personality's strips, a 10-bit fader, a 7-bit button and a
 *     6-bit id, a delta in -64..63, 15 ring LEDs, a channel below 0x20 and 14 segments, 7-bit
 *     LED bits, scribble characters and counter patterns), DIGINET_E_ARG for a missing
 *     personality, and on every failure leaves the command as it was.
 *     Mutant: fuzz/mutants/codec-range.patch, the fader takes the strip one past the last;
 *     seed fader-past-last-strip.
 *   - round-trip: what an encoder makes, the decoder reads back as exactly one event of its
 *     kind with the values encoded, using every byte; the command's key names its address
 *     (diginet_codec.h, enum diginet_key_kind) and only scribble and counter writes are paced
 *     as display writes.
 *     Mutant: fuzz/mutants/codec-round-trip.patch, the fader LSB shifted by 3 instead of 4;
 *     seed fader-full.
 *   - text: what the text helpers accept, the encoders take: diginet_scribble_text() writes
 *     n 7-bit bytes and reports at most the text's length as used, and those bytes encode;
 *     digits and dots diginet_counter_text() accepts encode; diginet_meter_segments() counts
 *     exactly the thermometers diginet_meter_mask() makes and refuses every other mask; and
 *     the ring helpers light the LEDs they name.
 *     Mutant: fuzz/mutants/codec-text.patch, the counter text accepts a dot on the rightmost
 *     digit, which has no bit; seed counter-text-last-dot.
 */
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

#include "fuzz.h"

#define OPS_MAX  256
#define TEXT_MAX 64

/* one encoder call: what it was given and what it returned */
struct call {
	int kind;
	const struct diginet_personality *p;
	unsigned a, b, c;     /* strip/button/channel/addr, value/id/mask/bits, on/right */
	int delta;
	uint8_t bytes[DIGINET_CMD_MAX_LEN];  /* scribble chars, counter digits, sysex payload */
	size_t n;
	int rc;
	struct diginet_cmd before, out;
};

static int seven_bit(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] & 0x80)
			return 0;
	return 1;
}

FUZZ_CHECK check_refusal(const struct call *k)
{
	if (k->kind == 11 && k->b == DIGINET_FN_SYSTEM) {
		/* function 0x70 writes the desk's memory: never made, and nothing written; with a
		 * device byte the wire can carry, refused as such */
		if (k->rc == DIGINET_OK || memcmp(&k->out, &k->before, sizeof k->out) ||
		    (k->a <= 0x7f && k->rc != DIGINET_E_REFUSED))
			abort();
		return;
	}
	if (k->rc == DIGINET_OK && diginet_body_check(k->out.bytes, k->out.len) != DIGINET_OK)
		abort();
}

/* whether the arguments are what the encoder's comment accepts */
static int in_range(const struct call *k)
{
	const struct diginet_personality *p = k->p;
	switch (k->kind) {
	case 0: return k->a < p->strips && k->b <= DIGINET_FADER_MAX;
	case 1: return k->a <= 0x7f && k->b <= 0x3f;
	case 2: return k->a < p->strips;
	case 3: return k->a < p->strips && k->delta >= -64 && k->delta <= 63;
	case 4: return k->delta >= -64 && k->delta <= 63;
	case 5: return k->a < p->strips && k->b < 1u << DIGINET_RING_LEDS;
	case 6: return k->a < 0x20 && k->b <= DIGINET_METER_SEGMENTS;
	case 7: return k->a < p->strips && k->b <= 0x7f;
	case 8: return k->b <= 0x7f;
	case 9: return k->a <= 0x7f && seven_bit(k->bytes, p->scribble_chars);
	case 10: return k->b <= 0x7f && seven_bit(k->bytes, DIGINET_COUNTER_DIGITS);
	default: /* 11 */
		return k->a <= 0x7f && k->b <= 0x7f && k->n + 5 <= DIGINET_CMD_MAX_LEN &&
		       seven_bit(k->bytes, k->n);
	}
}

FUZZ_CHECK check_range(const struct call *k)
{
	if (k->kind == 11 && k->b == DIGINET_FN_SYSTEM)
		return;   /* the refusal property's */
	int needs_p = k->kind != 1 && k->kind != 4 && k->kind != 11;
	int ok = needs_p && !k->p ? 0 : in_range(k);
	if (needs_p && !k->p && k->rc != DIGINET_E_ARG)
		abort();
	/* success exactly in range */
	if ((k->rc == DIGINET_OK) != ok)
		abort();
	/* a failure is a failure code, with the command as it was */
	if (k->rc != DIGINET_OK &&
	    ((k->rc != DIGINET_E_RANGE && k->rc != DIGINET_E_ARG && k->rc != DIGINET_E_SPACE) ||
	     memcmp(&k->out, &k->before, sizeof k->out)))
		abort();
}

FUZZ_CHECK check_round_trip(const struct call *k)
{
	const struct diginet_personality *p = k->p;
	const struct diginet_cmd *o = &k->out;
	struct diginet_decoder d;
	struct diginet_event ev;
	uint32_t key;
	uint8_t kind;
	int display = 0;

	diginet_decoder_init(&d, p, o->bytes, o->len);
	/* one event, then the end: every byte used */
	if (o->len == 0 || o->len > DIGINET_CMD_MAX_LEN || diginet_decoder_next(&d, &ev) != 1)
		abort();
	struct diginet_event last;
	if (diginet_decoder_next(&d, &last) != 0)
		abort();
	switch (k->kind) {
	case 0:
		kind = DIGINET_EV_FADER, key = DIGINET_KEY(DIGINET_KEY_FADER, k->a);
		if (ev.strip != k->a || ev.value != k->b || ev.lsb_missing)
			abort();
		break;
	case 1:
		key = DIGINET_KEY(DIGINET_KEY_LED, k->a << 8 | k->b);
		if (k->b >= DIGINET_ZONE_FIRST && k->b <= DIGINET_ZONE_LAST)
			kind = DIGINET_EV_SECTION_BUTTON;
		else
			kind = k->a == DIGINET_BTN_TOUCH ? DIGINET_EV_TOUCH : DIGINET_EV_STRIP_BUTTON;
		if (ev.button != k->a || ev.on != !!k->c ||
		    (kind == DIGINET_EV_SECTION_BUTTON ? ev.zone : ev.strip) != k->b)
			abort();
		break;
	case 2:
		kind = DIGINET_EV_TOUCH, key = DIGINET_KEY(DIGINET_KEY_INPUT, 0);
		if (ev.strip != k->a || ev.on != !!k->c)
			abort();
		break;
	case 3:
		kind = DIGINET_EV_VPOT, key = DIGINET_KEY(DIGINET_KEY_INPUT, 0);
		if (ev.strip != k->a || ev.delta != k->delta)
			abort();
		break;
	case 4:
		kind = DIGINET_EV_JOG, key = DIGINET_KEY(DIGINET_KEY_INPUT, 0);
		if (ev.delta != k->delta)
			abort();
		break;
	case 5:
		kind = DIGINET_EV_RING, key = DIGINET_KEY(DIGINET_KEY_RING, k->a);
		if (ev.strip != k->a || ev.mask != k->b || ev.device != p->device)
			abort();
		break;
	case 6:
		kind = DIGINET_EV_METER;
		key = DIGINET_KEY(DIGINET_KEY_METER, k->a | (k->c ? 0x20 : 0));
		if (ev.strip != k->a || ev.right != !!k->c || ev.mask != diginet_meter_mask(k->b) ||
		    ev.segments != (int)k->b || ev.device != p->device)
			abort();
		break;
	case 7:
	case 8: {
		unsigned addr = k->kind == 7 ? k->a : p->counter_addr;
		kind = DIGINET_EV_STRIP_LEDS, key = DIGINET_KEY(DIGINET_KEY_LEDS, addr);
		if (ev.addr != addr || ev.mask != k->b || ev.device != p->device)
			abort();
		break;
	}
	case 9:
		kind = DIGINET_EV_SCRIBBLE, key = DIGINET_KEY(DIGINET_KEY_SCRIBBLE, k->a), display = 1;
		if (ev.addr != k->a || ev.len != p->scribble_chars || ev.text[ev.len] != '\0' ||
		    memcmp(ev.text, k->bytes, ev.len) || ev.device != p->device)
			abort();
		break;
	case 10:
		kind = DIGINET_EV_COUNTER, key = DIGINET_KEY(DIGINET_KEY_COUNTER, p->counter_addr), display = 1;
		if (ev.addr != p->counter_addr || ev.dots != k->b ||
		    memcmp(ev.seg, k->bytes, DIGINET_COUNTER_DIGITS) || ev.device != p->device)
			abort();
		break;
	default: /* 11: the message as given, whatever the decoder makes of its function */
		kind = (uint8_t)ev.kind, key = 0;
		display = k->b == DIGINET_FN_SCRIBBLE || k->b == DIGINET_FN_COUNTER;
		if (ev.msg.status != 0xf0 || ev.msg.sysex != o->bytes + 1 || ev.msg.sysex_len != k->n + 3 ||
		    o->bytes[2] != k->a || o->bytes[3] != k->b || memcmp(o->bytes + 4, k->bytes, k->n))
			abort();
		break;
	}
	if (ev.kind != kind || o->key != key || o->display != display)
		abort();
}

FUZZ_CHECK check_text_scribble(const char *text, const struct diginet_personality *p, unsigned addr)
{
	uint8_t chars[DIGINET_SCRIBBLE_MAX];
	struct diginet_cmd out;

	memset(chars, 0xff, sizeof chars);
	size_t used = diginet_scribble_text(text, chars, p->scribble_chars);
	if (used > strlen(text) || !seven_bit(chars, p->scribble_chars))
		abort();
	if (diginet_scribble_encode(p, addr & 0x7f, chars, &out) != DIGINET_OK)
		abort();
}

FUZZ_CHECK check_text_counter(const char *text, const struct diginet_personality *p)
{
	uint8_t seg[DIGINET_COUNTER_DIGITS], dots = 0;
	struct diginet_cmd out;

	int r = diginet_counter_text(text, seg, &dots);
	if (r != DIGINET_OK && r != DIGINET_E_RANGE)
		abort();
	if (r == DIGINET_OK && diginet_counter_encode(p, seg, dots, &out) != DIGINET_OK)
		abort();
}

FUZZ_CHECK check_text_masks(unsigned n, uint16_t mask)
{
	unsigned want = n > DIGINET_METER_SEGMENTS ? DIGINET_METER_SEGMENTS : n;
	if (diginet_meter_segments(diginet_meter_mask(n)) != (int)want)
		abort();
	/* a thermometer of up to 14 segments is counted, every other mask refused */
	int thermo = (mask & (mask + 1u)) == 0 && mask < 1u << DIGINET_METER_SEGMENTS;
	int seg = diginet_meter_segments(mask);
	if (thermo ? seg < 0 || diginet_meter_mask((unsigned)seg) != mask : seg != -1)
		abort();
	uint16_t dot = diginet_ring_dot(n), fill = diginet_ring_fill(n);
	if (n < DIGINET_RING_LEDS ? dot != 1u << n : dot != 0)
		abort();
	if (n <= DIGINET_RING_LEDS ? fill != (1u << n) - 1 : fill != 0)
		abort();
}

static void text_arg(struct fuzz_in *in, char *text)
{
	const uint8_t *p;
	size_t n = fuzz_take(in, fuzz_u16(in) % (TEXT_MAX + 1), &p);
	memcpy(text, p, n);
	text[n] = '\0';
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const enum diginet_desk DESK[3] = {
		DIGINET_DESK_UNKNOWN, DIGINET_DESK_CONTROL24, DIGINET_DESK_PROCONTROL,
	};
	char text[TEXT_MAX + 1];

	if (size >= FUZZ_INPUT_MAX)
		return 0;
	struct fuzz_in in = fuzz_in(data, size);
	for (int ops = 0; ops < OPS_MAX && in.n; ops++) {
		uint8_t op = fuzz_u8(&in);
		struct call k;
		const uint8_t *pp;
		memset(&k, 0, sizeof k);
		k.kind = op % 15;
		k.p = diginet_personality_of(DESK[op / 15 % 3]);
		const struct diginet_personality *tp = k.p ? k.p : diginet_personality_of(DIGINET_DESK_CONTROL24);
		memset(&k.before, 0xa5, sizeof k.before);
		memcpy(&k.out, &k.before, sizeof k.out);   /* padding too: it is compared */
		switch (k.kind) {
		case 0:
			k.a = fuzz_u8(&in), k.b = fuzz_u16(&in);
			k.rc = diginet_fader_encode(k.p, k.a, k.b, &k.out);
			break;
		case 1:
			k.a = fuzz_u8(&in), k.b = fuzz_u8(&in), k.c = fuzz_u8(&in) & 1;
			k.rc = diginet_button_encode(k.a, k.b, (int)k.c, &k.out);
			break;
		case 2:
			k.a = fuzz_u8(&in), k.c = fuzz_u8(&in) & 1;
			k.rc = diginet_touch_encode(k.p, k.a, (int)k.c, &k.out);
			break;
		case 3:
			k.a = fuzz_u8(&in), k.delta = (int16_t)fuzz_u16(&in);
			k.rc = diginet_vpot_encode(k.p, k.a, k.delta, &k.out);
			break;
		case 4:
			k.delta = (int16_t)fuzz_u16(&in);
			k.rc = diginet_jog_encode(k.delta, &k.out);
			break;
		case 5:
			k.a = fuzz_u8(&in), k.b = fuzz_u16(&in);
			k.rc = diginet_ring_encode(k.p, k.a, (uint16_t)k.b, &k.out);
			break;
		case 6:
			k.a = fuzz_u8(&in), k.c = fuzz_u8(&in) & 1, k.b = fuzz_u8(&in);
			k.rc = diginet_meter_encode(k.p, k.a, (int)k.c, k.b, &k.out);
			break;
		case 7:
			k.a = fuzz_u8(&in), k.b = fuzz_u8(&in);
			k.rc = diginet_strip_leds_encode(k.p, k.a, k.b, &k.out);
			break;
		case 8:
			k.b = fuzz_u8(&in);
			k.rc = diginet_counter_leds_encode(k.p, k.b, &k.out);
			break;
		case 9:
			k.a = fuzz_u8(&in);
			for (int i = 0; i < DIGINET_SCRIBBLE_MAX; i++)
				k.bytes[i] = fuzz_u8(&in);
			k.rc = diginet_scribble_encode(k.p, k.a, k.bytes, &k.out);
			break;
		case 10:
			k.b = fuzz_u8(&in);
			for (int i = 0; i < DIGINET_COUNTER_DIGITS; i++)
				k.bytes[i] = fuzz_u8(&in);
			k.rc = diginet_counter_encode(k.p, k.bytes, (uint8_t)k.b, &k.out);
			break;
		case 11:
			k.a = fuzz_u8(&in), k.b = fuzz_u8(&in);
			k.n = fuzz_take(&in, fuzz_u8(&in) % (DIGINET_CMD_MAX_LEN + 1), &pp);
			memcpy(k.bytes, pp, k.n);
			k.rc = diginet_sysex_encode((uint8_t)k.a, (uint8_t)k.b, k.bytes, k.n, &k.out);
			break;
		case 12:
			k.a = fuzz_u8(&in);
			text_arg(&in, text);
			check_text_scribble(text, tp, k.a);
			continue;
		case 13:
			text_arg(&in, text);
			check_text_counter(text, tp);
			continue;
		default: {
			unsigned n = fuzz_u8(&in);
			check_text_masks(n, fuzz_u16(&in));
			continue;
		}
		}
		check_refusal(&k);
		check_range(&k);
		if (k.rc == DIGINET_OK)
			check_round_trip(&k);
	}
	return 0;
}
