// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* Encoders for every control, and the 0x70 refusal (docs/protocol.md, "The command set";
 * the assumptions A1-A7 are the section "Where the sources are silent"). */
#include <string.h>

#include <diginet/diginet_codec.h>

/* ---- personalities ---------------------------------------------------------------- */

static const struct diginet_personality personalities[] = {
	{ DIGINET_DESK_CONTROL24,  "CNTRL|24", 0x01, 24, 4, 0x19 },
	{ DIGINET_DESK_PROCONTROL, "MAINUNIT", 0x00,  8, 8, 0x09 },
};

const struct diginet_personality *diginet_personality_from_name(const char *name)
{
	if (!name)
		return NULL;
	for (size_t i = 0; i < sizeof personalities / sizeof personalities[0]; i++)
		if (!strcmp(name, personalities[i].announce_name))
			return &personalities[i];
	return NULL;
}

const struct diginet_personality *diginet_personality_of(enum diginet_desk desk)
{
	for (size_t i = 0; i < sizeof personalities / sizeof personalities[0]; i++)
		if (personalities[i].desk == desk)
			return &personalities[i];
	return NULL;
}

/* ---- helpers ------------------------------------------------------------------------ */

static void put3(struct diginet_cmd *out, uint8_t a, uint8_t b, uint8_t c, uint32_t key)
{
	out->bytes[0] = a;
	out->bytes[1] = b;
	out->bytes[2] = c;
	out->len = 3;
	out->display = 0;
	out->key = key;
}

int diginet_body_check(const uint8_t *body, size_t len)
{
	struct diginet_cursor c;
	struct diginet_msg m;
	int r;
	diginet_cursor_init(&c, body, len);
	while ((r = diginet_msg_next(&c, &m)) != 0) {
		if (r == 1 && m.status == 0xf0 && m.sysex_len >= 3 &&
		    m.sysex[0] == DIGINET_SYSEX_MAKER && m.sysex[2] == DIGINET_FN_SYSTEM)
			return DIGINET_E_REFUSED;
	}
	/* A cut-short F0 13 xx 70 has no F7 for the cursor to find: look for the prefix too. */
	for (size_t i = 0; i + 3 < len; i++)
		if (body[i] == 0xf0 && body[i + 1] == DIGINET_SYSEX_MAKER &&
		    body[i + 3] == DIGINET_FN_SYSTEM)
			return DIGINET_E_REFUSED;
	return DIGINET_OK;
}

int diginet_sysex_encode(uint8_t device, uint8_t fn, const uint8_t *payload, size_t len,
			 struct diginet_cmd *out)
{
	if (!out || (len && !payload) || device > 0x7f)
		return DIGINET_E_ARG;
	if (fn == DIGINET_FN_SYSTEM)
		return DIGINET_E_REFUSED;
	if (fn > 0x7f)
		return DIGINET_E_RANGE;
	if (len + 5 > DIGINET_CMD_MAX_LEN)
		return DIGINET_E_SPACE;
	for (size_t i = 0; i < len; i++)
		if (payload[i] & 0x80)
			return DIGINET_E_RANGE;
	out->bytes[0] = 0xf0;
	out->bytes[1] = DIGINET_SYSEX_MAKER;
	out->bytes[2] = device;
	out->bytes[3] = fn;
	if (len)
		memcpy(out->bytes + 4, payload, len);
	out->bytes[4 + len] = 0xf7;
	out->len = (uint8_t)(len + 5);
	out->display = fn == DIGINET_FN_SCRIBBLE || fn == DIGINET_FN_COUNTER;
	out->key = 0;
	return DIGINET_OK;
}

/* ---- faders, buttons, V-Pots ------------------------------------------------------------ */

int diginet_fader_encode(const struct diginet_personality *p, unsigned strip, unsigned value,
			 struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	if (strip >= p->strips || value > DIGINET_FADER_MAX)
		return DIGINET_E_RANGE;
	out->bytes[0] = 0xb0;
	out->bytes[1] = (uint8_t)strip;
	out->bytes[2] = (uint8_t)(value >> 3);
	out->bytes[3] = (uint8_t)(0x20 + strip);
	out->bytes[4] = (uint8_t)((value & 7) << 4);
	out->len = 5;
	out->display = 0;
	out->key = DIGINET_KEY(DIGINET_KEY_FADER, strip);
	return DIGINET_OK;
}

int diginet_button_encode(unsigned button, unsigned id, int on, struct diginet_cmd *out)
{
	if (!out)
		return DIGINET_E_ARG;
	if (button > 0x7f || id > 0x3f)
		return DIGINET_E_RANGE;
	put3(out, 0x90, (uint8_t)button, (uint8_t)((on ? 0x40 : 0) | id),
	     DIGINET_KEY(DIGINET_KEY_LED, button << 8 | id));
	return DIGINET_OK;
}

int diginet_touch_encode(const struct diginet_personality *p, unsigned strip, int touched,
			 struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	if (strip >= p->strips)
		return DIGINET_E_RANGE;
	int r = diginet_button_encode(DIGINET_BTN_TOUCH, strip, touched, out);
	out->key = DIGINET_KEY(DIGINET_KEY_INPUT, 0);
	return r;
}

static int delta_byte(int delta, uint8_t *b)
{
	if (delta < -64 || delta > 63)
		return DIGINET_E_RANGE;
	*b = (uint8_t)(delta + 64);
	return DIGINET_OK;
}

int diginet_vpot_encode(const struct diginet_personality *p, unsigned strip, int delta,
			struct diginet_cmd *out)
{
	uint8_t b;
	if (!p || !out)
		return DIGINET_E_ARG;
	if (strip >= p->strips || delta_byte(delta, &b))
		return DIGINET_E_RANGE;
	put3(out, 0xb0, (uint8_t)(0x40 | strip), b, DIGINET_KEY(DIGINET_KEY_INPUT, 0));
	return DIGINET_OK;
}

int diginet_jog_encode(int delta, struct diginet_cmd *out)
{
	uint8_t b;
	if (!out)
		return DIGINET_E_ARG;
	if (delta_byte(delta, &b))
		return DIGINET_E_RANGE;
	put3(out, 0xb0, DIGINET_JOG_CC, b, DIGINET_KEY(DIGINET_KEY_INPUT, 0));
	return DIGINET_OK;
}

/* ---- rings ---------------------------------------------------------------------------- */

uint16_t diginet_ring_dot(unsigned pos)
{
	return pos < DIGINET_RING_LEDS ? (uint16_t)(1u << pos) : 0;
}

uint16_t diginet_ring_fill(unsigned n)
{
	return n <= DIGINET_RING_LEDS ? (uint16_t)((1u << n) - 1) : 0;
}

int diginet_ring_encode(const struct diginet_personality *p, unsigned strip, uint16_t mask,
			struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	if (strip >= p->strips || mask >> DIGINET_RING_LEDS)
		return DIGINET_E_RANGE;
	uint8_t b1 = 0, b2 = 0;
	for (int k = 0; k < 7; k++) {
		if (mask & (1u << (1 + k)))
			b1 |= (uint8_t)(1u << (6 - k));   /* LED 2 + k */
		if (mask & (1u << (8 + k)))
			b2 |= (uint8_t)(1u << (6 - k));   /* LED 9 + k */
	}
	uint8_t pl[3] = { (uint8_t)(strip | ((mask & 1u) ? 0x40 : 0)), b1, b2 };
	int r = diginet_sysex_encode(p->device, DIGINET_FN_RING, pl, 3, out);
	if (r == DIGINET_OK)
		out->key = DIGINET_KEY(DIGINET_KEY_RING, strip);
	return r;
}

/* ---- meters --------------------------------------------------------------------------- */

uint16_t diginet_meter_mask(unsigned segments)
{
	if (segments > DIGINET_METER_SEGMENTS)
		segments = DIGINET_METER_SEGMENTS;
	return (uint16_t)((1u << segments) - 1);
}

int diginet_meter_segments(uint16_t mask)
{
	int n = 0;
	while (n < DIGINET_METER_SEGMENTS && (mask & (1u << n)))
		n++;
	return (mask >> n) ? -1 : n;
}

int diginet_meter_encode(const struct diginet_personality *p, unsigned channel, int right,
			 unsigned segments, struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	if (channel >= 0x20 || segments > DIGINET_METER_SEGMENTS)
		return DIGINET_E_RANGE;
	uint16_t m = diginet_meter_mask(segments);
	uint8_t ch = (uint8_t)(channel | (right ? 0x20 : 0));
	uint8_t pl[3] = { ch, (uint8_t)(m >> 7), (uint8_t)(m & 0x7f) };
	int r = diginet_sysex_encode(p->device, DIGINET_FN_METER, pl, 3, out);
	if (r == DIGINET_OK)
		out->key = DIGINET_KEY(DIGINET_KEY_METER, ch);
	return r;
}

/* ---- automation and counter-mode LEDs ----------------------------------------------- */

static int leds_encode(const struct diginet_personality *p, unsigned addr, unsigned bits,
		       struct diginet_cmd *out)
{
	if (bits > 0x7f)
		return DIGINET_E_RANGE;
	uint8_t pl[2] = { (uint8_t)addr, (uint8_t)bits };
	int r = diginet_sysex_encode(p->device, DIGINET_FN_LEDS, pl, 2, out);
	if (r == DIGINET_OK)
		out->key = DIGINET_KEY(DIGINET_KEY_LEDS, addr);
	return r;
}

int diginet_strip_leds_encode(const struct diginet_personality *p, unsigned strip,
			      unsigned bits, struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	if (strip >= p->strips)
		return DIGINET_E_RANGE;
	return leds_encode(p, strip, bits, out);
}

int diginet_counter_leds_encode(const struct diginet_personality *p, unsigned bits,
				struct diginet_cmd *out)
{
	if (!p || !out)
		return DIGINET_E_ARG;
	return leds_encode(p, p->counter_addr, bits, out);
}

/* ---- scribble strips -------------------------------------------------------------- */

size_t diginet_scribble_text(const char *text, uint8_t *out, size_t n)
{
	size_t i = 0, o = 0;
	if (!out)
		return 0;
	while (text && text[i] && o < n) {
		unsigned char c = (unsigned char)text[i];
		if (c == '.' && text[i + 1] >= '1' && text[i + 1] <= '9') {
			out[o++] = (uint8_t)(text[i + 1] - 26);  /* dot plus small digit */
			i += 2;
			continue;
		}
		out[o++] = c < 0x80 ? c : '?';
		i++;
	}
	while (o < n)
		out[o++] = ' ';
	return i;
}

int diginet_scribble_encode(const struct diginet_personality *p, unsigned addr,
			    const uint8_t *chars, struct diginet_cmd *out)
{
	if (!p || !out || !chars)
		return DIGINET_E_ARG;
	if (addr > 0x7f)
		return DIGINET_E_RANGE;
	uint8_t pl[2 + DIGINET_SCRIBBLE_MAX];
	pl[0] = (uint8_t)addr;
	pl[1] = 0x00;
	memcpy(pl + 2, chars, p->scribble_chars);
	int r = diginet_sysex_encode(p->device, DIGINET_FN_SCRIBBLE, pl,
				     2u + p->scribble_chars, out);
	if (r == DIGINET_OK)
		out->key = DIGINET_KEY(DIGINET_KEY_SCRIBBLE, addr);
	return r;
}

/* ---- the counter ---------------------------------------------------------------------- */

/* Bit 0 = a ... bit 6 = g (docs/protocol.md, A3). */
int diginet_seg7(char c)
{
	switch (c) {
	case '0': return 0x3f; case '1': return 0x06; case '2': return 0x5b; case '3': return 0x4f;
	case '4': return 0x66; case '5': return 0x6d; case '6': return 0x7d; case '7': return 0x07;
	case '8': return 0x7f; case '9': return 0x6f;
	case 'A': case 'a': return 0x77;
	case 'b': case 'B': return 0x7c;
	case 'C': case 'c': return 0x39;
	case 'd': case 'D': return 0x5e;
	case 'E': case 'e': return 0x79;
	case 'F': case 'f': return 0x71;
	case 'H': return 0x76;
	case 'h': return 0x74;
	case 'J': case 'j': return 0x1e;
	case 'L': case 'l': return 0x38;
	case 'o': case 'O': return 0x5c;
	case 'P': case 'p': return 0x73;
	case 'r': case 'R': return 0x50;
	case 'S': case 's': return 0x6d;
	case 'U': case 'u': return 0x3e;
	case 'Y': case 'y': return 0x6e;
	case 'Z': case 'z': return 0x5b;
	case '-': return 0x40;
	case ' ': return 0x00;
	default:  return -1;
	}
}

int diginet_counter_text(const char *text, uint8_t seg[DIGINET_COUNTER_DIGITS], uint8_t *dots)
{
	uint8_t s[DIGINET_COUNTER_DIGITS];
	int dot[DIGINET_COUNTER_DIGITS] = { 0 };
	int n = 0;
	if (!text || !seg || !dots)
		return DIGINET_E_ARG;
	for (const char *t = text; *t; t++) {
		if (*t == '.' && n > 0 && !dot[n - 1]) {
			dot[n - 1] = 1;
			continue;
		}
		int v = diginet_seg7(*t == '.' ? ' ' : *t);
		if (v < 0 || n == DIGINET_COUNTER_DIGITS)
			return DIGINET_E_RANGE;
		if (*t == '.')
			dot[n] = 1;
		s[n++] = (uint8_t)v;
	}
	int lead = DIGINET_COUNTER_DIGITS - n;   /* right-aligned */
	uint8_t d = 0;
	for (int i = 0; i < DIGINET_COUNTER_DIGITS; i++) {
		int from = i - lead;
		seg[i] = from >= 0 ? s[from] : 0;
		if (from >= 0 && dot[from]) {
			if (i == 0)
				return DIGINET_E_RANGE;  /* the leftmost dot has no bit (A5) */
			d |= DIGINET_COUNTER_DOT(i);
		}
	}
	*dots = d;
	return DIGINET_OK;
}

int diginet_counter_encode(const struct diginet_personality *p,
			   const uint8_t seg[DIGINET_COUNTER_DIGITS], uint8_t dots,
			   struct diginet_cmd *out)
{
	if (!p || !out || !seg)
		return DIGINET_E_ARG;
	uint8_t pl[2 + DIGINET_COUNTER_DIGITS];
	pl[0] = p->counter_addr;
	pl[1] = dots;
	for (int k = 0; k < DIGINET_COUNTER_DIGITS; k++)
		pl[2 + k] = seg[DIGINET_COUNTER_DIGITS - 1 - k];   /* d8 first: rightmost first */
	int r = diginet_sysex_encode(p->device, DIGINET_FN_COUNTER, pl, sizeof pl, out);
	if (r == DIGINET_OK)
		out->key = DIGINET_KEY(DIGINET_KEY_COUNTER, p->counter_addr);
	return r;
}
