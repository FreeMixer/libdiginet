// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* Commands to control events, both directions: what the desk sends (faders, touch, keys,
 * V-Pots, jog) and what a host sends it (LEDs, rings, meters, scribble strips, counter). The
 * running status is already expanded by the cursor; a fader's MSB and LSB are paired here. */
#include <string.h>

#include <diginet/diginet_codec.h>

void diginet_decoder_init(struct diginet_decoder *d, const struct diginet_personality *p,
			  const uint8_t *body, size_t len)
{
	if (!d)
		return;
	diginet_cursor_init(&d->c, body, len);
	d->p = p ? p : diginet_personality_of(DIGINET_DESK_CONTROL24);
}

static void decode_note(const struct diginet_msg *m, struct diginet_event *ev)
{
	uint8_t id = m->d2 & 0x3f;
	ev->on = (m->d2 & 0x40) != 0;
	ev->button = m->d1;
	if (id >= DIGINET_ZONE_FIRST && id <= DIGINET_ZONE_LAST) {
		ev->kind = DIGINET_EV_SECTION_BUTTON;
		ev->zone = id;
	} else if (m->d1 == DIGINET_BTN_TOUCH) {
		ev->kind = DIGINET_EV_TOUCH;
		ev->strip = id;
	} else {
		ev->kind = DIGINET_EV_STRIP_BUTTON;
		ev->strip = id;
	}
}

static void decode_sysex(const struct diginet_decoder *d, const struct diginet_msg *m,
			 struct diginet_event *ev)
{
	const uint8_t *s = m->sysex;
	size_t n = m->sysex_len;
	(void)d;
	ev->kind = DIGINET_EV_OTHER;
	if (n < 3 || s[0] != DIGINET_SYSEX_MAKER)
		return;
	ev->device = s[1];
	const uint8_t *pl = s + 3;
	size_t pn = n - 3;
	switch (s[2]) {
	case DIGINET_FN_RING:
		if (pn != 3)
			return;
		ev->kind = DIGINET_EV_RING;
		ev->strip = pl[0] & 0x3f;
		ev->mask = (pl[0] & 0x40) ? 1 : 0;
		for (int k = 0; k < 7; k++) {
			if (pl[1] & (1u << (6 - k)))
				ev->mask |= (uint16_t)(1u << (1 + k));
			if (pl[2] & (1u << (6 - k)))
				ev->mask |= (uint16_t)(1u << (8 + k));
		}
		return;
	case DIGINET_FN_METER:
		if (pn != 3)
			return;
		ev->kind = DIGINET_EV_METER;
		ev->addr = pl[0];
		ev->strip = pl[0] & 0x1f;
		ev->right = (pl[0] & 0x20) != 0;
		ev->mask = (uint16_t)((pl[1] & 0x7f) << 7 | (pl[2] & 0x7f));
		ev->segments = (int8_t)diginet_meter_segments(ev->mask);
		return;
	case DIGINET_FN_LEDS:
		if (pn != 2)
			return;
		ev->kind = DIGINET_EV_STRIP_LEDS;
		ev->addr = pl[0];
		ev->strip = pl[0];
		ev->mask = pl[1];
		return;
	case DIGINET_FN_SCRIBBLE:
		if (pn < 3 || pn - 2 > DIGINET_SCRIBBLE_MAX)
			return;
		ev->kind = DIGINET_EV_SCRIBBLE;
		ev->addr = pl[0];
		ev->len = (uint8_t)(pn - 2);
		memcpy(ev->text, pl + 2, ev->len);
		ev->text[ev->len] = '\0';
		return;
	case DIGINET_FN_COUNTER:
		if (pn != 2 + DIGINET_COUNTER_DIGITS)
			return;
		ev->kind = DIGINET_EV_COUNTER;
		ev->addr = pl[0];
		ev->dots = pl[1];
		for (int k = 0; k < DIGINET_COUNTER_DIGITS; k++)
			ev->seg[DIGINET_COUNTER_DIGITS - 1 - k] = pl[2 + k];
		return;
	case DIGINET_FN_SYSTEM:
		ev->kind = DIGINET_EV_SYSTEM;
		return;
	default:
		return;
	}
}

int diginet_decoder_next(struct diginet_decoder *d, struct diginet_event *ev)
{
	struct diginet_msg m;
	if (!d || !ev)
		return DIGINET_E_ARG;
	int r = diginet_msg_next(&d->c, &m);
	if (r != 1)
		return r;
	memset(ev, 0, sizeof *ev);
	ev->msg = m;
	ev->kind = DIGINET_EV_OTHER;

	if ((m.status & 0xf0) == 0x90) {
		decode_note(&m, ev);
		return 1;
	}
	if (m.status == 0xf0) {
		decode_sysex(d, &m, ev);
		return 1;
	}
	if ((m.status & 0xf0) != 0xb0)
		return 1;

	if (m.d1 < 0x20) {
		/* A fader MSB; the LSB is the next control change on 0x20 + tt, if it is there. */
		ev->kind = DIGINET_EV_FADER;
		ev->strip = m.d1;
		ev->value = (uint16_t)(m.d2 << 3);
		struct diginet_cursor peek = d->c;
		struct diginet_msg lsb;
		if (diginet_msg_next(&peek, &lsb) == 1 && (lsb.status & 0xf0) == 0xb0 &&
		    lsb.d1 == 0x20 + m.d1) {
			ev->value |= (uint16_t)((lsb.d2 >> 4) & 7);
			d->c = peek;
		} else {
			ev->lsb_missing = 1;
		}
		return 1;
	}
	if (m.d1 == DIGINET_JOG_CC) {
		ev->kind = DIGINET_EV_JOG;
		ev->delta = (int16_t)(m.d2 - 64);
		return 1;
	}
	if (m.d1 >= 0x40 && m.d1 < 0x40 + DIGINET_ZONE_FIRST) {
		ev->kind = DIGINET_EV_VPOT;
		ev->strip = (uint8_t)(m.d1 - 0x40);
		ev->delta = (int16_t)(m.d2 - 64);
		return 1;
	}
	return 1;
}
