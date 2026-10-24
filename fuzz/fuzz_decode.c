// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE COMMAND GRAMMAR (src/diginet_msg.c, src/diginet_decode.c and the
 * refusal of src/diginet_codec.c), the reading of protocol/diginet.ksy's `commands`,
 * `message` and `sysex` over the body of a data frame, and the events made of it.
 *
 * Input: [sel] then the rest.
 *   sel % 3 picks the personality the decoder reads addresses with: none (the decoder's
 *   default), Control|24, ProControl.
 *   sel & 0x80: the rest is one whole Ethernet frame, parsed by diginet_frame_parse(), and its
 *   body is decoded; a frame the parser refuses decodes as an empty body. Otherwise the rest
 *   is the body itself.
 * The rest is copied into an allocation of exactly its length.
 *
 * Every message of the body is read twice: by the cursor alone (diginet_msg_next) and by the
 * decoder (diginet_decoder_next), which runs its own cursor; the two must agree.
 *
 * Properties, each an abort():
 *   - cursor: every call moves the cursor forward, never past the body, and ends; a message
 *     lies inside the body at the cursor's place: an F0 message runs to its first F7 with
 *     its payload between them and cancels running status; a channel message has its status
 *     byte or the running status in force, then one data byte for C0 and D0 and two for
 *     every other status (diginet.ksy, `data2`), each under 0x80. A refused byte is a data
 *     byte with no running status (E_NO_STATUS) or a status byte F1..FF (E_STATUS), stepped
 *     over; a message cut short (E_TRUNCATED) stops at the end of the body or at the status
 *     byte where a data byte was due.
 *     Mutant: fuzz/mutants/decode-cursor.patch, the first data byte of a channel message is
 *     not checked for bit 7; seed status-for-data.
 *   - events: the decoder returns what the cursor returns, in the same order, each event
 *     carrying the message it came from; its kind is that message's family (90 a button, a
 *     touch or a zone key; B0 a fader, a jog, a V-Pot or other; F0 a sysex kind); a fader
 *     MSB (B0 tt, tt < 0x20) takes the next message as its LSB exactly when that message is
 *     B0 (20+tt), the position then MSB << 3 | LSB >> 4 & 7 (diginet_codec.h), and else says
 *     lsb_missing.
 *     Mutant: fuzz/mutants/decode-events.patch, the decoder reads the LSB but does not step
 *     past it; seed fader_move.
 *   - refusal: the system family, F0 13 xx 70, is never encoded. A body holding one, whole
 *     or cut short, is refused by diginet_body_check() and by diginet_frame_build(); the
 *     decoder reports it as DIGINET_EV_SYSTEM and no other sysex as that; and a body is
 *     refused only when an F0 13 xx 70 is in it.
 *     Mutant: fuzz/mutants/decode-refusal.patch, the scan for a cut-short system message
 *     misses one that ends the body; seed system-cut-short.
 */
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

#include "fuzz.h"

/* a message the decoder or a refusal must know: where an F0 13 xx 70 starts */
static int system_at(const uint8_t *b, size_t len, size_t at)
{
	return at + 3 < len && b[at] == 0xf0 && b[at + 1] == DIGINET_SYSEX_MAKER &&
	       b[at + 3] == DIGINET_FN_SYSTEM;
}

static int is_system(const struct diginet_msg *m)
{
	return m->status == 0xf0 && m->sysex_len >= 3 && m->sysex[0] == DIGINET_SYSEX_MAKER &&
	       m->sysex[2] == DIGINET_FN_SYSTEM;
}

FUZZ_CHECK check_cursor(const uint8_t *b, size_t len, size_t at, uint8_t status_in, int r,
			const struct diginet_msg *m, const struct diginet_cursor *c)
{
	if (r == 0) {
		/* the end, and only at the end */
		if (at < len || c->pos != at)
			abort();
		return;
	}
	/* forward, never past the body */
	if (c->pos <= at || c->pos > len)
		abort();
	switch (r) {
	case 1:
		break;
	case DIGINET_E_NO_STATUS:
		if (b[at] >= 0x80 || status_in || c->pos != at + 1)
			abort();
		return;
	case DIGINET_E_STATUS:
		if (b[at] <= 0xf0 || c->pos != at + 1 || c->status)
			abort();
		return;
	case DIGINET_E_TRUNCATED:
		/* at the end, or at the status byte that came where a data byte was due */
		if (c->pos != len && !(b[c->pos] & 0x80))
			abort();
		if (b[at] == 0xf0 && (c->pos != len || memchr(b + at, 0xf7, len - at)))
			abort();
		return;
	default:
		abort();
	}
	if (m->offset != at || m->len == 0 || m->offset + m->len != c->pos)
		abort();
	if (m->status == 0xf0) {
		/* F0, the payload, F7: the first F7, and running status cancelled */
		if (b[at] != 0xf0 || b[c->pos - 1] != 0xf7 || m->running || c->status ||
		    m->sysex != b + at + 1 || m->sysex_len != m->len - 2 ||
		    memchr(m->sysex, 0xf7, m->sysex_len))
			abort();
		return;
	}
	/* a channel message: its own status byte or the one in force, then its data bytes */
	if (m->status < 0x80 || m->status >= 0xf0 || m->running != (b[at] < 0x80))
		abort();
	if (m->running ? m->status != status_in : m->status != b[at])
		abort();
	size_t data = (m->status & 0xe0) == 0xc0 ? 1 : 2;
	size_t d = at + !m->running;
	if (m->len != data + !m->running || m->d1 != b[d] || m->d1 >= 0x80 ||
	    (data == 2 ? m->d2 != b[d + 1] || m->d2 >= 0x80 : m->d2 != 0))
		abort();
	if (c->status != m->status)
		abort();
}

static int same_msg(const struct diginet_msg *a, const struct diginet_msg *b)
{
	return a->status == b->status && a->running == b->running && a->d1 == b->d1 && a->d2 == b->d2 &&
	       a->sysex == b->sysex && a->sysex_len == b->sysex_len && a->offset == b->offset &&
	       a->len == b->len;
}

/* the decoder's event against the lockstep cursor `ls`, which it must match; a fader that
 * took its LSB moves `ls` past it too */
FUZZ_CHECK check_events(int rd, const struct diginet_event *ev, struct diginet_cursor *ls)
{
	struct diginet_msg m, lsb;
	int r = diginet_msg_next(ls, &m);

	if (rd != r)
		abort();
	if (r != 1)
		return;
	if (!same_msg(&ev->msg, &m))
		abort();
	uint8_t family = m.status & 0xf0;
	switch (ev->kind) {
	case DIGINET_EV_SECTION_BUTTON:
	case DIGINET_EV_TOUCH:
	case DIGINET_EV_STRIP_BUTTON:
		if (family != 0x90 || ev->button != m.d1 || ev->on != !!(m.d2 & 0x40))
			abort();
		return;
	case DIGINET_EV_FADER: {
		if (family != 0xb0 || m.d1 >= 0x20 || ev->strip != m.d1)
			abort();
		struct diginet_cursor peek = *ls;
		int took = diginet_msg_next(&peek, &lsb) == 1 && (lsb.status & 0xf0) == 0xb0 &&
			   lsb.d1 == 0x20 + m.d1;
		if (took == ev->lsb_missing)
			abort();
		if (ev->value != (uint16_t)(m.d2 << 3 | (took ? lsb.d2 >> 4 & 7 : 0)))
			abort();
		if (took)
			*ls = peek;
		return;
	}
	case DIGINET_EV_JOG:
	case DIGINET_EV_VPOT:
		if (family != 0xb0 || ev->delta != (int16_t)(m.d2 - 64))
			abort();
		return;
	case DIGINET_EV_RING:
	case DIGINET_EV_METER:
	case DIGINET_EV_STRIP_LEDS:
	case DIGINET_EV_SCRIBBLE:
	case DIGINET_EV_COUNTER:
	case DIGINET_EV_SYSTEM:
		if (m.status != 0xf0 || m.sysex_len < 3 || m.sysex[0] != DIGINET_SYSEX_MAKER ||
		    ev->device != m.sysex[1])
			abort();
		return;
	case DIGINET_EV_OTHER:
		/* a note is always a key, and a fader MSB always a fader */
		if (family == 0x90 || (family == 0xb0 && m.d1 < 0x20))
			abort();
		return;
	default:
		abort();
	}
}

struct seen {
	int system_msg;      /* the cursor read a whole F0 13 xx 70 */
	int system_cut;      /* a message cut short starts F0 13 xx 70 */
};

FUZZ_CHECK check_refusal_event(const struct diginet_event *ev)
{
	/* the decoder names the system family, and nothing else, as DIGINET_EV_SYSTEM */
	if ((ev->kind == DIGINET_EV_SYSTEM) != is_system(&ev->msg))
		abort();
}

FUZZ_CHECK check_refusal(const uint8_t *b, size_t len, const struct seen *s)
{
	static const uint8_t DST[DIGINET_MAC_LEN] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
	static const uint8_t SRC[DIGINET_MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t frame[DIGINET_MAX_FRAME_LEN];
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA };
	int refused = diginet_body_check(b, len) == DIGINET_E_REFUSED;
	int any = 0;

	for (size_t i = 0; i < len && !any; i++)
		any = system_at(b, len, i);
	/* a whole system message, or one cut short, is refused */
	if ((s->system_msg || s->system_cut) && !refused)
		abort();
	/* and a body is refused only when one is in it */
	if (refused && !any)
		abort();
	if (len <= DIGINET_MAX_BODY_LEN) {
		int n = diginet_frame_build(frame, sizeof frame, DST, SRC, &h, b, len, DIGINET_SUM_BODY);
		if (refused ? n != DIGINET_E_REFUSED : n < 0)
			abort();
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const enum diginet_desk DESK[3] = {
		DIGINET_DESK_UNKNOWN, DIGINET_DESK_CONTROL24, DIGINET_DESK_PROCONTROL,
	};
	struct diginet_frame f;
	struct diginet_cursor c, ls;
	struct diginet_decoder d;
	struct diginet_msg m;
	struct diginet_event ev;
	struct seen s = { 0, 0 };

	if (size >= FUZZ_INPUT_MAX || size == 0)
		return 0;
	uint8_t sel = data[0];
	uint8_t *buf = fuzz_dup(data + 1, size - 1);
	const uint8_t *body = buf;
	size_t len = size - 1;
	if (sel & 0x80) {
		if (diginet_frame_parse(buf, len, &f) == DIGINET_OK) {
			body = f.body;
			len = f.body_len;
		} else {
			len = 0;
		}
	}
	const struct diginet_personality *p = diginet_personality_of(DESK[sel % 3]);

	/* the cursor alone; every call moves it, so this ends within len + 1 calls */
	diginet_cursor_init(&c, body, len);
	for (;;) {
		size_t at = c.pos;
		uint8_t status_in = c.status;
		int r = diginet_msg_next(&c, &m);
		check_cursor(body, len, at, status_in, r, &m, &c);
		if (r == 0)
			break;
		if (r == 1 && is_system(&m))
			s.system_msg = 1;
		if (r == DIGINET_E_TRUNCATED && system_at(body, len, at))
			s.system_cut = 1;
	}

	/* the decoder, against a cursor of its own */
	diginet_decoder_init(&d, p, body, len);
	diginet_cursor_init(&ls, body, len);
	for (;;) {
		int rd = diginet_decoder_next(&d, &ev);
		check_events(rd, &ev, &ls);
		if (rd == 0)
			break;
		if (rd == 1)
			check_refusal_event(&ev);
	}
	check_refusal(body, len, &s);
	free(buf);
	return 0;
}
