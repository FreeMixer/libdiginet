/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet: the controls. Encoders and decoders for every control docs/protocol.md
 * decodes, and one personality per desk. Pure functions over caller memory: no socket, no
 * clock, no allocation.
 *
 * The encoders build one command at a time (struct diginet_cmd). Each carries a key that
 * names the address it writes (fader n, ring n, scribble address, meter channel, LED), so a
 * transport can keep only the latest value per address. The system and diagnostic family
 * (F0 13 xx 70 ...) writes the desk's memory: no encoder makes it, diginet_sysex_encode()
 * refuses it and diginet_frame_build() refuses any body that holds it.
 */
#ifndef DIGINET_CODEC_H
#define DIGINET_CODEC_H

#include <diginet/diginet.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- personalities ------------------------------------------------------------------- */

enum diginet_desk {
	DIGINET_DESK_UNKNOWN = 0,
	DIGINET_DESK_CONTROL24,   /* announce name "CNTRL|24" */
	DIGINET_DESK_PROCONTROL,  /* announce name "MAINUNIT" */
};

struct diginet_personality {
	enum diginet_desk desk;
	const char *announce_name;
	uint8_t device;           /* the byte after F0 13: 01 Control|24, 00 ProControl */
	uint8_t strips;           /* 24, 8 */
	uint8_t scribble_chars;   /* 4, 8 */
	uint8_t counter_addr;     /* 0x19, 0x09 */
};

/* The personality an announce name selects, or NULL for a name no source describes. */
const struct diginet_personality *diginet_personality_from_name(const char *name);
const struct diginet_personality *diginet_personality_of(enum diginet_desk desk);

/* ---- commands ------------------------------------------------------------------------ */

#define DIGINET_CMD_MAX_LEN 24

/* Key kinds: the high byte of diginet_cmd.key. The low 16 bits are the address. */
enum diginet_key_kind {
	DIGINET_KEY_FADER    = 1,  /* strip */
	DIGINET_KEY_LED      = 2,  /* button << 8 | track-or-zone */
	DIGINET_KEY_RING     = 3,  /* strip */
	DIGINET_KEY_METER    = 4,  /* channel address (0x20 set for the right side) */
	DIGINET_KEY_LEDS     = 5,  /* F0 13 dd 20: strip, or the counter-mode address */
	DIGINET_KEY_COUNTER  = 6,  /* counter address */
	DIGINET_KEY_SCRIBBLE = 7,  /* scribble address */
	DIGINET_KEY_INPUT    = 8,  /* desk-side commands (touch, V-Pot, jog): never coalesced */
	DIGINET_KEY_KEEPALIVE = 9,
};

#define DIGINET_KEY(kind, addr) (((uint32_t)(kind) << 16) | ((uint32_t)(addr) & 0xffff))
#define DIGINET_KEY_KIND(key)   ((uint8_t)((key) >> 16))

struct diginet_cmd {
	uint8_t  bytes[DIGINET_CMD_MAX_LEN];
	uint8_t  len;
	uint8_t  display;  /* 1 for scribble and counter writes, which a transport paces */
	uint32_t key;
};

/* Every encoder returns DIGINET_OK, or DIGINET_E_ARG / DIGINET_E_RANGE / DIGINET_E_REFUSED
 * with *out untouched. */

/* Fader: B0 tt MSB (20+tt) LSB, a 10-bit position, MSB = v >> 3, LSB = (v & 7) << 4. */
#define DIGINET_FADER_MAX 1023
int diginet_fader_encode(const struct diginet_personality *p, unsigned strip, unsigned value,
			 struct diginet_cmd *out);

/* Button or LED: 90 bb (40 if on | id). id is a strip (00..strips-1) or a zone (18..1D). */
int diginet_button_encode(unsigned button, unsigned id, int on, struct diginet_cmd *out);

/* Strip buttons (bb) and section zones. */
enum diginet_strip_button {
	DIGINET_BTN_REC_ARM = 0x00, DIGINET_BTN_PAN_SEND = 0x01, DIGINET_BTN_EQ = 0x02,
	DIGINET_BTN_DYNAMICS = 0x03, DIGINET_BTN_ACTIVE = 0x04, DIGINET_BTN_AUTO_MODE = 0x05,
	DIGINET_BTN_SELECT = 0x06, DIGINET_BTN_SOLO = 0x07, DIGINET_BTN_MUTE = 0x08,
	DIGINET_BTN_TOUCH = 0x09, DIGINET_BTN_INSERTS = 0x0a, DIGINET_BTN_PEAK = 0x0b,
	DIGINET_BTN_SOURCE = 0x0c, DIGINET_BTN_ROLL_OFF = 0x0d,
};
#define DIGINET_ZONE_FIRST 0x18
#define DIGINET_ZONE_LAST  0x1d

/* Fader touch, as the desk sends it: 90 09 (40 if touched | tt). */
int diginet_touch_encode(const struct diginet_personality *p, unsigned strip, int touched,
			 struct diginet_cmd *out);

/* V-Pot turn, as the desk sends it: B0 (40 | tt) dd, delta = dd - 64. Jog: B0 5C dd. */
#define DIGINET_JOG_CC 0x5c
int diginet_vpot_encode(const struct diginet_personality *p, unsigned strip, int delta,
			struct diginet_cmd *out);
int diginet_jog_encode(int delta, struct diginet_cmd *out);

/* V-Pot ring, 15 LEDs, bit 0 of mask = LED 1 ... bit 14 = LED 15:
 * F0 13 dd 00 (tt | 0x40 if LED 1) b1 b2 F7 (see docs/protocol.md, A1). */
#define DIGINET_RING_LEDS 15
int diginet_ring_encode(const struct diginet_personality *p, unsigned strip, uint16_t mask,
			struct diginet_cmd *out);
/* One LED lit at pos (0..14); LEDs 0..n-1 lit (n 0..15). Out of range gives 0. */
uint16_t diginet_ring_dot(unsigned pos);
uint16_t diginet_ring_fill(unsigned n);

/* Meter, a thermometer over 14 bits: F0 13 dd 10 ch hi lo F7, ch | 0x20 for the right
 * side, bus meters from channel 24 (docs/protocol.md, A2). */
#define DIGINET_METER_SEGMENTS 14
int diginet_meter_encode(const struct diginet_personality *p, unsigned channel, int right,
			 unsigned segments, struct diginet_cmd *out);
uint16_t diginet_meter_mask(unsigned segments);
/* Lit segments of a mask: the count of contiguous low bits; -1 if the mask is not a
 * thermometer. */
int diginet_meter_segments(uint16_t mask);

/* Strip automation LEDs and the counter-mode LEDs: F0 13 dd 20 tt bits F7. */
enum diginet_auto_led {
	DIGINET_AUTO_WRITE = 0x40, DIGINET_AUTO_TOUCH = 0x20, DIGINET_AUTO_LATCH = 0x10,
	DIGINET_AUTO_TRIM = 0x08, DIGINET_AUTO_READ = 0x04,
};
int diginet_strip_leds_encode(const struct diginet_personality *p, unsigned strip,
			      unsigned bits, struct diginet_cmd *out);
int diginet_counter_leds_encode(const struct diginet_personality *p, unsigned bits,
				struct diginet_cmd *out);

/* Scribble strip: F0 13 dd 40 aa 00 c1..cN F7, N = the personality's scribble_chars.
 * chars must be 7-bit. */
#define DIGINET_SCRIBBLE_MAX 8
int diginet_scribble_encode(const struct diginet_personality *p, unsigned addr,
			    const uint8_t *chars, struct diginet_cmd *out);
/* Text to scribble bytes: ASCII, padded with spaces, cut at n; ".1".."9" become the dot
 * plus small digit glyph (chr(digit) - 26, 0x17..0x1F). Non-ASCII bytes become '?'.
 * Returns the number of input bytes used. */
size_t diginet_scribble_text(const char *text, uint8_t *out, size_t n);

/* 8-digit seven-segment counter: F0 13 dd 30 aa dots d8..d1 F7. seg[0] is the leftmost
 * digit as shown; the wire carries the digits in reverse (docs/protocol.md, A3-A5). */
#define DIGINET_COUNTER_DIGITS 8
int diginet_counter_encode(const struct diginet_personality *p,
			   const uint8_t seg[DIGINET_COUNTER_DIGITS], uint8_t dots,
			   struct diginet_cmd *out);
/* Seven-segment pattern of a character: 0-9, A b C d E F H h J L o P r S U Y Z -, space;
 * bit 6 = segment a ... bit 0 = segment g. Returns -1 for a character the display cannot
 * show. */
int diginet_seg7(char c);
/* Text to digits and dots: a '.' after a character lights that digit's dot. Returns
 * DIGINET_OK, DIGINET_E_RANGE for a character without a pattern, more than 8 digits, or a
 * dot on the rightmost digit. Shorter text is right-aligned. */
int diginet_counter_text(const char *text, uint8_t seg[DIGINET_COUNTER_DIGITS], uint8_t *dots);
/* dots bit k is the dot of display digit k, counted from the left (0 = leftmost); the
 * rightmost digit, 7, has no bit. */
#define DIGINET_COUNTER_DOT(display_digit) ((uint8_t)(1u << (display_digit)))

/* A system-exclusive command F0 13 dd fn payload F7. Refuses fn 0x70 (DIGINET_E_REFUSED)
 * and payload bytes with bit 7 set. Every sysex encoder above goes through it. */
#define DIGINET_SYSEX_MAKER 0x13
#define DIGINET_FN_RING     0x00
#define DIGINET_FN_METER    0x10
#define DIGINET_FN_LEDS     0x20
#define DIGINET_FN_COUNTER  0x30
#define DIGINET_FN_SCRIBBLE 0x40
#define DIGINET_FN_SYSTEM   0x70
int diginet_sysex_encode(uint8_t device, uint8_t fn, const uint8_t *payload, size_t len,
			 struct diginet_cmd *out);

/* 0 when a body holds no F0 13 xx 70 message, DIGINET_E_REFUSED when it does. */
int diginet_body_check(const uint8_t *body, size_t len);

/* ---- decoding -------------------------------------------------------------------------- */

enum diginet_event_kind {
	DIGINET_EV_FADER = 1,   /* strip, value; lsb_missing when only the MSB came */
	DIGINET_EV_TOUCH,       /* strip, on */
	DIGINET_EV_STRIP_BUTTON,/* strip, button, on: a press from the desk or an LED to it */
	DIGINET_EV_SECTION_BUTTON, /* zone, button, on */
	DIGINET_EV_VPOT,        /* strip, delta */
	DIGINET_EV_JOG,         /* delta */
	DIGINET_EV_RING,        /* strip, mask */
	DIGINET_EV_METER,       /* channel, right, mask, segments */
	DIGINET_EV_STRIP_LEDS,  /* addr (strip or counter address), bits */
	DIGINET_EV_SCRIBBLE,    /* addr, text (len chars, NUL-terminated) */
	DIGINET_EV_COUNTER,     /* addr, seg[] in display order, dots */
	DIGINET_EV_SYSTEM,      /* a 0x70 message (only ever from the desk) */
	DIGINET_EV_OTHER,       /* well formed, not one of the above: see msg */
};

struct diginet_event {
	enum diginet_event_kind kind;
	uint8_t strip, button, zone, on, right, addr, lsb_missing;
	uint16_t value;       /* fader position */
	int16_t delta;        /* V-Pot, jog */
	uint16_t mask;        /* ring LEDs, meter bits, LED bits */
	int8_t segments;      /* meter */
	uint8_t len;          /* scribble characters */
	char text[DIGINET_SCRIBBLE_MAX + 1];
	uint8_t seg[DIGINET_COUNTER_DIGITS];
	uint8_t dots;
	uint8_t device;       /* sysex device byte */
	struct diginet_msg msg;  /* the (first) message the event came from */
};

struct diginet_decoder {
	struct diginet_cursor c;
	const struct diginet_personality *p;
};

/* p may be NULL (the Control|24 layout is then assumed for addresses). */
void diginet_decoder_init(struct diginet_decoder *d, const struct diginet_personality *p,
			  const uint8_t *body, size_t len);
/* 1 with *ev filled, 0 at the end, or a negative code from the cursor (decoding may go on). */
int diginet_decoder_next(struct diginet_decoder *d, struct diginet_event *ev);

#ifdef __cplusplus
}
#endif

#endif
