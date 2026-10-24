// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE FRAME (src/diginet_frame.c), the reading of protocol/diginet.ksy's
 * top-level seq, `header` and `announce` that every byte from the desk goes through first.
 *
 * Input: one Ethernet frame, FCS excluded, of any length and content. It is copied into an
 * allocation of exactly its length, so a read past the frame is a sanitizer report.
 *
 * Where a property needs to know what a frame says, it asks the builder: a frame the parser
 * reads is built again by diginet_frame_build() from what the parser read, and the two must
 * agree. The offsets used below are the constants of include/diginet/diginet.h.
 *
 * Properties, each an abort():
 *   - parse: diginet_frame_parse() refuses exactly what diginet.h says it refuses (a frame
 *     shorter than the two headers, an EtherType that is not 0x885F, a numbytes under 16 or
 *     past the buffer), each with its own code; what it accepts it reads inside the buffer:
 *     the body right after the header, numbytes - 16 bytes of it, the rest padding, the body
 *     sum the library's own sum16, sum_matches exactly when the header says that sum, and a
 *     keepalive exactly a data frame whose body is the one byte 00.
 *     Mutant: fuzz/mutants/frame-parse.patch, the EtherType refusal tests for 0 instead of
 *     for 0x885F; seed wrong-ethertype.
 *   - round-trip: a frame the parser accepts is the frame diginet_frame_build() makes from its
 *     fields: byte for byte up to the end of the body, the sum field the body's sum, padding
 *     zero up to 60 bytes, and it parses back to the same fields. The builder refuses exactly
 *     a body diginet_body_check() refuses (the F0 13 xx 70 system family, never sent) and one
 *     past DIGINET_MAX_BODY_LEN, and a buffer one byte short is DIGINET_E_SPACE.
 *     Mutant: fuzz/mutants/frame-round-trip.patch, the builder writes the send counter where
 *     the ack counter goes; seed ack.
 *   - announce: diginet_announce_parse() reads only an e0 or e1 of at least 33 body bytes;
 *     `unknown` is the first 15 body bytes, the version the bytes at 15 and the name the
 *     bytes at 24, each up to its first NUL and at most 9, always terminated.
 *     Mutant: fuzz/mutants/frame-announce.patch, the name read one byte early; seed
 *     announce_cntrl24.
 */
#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

#include "fuzz.h"

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

FUZZ_CHECK check_parse(const uint8_t *buf, size_t len, int r, const struct diginet_frame *f)
{
	/* the refusals, in the order diginet.h gives them */
	if (len < DIGINET_BODY_OFFSET) {
		if (r != DIGINET_E_SHORT)
			abort();
		return;
	}
	if (be16(buf + 12) != DIGINET_ETHERTYPE) {
		if (r != DIGINET_E_ETHERTYPE)
			abort();
		return;
	}
	size_t numbytes = be16(buf + DIGINET_ETH_HDR_LEN);
	if (numbytes < DIGINET_HDR_LEN || numbytes > len - DIGINET_ETH_HDR_LEN) {
		if (r != DIGINET_E_LENGTH)
			abort();
		return;
	}
	/* accepted, and read inside the buffer */
	if (r != DIGINET_OK)
		abort();
	if (f->h.numbytes != numbytes || f->body != buf + DIGINET_BODY_OFFSET ||
	    f->body_len != numbytes - DIGINET_HDR_LEN ||
	    DIGINET_BODY_OFFSET + f->body_len + f->pad_len != len)
		abort();
	if (memcmp(f->dst, buf, DIGINET_MAC_LEN) || memcmp(f->src, buf + DIGINET_MAC_LEN, DIGINET_MAC_LEN) ||
	    f->ethertype != DIGINET_ETHERTYPE)
		abort();
	/* the sum the parser reports is the library's sum of the body, compared to the header's */
	if (f->body_sum != diginet_sum16(f->body, f->body_len) || f->sum_matches != (f->h.sum == f->body_sum))
		abort();
	int ka = f->h.cmd == DIGINET_CMD_DATA && f->body_len == 1 && f->body[0] == 0x00;
	if (diginet_frame_is_keepalive(f) != ka)
		abort();
}

FUZZ_CHECK check_round_trip(const uint8_t *buf, const struct diginet_frame *f)
{
	size_t used = DIGINET_BODY_OFFSET + f->body_len;
	size_t want = used < DIGINET_MIN_FRAME_LEN ? DIGINET_MIN_FRAME_LEN : used;
	uint8_t *out = malloc(want);
	struct diginet_frame g;
	int refused = diginet_body_check(f->body, f->body_len) != DIGINET_OK;

	if (!out)
		abort();
	int n = diginet_frame_build(out, want, f->dst, f->src, &f->h, f->body, f->body_len, DIGINET_SUM_BODY);
	if (f->body_len > DIGINET_MAX_BODY_LEN) {
		/* a body no Ethernet frame carries is not built */
		if (n != DIGINET_E_LENGTH)
			abort();
		free(out);
		return;
	}
	if (refused) {
		/* the system family is never built, whatever the room */
		if (n != DIGINET_E_REFUSED)
			abort();
		free(out);
		return;
	}
	if (n != (int)want)
		abort();
	/* byte for byte up to the end of the body, but for the sum, which the builder computes */
	if (memcmp(out, buf, DIGINET_ETH_HDR_LEN + 2) ||
	    memcmp(out + DIGINET_ETH_HDR_LEN + 4, buf + DIGINET_ETH_HDR_LEN + 4, used - DIGINET_ETH_HDR_LEN - 4))
		abort();
	if (be16(out + DIGINET_ETH_HDR_LEN + 2) != f->body_sum)
		abort();
	for (size_t i = used; i < want; i++)
		if (out[i] != 0)
			abort();
	/* and it reads back as the same frame, its sum matching */
	if (diginet_frame_parse(out, want, &g) != DIGINET_OK || !g.sum_matches ||
	    g.h.numbytes != f->h.numbytes || g.h.send_counter != f->h.send_counter ||
	    g.h.ack_counter != f->h.ack_counter || g.h.retry != f->h.retry || g.h.cmd != f->h.cmd ||
	    g.h.num_commands != f->h.num_commands || g.body_len != f->body_len ||
	    memcmp(g.body, f->body, f->body_len))
		abort();
	/* the zero-sum mode differs only in the sum */
	if (diginet_frame_build(out, want, f->dst, f->src, &f->h, f->body, f->body_len, DIGINET_SUM_ZERO) != n ||
	    be16(out + DIGINET_ETH_HDR_LEN + 2) != 0)
		abort();
	/* one byte short is no room */
	if (diginet_frame_build(out, want - 1, f->dst, f->src, &f->h, f->body, f->body_len,
				DIGINET_SUM_BODY) != DIGINET_E_SPACE)
		abort();
	free(out);
}

/* a fixed string field as diginet.h reads it: up to its first NUL, at most 9 characters */
static int field_is(const char *s, const uint8_t *p)
{
	size_t n = 0;
	while (n < 9 && p[n])
		n++;
	return strlen(s) == n && !memcmp(s, p, n);
}

FUZZ_CHECK check_announce(const struct diginet_frame *f)
{
	struct diginet_announce a;
	int r = diginet_announce_parse(f, &a);

	if (f->h.cmd != DIGINET_CMD_ANNOUNCE && f->h.cmd != DIGINET_CMD_ANNOUNCE_SESSION) {
		if (r != DIGINET_E_NOT_ANNOUNCE)
			abort();
		return;
	}
	if (f->body_len < 33) {
		if (r != DIGINET_E_LENGTH)
			abort();
		return;
	}
	if (r != DIGINET_OK || a.unknown != f->body || a.unknown_len != 15)
		abort();
	/* both strings terminated inside their fields, and each the bytes at its offset */
	if (!memchr(a.version, 0, sizeof a.version) || !memchr(a.name, 0, sizeof a.name))
		abort();
	if (!field_is(a.version, f->body + 15) || !field_is(a.name, f->body + 24))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct diginet_frame f;

	if (size >= FUZZ_INPUT_MAX)
		return 0;
	uint8_t *buf = fuzz_dup(data, size);
	memset(&f, 0, sizeof f);
	int r = diginet_frame_parse(buf, size, &f);
	check_parse(buf, size, r, &f);
	if (r == DIGINET_OK) {
		check_round_trip(buf, &f);
		check_announce(&f);
	}
	free(buf);
	return 0;
}
