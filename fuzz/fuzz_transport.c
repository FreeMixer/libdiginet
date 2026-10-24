// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* libFuzzer harness: THE SESSION (transport/src/diginet_session.c), the state machine of
 * include/diginet/transport/diginet_session.h fed desk frames in any order and from every
 * state, with commands submitted, time passing and the host waking and closing as the input
 * chooses.
 *
 * The session's io is the harness: send records each frame the session sends (and fails one
 * when the input asks), recv hands diginet_session_poll() a frame the input chose, and the
 * clock is a time the input moves. No socket, no clock, no thread.
 *
 * Input: [flags] [config], then up to OPS_MAX operations, each [op] and its arguments.
 *   flags: bit 0 auto_wake, bit 1 the zero header sum, bit 2 desk_mac_set (the Control|24
 *   below), bit 3 raw commands (else tagged, see op 4).
 *   config: max_retries u8 % 8, ack_timeout_ms 1 + u8, keepalive_ms 1 + u16, backoff_ms u8,
 *   offline_ms 1 + u16, wake_timeout_ms 1 + u16, display_gap_us u16, max_cmds 1 + u8 % 255,
 *   max_body 24 + u16 % 1461.
 *   op % 9:
 *     0 u16-len bytes      one raw frame to diginet_session_rx()
 *     1 sel s16 a16 retry u16-len bytes
 *                          one frame built by diginet_frame_build(): sel & 7 the command
 *                          (data, a0, e0, e1, e2, e3, an unknown 0x55, data), sel >> 3 & 3 the
 *                          source (the desk, another Digidesign desk, this host, a non-
 *                          Digidesign MAC), sel >> 5 & 3 the destination (this host,
 *                          broadcast, another host, this host); sel & 0x80 acks the last
 *                          frame the session sent instead of a16; then the bytes are the body
 *                          (at most DIGINET_MAX_BODY_LEN)
 *     2 sel mac name       an announce: sel & 1 e1 else e0, from the desk to broadcast; the
 *                          host's MAC at body offset mac % 16 when that is under 10, another
 *                          host's at mac % 16 - 10 when under 13, else none; name % 3 is
 *                          "CNTRL|24", "MAINUNIT" or "OTHER"
 *     3 scale u16          time passes by u16 times 1 us, 1 ms, 100 ms or 1 s; then tick
 *     4                    a command to diginet_session_submit():
 *                            tagged: kind addr flags len, then len % 22 + 3 bytes of which
 *                            the harness writes the first three (A0 and a serial number, so
 *                            it can tell each command in a sent body) and the input the rest;
 *                            raw: kind addr flags, then u16-len bytes (at most 24)
 *                          kind % 9 + 1 is the key kind, addr its address, flags bit 0 the
 *                          display flag
 *     5                    diginet_session_wake()
 *     6                    diginet_session_close()
 *     7                    the next send fails (-EIO)
 *     8 pf u16-len bytes   diginet_session_poll(), its recv handing over this frame; pf bit 0:
 *                          twice (the drain after the tick), bit 1: recv fails instead
 *
 * The harness keeps a model of what the header promises, from what it sees: the frames the
 * session sends and the notices it gives.
 *
 * Properties, each an abort():
 *   - ack: every data frame the desk sends this host is ACKed at once, while the session is
 *     not closed: one a0 to the desk echoing the frame's send counter; and no other frame is.
 *     Mutant: fuzz/mutants/transport-ack.patch, the ACK echoes the frame's ack counter;
 *     seed data-acked.
 *   - inflight: one host frame is in flight: a new data frame goes out only when the last one
 *     was ACKed, dropped or ended with the session; a retransmission is that frame again with
 *     retry 1, 2, ... never past max_retries; DIGINET_N_ACK_LOST comes for it after exactly
 *     max_retries retransmissions, and DIGINET_N_ACKED only for the frame in flight, once.
 *     Mutant: fuzz/mutants/transport-inflight.patch, one retransmission past max_retries;
 *     seed wake-unanswered.
 *   - latest: latest wins, and nothing is lost (tagged commands): a sent body is commands
 *     submitted and not sent before, none replaced by a newer one for its key; the queue
 *     holds exactly the commands submitted, not yet sent and not replaced; a coalescable
 *     command is never refused for room while its key is queued.
 *     Mutant: fuzz/mutants/transport-latest.patch, a newer command takes the queued one's
 *     key but not its bytes; seed coalesce.
 *   - refusal: the system family is never encoded: a command diginet_body_check() refuses is
 *     refused by diginet_session_submit() and not queued, and every frame the session sends
 *     parses and carries a body diginet_body_check() passes.
 *     Mutant: fuzz/mutants/transport-refusal.patch, submit checks all but the last byte;
 *     seed submit-system-cut-short.
 *   - state: the session goes ONLINE only after an a0 for its e2 and an e1 naming this host
 *     since that e2, and never sends e2 while the desk's latest announce is a session with
 *     another host.
 *     Mutant: fuzz/mutants/transport-state.patch, the foreign session refuses a wake only
 *     while online; seed wake-foreign.
 */
#include <errno.h>

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>

#include "fuzz.h"

#define OPS_MAX     1024
#define TAG         0xa0
#define CMDS_MAX    OPS_MAX

static const uint8_t HOST[DIGINET_MAC_LEN]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t OTHER[DIGINET_MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t DESK[DIGINET_MAC_LEN]  = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
static const uint8_t DESK2[DIGINET_MAC_LEN] = { 0x00, 0xa0, 0x7e, 0x08, 0x00, 0x01 };
static const uint8_t NOTDD[DIGINET_MAC_LEN] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t BCAST[DIGINET_MAC_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static struct diginet_session g_s;
static uint64_t g_now;
static int g_fail_next;
static int g_raw;

/* what the frame being received has made the session send */
static unsigned g_acks;
static struct diginet_frame g_ack;
static uint32_t g_last_counter;   /* of the last data or e2 frame sent */

/* the frame in flight */
static struct {
	int on;
	uint8_t cmd;
	uint32_t counter;
	uint32_t retries;
	uint8_t body[DIGINET_MAX_BODY_LEN];
	size_t body_len;
} g_fly;

/* the handshake since the last e2, and the desk's latest announce */
static int g_e2_acked, g_e1_us, g_foreign;

/* the tagged commands */
enum { PENDING = 1, SENT, REPLACED };
static struct tagged {
	int st;
	uint32_t key;
	uint8_t bytes[DIGINET_CMD_MAX_LEN];
	uint8_t len;
} g_cmd[CMDS_MAX];
static unsigned g_ncmd, g_pending;

/* what poll's recv hands over: the frame, how many times, or a failure */
static const uint8_t *g_rx;
static size_t g_rx_len;
static int g_rx_times, g_rx_fail;

static int coalescable(uint32_t key)
{
	uint8_t k = DIGINET_KEY_KIND(key);
	return k != DIGINET_KEY_INPUT && k != DIGINET_KEY_KEEPALIVE;
}

/* ---------------------------------------------------------------- the properties */

FUZZ_CHECK check_refusal_sent(const uint8_t *frame, size_t len, struct diginet_frame *f)
{
	/* a frame, from this host, with no system message in it */
	if (diginet_frame_parse(frame, len, f) != DIGINET_OK || memcmp(f->src, HOST, DIGINET_MAC_LEN))
		abort();
	if (diginet_body_check(f->body, f->body_len) != DIGINET_OK)
		abort();
}

FUZZ_CHECK check_refusal_submit(const struct diginet_cmd *c, int rc, unsigned queued_before)
{
	if (diginet_body_check(c->bytes, c->len) != DIGINET_OK) {
		if (rc != DIGINET_E_REFUSED || g_s.queued != queued_before)
			abort();
	} else if (rc == DIGINET_E_REFUSED) {
		abort();
	}
}

FUZZ_CHECK check_inflight_new(const struct diginet_frame *f)
{
	/* one in flight: a data frame waits for the last one to be done */
	if (f->h.cmd == DIGINET_CMD_DATA && g_fly.on)
		abort();
}

FUZZ_CHECK check_inflight_retry(const struct diginet_frame *f)
{
	/* the frame in flight again, its retry counting up, never past the bound */
	if (!g_fly.on || f->h.cmd != g_fly.cmd || f->h.send_counter != g_fly.counter ||
	    f->body_len != g_fly.body_len || memcmp(f->body, g_fly.body, f->body_len))
		abort();
	if (f->h.retry != g_fly.retries + 1 || f->h.retry > g_s.cfg.max_retries)
		abort();
}

FUZZ_CHECK check_inflight_acked(const struct diginet_notice *n)
{
	if (!g_fly.on || n->counter != g_fly.counter)
		abort();
}

FUZZ_CHECK check_inflight_lost(const struct diginet_notice *n)
{
	/* dropped after exactly max_retries retransmissions */
	if (!g_fly.on || n->counter != g_fly.counter || g_fly.retries != g_s.cfg.max_retries ||
	    n->retry != g_s.cfg.max_retries)
		abort();
}

FUZZ_CHECK check_state_wake(void)
{
	/* never e2 into another host's session */
	if (g_foreign)
		abort();
}

FUZZ_CHECK check_state_online(void)
{
	if (!g_e2_acked || !g_e1_us)
		abort();
}

static struct tagged *tagged_of(const uint8_t *b, size_t n)
{
	if (n < 3 || b[0] != TAG)
		return NULL;
	unsigned serial = b[1] | (unsigned)b[2] << 7;
	return serial < g_ncmd ? &g_cmd[serial] : NULL;
}

FUZZ_CHECK check_latest_sent(const uint8_t *body, size_t len)
{
	size_t at = 0;
	while (at < len) {
		/* each command in the body one submitted, still the latest for its key, sent once */
		struct tagged *t = tagged_of(body + at, len - at);
		if (!t || t->st != PENDING || t->len > len - at || memcmp(body + at, t->bytes, t->len))
			abort();
		t->st = SENT;
		g_pending--;
		at += t->len;
	}
}

FUZZ_CHECK check_latest_queue(void)
{
	/* the queue is what is pending, nothing lost and nothing stale */
	if (g_s.queued != g_pending)
		abort();
	for (unsigned i = 0; i < g_s.queued; i++) {
		const struct diginet_cmd *c = &g_s.queue[i];
		struct tagged *t = tagged_of(c->bytes, c->len);
		if (!t || t->st != PENDING || c->len != t->len || memcmp(c->bytes, t->bytes, t->len))
			abort();
	}
}

FUZZ_CHECK check_latest_submit(const struct diginet_cmd *c, int rc, int had_key)
{
	/* the latest value for a queued key always has room */
	if (rc == DIGINET_E_SPACE && (g_pending < DIGINET_QUEUE_MAX || (coalescable(c->key) && had_key)))
		abort();
}

/* `times`: how often the session was handed the frame */
FUZZ_CHECK check_ack(const uint8_t *frame, size_t len, int desk_known, const uint8_t *desk_mac,
		     enum diginet_session_state before, unsigned times)
{
	struct diginet_frame f;
	int want = diginet_frame_parse(frame, len, &f) == DIGINET_OK && f.h.cmd == DIGINET_CMD_DATA &&
		   memcmp(f.src, HOST, DIGINET_MAC_LEN) &&
		   (!memcmp(f.dst, HOST, DIGINET_MAC_LEN) || !memcmp(f.dst, BCAST, DIGINET_MAC_LEN)) &&
		   desk_known && !memcmp(f.src, desk_mac, DIGINET_MAC_LEN) && before != DIGINET_S_CLOSED;
	unsigned acks = want ? times : 0;
	if (g_acks != acks)
		abort();
	/* to the desk, echoing the frame's send counter, with no body */
	if (acks && (g_ack.h.ack_counter != f.h.send_counter || memcmp(g_ack.dst, desk_mac, DIGINET_MAC_LEN) ||
		     g_ack.body_len != 0))
		abort();
}

/* ---------------------------------------------------------------- the io and the notices */

static int io_send(void *ctx, const uint8_t *frame, size_t len)
{
	struct diginet_frame f;
	int fail = g_fail_next;

	(void)ctx;
	g_fail_next = 0;
	check_refusal_sent(frame, len, &f);
	switch (f.h.cmd) {
	case DIGINET_CMD_ACK:
		g_acks++;
		g_ack = f;
		break;
	case DIGINET_CMD_WAKE:
		if (f.h.retry) {
			check_inflight_retry(&f);
			g_fly.retries++;
			break;
		}
		check_state_wake();
		g_e2_acked = g_e1_us = 0;
		g_last_counter = f.h.send_counter;
		if (fail)
			break;   /* diginet_session_wake() fails, and leaves what was in flight */
		g_fly.on = 1, g_fly.cmd = f.h.cmd, g_fly.counter = f.h.send_counter, g_fly.retries = 0;
		g_fly.body_len = 0;
		break;
	case DIGINET_CMD_DATA:
		if (f.h.retry) {
			check_inflight_retry(&f);
			g_fly.retries++;
			break;
		}
		check_inflight_new(&f);
		g_last_counter = f.h.send_counter;
		g_fly.on = 1, g_fly.cmd = f.h.cmd, g_fly.counter = f.h.send_counter, g_fly.retries = 0;
		g_fly.body_len = f.body_len;
		memcpy(g_fly.body, f.body, f.body_len);
		if (!g_raw && !diginet_frame_is_keepalive(&f))
			check_latest_sent(f.body, f.body_len);
		break;
	default:
		break;
	}
	return fail ? -EIO : 0;
}

static int io_recv(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
	(void)ctx;
	(void)timeout_ms;
	if (g_rx_fail) {
		g_rx_fail = 0;
		return -EIO;
	}
	if (!g_rx || !g_rx_times)
		return 0;
	g_rx_times--;
	size_t n = g_rx_len < cap ? g_rx_len : cap;
	memcpy(buf, g_rx, n);
	return (int)n;
}

static uint64_t io_now(void *ctx)
{
	(void)ctx;
	return g_now;
}

static void notice(void *ctx, const struct diginet_notice *n)
{
	(void)ctx;
	switch (n->kind) {
	case DIGINET_N_STATE:
		if (n->state == DIGINET_S_ONLINE)
			check_state_online();
		if (n->state == DIGINET_S_IDLE || n->state == DIGINET_S_CLOSED)
			g_fly.on = 0;
		break;
	case DIGINET_N_ACKED:
		check_inflight_acked(n);
		if (g_fly.cmd == DIGINET_CMD_WAKE)
			g_e2_acked = 1;
		g_fly.on = 0;
		break;
	case DIGINET_N_ACK_LOST:
		check_inflight_lost(n);
		g_fly.on = 0;
		break;
	case DIGINET_N_DESK:
		if (n->frame->h.cmd == DIGINET_CMD_ANNOUNCE_SESSION && n->mac_offset >= 0)
			g_e1_us = 1, g_foreign = 0;
		else if (n->frame->h.cmd == DIGINET_CMD_ANNOUNCE_SESSION)
			g_foreign = 1;
		else
			g_foreign = 0;
		break;
	default:
		break;
	}
}

/* ---------------------------------------------------------------- the operations */

/* a frame received, alone or through poll (poll_flags bit 0: recv hands it over twice, as a
 * desk's retransmission waiting behind it; bit 1: recv fails instead), and the ack property
 * over it */
static void receive(const uint8_t *p, size_t n, int by_poll, unsigned poll_flags)
{
	uint8_t *frame = fuzz_dup(p, n);
	int desk_known = g_s.desk_known;
	uint8_t desk_mac[DIGINET_MAC_LEN];
	enum diginet_session_state before = g_s.state;
	unsigned times = 1;

	memcpy(desk_mac, g_s.desk_mac, DIGINET_MAC_LEN);
	g_acks = 0;
	if (by_poll) {
		g_rx = frame;
		g_rx_len = n > DIGINET_MAX_FRAME_LEN ? DIGINET_MAX_FRAME_LEN : n;
		g_rx_times = times = poll_flags & 1 ? 2 : 1;
		g_rx_fail = poll_flags >> 1 & 1;
		if (g_rx_fail)
			times = 0;
		diginet_session_poll(&g_s, 0);
		g_rx = NULL;
		g_rx_fail = 0;
		if (n > DIGINET_MAX_FRAME_LEN)
			n = DIGINET_MAX_FRAME_LEN;   /* what recv handed over */
	} else {
		diginet_session_rx(&g_s, frame, n, g_now);
	}
	check_ack(frame, n, desk_known, desk_mac, before, times);
	free(frame);
}

static void build_and_receive(const uint8_t *dst, const uint8_t *src, const struct diginet_header *h,
			      const uint8_t *body, size_t len)
{
	uint8_t frame[DIGINET_MAX_FRAME_LEN];
	int n = diginet_frame_build(frame, sizeof frame, dst, src, h, body, len, DIGINET_SUM_BODY);
	if (n > 0)
		receive(frame, (size_t)n, 0, 0);
}

static void op_frame(struct fuzz_in *in)
{
	static const uint8_t CMD[7] = {
		DIGINET_CMD_DATA, DIGINET_CMD_ACK, DIGINET_CMD_ANNOUNCE, DIGINET_CMD_ANNOUNCE_SESSION,
		DIGINET_CMD_WAKE, DIGINET_CMD_DISCONNECT, 0x55,
	};
	static const uint8_t *const SRC[4] = { DESK, DESK2, HOST, NOTDD };
	static const uint8_t *const DST[4] = { HOST, BCAST, OTHER, HOST };
	uint8_t sel = fuzz_u8(in);
	struct diginet_header h = { .cmd = CMD[(sel & 7) % 7], .num_commands = 1 };
	const uint8_t *body;

	h.send_counter = fuzz_u16(in);
	h.ack_counter = fuzz_u16(in);
	if (sel & 0x80)
		h.ack_counter = g_last_counter;
	h.retry = fuzz_u8(in) & 3;
	size_t len = fuzz_take(in, fuzz_u16(in) % (DIGINET_MAX_BODY_LEN + 1), &body);
	build_and_receive(DST[sel >> 5 & 3], SRC[sel >> 3 & 3], &h, body, len);
}

static void op_announce(struct fuzz_in *in)
{
	static const char *const NAME[3] = { "CNTRL|24", "MAINUNIT", "OTHER" };
	uint8_t sel = fuzz_u8(in), mac = fuzz_u8(in) % 16, name = fuzz_u8(in) % 3;
	uint8_t body[DIGINET_ANNOUNCE_BODY_LEN];
	struct diginet_header h = { .cmd = sel & 1 ? DIGINET_CMD_ANNOUNCE_SESSION : DIGINET_CMD_ANNOUNCE };

	memset(body, 0, sizeof body);
	if (mac < 10)
		memcpy(body + mac, HOST, DIGINET_MAC_LEN);
	else if (mac < 13)
		memcpy(body + mac - 10, OTHER, DIGINET_MAC_LEN);
	memcpy(body + 15, "1.37", 4);
	memcpy(body + 24, NAME[name], strlen(NAME[name]));
	build_and_receive(BCAST, DESK, &h, body, sizeof body);
}

static void op_submit(struct fuzz_in *in)
{
	struct diginet_cmd c;
	const uint8_t *p;
	unsigned before = g_s.queued;

	memset(&c, 0, sizeof c);
	c.key = DIGINET_KEY(fuzz_u8(in) % 9 + 1, fuzz_u8(in));
	c.display = fuzz_u8(in) & 1;
	if (g_raw) {
		c.len = (uint8_t)fuzz_take(in, fuzz_u16(in) % (DIGINET_CMD_MAX_LEN + 1), &p);
		memcpy(c.bytes, p, c.len);
		int rc = diginet_session_submit(&g_s, &c);
		check_refusal_submit(&c, rc, before);
		return;
	}
	unsigned serial = g_ncmd;
	c.len = (uint8_t)(fuzz_u8(in) % 22 + 3);
	c.bytes[0] = TAG;
	c.bytes[1] = serial & 0x7f;
	c.bytes[2] = serial >> 7 & 0x7f;
	size_t n = fuzz_take(in, c.len - 3u, &p);
	memcpy(c.bytes + 3, p, n);
	int had_key = 0;
	for (unsigned i = 0; i < g_ncmd; i++)
		if (g_cmd[i].st == PENDING && g_cmd[i].key == c.key)
			had_key = 1;
	int rc = diginet_session_submit(&g_s, &c);
	check_refusal_submit(&c, rc, before);
	check_latest_submit(&c, rc, had_key);
	if (rc != DIGINET_OK)
		return;
	if (coalescable(c.key))
		for (unsigned i = 0; i < g_ncmd; i++)
			if (g_cmd[i].st == PENDING && g_cmd[i].key == c.key)
				g_cmd[i].st = REPLACED, g_pending--;
	g_cmd[serial].st = PENDING;
	g_cmd[serial].key = c.key;
	g_cmd[serial].len = c.len;
	memcpy(g_cmd[serial].bytes, c.bytes, c.len);
	g_ncmd++;
	g_pending++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint64_t SCALE[4] = { 1, 1000, 100000, 1000000 };
	struct diginet_session_config cfg;
	struct diginet_io io = { NULL, io_send, io_recv, io_now };
	const uint8_t *p;

	if (size >= FUZZ_INPUT_MAX)
		return 0;
	struct fuzz_in in = fuzz_in(data, size);
	uint8_t flags = fuzz_u8(&in);
	diginet_session_config_default(&cfg);
	memcpy(cfg.host_mac, HOST, DIGINET_MAC_LEN);
	cfg.auto_wake = flags & 1;
	cfg.sum_mode = flags & 2 ? DIGINET_SUM_ZERO : DIGINET_SUM_BODY;
	if (flags & 4) {
		memcpy(cfg.desk_mac, DESK, DIGINET_MAC_LEN);
		cfg.desk_mac_set = 1;
	}
	cfg.max_retries = fuzz_u8(&in) % 8;
	cfg.ack_timeout_ms = 1u + fuzz_u8(&in);
	cfg.keepalive_ms = 1u + fuzz_u16(&in);
	cfg.backoff_ms = fuzz_u8(&in);
	cfg.offline_ms = 1u + fuzz_u16(&in);
	cfg.wake_timeout_ms = 1u + fuzz_u16(&in);
	cfg.display_gap_us = fuzz_u16(&in);
	cfg.max_cmds = 1u + fuzz_u8(&in) % 255;
	cfg.max_body = DIGINET_CMD_MAX_LEN + fuzz_u16(&in) % (DIGINET_MAX_BODY_LEN - DIGINET_CMD_MAX_LEN + 1);

	g_raw = flags >> 3 & 1;
	g_now = 1000000;
	g_fail_next = 0;
	g_last_counter = 0;
	memset(&g_fly, 0, sizeof g_fly);
	g_e2_acked = g_e1_us = g_foreign = 0;
	g_ncmd = g_pending = 0;
	g_rx = NULL;
	if (diginet_session_init(&g_s, &cfg, &io, notice, NULL) != DIGINET_OK)
		return 0;

	for (int ops = 0; ops < OPS_MAX && in.n; ops++) {
		size_t n;
		switch (fuzz_u8(&in) % 9) {
		case 0:
			n = fuzz_record(&in, &p);
			receive(p, n, 0, 0);
			break;
		case 1:
			op_frame(&in);
			break;
		case 2:
			op_announce(&in);
			break;
		case 3: {
			uint64_t scale = SCALE[fuzz_u8(&in) % 4];
			g_now += scale * fuzz_u16(&in);
			diginet_session_tick(&g_s, g_now);
			break;
		}
		case 4:
			op_submit(&in);
			break;
		case 5:
			diginet_session_wake(&g_s, g_now);
			break;
		case 6:
			diginet_session_close(&g_s, g_now);
			break;
		case 7:
			g_fail_next = 1;
			break;
		default: {
			unsigned pf = fuzz_u8(&in);
			n = fuzz_record(&in, &p);
			receive(p, n, 1, pf);
			break;
		}
		}
		if (!g_raw)
			check_latest_queue();
	}
	return 0;
}
