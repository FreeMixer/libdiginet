// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The session against the desk emulator (tests/desk_emu.c), on a virtual clock: no
 * hardware, no privileges, minutes of desk time in milliseconds.
 *
 *  1. ONLINE     e0 -> e2 -> a0 + e1 naming us = ONLINE; neither half alone is enough;
 *                no answer -> back to IDLE and a fresh e2 at the next e0.
 *  2. ACK        every desk data frame is ACKed with its counter; a desk retry is ACKed
 *                again, never delivered twice, and holds our frames for 300 ms.
 *  3. RETRANSMIT a lost ACK: the same frame again, retry 1, 2, ...; after max_retries the
 *                frame is dropped and reported.
 *  4. KEEPALIVE  every 10 s on its own clock, idle and under thousands of ACKs; the desk
 *                emulator, like the ProControl, is not kept alive by ACKs.
 *  5. COALESCE   latest wins per address; batches cap at 48 commands / 314 bytes; display
 *                frames are paced 2 ms apart.
 *  6. OFFLINE    on silence, on e0, on a desk e3.
 *  7. FOREIGN    never e2 while the desk announces another host's session.
 *  8. SUM        the header sum per the switch, checked by a desk that insists on it.
 *  9. CLOSE      e3 on close.
 */
#include "golden.h"
#include "desk_emu.h"

#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>

static const uint8_t DESK_MAC[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
static const uint8_t HOST_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t OTHER_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x99 };

#define MS 1000ull
#define S  1000000ull

static struct desk_emu E;
static struct diginet_session SS;
static struct diginet_session *S_ = &SS;
static uint64_t now;
static uint64_t next_announce;
static uint64_t announce_period = 7 * S;

#define NLOG 8192
static struct diginet_notice nlog[NLOG];
static uint64_t nlog_at[NLOG];
static int nn;
static int desk_offsets[64], ndesk;
static unsigned data_frames;
static uint8_t last_data[64];
static size_t last_data_len;

static void on_notice(void *ctx, const struct diginet_notice *n)
{
	(void)ctx;
	if (nn < NLOG) {
		nlog[nn] = *n;
		nlog[nn].frame = NULL;
		nlog[nn].announce = NULL;
		nlog[nn].body = NULL;
		nlog_at[nn] = now;
		nn++;
	}
	if (n->kind == DIGINET_N_DESK && ndesk < 64)
		desk_offsets[ndesk++] = n->mac_offset;
	if (n->kind == DIGINET_N_DATA) {
		data_frames++;
		last_data_len = n->body_len < sizeof last_data ? n->body_len : sizeof last_data;
		memcpy(last_data, n->body, last_data_len);
	}
}

static int io_send(void *ctx, const uint8_t *f, size_t len)
{
	(void)ctx;
	emu_from_host(&E, f, len, now);
	return 0;
}

static uint64_t io_now(void *ctx) { (void)ctx; return now; }

static void pump(void)
{
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	size_t n;
	while ((n = emu_pop(&E, b, sizeof b)))
		diginet_session_rx(S_, b, n, now);
	diginet_session_tick(S_, now);
}

/* Advance the virtual clock by `us` in steps of `step`, announcing every 7 s and calling
 * `each` (if any) at every step. */
static void run(uint64_t us, uint64_t step, void (*each)(void))
{
	uint64_t end = now + us;
	while (now < end) {
		now += step;
		emu_tick(&E, now);
		if (now >= next_announce) {
			emu_announce(&E, now);
			next_announce = now + announce_period;
		}
		if (each)
			each();
		pump();
	}
}

static struct diginet_session_config cfg;

static void start_with(void (*tweak)(struct diginet_session_config *))
{
	struct diginet_io io = { .ctx = NULL, .send = io_send, .recv = NULL, .now_us = io_now };
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");
	diginet_session_config_default(&cfg);
	memcpy(cfg.host_mac, HOST_MAC, 6);
	if (tweak)
		tweak(&cfg);
	CHK(diginet_session_init(S_, &cfg, &io, on_notice, NULL) == DIGINET_OK);
	now = 1000 * S;
	next_announce = now;
	nn = 0;
	ndesk = 0;
	data_frames = 0;
}

static void start(void) { start_with(NULL); }

static int count_kind(enum diginet_notice_kind k)
{
	int c = 0;
	for (int i = 0; i < nn; i++)
		c += nlog[i].kind == k;
	return c;
}

static int find_state(enum diginet_session_state st, enum diginet_reason why)
{
	for (int i = 0; i < nn; i++)
		if (nlog[i].kind == DIGINET_N_STATE && nlog[i].state == st && nlog[i].reason == why)
			return i;
	return -1;
}

static void go_online(void)
{
	run(10 * MS, 1 * MS, NULL);
	CHK(S_->state == DIGINET_S_ONLINE);
	if (S_->state != DIGINET_S_ONLINE) {
		fprintf(stderr, "NOT A RESULT: the session never came online\n");
		exit(2);
	}
}

static const struct diginet_personality *C24;

static struct diginet_cmd fader(unsigned strip, unsigned v)
{
	struct diginet_cmd c;
	CHK(diginet_fader_encode(C24, strip, v, &c) == 0);
	return c;
}

/* Index of the n-th (0-based) logged host data frame holding these bytes, or -1. */
static int find_rx(const uint8_t *bytes, size_t len, int nth)
{
	for (unsigned i = 0; i < E.nlog; i++) {
		const struct emu_rx *r = &E.log[i];
		if (r->cmd != DIGINET_CMD_DATA)
			continue;
		for (size_t k = 0; k + len <= r->body_len; k++)
			if (!memcmp(r->body + k, bytes, len)) {
				if (nth-- == 0)
					return (int)i;
				break;
			}
	}
	return -1;
}

/* ---- 1 ------------------------------------------------------------------------------- */

static void test_online(void)
{
	start();
	go_online();
	CHK(E.wakes == 1 && E.in_session && !memcmp(E.session_mac, HOST_MAC, 6));
	CHK(S_->personality && S_->personality->desk == DIGINET_DESK_CONTROL24);
	/* The order of what the host saw: e0, our e2, its a0, the e1 naming us, ONLINE. */
	int i = 0;
	CHK(nlog[i].kind == DIGINET_N_DESK && nlog[i].mac_offset == -1); i++;
	CHK(nlog[i].kind == DIGINET_N_STATE && nlog[i].state == DIGINET_S_WAKING && nlog[i].reason == DIGINET_R_WAKE); i++;
	CHK(nlog[i].kind == DIGINET_N_ACKED); i++;
	CHK(nlog[i].kind == DIGINET_N_DESK && nlog[i].mac_offset == 0); i++;
	CHK(nlog[i].kind == DIGINET_N_STATE && nlog[i].state == DIGINET_S_ONLINE && nlog[i].reason == DIGINET_R_ONLINE);
	/* The e2 the desk got: no body, no commands. */
	CHK(E.nlog >= 1 && E.log[0].cmd == DIGINET_CMD_WAKE && E.log[0].body_len == 0 && E.log[0].ncmds == 0);

	/* An e1 naming us without the a0 is not enough, nor is the a0 alone. */
	start();
	E.ack_wake = 0;
	run(5 * MS, 1 * MS, NULL);
	CHK(S_->state == DIGINET_S_WAKING && E.wakes == 1);
	E.in_session = 1;
	memcpy(E.session_mac, HOST_MAC, 6);
	emu_announce(&E, now);
	pump();
	CHK(S_->state == DIGINET_S_WAKING);
	uint8_t f[64];
	struct diginet_header h = { .cmd = DIGINET_CMD_ACK, .ack_counter = E.log[0].counter };
	int n = diginet_frame_build(f, sizeof f, HOST_MAC, DESK_MAC, &h, NULL, 0, DIGINET_SUM_BODY);
	CHK(diginet_session_rx(S_, f, (size_t)n, now) == 0);
	CHK(S_->state == DIGINET_S_ONLINE);

	start();
	E.ack_wake = 0;
	run(5 * MS, 1 * MS, NULL);
	h.ack_counter = E.log[0].counter;
	n = diginet_frame_build(f, sizeof f, HOST_MAC, DESK_MAC, &h, NULL, 0, DIGINET_SUM_BODY);
	diginet_session_rx(S_, f, (size_t)n, now);
	CHK(S_->state == DIGINET_S_WAKING);   /* a0 alone */

	/* No answer at all: back to IDLE after wake_timeout, then a fresh e2 at the next e0. */
	start();
	E.ack_wake = 0;
	run(3500 * MS, 1 * MS, NULL);
	CHK(S_->state == DIGINET_S_IDLE && find_state(DIGINET_S_IDLE, DIGINET_R_WAKE_TIMEOUT) >= 0);
	CHK(E.wakes >= 1 && E.log[1].cmd == DIGINET_CMD_WAKE && E.log[1].retry == 1);  /* e2 retried */
	unsigned w = E.wakes;
	E.ack_wake = 1;
	run(4 * S, 1 * MS, NULL);
	CHK(E.wakes == w + 1 && S_->state == DIGINET_S_ONLINE);

	/* Manual wake (auto_wake off): nothing until asked. */
	start_with(NULL);
	S_->cfg.auto_wake = 0;
	run(10 * MS, 1 * MS, NULL);
	CHK(S_->state == DIGINET_S_IDLE && E.wakes == 0 && S_->desk_known);
	CHK(diginet_session_wake(S_, now) == 0);
	pump();
	CHK(S_->state == DIGINET_S_ONLINE && E.wakes == 1);
}

/* ---- 2 ------------------------------------------------------------------------------- */

static void test_ack(void)
{
	static const uint8_t mute[] = { 0x90, 0x08, 0x40 };
	start();
	go_online();
	unsigned acks0 = E.acks_from_host;
	for (int i = 0; i < 100; i++) {
		uint32_t c = emu_send_data(&E, mute, 3, 1, 0, 0);
		pump();
		CHK(E.last_acked_by_host == c);
	}
	CHK(E.acks_from_host == acks0 + 100);
	CHK(data_frames == 100 && last_data_len == 3 && !memcmp(last_data, mute, 3));

	/* A desk retry: ACKed again, not delivered again, and our frames wait 300 ms. */
	uint32_t c = E.seq;
	emu_send_data(&E, mute, 3, 1, 1, c);
	pump();
	CHK(E.acks_from_host == acks0 + 101 && E.last_acked_by_host == c);
	CHK(data_frames == 100 && S_->stats.rx_duplicates == 1 && S_->stats.rx_desk_retries == 1);
	uint64_t retry_at = now;
	/* A keepalive due while the back-off holds is due when the back-off ends, so a poll
	 * loop waits until then instead of spinning on a deadline of now. */
	uint64_t next_ka = S_->next_keepalive_us;
	S_->next_keepalive_us = now;
	CHK(diginet_session_deadline(S_, now) == retry_at + 300 * MS);
	S_->next_keepalive_us = next_ka;
	struct diginet_cmd fc = fader(3, 700);
	CHK(diginet_session_submit(S_, &fc) == 0);
	run(290 * MS, 1 * MS, NULL);
	CHK(find_rx(fc.bytes, fc.len, 0) < 0);
	run(20 * MS, 1 * MS, NULL);
	int at = find_rx(fc.bytes, fc.len, 0);
	CHK(at >= 0 && E.log[at].at_us >= retry_at + 300 * MS && E.log[at].at_us <= retry_at + 302 * MS);

	/* A retry carrying a new counter is new data: delivered. */
	emu_send_data(&E, mute, 3, 1, 1, 0);
	pump();
	CHK(data_frames == 101);

	/* A desk keepalive is ACKed and not delivered. */
	static const uint8_t ka[] = { 0x00 };
	unsigned a = E.acks_from_host;
	emu_send_data(&E, ka, 1, 1, 0, 0);
	pump();
	CHK(E.acks_from_host == a + 1 && data_frames == 101);
}

/* ---- 3 ------------------------------------------------------------------------------- */

static void test_retransmit(void)
{
	start();
	go_online();
	E.drop_acks = 2;
	struct diginet_cmd fc = fader(0, 512);
	CHK(diginet_session_submit(S_, &fc) == 0);
	run(1 * S, 1 * MS, NULL);
	int a = find_rx(fc.bytes, fc.len, 0), b = find_rx(fc.bytes, fc.len, 1), c = find_rx(fc.bytes, fc.len, 2);
	CHK(a >= 0 && b >= 0 && c >= 0 && find_rx(fc.bytes, fc.len, 3) < 0);
	if (a >= 0 && b >= 0 && c >= 0) {
		CHK(E.log[a].retry == 0 && E.log[b].retry == 1 && E.log[c].retry == 2);
		CHK(E.log[a].counter == E.log[b].counter && E.log[b].counter == E.log[c].counter);
		CHK(!E.log[a].acked && !E.log[b].acked && E.log[c].acked);
		CHK(E.log[b].at_us - E.log[a].at_us == 100 * MS && E.log[c].at_us - E.log[b].at_us == 100 * MS);
	}
	CHK(S_->stats.tx_retransmits == 2 && S_->stats.ack_lost == 0);
	CHK(emu_count_cmd(&E, fc.bytes, fc.len) == 1);   /* one first send */

	/* Never ACKed: 1 + max_retries sends, then dropped and reported; the next one goes. */
	E.drop_acks = 6;
	struct diginet_cmd lost = fader(1, 100), next = fader(2, 200);
	CHK(diginet_session_submit(S_, &lost) == 0);
	run(2 * S, 1 * MS, NULL);
	CHK(find_rx(lost.bytes, lost.len, 5) >= 0 && find_rx(lost.bytes, lost.len, 6) < 0);
	CHK(S_->stats.ack_lost == 1 && count_kind(DIGINET_N_ACK_LOST) == 1);
	CHK(!S_->inflight);
	CHK(diginet_session_submit(S_, &next) == 0);
	run(10 * MS, 1 * MS, NULL);
	int k = find_rx(next.bytes, next.len, 0);
	CHK(k >= 0 && E.log[k].acked);
}

/* ---- 4 ------------------------------------------------------------------------------- */

static void keepalive_gaps(uint64_t *maxgap, uint64_t *mingap, unsigned *count)
{
	uint64_t last = 0;
	*maxgap = 0;
	*mingap = ~0ull;
	*count = 0;
	for (unsigned i = 0; i < E.nlog; i++) {
		const struct emu_rx *r = &E.log[i];
		if (r->cmd != DIGINET_CMD_DATA || r->body_len != 1 || r->body[0] != 0 || r->retry)
			continue;
		if (last) {
			uint64_t g = r->at_us - last;
			if (g > *maxgap) *maxgap = g;
			if (g < *mingap) *mingap = g;
		}
		last = r->at_us;
		(*count)++;
	}
}

static void desk_chatter(void)
{
	static const uint8_t fad[] = { 0xb0, 0x00, 0x40, 0x20, 0x00 };
	if ((now / MS) % 20 == 0)
		emu_send_data(&E, fad, 5, 1, 0, 0);
}

static void test_keepalive(void)
{
	uint64_t maxg, ming;
	unsigned n;

	/* Idle: one every 10 s exactly. */
	start();
	go_online();
	run(65 * S, 10 * MS, NULL);
	keepalive_gaps(&maxg, &ming, &n);
	CHK(n == 6 && maxg == 10 * S && ming == 10 * S);
	CHK(E.keepalives == 6 && S_->stats.tx_keepalives == 6);

	/* Under load: the desk sends a frame every 20 ms for 65 s and we ACK each one. ACKs
	 * must not stand in for the keepalive: if they did, none would go and the desk would
	 * drop us after its 30 s timeout. */
	start();
	go_online();
	unsigned acks0 = E.acks_from_host;
	run(65 * S, 1 * MS, desk_chatter);
	unsigned acks = E.acks_from_host - acks0;
	keepalive_gaps(&maxg, &ming, &n);
	fprintf(stderr, "keepalive under load: %u ACKs, %u keepalives, gaps %llu..%llu ms\n",
		acks, n, (unsigned long long)(ming / MS), (unsigned long long)(maxg / MS));
	CHK(acks >= 3000);
	CHK(n == 6 && maxg <= 10 * S + 2 * MS && ming >= 10 * S - 2 * MS);
	CHK(S_->state == DIGINET_S_ONLINE && E.in_session);
	CHK(find_state(DIGINET_S_IDLE, DIGINET_R_DESK_OFFLINE) < 0);

	/* A keepalive due while a frame is in flight goes as soon as it is ACKed. */
	start();
	go_online();
	run(9990 * MS, 10 * MS, NULL);
	E.drop_acks = 1;
	struct diginet_cmd fc = fader(5, 5);
	diginet_session_submit(S_, &fc);
	run(400 * MS, 1 * MS, NULL);
	keepalive_gaps(&maxg, &ming, &n);
	CHK(n == 1);
	int k = find_rx(fc.bytes, fc.len, 1);   /* the retransmit */
	for (unsigned i = 0; k >= 0 && i < E.nlog; i++)
		if (E.log[i].cmd == DIGINET_CMD_DATA && E.log[i].body_len == 1 && E.log[i].body[0] == 0)
			CHK(E.log[i].at_us == E.log[k].at_us);
}

/* ---- 5 ------------------------------------------------------------------------------- */

static void test_coalesce(void)
{
	start();
	go_online();
	E.drop_acks = 1;   /* hold the first frame in flight for one ack timeout */
	struct diginet_cmd f100 = fader(0, 100), f200 = fader(0, 200), f300 = fader(0, 300), f400 = fader(0, 400);
	struct diginet_cmd g1 = fader(1, 900);
	CHK(diginet_session_submit(S_, &f100) == 0);
	pump();
	CHK(S_->inflight && S_->queued == 0);
	CHK(diginet_session_submit(S_, &f200) == 0);
	CHK(diginet_session_submit(S_, &g1) == 0);
	CHK(diginet_session_submit(S_, &f300) == 0);
	struct diginet_cmd on, off, m1, m2;
	CHK(diginet_button_encode(DIGINET_BTN_MUTE, 0, 1, &on) == 0);
	CHK(diginet_button_encode(DIGINET_BTN_MUTE, 0, 0, &off) == 0);
	CHK(diginet_meter_encode(C24, 0, 0, 3, &m1) == 0);
	CHK(diginet_meter_encode(C24, 0, 0, 9, &m2) == 0);
	CHK(diginet_session_submit(S_, &on) == 0);
	CHK(diginet_session_submit(S_, &m1) == 0);
	CHK(diginet_session_submit(S_, &off) == 0);
	CHK(diginet_session_submit(S_, &m2) == 0);
	CHK(diginet_session_submit(S_, &f400) == 0);
	CHK(S_->queued == 4 && S_->stats.coalesced == 4);
	/* In place: the order of first submission is kept. */
	CHK(S_->queue[0].key == f400.key && !memcmp(S_->queue[0].bytes, f400.bytes, 5));
	CHK(S_->queue[1].key == g1.key && S_->queue[2].key == off.key && S_->queue[3].key == m2.key);
	run(500 * MS, 1 * MS, NULL);
	CHK(emu_count_cmd(&E, f100.bytes, 5) == 1);
	CHK(emu_count_cmd(&E, f200.bytes, 5) == 0 && emu_count_cmd(&E, f300.bytes, 5) == 0);
	CHK(emu_count_cmd(&E, f400.bytes, 5) == 1 && emu_count_cmd(&E, g1.bytes, 5) == 1);
	CHK(emu_count_cmd(&E, on.bytes, 3) == 0 && emu_count_cmd(&E, off.bytes, 3) == 1);
	CHK(emu_count_cmd(&E, m1.bytes, m1.len) == 0 && emu_count_cmd(&E, m2.bytes, m2.len) == 1);
	int k = find_rx(f400.bytes, 5, 0);
	CHK(k >= 0 && E.log[k].ncmds == 4 && E.log[k].body_len == 5 + 5 + 3 + 8);

	/* Desk-side input commands are never merged. */
	struct diginet_cmd v;
	CHK(diginet_vpot_encode(C24, 0, 1, &v) == 0);
	unsigned q = S_->queued;
	S_->state = DIGINET_S_IDLE;   /* hold the queue */
	diginet_session_submit(S_, &v);
	diginet_session_submit(S_, &v);
	CHK(S_->queued == q + 2);
	S_->queued = q;
	S_->state = DIGINET_S_ONLINE;

	/* Batching: 60 LEDs go as 48 + 12. */
	start();
	go_online();
	unsigned first = E.nlog;
	for (unsigned i = 0; i < 60; i++) {
		struct diginet_cmd l;
		CHK(diginet_button_encode(i / 24, i % 24, 1, &l) == 0);
		CHK(diginet_session_submit(S_, &l) == 0);
	}
	run(5 * MS, 100, NULL);
	CHK(E.nlog == first + 2);
	CHK(E.log[first].ncmds == 48 && E.log[first].body_len == 144);
	CHK(E.log[first + 1].ncmds == 12 && E.log[first + 1].body_len == 36);
	CHK(E.log[first].counter + 12 == E.log[first + 1].counter);

	/* Display writes: 32 scribbles (11 bytes) fill 28 to a frame (308 <= 314), and the
	 * second display frame follows the first by 2 ms although the ACK is immediate. */
	first = E.nlog;
	for (unsigned i = 0; i < 32; i++) {
		struct diginet_cmd sc;
		uint8_t t[4];
		diginet_scribble_text("abcd", t, 4);
		CHK(diginet_scribble_encode(C24, i, t, &sc) == 0);
		CHK(diginet_session_submit(S_, &sc) == 0);
	}
	struct diginet_cmd fz = fader(7, 7);
	run(100, 100, NULL);
	CHK(diginet_session_submit(S_, &fz) == 0);   /* not a display write: not held */
	run(5 * MS, 100, NULL);
	CHK(E.nlog == first + 3);
	CHK(E.log[first].ncmds == 28 && E.log[first].body_len == 308);
	CHK(E.log[first + 1].ncmds == 1 && E.log[first + 1].body_len == 5);
	CHK(E.log[first + 1].at_us - E.log[first].at_us < 2 * MS);
	CHK(E.log[first + 2].ncmds == 4 && E.log[first + 2].at_us - E.log[first].at_us >= 2 * MS &&
	    E.log[first + 2].at_us - E.log[first].at_us <= 2 * MS + 100);
}

/* ---- 6 ------------------------------------------------------------------------------- */

static void test_offline(void)
{
	start();
	go_online();
	E.mute = 1;
	uint64_t t0 = now;
	run(30 * S, 10 * MS, NULL);
	int i = find_state(DIGINET_S_IDLE, DIGINET_R_SILENCE);
	CHK(i >= 0 && S_->state == DIGINET_S_IDLE);
	if (i >= 0)
		CHK(nlog_at[i] - t0 >= 25 * S - 20 * MS && nlog_at[i] - t0 <= 25 * S + 20 * MS);

	/* e0 while online: offline, and back online with a fresh e2. */
	start();
	go_online();
	emu_drop_session(&E);
	emu_announce(&E, now);
	pump();
	CHK(find_state(DIGINET_S_IDLE, DIGINET_R_DESK_OFFLINE) >= 0);
	CHK(E.wakes == 2 && S_->state == DIGINET_S_ONLINE);

	/* The desk's own timeout, when the host stops keeping it alive: the emulator falls
	 * back to e0 and the session sees it. */
	start();
	go_online();
	S_->cfg.keepalive_ms = 60000;
	S_->next_keepalive_us = now + 60 * S;
	S_->cfg.auto_wake = 0;
	run(40 * S, 10 * MS, NULL);
	CHK(find_state(DIGINET_S_IDLE, DIGINET_R_DESK_OFFLINE) >= 0 && !E.in_session);

	/* A desk e3. */
	start();
	go_online();
	uint8_t f[64];
	struct diginet_header h = { .cmd = DIGINET_CMD_DISCONNECT };
	int n = diginet_frame_build(f, sizeof f, HOST_MAC, DESK_MAC, &h, NULL, 0, DIGINET_SUM_BODY);
	diginet_session_rx(S_, f, (size_t)n, now);
	CHK(find_state(DIGINET_S_IDLE, DIGINET_R_DESK_DISCONNECT) >= 0);
}

/* ---- 7 ------------------------------------------------------------------------------- */

static void test_foreign(void)
{
	start();
	E.foreign = 1;
	memcpy(E.session_mac, OTHER_MAC, 6);
	run(60 * S, 10 * MS, NULL);
	CHK(E.wakes == 0 && S_->state == DIGINET_S_IDLE && S_->foreign);
	CHK(count_kind(DIGINET_N_FOREIGN) >= 8);
	CHK(diginet_session_wake(S_, now) == DIGINET_E_REFUSED && E.wakes == 0);
	/* Nor does close send e3 into another host's session. */
	/* The other host lets go: e0, and now we may wake. */
	E.foreign = 0;
	emu_announce(&E, now);
	pump();
	CHK(E.wakes == 1 && S_->state == DIGINET_S_ONLINE);

	/* Taken over while online: offline, and no e2 while the other host holds it. */
	E.in_session = 0;
	E.foreign = 1;
	memcpy(E.session_mac, OTHER_MAC, 6);
	emu_announce(&E, now);
	pump();
	CHK(find_state(DIGINET_S_IDLE, DIGINET_R_FOREIGN) >= 0);
	run(30 * S, 10 * MS, NULL);
	CHK(E.wakes == 1);
}

/* ---- 8 ------------------------------------------------------------------------------- */

static void sum_zero(struct diginet_session_config *c) { c->sum_mode = DIGINET_SUM_ZERO; }

static void test_sum(void)
{
	start();
	E.require_sum = 1;
	go_online();
	struct diginet_cmd fc = fader(0, 512);
	diginet_session_submit(S_, &fc);
	run(10 * MS, 1 * MS, NULL);
	int k = find_rx(fc.bytes, 5, 0);
	CHK(k >= 0 && E.log[k].acked && E.log[k].sum == 0x0110);

	start_with(sum_zero);
	E.require_sum = 1;
	go_online();   /* e2 has no body: its sum is zero either way */
	diginet_session_submit(S_, &fc);
	run(1 * S, 1 * MS, NULL);
	k = find_rx(fc.bytes, 5, 0);
	CHK(k >= 0 && !E.log[k].acked && E.log[k].sum == 0);
	CHK(S_->stats.ack_lost == 1);
}

/* ---- 9 ------------------------------------------------------------------------------- */

static void test_close_and_filters(void)
{
	start();
	go_online();
	CHK(diginet_session_close(S_, now) == 0);
	CHK(S_->state == DIGINET_S_CLOSED && E.disconnects == 1 && !E.in_session);
	unsigned n = E.nlog;
	run(30 * S, 10 * MS, NULL);
	CHK(E.nlog == n);   /* nothing more from a closed session */

	/* A 0x70 command never enters the queue. */
	start();
	go_online();
	struct diginet_cmd bad = { .bytes = { 0xf0, 0x13, 0x01, 0x70, 0x00, 0x6e, 0xf7 }, .len = 7,
				   .key = DIGINET_KEY(DIGINET_KEY_SCRIBBLE, 0) };
	CHK(diginet_session_submit(S_, &bad) == DIGINET_E_REFUSED && S_->queued == 0);

	/* An announce from a MAC outside the Digidesign OUI is not a desk. */
	start();
	E.mac[0] = 0x02;
	run(8 * S, 10 * MS, NULL);
	CHK(!S_->desk_known && E.wakes == 0);

	/* A frame for another host is not ours. */
	start();
	go_online();
	uint8_t f[64], body[] = { 0x90, 0x08, 0x40 };
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .send_counter = 77, .num_commands = 1 };
	int len = diginet_frame_build(f, sizeof f, OTHER_MAC, DESK_MAC, &h, body, 3, DIGINET_SUM_BODY);
	unsigned acks = E.acks_from_host;
	diginet_session_rx(S_, f, (size_t)len, now);
	pump();
	CHK(E.acks_from_host == acks && data_frames == 0);
}

int main(void)
{
	C24 = diginet_personality_of(DIGINET_DESK_CONTROL24);
	test_online();
	test_ack();
	test_retransmit();
	test_keepalive();
	test_coalesce();
	test_offline();
	test_foreign();
	test_sum();
	test_close_and_filters();
	if (fails) {
		fprintf(stderr, "test_transport: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_transport: ok\n");
	return 0;
}
