// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The desk mux (diginet_mux.h) against desk emulators on two interfaces, on a virtual clock: the
 * io hands each frame the mux sends to the emulator on the interface it names, and each
 * emulator's frames to the mux with its interface.
 *
 *  1. TWO DESKS  two desks on two interfaces through one mux: each appears with its interface,
 *                is attached, comes online, and gets only its own frames, sent out of its own
 *                interface from that interface's MAC; each desk's keys reach its own session.
 *  2. PINNED     a present desk's frames on another interface are set aside.
 *  3. GONE       a desk silent for gone_ms is gone, exactly then; an attached one goes when its
 *                session ends on silence; it appears again when it announces again.
 *  4. SET ASIDE  frames from no desk, a data frame from an unknown desk, a frame of no grammar;
 *                a ninth desk.
 *  5. DEAF       a deaf desk is reported through its session's notice; the other is untouched.
 *  6. RETAKE     a restarted host takes its own session back on the desk's e1 naming it, at
 *                once (< 1 s), through the mux.
 *  7. ATTACH     its refusals; a desk attached later, and detached.
 *  8. DEADLINE   never later than a session's or the gone rule's.
 *  9. MOVED      a desk moved to another interface of this host, still announcing e1 naming the
 *                first one, is re-taken at once (< 1 s) from the new interface's MAC, with no
 *                FOREIGN; an e1 naming a MAC of no interface of this host is still refused; and
 *                with an io that lists no host MACs the move is FOREIGN, as it was.
 */
#include <errno.h>

#include "golden.h"
#include "desk_emu.h"

#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_mux.h>

#define MS 1000ull
#define S  1000000ull
#define NDESK 2

static const uint8_t DESK[NDESK][6] = { { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x0a },
					{ 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x0b } };
static const uint8_t HOST[NDESK][6] = { { 0x02, 0x00, 0x00, 0x00, 0x0a, 0x01 },
					{ 0x02, 0x00, 0x00, 0x00, 0x0b, 0x01 } };
static const int IFX[NDESK] = { 2, 3 };
static const uint8_t ELSEWHERE[6] = { 0x02, 0x00, 0x00, 0x00, 0x0c, 0x01 };   /* another host */
static int at[NDESK];                          /* the interface each desk is cabled to; 0: none */

static struct desk_emu E[NDESK];
static struct diginet_mux M;
static uint64_t now, next_ann[NDESK];
static int auto_attach = 1;

/* what the mux did */
static unsigned sent_on[16];                   /* frames sent, by ifindex */
static int wrong_src;                          /* a frame sent from another interface's MAC */
#define NLOG 4096
static struct {
	enum diginet_mux_notice_kind kind;
	unsigned desk;
	int ifindex;
	uint8_t mac[6];
	enum diginet_notice_kind skind;
	enum diginet_session_state state;
	enum diginet_reason reason;
	uint32_t counter;
	int personality;
	uint64_t at;
} L[NLOG];
static int nl;

/* the interface: its slot in IFX and HOST */
static int iface(int ifindex)
{
	for (int i = 0; i < NDESK; i++)
		if (IFX[i] == ifindex)
			return i;
	return -1;
}

static int io_send(void *ctx, int ifindex, const uint8_t *f, size_t len)
{
	(void)ctx;
	if (ifindex >= 0 && ifindex < 16)
		sent_on[ifindex]++;
	int i = iface(ifindex);
	if (i < 0)
		return -ENXIO;
	if (len < 12 || memcmp(f + 6, HOST[i], 6))
		wrong_src++;
	for (int k = 0; k < NDESK; k++)
		if (at[k] == ifindex)
			emu_from_host(&E[k], f, len, now);
	return 0;
}

static int io_if_mac(void *ctx, int ifindex, uint8_t mac[6])
{
	(void)ctx;
	int i = iface(ifindex);
	if (i < 0)
		return -ENODEV;
	memcpy(mac, HOST[i], 6);
	return 0;
}

static int io_host_macs(void *ctx, uint8_t (*macs)[6], unsigned cap)
{
	(void)ctx;
	unsigned n = 0;
	for (int i = 0; i < NDESK && n < cap; i++)
		memcpy(macs[n++], HOST[i], 6);
	return (int)n;
}

static uint64_t io_now(void *ctx) { (void)ctx; return now; }

static void on_notice(void *ctx, const struct diginet_mux_notice *n)
{
	(void)ctx;
	if (nl < NLOG) {
		L[nl].kind = n->kind;
		L[nl].desk = n->desk;
		L[nl].ifindex = n->ifindex;
		memcpy(L[nl].mac, n->mac, 6);
		L[nl].personality = n->personality ? (int)n->personality->desk : -1;
		if (n->session) {
			L[nl].skind = n->session->kind;
			L[nl].state = n->session->state;
			L[nl].reason = n->session->reason;
			L[nl].counter = n->session->counter;
		}
		L[nl].at = now;
		nl++;
	}
	if (n->kind == DIGINET_MUX_N_APPEARED && auto_attach)
		CHK(diginet_mux_attach(&M, n->desk, NULL) == DIGINET_OK);
}

static void pump(void)
{
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	size_t n;
	for (int k = 0; k < NDESK; k++)
		while ((n = emu_pop(&E[k], b, sizeof b)))
			if (at[k])
				diginet_mux_rx(&M, b, n, at[k], now);
	diginet_mux_tick(&M, now);
}

/* the clock moves by `step`; each desk announces every 7 s, desk 1 half a second after desk 0 */
static void run(uint64_t us, uint64_t step)
{
	uint64_t end = now + us;
	while (now < end) {
		now += step;
		for (int k = 0; k < NDESK; k++) {
			emu_tick(&E[k], now);
			if (now >= next_ann[k]) {
				emu_announce(&E[k], now);
				next_ann[k] = now + 7 * S;
			}
		}
		pump();
	}
}

static void start(const char *name0, const char *name1)
{
	struct diginet_mux_io io = { .ctx = NULL, .send = io_send, .recv = NULL, .if_mac = io_if_mac, .now_us = io_now,
				     .host_macs = io_host_macs };
	emu_init(&E[0], DESK[0], name0, "1.08");
	emu_init(&E[1], DESK[1], name1, "1.08");
	CHK(diginet_mux_init(&M, NULL, &io, on_notice, NULL) == DIGINET_OK);
	now = 1000 * S;
	next_ann[0] = now;
	next_ann[1] = now + 500 * MS;
	at[0] = IFX[0];
	at[1] = IFX[1];
	memset(sent_on, 0, sizeof sent_on);
	wrong_src = 0;
	nl = 0;
	auto_attach = 1;
}

static int count(enum diginet_mux_notice_kind k, int desk)
{
	int c = 0;
	for (int i = 0; i < nl; i++)
		c += L[i].kind == k && (desk < 0 || (int)L[i].desk == desk);
	return c;
}

static int find(enum diginet_mux_notice_kind k, int desk, int nth)
{
	for (int i = 0; i < nl; i++)
		if (L[i].kind == k && (desk < 0 || (int)L[i].desk == desk) && nth-- == 0)
			return i;
	return -1;
}

static int find_session(int desk, enum diginet_notice_kind sk, enum diginet_reason why)
{
	for (int i = 0; i < nl; i++)
		if (L[i].kind == DIGINET_MUX_N_SESSION && (int)L[i].desk == desk && L[i].skind == sk &&
		    (sk != DIGINET_N_STATE || L[i].reason == why))
			return i;
	return -1;
}

static struct diginet_session *sess(int desk) { return diginet_mux_session(&M, (unsigned)desk); }

static struct diginet_cmd fader(unsigned strip, unsigned v)
{
	struct diginet_cmd c;
	CHK(diginet_fader_encode(diginet_personality_of(DIGINET_DESK_CONTROL24), strip, v, &c) == 0);
	return c;
}

/* ---- 1 ------------------------------------------------------------------------------- */

static void test_two_desks(void)
{
	start("CNTRL|24", "MAINUNIT");
	run(1 * S, 1 * MS);
	CHK(count(DIGINET_MUX_N_APPEARED, -1) == 2);
	int a = diginet_mux_find(&M, DESK[0]), b = diginet_mux_find(&M, DESK[1]);
	CHK(a >= 0 && b >= 0 && a != b);
	if (a < 0 || b < 0)
		exit(2);
	int i = find(DIGINET_MUX_N_APPEARED, a, 0), j = find(DIGINET_MUX_N_APPEARED, b, 0);
	CHK(i >= 0 && L[i].ifindex == IFX[0] && !memcmp(L[i].mac, DESK[0], 6) && L[i].personality == DIGINET_DESK_CONTROL24);
	CHK(j >= 0 && L[j].ifindex == IFX[1] && !memcmp(L[j].mac, DESK[1], 6) && L[j].personality == DIGINET_DESK_PROCONTROL);
	CHK(sess(a) && sess(a)->state == DIGINET_S_ONLINE && sess(b) && sess(b)->state == DIGINET_S_ONLINE);
	CHK(!memcmp(M.desks[a].host_mac, HOST[0], 6) && !memcmp(M.desks[b].host_mac, HOST[1], 6));
	CHK(E[0].wakes == 1 && E[1].wakes == 1 && E[0].in_session && E[1].in_session);
	CHK(!memcmp(E[0].session_mac, HOST[0], 6) && !memcmp(E[1].session_mac, HOST[1], 6));

	/* each fader to its own desk only, out of its own interface, from its own MAC */
	struct diginet_cmd fa = fader(0, 100), fb = fader(5, 900);
	CHK(diginet_session_submit(sess(a), &fa) == DIGINET_OK);
	CHK(diginet_session_submit(sess(b), &fb) == DIGINET_OK);
	run(50 * MS, 1 * MS);
	CHK(emu_count_cmd(&E[0], fa.bytes, fa.len) == 1 && emu_count_cmd(&E[1], fa.bytes, fa.len) == 0);
	CHK(emu_count_cmd(&E[1], fb.bytes, fb.len) == 1 && emu_count_cmd(&E[0], fb.bytes, fb.len) == 0);
	CHK(!sess(a)->inflight && !sess(b)->inflight && sess(a)->stats.ack_lost == 0 && sess(b)->stats.ack_lost == 0);
	CHK(wrong_src == 0 && sent_on[IFX[0]] > 0 && sent_on[IFX[1]] > 0);

	/* each desk's key reaches its own session */
	static const uint8_t mute3[] = { 0x90, 0x08, 0x42 };
	emu_send_data(&E[1], mute3, 3, 1, 0, 0);
	run(5 * MS, 1 * MS);
	int k = find_session(b, DIGINET_N_DATA, DIGINET_R_NONE);
	CHK(k >= 0 && find_session(a, DIGINET_N_DATA, DIGINET_R_NONE) < 0);
	CHK(sess(b)->stats.rx_data == 1 && sess(a)->stats.rx_data == 0);

	/* minutes of both: keepalives each on its own interface, neither session lost */
	run(60 * S, 10 * MS);
	CHK(sess(a)->state == DIGINET_S_ONLINE && sess(b)->state == DIGINET_S_ONLINE);
	/* both desks announce e1 naming their host: one wake each, and the sessions never change
	 * state */
	CHK(E[0].keepalives >= 5 && E[1].keepalives >= 5 && E[0].wakes == 1 && E[1].wakes == 1);
	CHK(E[0].in_session && E[1].in_session && sess(a)->stats.ack_lost == 0 && sess(b)->stats.ack_lost == 0);
	CHK(count(DIGINET_MUX_N_GONE, -1) == 0 && wrong_src == 0);
	/* frames only to the two interfaces the desks are on */
	unsigned other = 0;
	for (int x = 0; x < 16; x++)
		if (x != IFX[0] && x != IFX[1])
			other += sent_on[x];
	CHK(other == 0);
}

/* ---- 2 ------------------------------------------------------------------------------- */

static void test_pinned(void)
{
	start("CNTRL|24", "CNTRL|24");
	run(1 * S, 1 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->state == DIGINET_S_ONLINE);
	uint64_t routed = M.stats.rx_routed, rx = sess(a)->stats.rx_frames;
	/* desk A's announce and a key of its, heard on desk B's interface */
	uint8_t f[DIGINET_MAX_FRAME_LEN];
	emu_announce(&E[0], now);
	size_t n = emu_pop(&E[0], f, sizeof f);
	CHK(n > 0 && diginet_mux_rx(&M, f, n, IFX[1], now) == DIGINET_OK);
	static const uint8_t key[] = { 0x90, 0x08, 0x40 };
	emu_send_data(&E[0], key, 3, 1, 0, 0);
	n = emu_pop(&E[0], f, sizeof f);
	CHK(n > 0 && diginet_mux_rx(&M, f, n, IFX[1], now) == DIGINET_OK);
	CHK(M.stats.rx_other_if == 2 && M.stats.rx_routed == routed && sess(a)->stats.rx_frames == rx);
	CHK(count(DIGINET_MUX_N_APPEARED, -1) == 2 && M.desks[a].ifindex == IFX[0]);
	CHK(find_session(a, DIGINET_N_DATA, DIGINET_R_NONE) < 0);
}

/* ---- 3 ------------------------------------------------------------------------------- */

static void test_gone(void)
{
	/* not attached: gone exactly gone_ms after its last frame, and not a millisecond before */
	start("CNTRL|24", "CNTRL|24");
	auto_attach = 0;
	run(1 * S, 1 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && !sess(a));
	E[0].mute = 1;
	uint64_t last = M.desks[a].last_rx_us;
	run(last + 30 * S - 1 * MS - now, 1 * MS);
	CHK(count(DIGINET_MUX_N_GONE, a) == 0 && diginet_mux_find(&M, DESK[0]) == a);
	run(1 * MS, 1 * MS);
	int g = find(DIGINET_MUX_N_GONE, a, 0);
	CHK(g >= 0 && L[g].at == last + 30 * S && !memcmp(L[g].mac, DESK[0], 6) && L[g].ifindex == IFX[0]);
	CHK(diginet_mux_find(&M, DESK[0]) < 0 && !M.desks[a].present);
	CHK(diginet_mux_find(&M, DESK[1]) >= 0 && count(DIGINET_MUX_N_GONE, -1) == 1);

	/* attached: its session ends on silence after offline_ms (25 s), and it is gone with it,
	 * before gone_ms; the other desk is untouched. (A ProControl: a Control|24 in an e0
	 * session loses it sooner, on its first unACKed keepalive, and goes at gone_ms.) */
	start("MAINUNIT", "CNTRL|24");
	run(1 * S, 1 * MS);
	a = diginet_mux_find(&M, DESK[0]);
	int b = diginet_mux_find(&M, DESK[1]);
	CHK(a >= 0 && b >= 0 && sess(a)->state == DIGINET_S_ONLINE);
	E[0].mute = 1;
	last = M.desks[a].last_rx_us;
	run(26 * S, 1 * MS);
	int s = find_session(a, DIGINET_N_STATE, DIGINET_R_SILENCE);
	g = find(DIGINET_MUX_N_GONE, a, 0);
	CHK(s >= 0 && g == s + 1 && L[g].at == L[s].at && L[g].at < last + 30 * S);
	CHK(diginet_mux_find(&M, DESK[0]) < 0 && sess(b) && sess(b)->state == DIGINET_S_ONLINE);

	/* it comes back: it appears again, is attached, and is online */
	E[0].mute = 0;
	emu_drop_session(&E[0]);
	next_ann[0] = now;
	run(1 * S, 1 * MS);
	CHK(count(DIGINET_MUX_N_APPEARED, -1) == 3);
	a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->state == DIGINET_S_ONLINE && E[0].wakes == 2);
}

/* ---- 4 ------------------------------------------------------------------------------- */

static void test_set_aside(void)
{
	start("CNTRL|24", "CNTRL|24");
	auto_attach = 0;
	uint8_t f[DIGINET_MAX_FRAME_LEN], body[DIGINET_ANNOUNCE_BODY_LEN];
	/* a data frame from a desk that has not announced; our own frame come back; a frame of no
	 * grammar; an announce from a MAC that is no Digidesign's */
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .send_counter = 1, .num_commands = 1 };
	static const uint8_t key[] = { 0x90, 0x08, 0x40 };
	int n = diginet_frame_build(f, sizeof f, HOST[0], DESK[0], &h, key, 3, DIGINET_SUM_BODY);
	CHK(diginet_mux_rx(&M, f, (size_t)n, IFX[0], now) == DIGINET_OK);
	h.cmd = DIGINET_CMD_WAKE;
	n = diginet_frame_build(f, sizeof f, DESK[0], HOST[0], &h, NULL, 0, DIGINET_SUM_BODY);
	CHK(diginet_mux_rx(&M, f, (size_t)n, IFX[0], now) == DIGINET_OK);
	CHK(diginet_mux_rx(&M, f, 10, IFX[0], now) != DIGINET_OK);
	memset(body, 0, sizeof body);
	memcpy(body + 24, "CNTRL|24", 8);
	h.cmd = DIGINET_CMD_ANNOUNCE;
	static const uint8_t NOTDD[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	static const uint8_t BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	n = diginet_frame_build(f, sizeof f, BC, NOTDD, &h, body, sizeof body, DIGINET_SUM_BODY);
	CHK(diginet_mux_rx(&M, f, (size_t)n, IFX[0], now) == DIGINET_OK);
	CHK(M.stats.rx_ignored == 4 && M.stats.appeared == 0 && count(DIGINET_MUX_N_APPEARED, -1) == 0);

	/* a ninth desk finds no slot */
	for (unsigned k = 0; k < DIGINET_MUX_MAX_DESKS + 1; k++) {
		uint8_t mac[6] = { 0x00, 0xa0, 0x7e, 0x55, 0x00, (uint8_t)k };
		n = diginet_frame_build(f, sizeof f, BC, mac, &h, body, sizeof body, DIGINET_SUM_BODY);
		CHK(diginet_mux_rx(&M, f, (size_t)n, IFX[0], now) == DIGINET_OK);
	}
	CHK(count(DIGINET_MUX_N_APPEARED, -1) == DIGINET_MUX_MAX_DESKS && M.stats.table_full == 1);
}

/* ---- 5 ------------------------------------------------------------------------------- */

static void test_deaf(void)
{
	start("CNTRL|24", "CNTRL|24");
	E[1].ack_wake = 0;
	run(25 * S, 10 * MS);
	int a = diginet_mux_find(&M, DESK[0]), b = diginet_mux_find(&M, DESK[1]);
	int i = find_session(b, DIGINET_N_DESK_DEAF, DIGINET_R_NONE);
	CHK(i >= 0 && L[i].counter == 3 && L[i].ifindex == IFX[1]);
	CHK(find_session(a, DIGINET_N_DESK_DEAF, DIGINET_R_NONE) < 0 && sess(a)->state == DIGINET_S_ONLINE);
	CHK(find_session(b, DIGINET_N_FOREIGN, DIGINET_R_NONE) < 0);
	/* a deaf desk announces: it is present, never gone */
	run(40 * S, 10 * MS);
	CHK(count(DIGINET_MUX_N_GONE, -1) == 0 && diginet_mux_find(&M, DESK[1]) == b);
}

/* ---- 6 ------------------------------------------------------------------------------- */

static void test_retake(void)
{
	start("CNTRL|24", "MAINUNIT");
	E[0].holds_after_e3 = 1;
	run(1 * S, 1 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a)->state == DIGINET_S_ONLINE);
	/* the host stops: e3, as a host that is shut down sends it */
	CHK(diginet_mux_detach(&M, (unsigned)a, now) == DIGINET_OK && E[0].disconnects == 1 && E[0].stale);
	CHK(!sess(a) && diginet_mux_detach(&M, (unsigned)a, now) == DIGINET_E_ARG);
	run(2 * S, 10 * MS);
	/* and starts again: a fresh mux; the desk still announces e1 naming this host */
	struct diginet_mux_io io = { .ctx = NULL, .send = io_send, .recv = NULL, .if_mac = io_if_mac, .now_us = io_now };
	CHK(diginet_mux_init(&M, NULL, &io, on_notice, NULL) == DIGINET_OK);
	nl = 0;
	run(next_ann[0] - now, 1 * MS);
	int i = find(DIGINET_MUX_N_APPEARED, -1, 0);
	CHK(i >= 0 && !memcmp(L[i].mac, DESK[0], 6));
	a = diginet_mux_find(&M, DESK[0]);
	int on = find_session(a, DIGINET_N_STATE, DIGINET_R_ONLINE);
	CHK(on >= 0 && L[on].at - L[i].at < 1 * S && E[0].wakes == 2 && E[0].in_session);
}

/* ---- 7 ------------------------------------------------------------------------------- */

static void test_attach(void)
{
	start("CNTRL|24", "CNTRL|24");
	auto_attach = 0;
	CHK(diginet_mux_attach(&M, 0, NULL) == DIGINET_E_ARG);              /* no desk */
	CHK(diginet_mux_attach(&M, DIGINET_MUX_MAX_DESKS, NULL) == DIGINET_E_ARG);
	run(1 * S, 1 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && !sess(a) && E[0].wakes == 0 && sent_on[IFX[0]] == 0);   /* present, left alone */
	/* attached later, by hand: woken by its next announce */
	struct diginet_session_config c;
	diginet_session_config_default(&c);
	c.keepalive_ms = 5000;
	CHK(diginet_mux_attach(&M, (unsigned)a, &c) == DIGINET_OK);
	CHK(diginet_mux_attach(&M, (unsigned)a, &c) == DIGINET_E_ARG);      /* twice */
	CHK(sess(a)->cfg.keepalive_ms == 5000 && sess(a)->cfg.desk_mac_set && !memcmp(sess(a)->cfg.desk_mac, DESK[0], 6));
	run(8 * S, 1 * MS);
	CHK(sess(a)->state == DIGINET_S_ONLINE && E[0].wakes == 1);
	/* a desk on an interface whose MAC cannot be read */
	uint8_t f[DIGINET_MAX_FRAME_LEN];
	emu_announce(&E[1], now);
	size_t n = emu_pop(&E[1], f, sizeof f);
	int b = diginet_mux_find(&M, DESK[1]);
	CHK(b >= 0);
	M.desks[b].present = 0;   /* forget it, then hear it on interface 9 */
	CHK(diginet_mux_rx(&M, f, n, 9, now) == DIGINET_OK);
	b = diginet_mux_find(&M, DESK[1]);
	CHK(b >= 0 && M.desks[b].ifindex == 9 && diginet_mux_attach(&M, (unsigned)b, NULL) == -ENODEV && !sess(b));
}

/* ---- 8 ------------------------------------------------------------------------------- */

static void test_deadline(void)
{
	start("CNTRL|24", "CNTRL|24");
	auto_attach = 0;
	run(1 * S, 1 * MS);
	CHK(diginet_mux_deadline(&M, now) <= now + 1 * S);
	/* both desks silent for 28.5 s: the deadline is the first one's gone time */
	E[0].mute = 1;
	E[1].mute = 1;
	run(28500 * MS, 10 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && diginet_mux_deadline(&M, now) == M.desks[a].last_rx_us + 30 * S);
	/* an attached session's own deadline (its wake timeout) is never passed */
	start("CNTRL|24", "CNTRL|24");
	E[0].ack_wake = 0;
	run(10 * MS, 1 * MS);
	a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a)->state == DIGINET_S_WAKING);
	CHK(diginet_mux_deadline(&M, now) <= diginet_session_deadline(sess(a), now));
	CHK(diginet_mux_deadline(&M, now) >= now);
}

/* ---- 9 ------------------------------------------------------------------------------- */

/* Desk 0 online on IFX[0], its host stopped (e3; the desk holds its e1 naming HOST[0]), the
 * desk cabled to IFX[1] instead and desk 1 unplugged, and the host started again: a fresh mux,
 * with io_host_macs or without. */
static void moved(int list_host_macs)
{
	start("CNTRL|24", "MAINUNIT");
	E[0].holds_after_e3 = 1;
	run(1 * S, 1 * MS);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->state == DIGINET_S_ONLINE && !memcmp(E[0].session_mac, HOST[0], 6));
	CHK(diginet_mux_detach(&M, (unsigned)a, now) == DIGINET_OK && E[0].stale);
	at[0] = IFX[1];
	at[1] = 0;
	E[1].mute = 1;
	run(2 * S, 10 * MS);
	struct diginet_mux_io io = { .ctx = NULL, .send = io_send, .recv = NULL, .if_mac = io_if_mac, .now_us = io_now,
				     .host_macs = list_host_macs ? io_host_macs : NULL };
	CHK(diginet_mux_init(&M, NULL, &io, on_notice, NULL) == DIGINET_OK);
	nl = 0;
	wrong_src = 0;
	run(next_ann[0] - now, 1 * MS);
}

static void test_moved(void)
{
	moved(1);
	int i = find(DIGINET_MUX_N_APPEARED, -1, 0);
	CHK(i >= 0 && !memcmp(L[i].mac, DESK[0], 6) && L[i].ifindex == IFX[1]);
	int a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->cfg.n_other_host_macs == 1 && !memcmp(sess(a)->cfg.other_host_macs[0], HOST[0], 6));
	int on = find_session(a, DIGINET_N_STATE, DIGINET_R_ONLINE);
	CHK(on >= 0 && L[on].at - L[i].at < 1 * S && find_session(a, DIGINET_N_FOREIGN, DIGINET_R_NONE) < 0);
	CHK(E[0].wakes == 2 && E[0].in_session && !E[0].stale && !memcmp(E[0].session_mac, HOST[1], 6));
	CHK(wrong_src == 0 && M.desks[a].ifindex == IFX[1] && !memcmp(M.desks[a].host_mac, HOST[1], 6));
	run(30 * S, 10 * MS);
	CHK(sess(a)->state == DIGINET_S_ONLINE && sess(a)->stats.ack_lost == 0);

	/* the io lists no host MACs: the e1 naming the first interface is another host's */
	moved(0);
	a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->cfg.n_other_host_macs == 0);
	CHK(find_session(a, DIGINET_N_FOREIGN, DIGINET_R_NONE) >= 0 && find_session(a, DIGINET_N_STATE, DIGINET_R_ONLINE) < 0);
	CHK(E[0].wakes == 1 && E[0].stale);

	/* a desk in session with a host that is none of this host's interfaces: refused, with the
	 * host MACs listed */
	start("CNTRL|24", "CNTRL|24");
	E[0].foreign = 1;
	memcpy(E[0].session_mac, ELSEWHERE, 6);
	run(10 * S, 10 * MS);
	a = diginet_mux_find(&M, DESK[0]);
	CHK(a >= 0 && sess(a) && sess(a)->cfg.n_other_host_macs == 1 && !memcmp(sess(a)->cfg.other_host_macs[0], HOST[1], 6));
	CHK(find_session(a, DIGINET_N_FOREIGN, DIGINET_R_NONE) >= 0 && sess(a)->state == DIGINET_S_IDLE);
	CHK(E[0].wakes == 0 && !memcmp(E[0].session_mac, ELSEWHERE, 6));
	int b = diginet_mux_find(&M, DESK[1]);
	CHK(b >= 0 && sess(b) && sess(b)->state == DIGINET_S_ONLINE);
}

int main(void)
{
	test_two_desks();
	test_pinned();
	test_gone();
	test_set_aside();
	test_deaf();
	test_retake();
	test_attach();
	test_deadline();
	test_moved();
	if (fails) {
		fprintf(stderr, "test_mux: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_mux: ok\n");
	return 0;
}
