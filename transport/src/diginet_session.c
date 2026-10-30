// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The session state machine (include/diginet/transport/diginet_session.h). */
#include <string.h>

#include <diginet/transport/diginet_session.h>

static const uint8_t BROADCAST[DIGINET_MAC_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void diginet_session_config_default(struct diginet_session_config *c)
{
	if (!c)
		return;
	memset(c, 0, sizeof *c);
	c->auto_wake = 1;
	c->sum_mode = DIGINET_SUM_BODY;
	c->keepalive_ms = 10000;
	c->ack_timeout_ms = 100;
	c->max_retries = 5;
	c->backoff_ms = 300;
	c->offline_ms = 25000;
	c->wake_timeout_ms = 3000;
	c->display_gap_us = 2000;
	c->max_cmds = 48;
	c->max_body = 314;
	c->deaf_wakes = 3;
}

const char *diginet_state_name(enum diginet_session_state st)
{
	switch (st) {
	case DIGINET_S_IDLE:   return "idle";
	case DIGINET_S_WAKING: return "waking";
	case DIGINET_S_ONLINE: return "online";
	case DIGINET_S_CLOSED: return "closed";
	}
	return "?";
}

const char *diginet_reason_name(enum diginet_reason r)
{
	switch (r) {
	case DIGINET_R_NONE:            return "none";
	case DIGINET_R_WAKE:            return "wake sent";
	case DIGINET_R_ONLINE:          return "desk took the session";
	case DIGINET_R_DESK_OFFLINE:    return "desk announced e0";
	case DIGINET_R_SILENCE:         return "silence";
	case DIGINET_R_FOREIGN:         return "desk in session with another host";
	case DIGINET_R_WAKE_TIMEOUT:    return "not online after e2";
	case DIGINET_R_DESK_DISCONNECT: return "desk sent e3";
	case DIGINET_R_CLOSED:          return "host sent e3";
	case DIGINET_R_ACK_LOST:        return "desk stopped ACKing";
	}
	return "?";
}

int diginet_session_init(struct diginet_session *s, const struct diginet_session_config *cfg,
			 const struct diginet_io *io, diginet_notice_fn notify, void *ctx)
{
	if (!s || !cfg || !io || !io->send || !notify)
		return DIGINET_E_ARG;
	if (!cfg->max_cmds || cfg->max_body < DIGINET_CMD_MAX_LEN || cfg->max_body > DIGINET_MAX_BODY_LEN ||
	    cfg->max_cmds > 255 || cfg->n_other_host_macs > DIGINET_SESSION_MAX_HOST_MACS)
		return DIGINET_E_ARG;
	memset(s, 0, sizeof *s);
	s->cfg = *cfg;
	s->io = *io;
	s->notify = notify;
	s->notify_ctx = ctx;
	s->state = DIGINET_S_IDLE;
	if (cfg->desk_mac_set) {
		memcpy(s->desk_mac, cfg->desk_mac, DIGINET_MAC_LEN);
		s->desk_known = 1;
	}
	return DIGINET_OK;
}

static uint64_t ms(uint32_t v) { return (uint64_t)v * 1000u; }

static void set_state(struct diginet_session *s, enum diginet_session_state st, enum diginet_reason why)
{
	if (s->state == st)
		return;
	struct diginet_notice n = { .kind = DIGINET_N_STATE, .state = st, .old_state = s->state, .reason = why };
	s->state = st;
	s->notify(s->notify_ctx, &n);
}

static int send_raw(struct diginet_session *s, const uint8_t *frame, size_t len)
{
	int r = s->io.send(s->io.ctx, frame, len);
	if (r == 0)
		s->stats.tx_frames++;
	return r;
}

/* Build and send a control frame (no body): ACK, e2, e3. An e2 carries send counter 0: a
 * Control|24 takes a session on no other, and only ACKs an e2 with the running counter
 * (measured 2026-10-30). */
static int send_control(struct diginet_session *s, uint8_t cmd, uint32_t ack_counter, uint8_t *keep, size_t *keep_len)
{
	uint8_t f[DIGINET_MIN_FRAME_LEN];
	struct diginet_header h = { .send_counter = cmd == DIGINET_CMD_WAKE ? 0 : s->host_counter,
				    .ack_counter = ack_counter, .cmd = cmd };
	int n = diginet_frame_build(f, sizeof f, s->desk_mac, s->cfg.host_mac, &h, NULL, 0, s->cfg.sum_mode);
	if (n < 0)
		return n;
	if (keep) {
		memcpy(keep, f, (size_t)n);
		*keep_len = (size_t)n;
	}
	return send_raw(s, f, (size_t)n);
}

static void inflight_start(struct diginet_session *s, uint32_t counter, uint64_t now)
{
	s->inflight = 1;
	s->inflight_counter = counter;
	s->inflight_retries = 0;
	s->inflight_sent_us = now;
}

/* Send an e2 as the frame in flight, so its a0 is matched as any other. The e2 becomes the
 * frame in flight only once it is sent: a failed send leaves the frame in flight, which the next
 * retransmission sends again, as it was. */
static int send_wake(struct diginet_session *s, uint64_t now_us)
{
	uint8_t e2[DIGINET_MIN_FRAME_LEN];
	size_t e2_len;
	int r = send_control(s, DIGINET_CMD_WAKE, 0, e2, &e2_len);
	if (r < 0)
		return r;
	memcpy(s->inflight_frame, e2, e2_len);
	s->inflight_len = e2_len;
	s->stats.tx_wakes++;
	inflight_start(s, 0, now_us);   /* its a0 echoes the 0 it carried */
	return DIGINET_OK;
}

int diginet_session_wake(struct diginet_session *s, uint64_t now_us)
{
	if (!s)
		return DIGINET_E_ARG;
	if (!s->desk_known)
		return DIGINET_E_ARG;
	if (s->foreign) {
		s->stats.refused++;
		return DIGINET_E_REFUSED;   /* never steal another host's session */
	}
	s->e1_named_us = 0;
	s->wake_acked = 0;
	s->wake_sent_us = now_us;
	int r = send_wake(s, now_us);
	if (r < 0)
		return r;
	set_state(s, DIGINET_S_WAKING, DIGINET_R_WAKE);
	return DIGINET_OK;
}

int diginet_session_close(struct diginet_session *s, uint64_t now_us)
{
	(void)now_us;
	if (!s)
		return DIGINET_E_ARG;
	int r = 0;
	if (s->desk_known && !s->foreign && s->state != DIGINET_S_CLOSED)
		r = send_control(s, DIGINET_CMD_DISCONNECT, 0, NULL, NULL);
	s->inflight = 0;
	set_state(s, DIGINET_S_CLOSED, DIGINET_R_CLOSED);
	return r;
}

static void session_lost(struct diginet_session *s, enum diginet_reason why)
{
	s->inflight = 0;
	s->desk_counter_valid = 0;
	set_state(s, DIGINET_S_IDLE, why);
}

/* Where this host's MAC sits in an e1 body's leading bytes, or -1 (docs/protocol.md, A6). */
static int find_mac(const struct diginet_announce *a, const uint8_t mac[DIGINET_MAC_LEN])
{
	for (size_t i = 0; i + DIGINET_MAC_LEN <= a->unknown_len; i++)
		if (!memcmp(a->unknown + i, mac, DIGINET_MAC_LEN))
			return (int)i;
	return -1;
}

/* Whether an e1 names one of this host's other MACs. */
static int names_other_host_mac(const struct diginet_session *s, const struct diginet_announce *a)
{
	for (unsigned i = 0; i < s->cfg.n_other_host_macs; i++)
		if (find_mac(a, s->cfg.other_host_macs[i]) >= 0)
			return 1;
	return 0;
}

/* Online on the a0 for the e2 and an e1 naming this host: in session every desk announces e1
 * (docs/protocol.md, "Discovery and handshake"). */
static void maybe_online(struct diginet_session *s)
{
	if (s->state == DIGINET_S_WAKING && s->wake_acked && s->e1_named_us) {
		s->next_keepalive_us = s->last_rx_us + ms(s->cfg.keepalive_ms);
		set_state(s, DIGINET_S_ONLINE, DIGINET_R_ONLINE);
	}
}

static void on_announce(struct diginet_session *s, const struct diginet_frame *f, uint64_t now)
{
	struct diginet_announce a;
	if (diginet_announce_parse(f, &a) != DIGINET_OK) {
		s->stats.rx_ignored++;
		return;
	}
	const struct diginet_personality *p = diginet_personality_from_name(a.name);
	if (p)
		s->personality = p;
	int off = f->h.cmd == DIGINET_CMD_ANNOUNCE_SESSION ? find_mac(&a, s->cfg.host_mac) : -1;

	struct diginet_notice n = { .kind = DIGINET_N_DESK, .state = s->state, .frame = f,
				    .announce = &a, .personality = p, .mac_offset = off };
	s->notify(s->notify_ctx, &n);
	s->announce_seen = 1;
	s->last_announce_us = now;

	if (f->h.cmd == DIGINET_CMD_ANNOUNCE) {
		s->foreign = 0;
		/* In session a desk announces only e1 naming its host: an e0 is a desk out of
		 * session, after a reboot, and the session is lost, then woken again. */
		if (s->state == DIGINET_S_ONLINE)
			session_lost(s, DIGINET_R_DESK_OFFLINE);
		if (s->state == DIGINET_S_IDLE && s->cfg.auto_wake)
			diginet_session_wake(s, now);
		return;
	}

	/* e1 */
	if (off >= 0) {
		s->foreign = 0;
		s->e1_named_us = 1;
		if (s->state == DIGINET_S_IDLE && s->cfg.auto_wake)
			diginet_session_wake(s, now);   /* our own session, still announced: take it */
		maybe_online(s);
		return;
	}
	if (names_other_host_mac(s, &a)) {
		s->foreign = 0;
		if (s->state == DIGINET_S_IDLE && s->cfg.auto_wake)
			diginet_session_wake(s, now);   /* ours on another interface of this host: take it here */
		return;
	}
	s->foreign = 1;
	s->deaf_count = 0;   /* it answers another host: not deaf */
	struct diginet_notice fn = { .kind = DIGINET_N_FOREIGN, .state = s->state, .frame = f, .announce = &a };
	s->notify(s->notify_ctx, &fn);
	if (s->state == DIGINET_S_ONLINE || s->state == DIGINET_S_WAKING)
		session_lost(s, DIGINET_R_FOREIGN);
}

static void on_ack(struct diginet_session *s, const struct diginet_frame *f)
{
	if (!s->inflight || f->h.ack_counter != s->inflight_counter) {
		s->stats.rx_ignored++;
		return;
	}
	s->inflight = 0;
	struct diginet_notice n = { .kind = DIGINET_N_ACKED, .state = s->state, .frame = f,
				    .counter = f->h.ack_counter, .retry = (uint16_t)s->inflight_retries };
	s->notify(s->notify_ctx, &n);
	if (s->state == DIGINET_S_WAKING) {
		s->wake_acked = 1;
		s->deaf_count = 0;
		maybe_online(s);
	}
}

static void on_data(struct diginet_session *s, const struct diginet_frame *f, uint64_t now)
{
	/* Every desk data frame is acknowledged, a retransmitted one again. */
	if (send_control(s, DIGINET_CMD_ACK, f->h.send_counter, NULL, NULL) == 0)
		s->stats.tx_acks++;
	s->stats.rx_data++;
	if (f->h.retry) {
		s->stats.rx_desk_retries++;
		s->backoff_until_us = now + ms(s->cfg.backoff_ms);
	}
	if (s->desk_counter_valid && f->h.send_counter == s->desk_counter && f->h.retry) {
		s->stats.rx_duplicates++;
		return;
	}
	s->desk_counter = f->h.send_counter;
	s->desk_counter_valid = 1;
	if (diginet_frame_is_keepalive(f))
		return;
	struct diginet_notice n = { .kind = DIGINET_N_DATA, .state = s->state, .frame = f,
				    .body = f->body, .body_len = f->body_len,
				    .counter = f->h.send_counter, .retry = f->h.retry };
	s->notify(s->notify_ctx, &n);
}

int diginet_session_rx(struct diginet_session *s, const uint8_t *buf, size_t len, uint64_t now_us)
{
	struct diginet_frame f;
	if (!s || !buf)
		return DIGINET_E_ARG;
	int r = diginet_frame_parse(buf, len, &f);
	if (r != DIGINET_OK) {
		s->stats.rx_ignored++;
		return r;
	}
	if (!memcmp(f.src, s->cfg.host_mac, DIGINET_MAC_LEN) ||
	    (memcmp(f.dst, s->cfg.host_mac, DIGINET_MAC_LEN) && memcmp(f.dst, BROADCAST, DIGINET_MAC_LEN))) {
		s->stats.rx_ignored++;   /* our own frame, or one for another host */
		return DIGINET_OK;
	}
	if (s->desk_known) {
		if (memcmp(f.src, s->desk_mac, DIGINET_MAC_LEN)) {
			s->stats.rx_ignored++;
			return DIGINET_OK;
		}
	} else {
		if (f.h.cmd != DIGINET_CMD_ANNOUNCE && f.h.cmd != DIGINET_CMD_ANNOUNCE_SESSION)
			return DIGINET_OK;
		if (!diginet_mac_is_digidesign(f.src)) {
			s->stats.rx_ignored++;
			return DIGINET_OK;
		}
		memcpy(s->desk_mac, f.src, DIGINET_MAC_LEN);
		s->desk_known = 1;
	}
	if (s->state == DIGINET_S_CLOSED)
		return DIGINET_OK;

	s->stats.rx_frames++;
	s->last_rx_us = now_us;
	switch (f.h.cmd) {
	case DIGINET_CMD_ANNOUNCE:
	case DIGINET_CMD_ANNOUNCE_SESSION:
		on_announce(s, &f, now_us);
		break;
	case DIGINET_CMD_ACK:
		on_ack(s, &f);
		break;
	case DIGINET_CMD_DATA:
		on_data(s, &f, now_us);
		break;
	case DIGINET_CMD_DISCONNECT:
		if (s->state == DIGINET_S_ONLINE || s->state == DIGINET_S_WAKING)
			session_lost(s, DIGINET_R_DESK_DISCONNECT);
		break;
	default:
		s->stats.rx_ignored++;
		break;
	}
	return diginet_session_tick(s, now_us);
}

/* ---- the queue -------------------------------------------------------------------------- */

static int coalescable(uint32_t key)
{
	uint8_t k = DIGINET_KEY_KIND(key);
	return k != 0 && k != DIGINET_KEY_INPUT && k != DIGINET_KEY_KEEPALIVE;
}

int diginet_session_submit(struct diginet_session *s, const struct diginet_cmd *c)
{
	if (!s || !c || !c->len || c->len > DIGINET_CMD_MAX_LEN)
		return DIGINET_E_ARG;
	if (diginet_body_check(c->bytes, c->len) != DIGINET_OK) {
		s->stats.refused++;
		return DIGINET_E_REFUSED;
	}
	if (coalescable(c->key)) {
		for (unsigned i = 0; i < s->queued; i++) {
			if (s->queue[i].key == c->key) {
				s->queue[i] = *c;   /* latest wins, in place */
				s->stats.coalesced++;
				return DIGINET_OK;
			}
		}
	}
	if (s->queued == DIGINET_QUEUE_MAX)
		return DIGINET_E_SPACE;
	s->queue[s->queued++] = *c;
	return DIGINET_OK;
}

/* Take what fits in one frame from the head of the queue into body; display writes only
 * when the pacing allows. Returns the number of commands taken. */
static unsigned take(struct diginet_session *s, uint8_t *body, size_t *body_len, int allow_display, int *has_display)
{
	unsigned taken = 0, kept = 0;
	size_t len = 0;
	*has_display = 0;
	for (unsigned i = 0; i < s->queued; i++) {
		struct diginet_cmd *c = &s->queue[i];
		int fits = taken < s->cfg.max_cmds && len + c->len <= s->cfg.max_body &&
			   (allow_display || !c->display);
		if (fits) {
			/* Two commands each whole alone can make an F0 13 xx 70 side by side, a body
			 * the frame builder refuses: such a one waits for a frame of its own. */
			memcpy(body + len, c->bytes, c->len);
			fits = diginet_body_check(body, len + c->len) == DIGINET_OK;
		}
		if (fits) {
			len += c->len;
			taken++;
			*has_display |= c->display;
		} else {
			if (kept != i)
				s->queue[kept] = *c;
			kept++;
		}
		if (taken == s->cfg.max_cmds || len == s->cfg.max_body) {
			for (unsigned j = i + 1; j < s->queued; j++)
				s->queue[kept++] = s->queue[j];
			break;
		}
	}
	s->queued = kept;
	*body_len = len;
	return taken;
}

static int send_data(struct diginet_session *s, const uint8_t *body, size_t body_len, unsigned ncmds, uint64_t now)
{
	struct diginet_header h = { .cmd = DIGINET_CMD_DATA, .num_commands = (uint8_t)ncmds };
	s->host_counter += ncmds;
	h.send_counter = s->host_counter;
	int n = diginet_frame_build(s->inflight_frame, sizeof s->inflight_frame, s->desk_mac,
				    s->cfg.host_mac, &h, body, body_len, s->cfg.sum_mode);
	if (n < 0)
		return n;
	s->inflight_len = (size_t)n;
	inflight_start(s, s->host_counter, now);
	s->stats.tx_data++;
	return send_raw(s, s->inflight_frame, s->inflight_len);
}

static int retransmit(struct diginet_session *s, uint64_t now)
{
	s->inflight_retries++;
	uint16_t retry = (uint16_t)s->inflight_retries;
	s->inflight_frame[DIGINET_ETH_HDR_LEN + 12] = (uint8_t)(retry >> 8);
	s->inflight_frame[DIGINET_ETH_HDR_LEN + 13] = (uint8_t)retry;
	s->inflight_sent_us = now;
	s->stats.tx_retransmits++;
	return send_raw(s, s->inflight_frame, s->inflight_len);
}

int diginet_session_tick(struct diginet_session *s, uint64_t now)
{
	if (!s)
		return DIGINET_E_ARG;
	if (s->state == DIGINET_S_CLOSED || s->state == DIGINET_S_IDLE)
		return DIGINET_OK;

	if (s->state == DIGINET_S_WAKING && now - s->wake_sent_us >= ms(s->cfg.wake_timeout_ms)) {
		/* Deaf: the desk still announces (within offline_ms) and lets wake after wake time out. */
		int announcing = s->announce_seen && now - s->last_announce_us < ms(s->cfg.offline_ms);
		s->deaf_count = announcing ? s->deaf_count + 1 : 0;
		session_lost(s, DIGINET_R_WAKE_TIMEOUT);
		if (s->cfg.deaf_wakes && s->deaf_count == s->cfg.deaf_wakes) {
			struct diginet_notice n = { .kind = DIGINET_N_DESK_DEAF, .state = s->state,
						    .counter = s->deaf_count };
			s->notify(s->notify_ctx, &n);
		}
		return DIGINET_OK;
	}
	if (s->state == DIGINET_S_ONLINE && now - s->last_rx_us >= ms(s->cfg.offline_ms)) {
		session_lost(s, DIGINET_R_SILENCE);
		return DIGINET_OK;
	}

	if (s->inflight && now - s->inflight_sent_us >= ms(s->cfg.ack_timeout_ms)) {
		if (s->inflight_retries < s->cfg.max_retries) {
			int r = retransmit(s, now);
			if (r < 0)
				return r;
		} else {
			s->inflight = 0;
			s->stats.ack_lost++;
			struct diginet_notice n = { .kind = DIGINET_N_ACK_LOST, .state = s->state,
						    .counter = s->inflight_counter,
						    .retry = (uint16_t)s->inflight_retries };
			s->notify(s->notify_ctx, &n);
			/* No ACK through every retry: the desk is gone (unplugged, powered off), which
			 * sends no e0. */
			if (s->state == DIGINET_S_ONLINE) {
				session_lost(s, DIGINET_R_ACK_LOST);
				return DIGINET_OK;
			}
		}
	}

	if (s->state != DIGINET_S_ONLINE || s->inflight || now < s->backoff_until_us)
		return DIGINET_OK;

	/* The keepalive runs on its own clock: nothing else moves next_keepalive_us. */
	if (now >= s->next_keepalive_us) {
		uint8_t ka = 0x00;
		s->next_keepalive_us += ms(s->cfg.keepalive_ms);
		if (s->next_keepalive_us <= now)
			s->next_keepalive_us = now + ms(s->cfg.keepalive_ms);
		s->stats.tx_keepalives++;
		return send_data(s, &ka, 1, 1, now);
	}

	if (!s->queued)
		return DIGINET_OK;
	int allow_display = !s->display_sent || now - s->last_display_us >= s->cfg.display_gap_us;
	uint8_t body[DIGINET_MAX_BODY_LEN];
	size_t body_len;
	int has_display;
	unsigned n = take(s, body, &body_len, allow_display, &has_display);
	if (!n)
		return DIGINET_OK;
	if (has_display) {
		s->display_sent = 1;
		s->last_display_us = now;
	}
	return send_data(s, body, body_len, n, now);
}

static uint64_t min64(uint64_t a, uint64_t b) { return a < b ? a : b; }

uint64_t diginet_session_deadline(const struct diginet_session *s, uint64_t now)
{
	uint64_t d = now + 1000000;  /* at least once a second */
	if (!s || s->state == DIGINET_S_CLOSED || s->state == DIGINET_S_IDLE)
		return d;
	if (s->state == DIGINET_S_WAKING)
		d = min64(d, s->wake_sent_us + ms(s->cfg.wake_timeout_ms));
	if (s->state == DIGINET_S_ONLINE) {
		d = min64(d, s->last_rx_us + ms(s->cfg.offline_ms));
		/* A keepalive due during a back-off goes when the back-off ends: tick() holds it
		 * until then, so the deadline is then too, or a poll loop would spin. */
		if (!s->inflight)
			d = min64(d, s->next_keepalive_us > s->backoff_until_us ? s->next_keepalive_us
									      : s->backoff_until_us);
	}
	if (s->inflight)
		return min64(d, s->inflight_sent_us + ms(s->cfg.ack_timeout_ms));
	if (s->state == DIGINET_S_ONLINE && s->queued) {
		uint64_t t = s->backoff_until_us > now ? s->backoff_until_us : now;
		int display_only = 1;
		for (unsigned i = 0; i < s->queued && display_only; i++)
			display_only = s->queue[i].display;
		if (display_only && s->display_sent)
			t = t > s->last_display_us + s->cfg.display_gap_us ? t : s->last_display_us + s->cfg.display_gap_us;
		d = min64(d, t);
	}
	return d < now ? now : d;
}

int diginet_session_poll(struct diginet_session *s, int max_wait_ms)
{
	uint8_t buf[DIGINET_MAX_FRAME_LEN];
	if (!s || !s->io.recv || !s->io.now_us)
		return DIGINET_E_ARG;
	uint64_t now = s->io.now_us(s->io.ctx);
	uint64_t due = diginet_session_deadline(s, now);
	uint64_t wait_us = due > now ? due - now : 0;
	int wait = (int)((wait_us + 999) / 1000);
	if (max_wait_ms >= 0 && wait > max_wait_ms)
		wait = max_wait_ms;
	int r = s->io.recv(s->io.ctx, buf, sizeof buf, wait);
	if (r < 0)
		return r;
	now = s->io.now_us(s->io.ctx);
	if (r > 0)
		diginet_session_rx(s, buf, (size_t)r, now);
	diginet_session_tick(s, now);
	/* Drain whatever else is already waiting. */
	while ((r = s->io.recv(s->io.ctx, buf, sizeof buf, 0)) > 0)
		diginet_session_rx(s, buf, (size_t)r, s->io.now_us(s->io.ctx));
	return r < 0 ? r : 0;
}
