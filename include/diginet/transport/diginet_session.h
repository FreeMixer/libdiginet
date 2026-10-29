/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet-transport: one host's session with one desk (docs/protocol.md, "Discovery and
 * handshake", "Acks, sequencing, retransmit", "Keepalive").
 *
 *   IDLE --(desk announces e0, or e1 naming this host; host sends e2)--> WAKING
 *   WAKING --(desk a0 for the e2, and an e1 naming this host from a desk that announces e1)--> ONLINE
 *   ONLINE --(e0 once the session was announced in e1, a host frame lost while it was not,
 *             silence, an e1 naming another host, desk e3)--> IDLE
 *   any --(diginet_session_close: host e3)--> CLOSED
 *
 * While a session lives:
 *   - every desk data frame is ACKed at once, its counter echoed;
 *   - one host data frame is in flight; with no ACK after ack_timeout it is sent again with
 *     the retry field set (1, 2, ...), and after max_retries it is dropped and reported;
 *   - after a desk retry the host holds its own frames for backoff_ms;
 *   - a keepalive goes every keepalive_ms on its own clock: ACKs and data never delay it;
 *   - commands queue by address (the key of struct diginet_cmd): a newer value replaces a
 *     queued one in place, so no stale value is ever sent;
 *   - frames hold at most max_cmds commands and max_body bytes, and a frame holding display
 *     writes follows the previous one by at least display_gap_us;
 *   - e2 is never sent while the desk announces a session with another host.
 *
 * The session is a state machine over caller time: diginet_session_rx() takes each frame,
 * diginet_session_tick() runs the timers, diginet_session_poll() does both over its io. No
 * allocation: the queue lives inside the struct.
 */
#ifndef DIGINET_SESSION_H
#define DIGINET_SESSION_H

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>

#ifdef __cplusplus
extern "C" {
#endif

enum diginet_session_state {
	DIGINET_S_IDLE = 0,
	DIGINET_S_WAKING,
	DIGINET_S_ONLINE,
	DIGINET_S_CLOSED,
};

/* Why the state changed. */
enum diginet_reason {
	DIGINET_R_NONE = 0,
	DIGINET_R_WAKE,          /* the host sent e2 */
	DIGINET_R_ONLINE,        /* a0, and an e1 naming this host if the desk announces e1 */
	DIGINET_R_DESK_OFFLINE,  /* e0 after an e1 named this host in this session */
	DIGINET_R_SILENCE,       /* nothing from the desk for offline_ms */
	DIGINET_R_FOREIGN,       /* the desk announced a session with another host */
	DIGINET_R_WAKE_TIMEOUT,  /* not online within wake_timeout_ms */
	DIGINET_R_DESK_DISCONNECT, /* the desk sent e3 */
	DIGINET_R_CLOSED,        /* the host sent e3 */
	DIGINET_R_ACK_LOST,      /* a host frame lost in a session no e1 has announced */
};

struct diginet_session_config {
	uint8_t host_mac[DIGINET_MAC_LEN];
	uint8_t desk_mac[DIGINET_MAC_LEN]; /* used when desk_mac_set: talk to this desk only */
	int desk_mac_set;
	int auto_wake;                  /* send e2 on an e0 or an e1 naming this host, while IDLE */
	enum diginet_sum_mode sum_mode; /* the header sum of host frames */
	uint32_t keepalive_ms;          /* 10000 */
	uint32_t ack_timeout_ms;        /* 100 */
	uint32_t max_retries;           /* 5 */
	uint32_t backoff_ms;            /* 300 */
	uint32_t offline_ms;            /* 25000 */
	uint32_t wake_timeout_ms;       /* 3000 */
	uint32_t display_gap_us;        /* 2000 */
	uint32_t max_cmds;              /* 48 */
	uint32_t max_body;              /* 314 */
};

void diginet_session_config_default(struct diginet_session_config *c);

enum diginet_notice_kind {
	DIGINET_N_DESK = 1,  /* an announce from the desk: announce, personality, mac_offset */
	DIGINET_N_STATE,     /* state, old_state, reason */
	DIGINET_N_DATA,      /* a desk data frame: body, body_len, counter (never a duplicate) */
	DIGINET_N_ACKED,     /* the desk ACKed host frame `counter` */
	DIGINET_N_ACK_LOST,  /* host frame `counter` dropped after max_retries */
	DIGINET_N_FOREIGN,   /* an e1 that does not name this host */
};

struct diginet_notice {
	enum diginet_notice_kind kind;
	enum diginet_session_state state, old_state;
	enum diginet_reason reason;
	const struct diginet_frame *frame;    /* the frame behind the notice, when there is one */
	const struct diginet_announce *announce;
	const struct diginet_personality *personality;
	int mac_offset;      /* N_DESK on e1: where this host's MAC sits in the body, or -1 */
	const uint8_t *body;
	size_t body_len;
	uint32_t counter;
	uint16_t retry;
};

typedef void (*diginet_notice_fn)(void *ctx, const struct diginet_notice *n);

struct diginet_session_stats {
	uint64_t rx_frames, rx_data, rx_duplicates, rx_desk_retries, rx_ignored;
	uint64_t tx_frames, tx_data, tx_acks, tx_keepalives, tx_wakes, tx_retransmits;
	uint64_t ack_lost, coalesced, refused;
};

#define DIGINET_QUEUE_MAX 512

struct diginet_session {
	struct diginet_session_config cfg;
	struct diginet_io io;
	diginet_notice_fn notify;
	void *notify_ctx;

	enum diginet_session_state state;
	int desk_known;
	uint8_t desk_mac[DIGINET_MAC_LEN];
	const struct diginet_personality *personality;
	int foreign;              /* the last announce was an e1 for another host */
	int e1_named_us;          /* since the last e2 */
	int wake_acked;           /* since the last e2 */
	uint64_t wake_sent_us;

	uint32_t host_counter;
	uint32_t desk_counter;    /* the last desk data counter delivered */
	int desk_counter_valid;

	uint64_t last_rx_us;
	uint64_t next_keepalive_us;
	uint64_t backoff_until_us;
	uint64_t last_display_us;
	int display_sent;

	/* the one host frame in flight */
	int inflight;
	uint8_t inflight_frame[DIGINET_MAX_FRAME_LEN];
	size_t inflight_len;
	uint32_t inflight_counter;
	uint32_t inflight_retries;
	uint64_t inflight_sent_us;

	struct diginet_cmd queue[DIGINET_QUEUE_MAX];
	unsigned queued;

	struct diginet_session_stats stats;
};

/* cfg is copied. io and notify may not be NULL (notify may be a no-op). */
int diginet_session_init(struct diginet_session *s, const struct diginet_session_config *cfg,
			 const struct diginet_io *io, diginet_notice_fn notify, void *ctx);

int diginet_session_rx(struct diginet_session *s, const uint8_t *frame, size_t len, uint64_t now_us);
int diginet_session_tick(struct diginet_session *s, uint64_t now_us);

/* The latest time at which tick must run again (now_us when it has work now). */
uint64_t diginet_session_deadline(const struct diginet_session *s, uint64_t now_us);

/* Wait for one frame up to max_wait_ms (less when a timer is due), then tick. Returns 0 or a
 * negative errno from the io. */
int diginet_session_poll(struct diginet_session *s, int max_wait_ms);

/* Queue a command; a queued command with the same key is replaced in place. Returns
 * DIGINET_OK, DIGINET_E_REFUSED for a body the frame builder would refuse, or
 * DIGINET_E_SPACE when the queue is full. Commands wait for ONLINE. */
int diginet_session_submit(struct diginet_session *s, const struct diginet_cmd *c);

/* Send e2 now. DIGINET_E_REFUSED while another host's e1 is the latest announce,
 * DIGINET_E_ARG when no desk has announced yet. */
int diginet_session_wake(struct diginet_session *s, uint64_t now_us);

/* Send e3 (when a desk is known and the session is not another host's) and go CLOSED. */
int diginet_session_close(struct diginet_session *s, uint64_t now_us);

const char *diginet_state_name(enum diginet_session_state st);
const char *diginet_reason_name(enum diginet_reason r);

#ifdef __cplusplus
}
#endif

#endif
