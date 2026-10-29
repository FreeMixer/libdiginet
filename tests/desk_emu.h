/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * A desk emulator: a test double that speaks the DigiNet protocol as docs/protocol.md
 * describes the desk. It announces e0 (idle) or e1 naming its host, answers e2 with a0 then
 * e1 (a Control|24 with a0 alone and e0 announces, unless a test sets announces_session as
 * the desk sometimes does), ACKs host data frames, drops back to e0 when its host goes quiet for too long, ends
 * the session on e3, and sends data frames of its own. Knobs make it misbehave on purpose:
 * drop ACKs, insist on the body sum, serve another host.
 *
 * It runs on caller time and keeps its frames to the host in a small queue, so a test can
 * drive it in-process with a virtual clock, or pump it over a socket.
 */
#ifndef DIGINET_DESK_EMU_H
#define DIGINET_DESK_EMU_H

#include <stddef.h>
#include <stdint.h>

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

#define EMU_OUT_MAX   256
#define EMU_LOG_MAX   4096

struct emu_rx {          /* one host frame as the desk saw it */
	uint64_t at_us;
	uint8_t cmd;
	uint32_t counter;
	uint16_t retry;
	uint16_t sum;
	uint8_t ncmds;
	uint8_t body[320];
	size_t body_len;
	int acked;
};

struct desk_emu {
	uint8_t mac[DIGINET_MAC_LEN];
	char name[10], version[10];
	uint8_t session_mac[DIGINET_MAC_LEN]; /* the host the desk is in session with */
	int in_session;
	int foreign;              /* in session with another host: announce e1 naming it */
	int announces_session;    /* from the name: a ProControl announces e1 in session, a
				   * Control|24 keeps announcing e0 */
	uint32_t seq;             /* the desk's own send counter */
	uint64_t last_host_us;    /* last frame from the session host */
	uint64_t host_timeout_us; /* the desk drops to e0 after this much silence */

	/* knobs */
	int drop_acks;            /* do not ACK the next n host data frames */
	int require_sum;          /* do not ACK a data frame whose header sum is not the body sum */
	int mute;                 /* send nothing at all (a desk that went away) */
	int ack_wake;             /* answer e2 (default 1) */
	int holds_after_e3;       /* after its host's e3, keep announcing e1 naming that host
				   * until host_timeout_us, as a Control|24 does for ~30 s */
	int stale;                /* a session the host closed that the desk still announces */

	/* what the desk has seen */
	struct emu_rx log[EMU_LOG_MAX];
	unsigned nlog;
	unsigned wakes, disconnects, keepalives, acks_from_host;
	uint32_t last_acked_by_host;

	/* frames queued for the host */
	uint8_t out[EMU_OUT_MAX][DIGINET_MAX_FRAME_LEN];
	size_t out_len[EMU_OUT_MAX];
	unsigned out_head, out_count;
};

void emu_init(struct desk_emu *e, const uint8_t mac[6], const char *name, const char *version);
/* Queue the periodic announce: e0, or e1 naming the session host. */
void emu_announce(struct desk_emu *e, uint64_t now_us);
/* Take one host frame. */
void emu_from_host(struct desk_emu *e, const uint8_t *frame, size_t len, uint64_t now_us);
/* Queue a desk data frame (retry 0 for a first send). Returns its counter. */
uint32_t emu_send_data(struct desk_emu *e, const uint8_t *body, size_t len, uint8_t ncmds,
		       uint16_t retry, uint32_t counter_or_0);
/* The desk's own timers: falls back to e0 when the host is silent past host_timeout_us. */
void emu_tick(struct desk_emu *e, uint64_t now_us);
/* Pop the next frame for the host; returns its length or 0. */
size_t emu_pop(struct desk_emu *e, uint8_t *buf, size_t cap);
/* Force the session to end as a desk reboot would; the next announce is e0. */
void emu_drop_session(struct desk_emu *e);

/* How many logged host data frames carried this command's bytes (first sends only). */
unsigned emu_count_cmd(const struct desk_emu *e, const uint8_t *bytes, size_t len);

#endif
