// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The desk emulator (tests/desk_emu.h). */
#include <string.h>

#include "desk_emu.h"

static const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void emu_init(struct desk_emu *e, const uint8_t mac[6], const char *name, const char *version)
{
	memset(e, 0, sizeof *e);
	memcpy(e->mac, mac, 6);
	strncpy(e->name, name, sizeof e->name - 1);
	strncpy(e->version, version, sizeof e->version - 1);
	e->host_timeout_us = 30u * 1000000u;
	e->ack_wake = 1;
}

static void queue(struct desk_emu *e, const uint8_t *dst, uint8_t cmd, uint32_t send, uint32_t ack,
		  uint16_t retry, uint8_t ncmds, const uint8_t *body, size_t len)
{
	if (e->mute || e->out_count == EMU_OUT_MAX)
		return;
	unsigned slot = (e->out_head + e->out_count) % EMU_OUT_MAX;
	struct diginet_header h = { .send_counter = send, .ack_counter = ack, .retry = retry,
				    .cmd = cmd, .num_commands = ncmds };
	int n = diginet_frame_build(e->out[slot], sizeof e->out[slot], dst, e->mac, &h, body, len,
				    DIGINET_SUM_BODY);
	if (n > 0) {
		e->out_len[slot] = (size_t)n;
		e->out_count++;
	}
}

void emu_announce(struct desk_emu *e, uint64_t now_us)
{
	(void)now_us;
	uint8_t body[DIGINET_ANNOUNCE_BODY_LEN];
	memset(body, 0, sizeof body);
	int session = e->in_session || e->foreign;
	if (session)
		memcpy(body, e->session_mac, 6);   /* where the emulator puts the host (A6) */
	memcpy(body + 15, e->version, strlen(e->version));
	memcpy(body + 24, e->name, strlen(e->name));
	queue(e, BCAST, session ? DIGINET_CMD_ANNOUNCE_SESSION : DIGINET_CMD_ANNOUNCE, 0, 0, 0, 0,
	      body, sizeof body);
}

void emu_drop_session(struct desk_emu *e)
{
	e->in_session = 0;
	e->foreign = 0;
}

void emu_from_host(struct desk_emu *e, const uint8_t *buf, size_t len, uint64_t now_us)
{
	struct diginet_frame f;
	if (diginet_frame_parse(buf, len, &f) != DIGINET_OK || memcmp(f.dst, e->mac, 6))
		return;
	if (e->foreign && memcmp(f.src, e->session_mac, 6))
		return;   /* busy with another host */

	if (e->nlog < EMU_LOG_MAX) {
		struct emu_rx *r = &e->log[e->nlog++];
		r->at_us = now_us;
		r->cmd = f.h.cmd;
		r->counter = f.h.send_counter;
		r->retry = f.h.retry;
		r->sum = f.h.sum;
		r->ncmds = f.h.num_commands;
		r->body_len = f.body_len < sizeof r->body ? f.body_len : sizeof r->body;
		memcpy(r->body, f.body, r->body_len);
		r->acked = 0;
	}
	struct emu_rx *r = e->nlog ? &e->log[e->nlog - 1] : NULL;

	switch (f.h.cmd) {
	case DIGINET_CMD_WAKE:
		e->wakes++;
		if (!e->ack_wake)
			return;
		memcpy(e->session_mac, f.src, 6);
		e->in_session = 1;
		e->last_host_us = now_us;
		queue(e, f.src, DIGINET_CMD_ACK, e->seq, f.h.send_counter, 0, 0, NULL, 0);
		if (r) r->acked = 1;
		emu_announce(e, now_us);   /* e1 naming the host */
		return;
	case DIGINET_CMD_DISCONNECT:
		e->disconnects++;
		e->in_session = 0;
		return;
	case DIGINET_CMD_ACK:
		e->acks_from_host++;
		e->last_acked_by_host = f.h.ack_counter;
		/* An ACK does not keep the session alive: 225 ACKs in a 48 s gap between
		 * keepalives did not stop a ProControl going back to e0 (docs/protocol.md,
		 * "Keepalive"). */
		return;
	case DIGINET_CMD_DATA:
		if (!e->in_session || memcmp(f.src, e->session_mac, 6))
			return;
		e->last_host_us = now_us;
		if (diginet_frame_is_keepalive(&f))
			e->keepalives++;
		if (e->require_sum && !f.sum_matches)
			return;
		if (e->drop_acks > 0) {
			e->drop_acks--;
			return;
		}
		queue(e, f.src, DIGINET_CMD_ACK, e->seq, f.h.send_counter, 0, 0, NULL, 0);
		if (r) r->acked = 1;
		return;
	default:
		return;
	}
}

uint32_t emu_send_data(struct desk_emu *e, const uint8_t *body, size_t len, uint8_t ncmds,
		       uint16_t retry, uint32_t counter)
{
	if (!counter) {
		e->seq += ncmds;
		counter = e->seq;
	}
	queue(e, e->session_mac, DIGINET_CMD_DATA, counter, 0, retry, ncmds, body, len);
	return counter;
}

void emu_tick(struct desk_emu *e, uint64_t now_us)
{
	if (e->in_session && now_us - e->last_host_us > e->host_timeout_us)
		e->in_session = 0;
}

size_t emu_pop(struct desk_emu *e, uint8_t *buf, size_t cap)
{
	if (!e->out_count)
		return 0;
	size_t n = e->out_len[e->out_head];
	if (n > cap)
		n = cap;
	memcpy(buf, e->out[e->out_head], n);
	e->out_head = (e->out_head + 1) % EMU_OUT_MAX;
	e->out_count--;
	return n;
}

unsigned emu_count_cmd(const struct desk_emu *e, const uint8_t *bytes, size_t len)
{
	unsigned n = 0;
	for (unsigned i = 0; i < e->nlog; i++) {
		const struct emu_rx *r = &e->log[i];
		if (r->cmd != DIGINET_CMD_DATA || r->retry)
			continue;
		for (size_t k = 0; k + len <= r->body_len; k++)
			if (!memcmp(r->body + k, bytes, len)) {
				n++;
				break;
			}
	}
	return n;
}
