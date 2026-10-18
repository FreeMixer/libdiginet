// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The command stream of a data frame, with running status expanded (protocol/diginet.ksy:
 * `commands`, `message`, `sysex`). C24-Engine expands running status before parsing;
 * ReaControl24 splits on known status bytes and mis-reads it (docs/protocol.md, "The
 * command set"). */
#include <diginet/diginet.h>

void diginet_cursor_init(struct diginet_cursor *c, const uint8_t *body, size_t len)
{
	if (!c)
		return;
	c->body = body;
	c->len = body ? len : 0;
	c->pos = 0;
	c->status = 0;
}

/* Data bytes after a channel status: two for every status but C0 and D0. */
static size_t channel_data_len(uint8_t status)
{
	uint8_t kind = status & 0xf0;
	return (kind == 0xc0 || kind == 0xd0) ? 1 : 2;
}

int diginet_msg_next(struct diginet_cursor *c, struct diginet_msg *m)
{
	if (!c || !m)
		return DIGINET_E_ARG;
	if (c->pos >= c->len)
		return 0;

	const uint8_t *b = c->body;
	size_t start = c->pos;
	uint8_t lead = b[start];

	m->offset = start;
	m->sysex = NULL;
	m->sysex_len = 0;
	m->d1 = m->d2 = 0;

	if (lead == 0xf0) {
		size_t i = start + 1;
		while (i < c->len && b[i] != 0xf7)
			i++;
		c->status = 0; /* system exclusive cancels running status */
		if (i >= c->len) {
			c->pos = c->len;
			return DIGINET_E_TRUNCATED;
		}
		m->status = 0xf0;
		m->running = 0;
		m->sysex = b + start + 1;
		m->sysex_len = i - start - 1;
		m->len = i + 1 - start;
		c->pos = i + 1;
		return 1;
	}

	size_t data_at;
	uint8_t status;
	if (lead & 0x80) {
		if (lead >= 0xf0) {
			/* F1..FF other than F0: nothing in the grammar carries them. */
			c->pos = start + 1;
			c->status = 0;
			return DIGINET_E_STATUS;
		}
		status = lead;
		data_at = start + 1;
		m->running = 0;
	} else {
		if (!c->status) {
			c->pos = start + 1;
			return DIGINET_E_NO_STATUS;
		}
		status = c->status;
		data_at = start;
		m->running = 1;
	}

	size_t n = channel_data_len(status);
	if (data_at + n > c->len) {
		c->pos = c->len;
		return DIGINET_E_TRUNCATED;
	}
	for (size_t i = 0; i < n; i++) {
		if (b[data_at + i] & 0x80) {
			/* A status byte where a data byte is due: the message is cut short. */
			c->pos = data_at + i;
			c->status = 0;
			return DIGINET_E_TRUNCATED;
		}
	}
	m->status = status;
	m->d1 = b[data_at];
	m->d2 = n > 1 ? b[data_at + 1] : 0;
	m->len = data_at + n - start;
	c->pos = data_at + n;
	c->status = status;
	return 1;
}
