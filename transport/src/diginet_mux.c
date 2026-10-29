// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The desk mux (include/diginet/transport/diginet_mux.h). No socket and no clock here: the
 * packet io it runs over is in diginet_io.c. */
#include <string.h>

#include <diginet/transport/diginet_mux.h>

void diginet_mux_config_default(struct diginet_mux_config *c)
{
	if (!c)
		return;
	memset(c, 0, sizeof *c);
	c->gone_ms = 30000;
	diginet_session_config_default(&c->session);
}

int diginet_mux_init(struct diginet_mux *m, const struct diginet_mux_config *cfg,
		     const struct diginet_mux_io *io, diginet_mux_notice_fn notify, void *ctx)
{
	if (!m || !io || !io->send || !io->if_mac || !notify)
		return DIGINET_E_ARG;
	memset(m, 0, sizeof *m);
	if (cfg)
		m->cfg = *cfg;
	else
		diginet_mux_config_default(&m->cfg);
	m->io = *io;
	m->notify = notify;
	m->notify_ctx = ctx;
	return DIGINET_OK;
}

static uint64_t ms(uint32_t v) { return (uint64_t)v * 1000u; }

static void notify_desk(struct diginet_mux *m, struct diginet_mux_desk *d, enum diginet_mux_notice_kind k,
			const struct diginet_announce *a, const struct diginet_notice *sn)
{
	struct diginet_mux_notice n = { .kind = k, .desk = d->slot, .mac = d->mac, .ifindex = d->ifindex,
					.announce = a, .session = sn };
	if (a)
		n.personality = diginet_personality_from_name(a->name);
	m->notify(m->notify_ctx, &n);
}

/* A desk's session sends out of the desk's interface. */
static int desk_send(void *ctx, const uint8_t *frame, size_t len)
{
	struct diginet_mux_desk *d = ctx;
	return d->mux->io.send(d->mux->io.ctx, d->ifindex, frame, len);
}

static uint64_t desk_now(void *ctx)
{
	struct diginet_mux_desk *d = ctx;
	return d->mux->io.now_us ? d->mux->io.now_us(d->mux->io.ctx) : 0;
}

static void desk_notice(void *ctx, const struct diginet_notice *sn)
{
	struct diginet_mux_desk *d = ctx;
	if (sn->kind == DIGINET_N_STATE && sn->state == DIGINET_S_IDLE && sn->reason == DIGINET_R_SILENCE)
		d->silent = 1;
	notify_desk(d->mux, d, DIGINET_MUX_N_SESSION, NULL, sn);
}

int diginet_mux_find(const struct diginet_mux *m, const uint8_t mac[DIGINET_MAC_LEN])
{
	if (!m || !mac)
		return -1;
	for (unsigned i = 0; i < DIGINET_MUX_MAX_DESKS; i++)
		if (m->desks[i].present && !memcmp(m->desks[i].mac, mac, DIGINET_MAC_LEN))
			return (int)i;
	return -1;
}

int diginet_mux_attach(struct diginet_mux *m, unsigned desk, const struct diginet_session_config *cfg)
{
	if (!m || desk >= DIGINET_MUX_MAX_DESKS)
		return DIGINET_E_ARG;
	struct diginet_mux_desk *d = &m->desks[desk];
	if (!d->present || d->attached)
		return DIGINET_E_ARG;
	struct diginet_session_config c = cfg ? *cfg : m->cfg.session;
	int r = m->io.if_mac(m->io.ctx, d->ifindex, c.host_mac);
	if (r < 0)
		return r;
	memcpy(c.desk_mac, d->mac, DIGINET_MAC_LEN);
	c.desk_mac_set = 1;
	struct diginet_io io = { .ctx = d, .send = desk_send, .recv = NULL, .now_us = desk_now };
	r = diginet_session_init(&d->session, &c, &io, desk_notice, d);
	if (r != DIGINET_OK)
		return r;
	memcpy(d->host_mac, c.host_mac, DIGINET_MAC_LEN);
	d->silent = 0;
	d->attached = 1;
	return DIGINET_OK;
}

int diginet_mux_detach(struct diginet_mux *m, unsigned desk, uint64_t now_us)
{
	if (!m || desk >= DIGINET_MUX_MAX_DESKS || !m->desks[desk].attached)
		return DIGINET_E_ARG;
	struct diginet_mux_desk *d = &m->desks[desk];
	int r = diginet_session_close(&d->session, now_us);
	d->attached = 0;
	d->silent = 0;
	return r;
}

struct diginet_session *diginet_mux_session(struct diginet_mux *m, unsigned desk)
{
	if (!m || desk >= DIGINET_MUX_MAX_DESKS || !m->desks[desk].attached)
		return NULL;
	return &m->desks[desk].session;
}

int diginet_mux_rx(struct diginet_mux *m, const uint8_t *frame, size_t len, int ifindex, uint64_t now_us)
{
	struct diginet_frame f;
	if (!m || !frame)
		return DIGINET_E_ARG;
	m->stats.rx_frames++;
	int r = diginet_frame_parse(frame, len, &f);
	if (r != DIGINET_OK) {
		m->stats.rx_ignored++;
		return r;
	}
	int i = diginet_mux_find(m, f.src);
	if (i >= 0) {
		struct diginet_mux_desk *d = &m->desks[i];
		if (d->ifindex != ifindex) {
			m->stats.rx_other_if++;   /* the same desk seen on a second interface */
			return DIGINET_OK;
		}
		m->stats.rx_routed++;
		d->last_rx_us = now_us;
		if (d->attached)
			diginet_session_rx(&d->session, frame, len, now_us);
		return DIGINET_OK;
	}

	/* A desk no slot holds: only its announce (an e0 or e1 the parser takes), from a Digidesign
	 * MAC, makes it present. */
	struct diginet_announce a;
	if (!diginet_mac_is_digidesign(f.src) || diginet_announce_parse(&f, &a) != DIGINET_OK) {
		m->stats.rx_ignored++;
		return DIGINET_OK;
	}
	struct diginet_mux_desk *d = NULL;
	for (unsigned k = 0; k < DIGINET_MUX_MAX_DESKS && !d; k++)
		if (!m->desks[k].present)
			d = &m->desks[k];
	if (!d) {
		m->stats.table_full++;
		return DIGINET_OK;
	}
	memset(d, 0, sizeof *d);
	d->present = 1;
	d->slot = (unsigned)(d - m->desks);
	d->mux = m;
	memcpy(d->mac, f.src, DIGINET_MAC_LEN);
	d->ifindex = ifindex;
	d->last_rx_us = now_us;
	m->stats.rx_routed++;
	m->stats.appeared++;
	notify_desk(m, d, DIGINET_MUX_N_APPEARED, &a, NULL);
	/* attached in that notice: the announce that made it appear is its session's first frame */
	if (d->present && d->attached)
		diginet_session_rx(&d->session, frame, len, now_us);
	return DIGINET_OK;
}

static void gone(struct diginet_mux *m, struct diginet_mux_desk *d)
{
	m->stats.gone++;
	notify_desk(m, d, DIGINET_MUX_N_GONE, NULL, NULL);
	memset(d, 0, sizeof *d);
}

int diginet_mux_tick(struct diginet_mux *m, uint64_t now_us)
{
	if (!m)
		return DIGINET_E_ARG;
	for (unsigned i = 0; i < DIGINET_MUX_MAX_DESKS; i++) {
		struct diginet_mux_desk *d = &m->desks[i];
		if (!d->present)
			continue;
		if (d->attached)
			diginet_session_tick(&d->session, now_us);
		if (d->silent || now_us - d->last_rx_us >= ms(m->cfg.gone_ms))
			gone(m, d);
	}
	return DIGINET_OK;
}

static uint64_t min64(uint64_t a, uint64_t b) { return a < b ? a : b; }

uint64_t diginet_mux_deadline(const struct diginet_mux *m, uint64_t now_us)
{
	uint64_t d = now_us + 1000000;  /* at least once a second */
	if (!m)
		return d;
	for (unsigned i = 0; i < DIGINET_MUX_MAX_DESKS; i++) {
		const struct diginet_mux_desk *k = &m->desks[i];
		if (!k->present)
			continue;
		if (k->silent)
			return now_us;
		d = min64(d, k->last_rx_us + ms(m->cfg.gone_ms));
		if (k->attached)
			d = min64(d, diginet_session_deadline(&k->session, now_us));
	}
	return d < now_us ? now_us : d;
}

int diginet_mux_poll(struct diginet_mux *m, int max_wait_ms)
{
	uint8_t buf[DIGINET_MAX_FRAME_LEN];
	if (!m || !m->io.recv || !m->io.now_us)
		return DIGINET_E_ARG;
	uint64_t now = m->io.now_us(m->io.ctx);
	uint64_t due = diginet_mux_deadline(m, now);
	uint64_t wait_us = due > now ? due - now : 0;
	int wait = (int)((wait_us + 999) / 1000);
	if (max_wait_ms >= 0 && wait > max_wait_ms)
		wait = max_wait_ms;
	int ifindex = 0;
	int r = m->io.recv(m->io.ctx, buf, sizeof buf, &ifindex, wait);
	if (r < 0)
		return r;
	now = m->io.now_us(m->io.ctx);
	if (r > 0)
		diginet_mux_rx(m, buf, (size_t)r, ifindex, now);
	diginet_mux_tick(m, now);
	/* Take whatever else is already waiting. */
	while ((r = m->io.recv(m->io.ctx, buf, sizeof buf, &ifindex, 0)) > 0)
		diginet_mux_rx(m, buf, (size_t)r, ifindex, m->io.now_us(m->io.ctx));
	return r < 0 ? r : 0;
}
