/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet-transport: the desk mux. One packet socket that hears every interface
 * (diginet_packet_open_any), many desks: each desk a session of its own (diginet_session.h),
 * fed only its own frames and sending out of the interface it was heard on, to it, from that
 * interface's MAC (docs/protocol.md, "One socket, every interface").
 *
 *   - A desk is keyed by its MAC. The first valid announce (e0 or e1) from a Digidesign MAC no
 *     desk holds makes it present on the interface it came in on: DIGINET_MUX_N_APPEARED, with
 *     the announce. From then on its frames come from that interface only; the same MAC heard
 *     on another interface while it is present (a bridge and its port both show a frame) is
 *     counted and set aside, never fed to its session.
 *   - The host attaches a present desk (diginet_mux_attach, from the APPEARED notice or
 *     later): a session for that desk alone, its host MAC the MAC of the desk's interface. Each
 *     notice of that session comes back as DIGINET_MUX_N_SESSION. An attached desk's frames go
 *     to its session, the announce that made it appear included when it is attached in that
 *     notice.
 *   - A desk is gone when nothing has come from it for gone_ms, or when its session ends on
 *     silence (DIGINET_R_SILENCE: nothing for offline_ms): DIGINET_MUX_N_GONE, and its slot,
 *     session included, is forgotten. gone_ms (30 s) is longer than three announce periods
 *     (6-9.4 s) and than the session's offline_ms (25 s), so an attached session gives up first.
 *   - Frames from anyone else, frames of no grammar, and desks past DIGINET_MUX_MAX_DESKS are
 *     counted and set aside.
 *
 * Like the session it is a state machine over caller time, with no thread and no allocation:
 * diginet_mux_rx() takes each frame with the interface it came in on, diginet_mux_tick() runs
 * the timers of the mux and of every attached session, diginet_mux_poll() does both over its
 * io. The struct holds every desk and its session, so it must not be moved once initialised.
 */
#ifndef DIGINET_MUX_H
#define DIGINET_MUX_H

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_session.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIGINET_MUX_MAX_DESKS 8

/* The wire under the mux. */
struct diginet_mux_io {
	void *ctx;
	/* Send one whole frame out of interface `ifindex`. 0, or a negative errno. */
	int (*send)(void *ctx, int ifindex, const uint8_t *frame, size_t len);
	/* Receive one frame and the interface it came in on, waiting at most timeout_ms (0: do not
	 * wait). Its length, 0 when nothing came, or a negative errno. Only diginet_mux_poll()
	 * calls it. */
	int (*recv)(void *ctx, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms);
	/* The MAC of interface `ifindex`. 0, or a negative errno. */
	int (*if_mac)(void *ctx, int ifindex, uint8_t mac[DIGINET_MAC_LEN]);
	/* A monotonic clock in microseconds. */
	uint64_t (*now_us)(void *ctx);
};

/* The io over an any-interface packet socket: diginet_packet_sendto(), diginet_packet_recvfrom(),
 * diginet_if_mac() and diginet_clock_us(). `store` holds the descriptor and must outlive `io`. */
void diginet_mux_io_packet(struct diginet_mux_io *io, struct diginet_fd_io *store, int fd);

struct diginet_mux_config {
	uint32_t gone_ms;                       /* 30000 */
	/* What diginet_mux_attach() gives a session when it is passed no config: the defaults,
	 * auto_wake on. desk_mac and host_mac are always the mux's own. */
	struct diginet_session_config session;
};

void diginet_mux_config_default(struct diginet_mux_config *c);

enum diginet_mux_notice_kind {
	DIGINET_MUX_N_APPEARED = 1, /* a desk's first announce: announce, personality */
	DIGINET_MUX_N_GONE,         /* nothing from the desk for gone_ms, or its session ended on
				     * silence; its slot is forgotten after this notice */
	DIGINET_MUX_N_SESSION,      /* a notice of the desk's session: session */
};

struct diginet_mux_notice {
	enum diginet_mux_notice_kind kind;
	unsigned desk;                                  /* its slot, 0..DIGINET_MUX_MAX_DESKS-1 */
	const uint8_t *mac;                             /* the desk's MAC */
	int ifindex;                                    /* the interface it is heard on */
	const struct diginet_announce *announce;        /* APPEARED */
	const struct diginet_personality *personality;  /* APPEARED: the desk its name selects, or NULL */
	const struct diginet_notice *session;           /* SESSION */
};

typedef void (*diginet_mux_notice_fn)(void *ctx, const struct diginet_mux_notice *n);

struct diginet_mux;

struct diginet_mux_desk {
	int present;
	int attached;
	uint8_t mac[DIGINET_MAC_LEN];
	int ifindex;
	uint8_t host_mac[DIGINET_MAC_LEN];      /* while attached */
	uint64_t last_rx_us;                    /* the last frame from it, on its interface */
	int silent;                             /* its session ended on silence: gone at once */
	unsigned slot;
	struct diginet_mux *mux;
	struct diginet_session session;         /* while attached */
};

struct diginet_mux_stats {
	uint64_t rx_frames;     /* every frame handed to diginet_mux_rx() */
	uint64_t rx_routed;     /* from a present desk, on its interface */
	uint64_t rx_other_if;   /* from a present desk, on another interface: set aside */
	uint64_t rx_ignored;    /* of no grammar, or from no desk: set aside */
	uint64_t table_full;    /* a new desk's announce with every slot taken */
	uint64_t appeared, gone;
};

struct diginet_mux {
	struct diginet_mux_config cfg;
	struct diginet_mux_io io;
	diginet_mux_notice_fn notify;
	void *notify_ctx;
	struct diginet_mux_desk desks[DIGINET_MUX_MAX_DESKS];
	struct diginet_mux_stats stats;
};

/* cfg is copied (NULL: the defaults). io->send and io->if_mac and notify may not be NULL. */
int diginet_mux_init(struct diginet_mux *m, const struct diginet_mux_config *cfg,
		     const struct diginet_mux_io *io, diginet_mux_notice_fn notify, void *ctx);

/* One frame, and the interface it came in on. DIGINET_OK, or the code of a frame of no grammar
 * (set aside). */
int diginet_mux_rx(struct diginet_mux *m, const uint8_t *frame, size_t len, int ifindex, uint64_t now_us);

/* The timers of every attached session, then the gone rule. */
int diginet_mux_tick(struct diginet_mux *m, uint64_t now_us);

/* The latest time at which tick must run again (now_us when it has work now). */
uint64_t diginet_mux_deadline(const struct diginet_mux *m, uint64_t now_us);

/* Wait for one frame up to max_wait_ms (less when a timer is due), then tick, then take whatever
 * else is waiting. 0, or a negative errno from the io. */
int diginet_mux_poll(struct diginet_mux *m, int max_wait_ms);

/* Give present desk `desk` a session of its own (cfg NULL: the config's session template), its
 * desk MAC that desk's and its host MAC the MAC of the desk's interface. DIGINET_OK;
 * DIGINET_E_ARG for a slot with no desk or one already attached; a negative errno when the
 * interface's MAC cannot be read; the session's own code for a config it refuses. Not from
 * inside a notice of that desk's session. */
int diginet_mux_attach(struct diginet_mux *m, unsigned desk, const struct diginet_session_config *cfg);

/* Close an attached desk's session (diginet_session_close: e3) and let it go; the desk stays
 * present. DIGINET_E_ARG when it is not attached. Not from inside a notice of that desk's
 * session. */
int diginet_mux_detach(struct diginet_mux *m, unsigned desk, uint64_t now_us);

/* The session of an attached desk, or NULL. */
struct diginet_session *diginet_mux_session(struct diginet_mux *m, unsigned desk);

/* The slot of the present desk with this MAC, or -1. */
int diginet_mux_find(const struct diginet_mux *m, const uint8_t mac[DIGINET_MAC_LEN]);

#ifdef __cplusplus
}
#endif

#endif
