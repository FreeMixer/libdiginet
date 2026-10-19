/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * libdiginet-transport: the wire under a session. A session never touches a socket or a
 * clock directly; it calls the three functions of a struct diginet_io. The packet socket is
 * one implementation, a socketpair or an in-process desk emulator is another, so every
 * behaviour of the session can be tested without hardware or privileges.
 */
#ifndef DIGINET_IO_H
#define DIGINET_IO_H

#include <stddef.h>
#include <stdint.h>

#include <diginet/diginet.h>

#ifdef __cplusplus
extern "C" {
#endif

struct diginet_io {
	void *ctx;
	/* Send one whole Ethernet frame. 0, or a negative errno. */
	int (*send)(void *ctx, const uint8_t *frame, size_t len);
	/* Receive one frame, waiting at most timeout_ms (0: do not wait). Returns its length,
	 * 0 when nothing came, or a negative errno. */
	int (*recv)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
	/* A monotonic clock in microseconds. */
	uint64_t (*now_us)(void *ctx);
};

/* CLOCK_MONOTONIC in microseconds. */
uint64_t diginet_clock_us(void);

/* An io over a descriptor that carries whole frames: an AF_PACKET socket from
 * diginet_packet_open(), one handed over by a privileged launcher, or one end of a
 * SOCK_SEQPACKET socketpair. Frames an AF_PACKET socket reports as outgoing are skipped.
 * `store` holds the state and must outlive `io`. */
struct diginet_fd_io {
	int fd;
};
void diginet_io_fd(struct diginet_io *io, struct diginet_fd_io *store, int fd);

/* An AF_PACKET socket bound to EtherType 0x885F on the interface `ifname`. The protocol is
 * given to bind(), never to socket(), so the socket hears nothing from any other interface.
 * Needs CAP_NET_RAW. On success returns the descriptor and fills the interface's MAC; on
 * failure returns a negative errno (-EPERM without the capability, -ENODEV for a name that
 * does not exist). */
int diginet_packet_open(const char *ifname, uint8_t mac[DIGINET_MAC_LEN]);

#ifdef __cplusplus
}
#endif

#endif
