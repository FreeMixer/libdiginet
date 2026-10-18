// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The descriptor io and the packet socket (include/diginet/transport/diginet_io.h). */
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include <diginet/transport/diginet_io.h>

uint64_t diginet_clock_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int fd_send(void *ctx, const uint8_t *frame, size_t len)
{
	struct diginet_fd_io *st = ctx;
	for (;;) {
		ssize_t n = send(st->fd, frame, len, 0);
		if (n == (ssize_t)len)
			return 0;
		if (n < 0 && errno == EINTR)
			continue;
		return n < 0 ? -errno : -EIO;
	}
}

static int fd_recv(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
	struct diginet_fd_io *st = ctx;
	for (;;) {
		struct pollfd p = { .fd = st->fd, .events = POLLIN };
		int r = poll(&p, 1, timeout_ms);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return -errno;
		if (r == 0)
			return 0;
		if (p.revents & (POLLHUP | POLLERR) && !(p.revents & POLLIN))
			return -EPIPE;
		struct sockaddr_ll from;
		socklen_t fl = sizeof from;
		memset(&from, 0, sizeof from);
		ssize_t n = recvfrom(st->fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
			return 0;
		if (n < 0)
			return -errno;
		if (n == 0)
			return -EPIPE;   /* the peer of a socketpair went away */
		if (fl >= sizeof(sa_family_t) && from.sll_family == AF_PACKET &&
		    from.sll_pkttype == PACKET_OUTGOING) {
			timeout_ms = 0;  /* our own frame looped back: look again, without waiting */
			continue;
		}
		return (int)n;
	}
}

static uint64_t fd_now(void *ctx)
{
	(void)ctx;
	return diginet_clock_us();
}

void diginet_io_fd(struct diginet_io *io, struct diginet_fd_io *store, int fd)
{
	store->fd = fd;
	io->ctx = store;
	io->send = fd_send;
	io->recv = fd_recv;
	io->now_us = fd_now;
}

int diginet_packet_open(const char *ifname, uint8_t mac[DIGINET_MAC_LEN])
{
	if (!ifname || !mac || strlen(ifname) >= IFNAMSIZ)
		return -EINVAL;
	unsigned idx = if_nametoindex(ifname);
	if (!idx)
		return -ENODEV;

	/* Protocol 0: deaf until bind() names the interface and the EtherType together. */
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
	memcpy(ifr.ifr_name, ifname, strlen(ifname));
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, DIGINET_MAC_LEN);

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(DIGINET_ETHERTYPE);
	sll.sll_ifindex = (int)idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}
