// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The descriptor io and the packet socket (include/diginet/transport/diginet_io.h). */
#include <errno.h>
#include <poll.h>
#include <spawn.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/if_packet.h>

#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_mux.h>

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

/* One frame from fd, and the interface it came in on (0 when fd is no packet socket). */
static int recv_one(int fd, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms)
{
	for (;;) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
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
		ssize_t n = recvfrom(fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
			return 0;
		if (n < 0)
			return -errno;
		if (n == 0)
			return -EPIPE;   /* the peer of a socketpair went away */
		int packet = fl >= sizeof(sa_family_t) && from.sll_family == AF_PACKET;
		if (packet && from.sll_pkttype == PACKET_OUTGOING) {
			timeout_ms = 0;  /* our own frame looped back: look again, without waiting */
			continue;
		}
		if (ifindex)
			*ifindex = packet ? from.sll_ifindex : 0;
		return (int)n;
	}
}

static int fd_recv(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
	struct diginet_fd_io *st = ctx;
	return recv_one(st->fd, buf, cap, NULL, timeout_ms);
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

/* ---- one socket for every interface ---- */

int diginet_packet_open_any(void)
{
	/* Protocol 0 until bind(), as above; then 0x885F on ifindex 0, every interface. */
	int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(DIGINET_ETHERTYPE);
	sll.sll_ifindex = 0;
	if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}

int diginet_packet_recvfrom(int fd, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms)
{
	if (fd < 0 || !buf || !ifindex)
		return -EINVAL;
	*ifindex = 0;
	return recv_one(fd, buf, cap, ifindex, timeout_ms);
}

int diginet_packet_sendto(int fd, int ifindex, const uint8_t *frame, size_t len)
{
	if (fd < 0 || ifindex <= 0 || !frame || len < DIGINET_ETH_HDR_LEN)
		return -EINVAL;
	struct sockaddr_ll to;
	memset(&to, 0, sizeof to);
	to.sll_family = AF_PACKET;
	to.sll_protocol = htons(DIGINET_ETHERTYPE);
	to.sll_ifindex = ifindex;
	to.sll_halen = DIGINET_MAC_LEN;
	memcpy(to.sll_addr, frame, DIGINET_MAC_LEN);
	for (;;) {
		ssize_t n = sendto(fd, frame, len, 0, (const struct sockaddr *)&to, sizeof to);
		if (n == (ssize_t)len)
			return 0;
		if (n < 0 && errno == EINTR)
			continue;
		return n < 0 ? -errno : -EIO;
	}
}

int diginet_if_mac(int ifindex, uint8_t mac[DIGINET_MAC_LEN])
{
	char name[IF_NAMESIZE];
	if (ifindex <= 0 || !mac)
		return -EINVAL;
	if (!if_indextoname((unsigned)ifindex, name))
		return errno == ENXIO ? -ENODEV : -errno;
	/* Any socket answers SIOCGIFHWADDR; a datagram one needs no capability. */
	int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -errno;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
	memcpy(ifr.ifr_name, name, strnlen(name, IFNAMSIZ - 1));
	int r = ioctl(s, SIOCGIFHWADDR, &ifr) < 0 ? -errno : 0;
	close(s);
	if (r == 0)
		memcpy(mac, ifr.ifr_hwaddr.sa_data, DIGINET_MAC_LEN);
	return r;
}

/* The desk mux's io over an any-interface socket (diginet_mux.h). */
static int mux_send(void *ctx, int ifindex, const uint8_t *frame, size_t len)
{
	struct diginet_fd_io *st = ctx;
	return diginet_packet_sendto(st->fd, ifindex, frame, len);
}

static int mux_recv(void *ctx, uint8_t *buf, size_t cap, int *ifindex, int timeout_ms)
{
	struct diginet_fd_io *st = ctx;
	return diginet_packet_recvfrom(st->fd, buf, cap, ifindex, timeout_ms);
}

static int mux_if_mac(void *ctx, int ifindex, uint8_t mac[DIGINET_MAC_LEN])
{
	(void)ctx;
	return diginet_if_mac(ifindex, mac);
}

void diginet_mux_io_packet(struct diginet_mux_io *io, struct diginet_fd_io *store, int fd)
{
	store->fd = fd;
	io->ctx = store;
	io->send = mux_send;
	io->recv = mux_recv;
	io->if_mac = mux_if_mac;
	io->now_us = fd_now;
}

/* ---- a packet socket handed over a Unix socket ---- */

int diginet_packet_send_fd(int unix_sock, int fd)
{
	if (unix_sock < 0 || fd < 0)
		return -EINVAL;
	char byte = 'F';
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(sizeof(int))];
	} c;
	memset(&c, 0, sizeof c);
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = c.buf,
			    .msg_controllen = sizeof c.buf };
	struct cmsghdr *h = CMSG_FIRSTHDR(&m);
	h->cmsg_level = SOL_SOCKET;
	h->cmsg_type = SCM_RIGHTS;
	h->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(h), &fd, sizeof fd);
	for (;;) {
		ssize_t n = sendmsg(unix_sock, &m, MSG_NOSIGNAL);
		if (n == 1)
			return 0;
		if (n < 0 && errno == EINTR)
			continue;
		return n < 0 ? -errno : -EIO;
	}
}

/* Room for a few descriptors, so a message that carries more than one is seen whole and every
 * one of them closed, not left open in this process by a truncated control message. */
#define FDS_ROOM 8

int diginet_packet_receive_fd(int unix_sock)
{
	if (unix_sock < 0)
		return -EINVAL;
	char byte;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(FDS_ROOM * sizeof(int))];
	} c;
	struct msghdr m;
	ssize_t n;
	do {
		memset(&c, 0, sizeof c);
		memset(&m, 0, sizeof m);
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_control = c.buf;
		m.msg_controllen = sizeof c.buf;
		n = recvmsg(unix_sock, &m, MSG_CMSG_CLOEXEC);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -errno;

	int fds[FDS_ROOM], nfds = 0;
	for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
		if (h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS)
			continue;
		size_t k = (h->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (size_t i = 0; i < k && nfds < FDS_ROOM; i++)
			memcpy(&fds[nfds++], CMSG_DATA(h) + i * sizeof(int), sizeof(int));
	}
	if (nfds == 0)
		return n == 0 ? -EPIPE : -EPROTO;
	int bad = nfds != 1 || (m.msg_flags & MSG_CTRUNC);
	if (!bad) {
		int domain = 0;
		socklen_t dl = sizeof domain;
		bad = getsockopt(fds[0], SOL_SOCKET, SO_DOMAIN, &domain, &dl) < 0 || domain != AF_PACKET;
	}
	if (bad) {
		for (int i = 0; i < nfds; i++)
			close(fds[i]);
		return -EPROTO;
	}
	return fds[0];
}

int diginet_packet_open_by_helper(const char *helper)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -errno;
	/* The child's end becomes its descriptor 3. When it already is 3, the dup2 action clears
	 * its close-on-exec flag (POSIX.1-2017, posix_spawn_file_actions_adddup2). */
	int child = sv[1];
	posix_spawn_file_actions_t fa;
	int r = posix_spawn_file_actions_init(&fa);
	if (r) {
		close(sv[0]);
		close(child);
		return -r;
	}
	r = posix_spawn_file_actions_adddup2(&fa, child, 3);
	pid_t pid = 0;
	char *argv[] = { (char *)(helper ? helper : "diginet-packet-helper"), NULL };
	char *envp[] = { NULL };
	if (!r)
		r = helper ? posix_spawn(&pid, helper, &fa, NULL, argv, envp)
			   : posix_spawnp(&pid, argv[0], &fa, NULL, argv, envp);
	posix_spawn_file_actions_destroy(&fa);
	close(child);
	if (r) {
		close(sv[0]);
		return -r;
	}
	/* The helper exits once it has passed the socket, or failed: an end of stream then. */
	int fd = diginet_packet_receive_fd(sv[0]);
	close(sv[0]);
	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (fd >= 0) {
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return fd;
		close(fd);
		return -EPROTO;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
		return -ENOENT;   /* the shell's word for a program it could not run */
	if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
		return -EPERM;
	return fd == -EPIPE ? -EPROTO : fd;
}
