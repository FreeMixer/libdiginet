// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The any-interface packet socket on real interfaces, without root (tests/netns.h): the test
 * enters a user and network namespace of its own and makes two veth pairs, hA <-> dA and
 * hB <-> dB, the h ends the host's interfaces and the d ends where a desk sits. Then:
 *
 *  - it gives up every capability, so diginet_packet_open_any() fails here (-EPERM), and takes
 *    the any-interface socket from diginet-packet-helper instead (diginet_packet_open_by_helper);
 *  - hB/dB is made only after that socket exists (by a child that kept the capabilities), and
 *    is heard all the same: the socket is bound to no interface;
 *  - a frame a desk sends on dA comes in named hA, one on dB named hB; our own frames are
 *    never handed back; a frame sent to hA's index goes out of hA only, and to hB's out of hB;
 *  - diginet_if_mac() reads each host interface's MAC;
 *  - a socket that taps every protocol, handed over in place of ours, also sees what this host
 *    sends as outgoing: diginet_packet_recvfrom() skips it (a socket bound to 0x885F gets none);
 *  - diginet_packet_receive_fd() refuses two packet sockets in one message, and closes both;
 *  - the helper's socket comes back when this process's 3 is free and a lower one is too, so
 *    the child's end of the socketpair is born on 3 (posix_spawn's dup2 onto itself).
 *
 *   tests/test_anyif <path to diginet-packet-helper>
 *
 * Exits 77 where unprivileged user and network namespaces are not allowed: nothing was tested. */
#define _GNU_SOURCE
#include "golden.h"
#include "netns.h"

#include <signal.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <diginet/transport/diginet_io.h>

static const uint8_t DESK_A[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x0a };
static const uint8_t DESK_B[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x0b };
static const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* A desk's announce on its own socket, a frame of the grammar from `src`. */
static int announce(int fd, const uint8_t src[6])
{
	uint8_t f[DIGINET_MAX_FRAME_LEN], body[DIGINET_ANNOUNCE_BODY_LEN];
	memset(body, 0, sizeof body);
	memcpy(body + 15, "1.08", 4);
	memcpy(body + 24, "CNTRL|24", 8);
	struct diginet_header h = { .cmd = DIGINET_CMD_ANNOUNCE };
	int n = diginet_frame_build(f, sizeof f, BCAST, src, &h, body, sizeof body, DIGINET_SUM_BODY);
	return n > 0 && send(fd, f, (size_t)n, 0) == n ? 0 : -1;
}

/* The next 0x885F frame on `fd` within `ms`, its source MAC and its interface. */
static int next_frame(int fd, int ms, uint8_t src[6], int *ifindex)
{
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	while (diginet_clock_us() < end) {
		int n = diginet_packet_recvfrom(fd, b, sizeof b, ifindex, 10);
		if (n >= DIGINET_ETH_HDR_LEN) {
			memcpy(src, b + 6, 6);
			return n;
		}
		if (n < 0)
			return n;
	}
	return 0;
}

/* Whether `fd` (a desk's socket, bound to its interface) receives a frame from `src` in `ms`. */
static int desk_hears(int fd, const uint8_t src[6], int ms)
{
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	while (diginet_clock_us() < end) {
		int ifx;
		int n = diginet_packet_recvfrom(fd, b, sizeof b, &ifx, 10);
		if (n >= DIGINET_ETH_HDR_LEN && !memcmp(b + 6, src, 6))
			return 1;
	}
	return 0;
}

/* The child that keeps the namespace's capabilities: on a byte from the parent it makes hB/dB,
 * opens a packet socket on dB and passes it back. */
static void admin(int ch)
{
	char c;
	if (read(ch, &c, 1) != 1)
		_exit(1);
	uint8_t mac[6];
	if (ns_veth("hB", "dB") < 0)
		_exit(2);
	int fd = diginet_packet_open("dB", mac);
	_exit(fd >= 0 && diginet_packet_send_fd(ch, fd) == 0 ? 0 : 3);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: test_anyif <diginet-packet-helper>\n");
		return 2;
	}
	if (ns_enter() < 0) {
		printf("test_anyif: no unprivileged user+net namespace (%s): nothing tested\n", strerror(errno));
		return 77;
	}
	if (ns_veth("hA", "dA") < 0) {
		printf("test_anyif: cannot make a veth pair in the namespace (%s): nothing tested\n", strerror(errno));
		return 77;
	}
	uint8_t mac[6];
	int desk_a = diginet_packet_open("dA", mac);
	if (desk_a == -EPERM) {
		printf("test_anyif: no CAP_NET_RAW in the namespace: nothing tested\n");
		return 77;
	}
	CHK(desk_a >= 0);
	/* A socket on hA that taps every protocol sees what it sends out of hA as outgoing; the
	 * receive skips it, and what is left on hA is nothing. */
	int tap = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = (int)if_nametoindex("hA");
	CHK(tap >= 0 && bind(tap, (struct sockaddr *)&sll, sizeof sll) == 0);
	{
		uint8_t f[DIGINET_MAX_FRAME_LEN], g[DIGINET_MAX_FRAME_LEN], hmac[6];
		struct diginet_header h = { .cmd = DIGINET_CMD_WAKE };
		CHK(diginet_if_mac(sll.sll_ifindex, hmac) == 0);
		int n = diginet_frame_build(f, sizeof f, DESK_A, hmac, &h, NULL, 0, DIGINET_SUM_BODY);
		/* sent by another socket: a packet socket is never handed what it sent itself */
		int other = diginet_packet_open("hA", hmac);
		CHK(other >= 0 && n > 0 && send(other, f, (size_t)n, 0) == n);
		close(other);
		/* The tap hears hA's other traffic too (IPv6 neighbour discovery): only our frame
		 * must not come back. */
		int ifx = -1, ours = 0;
		uint64_t end = diginet_clock_us() + 200000;
		while (diginet_clock_us() < end) {
			int got = diginet_packet_recvfrom(tap, g, sizeof g, &ifx, 10);
			ours += got == n && !memcmp(g, f, (size_t)n);
		}
		CHK(ours == 0);
	}

	int ch[2];
	CHK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ch) == 0);
	pid_t kid = fork();
	if (kid == 0) {
		close(ch[0]);
		admin(ch[1]);
	}
	close(ch[1]);

	/* Unprivileged from here: the socket can only come from the helper. */
	CHK(ns_drop_caps() == 0);
	CHK(diginet_packet_open_any() == -EPERM);
	CHK(diginet_packet_open("dA", mac) == -EPERM);
	/* Descriptors 0 and 3 free: the socketpair inside is born as 0 and 3. */
	int saved0 = fcntl(0, F_DUPFD_CLOEXEC, 20), saved3 = fcntl(3, F_DUPFD_CLOEXEC, 20);
	close(0);
	close(3);
	int any = diginet_packet_open_by_helper(argv[1]);
	if (any == 0 || any == 3) {
		int moved = fcntl(any, F_DUPFD_CLOEXEC, 20);
		close(any);
		any = moved;
	}
	if (saved3 >= 0)
		dup2(saved3, 3);
	dup2(saved0, 0);
	close(saved0);
	if (saved3 >= 0)
		close(saved3);
	CHK(any >= 0);
	if (any < 0 || desk_a < 0) {
		fprintf(stderr, "test_anyif: the helper gave no socket (%s)\n", strerror(-any));
		kill(kid, SIGKILL);
		return 1;
	}
	int domain = 0;
	socklen_t dl = sizeof domain;
	CHK(getsockopt(any, SOL_SOCKET, SO_DOMAIN, &domain, &dl) == 0 && domain == AF_PACKET);

	/* hB/dB comes up only now, after the socket was opened. */
	CHK(write(ch[0], "B", 1) == 1);
	int desk_b = diginet_packet_receive_fd(ch[0]);
	int st = 0;
	waitpid(kid, &st, 0);
	CHK(desk_b >= 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	if (desk_b < 0)
		return 1;

	int ha = (int)if_nametoindex("hA"), hb = (int)if_nametoindex("hB");
	int da = (int)if_nametoindex("dA"), db = (int)if_nametoindex("dB");
	CHK(ha > 0 && hb > 0 && ha != hb);
	uint8_t mac_a[6], mac_b[6], want[6];
	CHK(diginet_if_mac(ha, mac_a) == 0 && diginet_if_mac(hb, mac_b) == 0 && memcmp(mac_a, mac_b, 6));
	struct ifreq ifr;
	int ctl = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof ifr);
	strcpy(ifr.ifr_name, "hA");
	CHK(ioctl(ctl, SIOCGIFHWADDR, &ifr) == 0);
	memcpy(want, ifr.ifr_hwaddr.sa_data, 6);
	close(ctl);
	CHK(!memcmp(mac_a, want, 6));
	CHK(diginet_if_mac(0, mac_a) == -EINVAL);
	CHK(diginet_if_mac(9999, want) == -ENODEV);

	/* Each desk's announce comes in named by the host interface it arrived on. Our own frames
	 * (on hA and hB as outgoing) are never handed back; the desk's frame leaving dA is seen on
	 * dA as outgoing and skipped too. */
	uint8_t src[6];
	int ifx = -1;
	CHK(announce(desk_a, DESK_A) == 0);
	CHK(next_frame(any, 500, src, &ifx) > 0 && !memcmp(src, DESK_A, 6) && ifx == ha);
	CHK(next_frame(any, 100, src, &ifx) == 0);
	CHK(announce(desk_b, DESK_B) == 0);
	CHK(next_frame(any, 500, src, &ifx) > 0 && !memcmp(src, DESK_B, 6) && ifx == hb);
	CHK(next_frame(any, 100, src, &ifx) == 0);

	/* A frame sent to hA's index goes out of hA only, to dA; one to hB's out of hB only. */
	uint8_t f[DIGINET_MAX_FRAME_LEN];
	struct diginet_header h = { .cmd = DIGINET_CMD_WAKE };
	int n = diginet_frame_build(f, sizeof f, DESK_A, mac_a, &h, NULL, 0, DIGINET_SUM_BODY);
	CHK(n > 0 && diginet_packet_sendto(any, ha, f, (size_t)n) == 0);
	CHK(desk_hears(desk_a, mac_a, 500));
	CHK(!desk_hears(desk_b, mac_a, 100));
	/* what arrived on dA is no frame of ours to the unbound socket: it came in on dA, from hA's
	 * MAC; the mux sets such a frame aside by its source, the socket hands it over */
	CHK(next_frame(any, 200, src, &ifx) > 0 && !memcmp(src, mac_a, 6) && ifx == da);
	n = diginet_frame_build(f, sizeof f, DESK_B, mac_b, &h, NULL, 0, DIGINET_SUM_BODY);
	CHK(n > 0 && diginet_packet_sendto(any, hb, f, (size_t)n) == 0);
	CHK(desk_hears(desk_b, mac_b, 500));
	CHK(!desk_hears(desk_a, mac_b, 100));
	CHK(next_frame(any, 200, src, &ifx) > 0 && !memcmp(src, mac_b, 6) && ifx == db);

	/* Two packet sockets in one message are refused, and both closed. */
	{
		int sv[2], two[2] = { dup(any), dup(desk_a) };
		CHK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
		char data = 'F';
		struct iovec iov = { .iov_base = &data, .iov_len = 1 };
		union {
			struct cmsghdr h;
			char buf[CMSG_SPACE(2 * sizeof(int))];
		} c;
		memset(&c, 0, sizeof c);
		struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = c.buf,
				    .msg_controllen = sizeof c.buf };
		struct cmsghdr *hd = CMSG_FIRSTHDR(&m);
		hd->cmsg_level = SOL_SOCKET;
		hd->cmsg_type = SCM_RIGHTS;
		hd->cmsg_len = CMSG_LEN(2 * sizeof(int));
		memcpy(CMSG_DATA(hd), two, sizeof two);
		CHK(sendmsg(sv[0], &m, 0) == 1);
		close(two[0]);
		close(two[1]);
		int lowest = fcntl(0, F_DUPFD, 0);
		close(lowest);
		CHK(diginet_packet_receive_fd(sv[1]) == -EPROTO);
		CHK(fcntl(lowest, F_GETFD) < 0 && fcntl(lowest + 1, F_GETFD) < 0);
		close(sv[0]);
		close(sv[1]);
	}

	/* sendto's refusals */
	CHK(diginet_packet_sendto(any, 0, f, (size_t)n) == -EINVAL);
	CHK(diginet_packet_sendto(any, ha, f, DIGINET_ETH_HDR_LEN - 1) == -EINVAL);
	CHK(diginet_packet_sendto(any, 9999, f, (size_t)n) == -ENXIO ||
	    diginet_packet_sendto(any, 9999, f, (size_t)n) == -ENODEV);

	if (fails) {
		fprintf(stderr, "test_anyif: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_anyif: ok (the helper's socket, unprivileged, on two veth pairs, one made after it)\n");
	return 0;
}
