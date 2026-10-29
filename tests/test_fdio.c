// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The descriptor io and diginet_session_poll() on the real clock, over a SOCK_SEQPACKET
 * socketpair with the desk emulator on the other end: the session comes online, a fader
 * move reaches the desk and is ACKed, a desk key press reaches the host. Then the packet
 * socket's refusals: an interface that does not exist, and no CAP_NET_RAW. Then the hand-over
 * of a packet socket over a Unix socket: what diginet_packet_receive_fd() refuses. */
#include "golden.h"
#include "emu_pump.h"

#include <fcntl.h>
#include <unistd.h>

#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>

static const uint8_t DESK_MAC[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
static const uint8_t HOST_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static int presses;

static void on_notice(void *ctx, const struct diginet_notice *n)
{
	(void)ctx;
	if (n->kind != DIGINET_N_DATA)
		return;
	struct diginet_decoder d;
	struct diginet_event ev;
	diginet_decoder_init(&d, NULL, n->body, n->body_len);
	while (diginet_decoder_next(&d, &ev) == 1)
		if (ev.kind == DIGINET_EV_STRIP_BUTTON && ev.button == DIGINET_BTN_MUTE && ev.strip == 4 && ev.on)
			presses++;
}

static struct desk_emu E;
static struct diginet_session S;

/* Whether descriptor fd is open in this process. */
static int is_open(int fd)
{
	return fcntl(fd, F_GETFD) >= 0;
}

/* Send `nfds` descriptors (none when 0) and `len` bytes of data in one message. */
static int send_fds(int sock, const int *fds, int nfds, size_t len)
{
	char data[1] = { 'F' };
	struct iovec iov = { .iov_base = data, .iov_len = len };
	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(4 * sizeof(int))];
	} c;
	memset(&c, 0, sizeof c);
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1 };
	if (nfds) {
		m.msg_control = c.buf;
		m.msg_controllen = CMSG_SPACE((size_t)nfds * sizeof(int));
		struct cmsghdr *h = CMSG_FIRSTHDR(&m);
		h->cmsg_level = SOL_SOCKET;
		h->cmsg_type = SCM_RIGHTS;
		h->cmsg_len = CMSG_LEN((size_t)nfds * sizeof(int));
		memcpy(CMSG_DATA(h), fds, (size_t)nfds * sizeof(int));
	}
	return sendmsg(sock, &m, 0) == (ssize_t)len ? 0 : -1;
}

static void handover(void)
{
	int sv[2], p[2];
	CHK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
	CHK(pipe(p) == 0);
	int un = socket(AF_UNIX, SOCK_DGRAM, 0);

	/* A descriptor that is no packet socket is refused, and closed: it never stays open here. */
	CHK(diginet_packet_send_fd(sv[0], p[0]) == 0);
	int before = fcntl(0, F_DUPFD, 0);   /* the lowest free descriptor now */
	close(before);
	CHK(diginet_packet_receive_fd(sv[1]) == -EPROTO);
	CHK(!is_open(before));
	/* So is a socket of another family. */
	CHK(diginet_packet_send_fd(sv[0], un) == 0);
	CHK(diginet_packet_receive_fd(sv[1]) == -EPROTO);
	CHK(!is_open(before));
	close(un);
	/* So is a message that carries two, both closed. */
	int two[2] = { p[0], p[1] };
	CHK(send_fds(sv[0], two, 2, 1) == 0);
	CHK(diginet_packet_receive_fd(sv[1]) == -EPROTO);
	CHK(!is_open(before) && !is_open(before + 1));
	/* Data with no descriptor is refused; the peer gone with none is -EPIPE. */
	CHK(send_fds(sv[0], NULL, 0, 1) == 0);
	CHK(diginet_packet_receive_fd(sv[1]) == -EPROTO);
	close(sv[0]);
	CHK(diginet_packet_receive_fd(sv[1]) == -EPIPE);
	close(sv[1]);
	close(p[0]);
	close(p[1]);
	CHK(diginet_packet_receive_fd(-1) == -EINVAL && diginet_packet_send_fd(-1, 0) == -EINVAL);

	/* No such helper program. */
	CHK(diginet_packet_open_by_helper("/nonexistent/diginet-packet-helper") == -ENOENT);
}

int main(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
		perror("socketpair");
		return 2;
	}
	struct diginet_fd_io st;
	struct diginet_io io;
	diginet_io_fd(&io, &st, sv[0]);
	struct diginet_session_config cfg;
	diginet_session_config_default(&cfg);
	memcpy(cfg.host_mac, HOST_MAC, 6);
	CHK(diginet_session_init(&S, &cfg, &io, on_notice, NULL) == 0);
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");

	uint64_t next_ann = 0, t0 = diginet_clock_us();
	int sent = 0, pressed = 0;
	struct diginet_cmd fc;
	CHK(diginet_fader_encode(diginet_personality_of(DIGINET_DESK_CONTROL24), 0, 512, &fc) == 0);
	while (diginet_clock_us() - t0 < 3000000) {
		emu_pump_fd(&E, sv[1], &next_ann, 7000000);
		CHK(diginet_session_poll(&S, 2) == 0);
		if (S.state == DIGINET_S_ONLINE && !sent) {
			CHK(diginet_session_submit(&S, &fc) == 0);
			sent = 1;
		}
		if (S.state == DIGINET_S_ONLINE && !pressed) {
			static const uint8_t mute5[] = { 0x90, 0x08, 0x44 };
			emu_send_data(&E, mute5, 3, 1, 0, 0);
			pressed = 1;
		}
		if (sent && presses && emu_count_cmd(&E, fc.bytes, fc.len) == 1 && !S.inflight)
			break;
	}
	CHK(S.state == DIGINET_S_ONLINE && E.in_session);
	CHK(emu_count_cmd(&E, fc.bytes, fc.len) == 1 && !S.inflight && S.stats.ack_lost == 0);
	CHK(presses == 1 && E.acks_from_host >= 1);

	/* The peer going away is an error from poll, not a hang. */
	close(sv[1]);
	int r = 0;
	for (int i = 0; i < 10 && r == 0; i++)
		r = diginet_session_poll(&S, 10);
	CHK(r < 0);
	close(sv[0]);

	/* The packet socket's refusals. */
	uint8_t mac[6];
	CHK(diginet_packet_open("nosuchif0", mac) == -ENODEV);
	CHK(diginet_packet_open(NULL, mac) == -EINVAL);
	int fd = diginet_packet_open("lo", mac);
	if (fd >= 0)
		close(fd);   /* this process holds CAP_NET_RAW */
	else
		CHK(fd == -EPERM || fd == -EACCES);

	handover();

	if (fails) {
		fprintf(stderr, "test_fdio: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_fdio: ok\n");
	return 0;
}
