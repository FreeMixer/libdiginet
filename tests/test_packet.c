// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The real AF_PACKET path, without root: the test enters a user and network namespace of
 * its own (where it holds CAP_NET_RAW over its private loopback), opens two packet
 * sockets bound to 0x885F on `lo`, and runs a session against the desk emulator across
 * them. Exits 77 where unprivileged namespaces are not allowed: nothing was tested then. */
#define _GNU_SOURCE
#include "golden.h"
#include "emu_pump.h"

#include <sched.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_session.h>

static const uint8_t DESK_MAC[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
static const uint8_t HOST_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

static void on_notice(void *ctx, const struct diginet_notice *n) { (void)ctx; (void)n; }

static struct desk_emu E;
static struct diginet_session S;

int main(void)
{
	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		printf("test_packet: no unprivileged user+net namespace (%s): nothing tested\n", strerror(errno));
		return 77;
	}
	int ctl = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;
	memset(&ifr, 0, sizeof ifr);
	strcpy(ifr.ifr_name, "lo");
	if (ctl < 0 || ioctl(ctl, SIOCGIFFLAGS, &ifr) < 0 ||
	    (ifr.ifr_flags |= IFF_UP, ioctl(ctl, SIOCSIFFLAGS, &ifr) < 0)) {
		printf("test_packet: cannot bring lo up in the namespace (%s): nothing tested\n", strerror(errno));
		return 77;
	}
	close(ctl);

	uint8_t mac[6];
	int host_fd = diginet_packet_open("lo", mac);
	int desk_fd = diginet_packet_open("lo", mac);
	if (host_fd == -EPERM || desk_fd == -EPERM) {
		printf("test_packet: no CAP_NET_RAW in the namespace: nothing tested\n");
		return 77;
	}
	CHK(host_fd >= 0 && desk_fd >= 0);
	if (host_fd < 0 || desk_fd < 0)
		return 1;

	struct diginet_fd_io st;
	struct diginet_io io;
	diginet_io_fd(&io, &st, host_fd);
	struct diginet_session_config cfg;
	diginet_session_config_default(&cfg);
	memcpy(cfg.host_mac, HOST_MAC, 6);
	CHK(diginet_session_init(&S, &cfg, &io, on_notice, NULL) == 0);
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");

	struct diginet_cmd fc;
	CHK(diginet_fader_encode(diginet_personality_of(DIGINET_DESK_CONTROL24), 0, 512, &fc) == 0);
	uint64_t next_ann = 0, t0 = diginet_clock_us();
	int sent = 0;
	while (diginet_clock_us() - t0 < 3000000) {
		emu_pump_fd(&E, desk_fd, &next_ann, 7000000);
		CHK(diginet_session_poll(&S, 2) == 0);
		if (S.state == DIGINET_S_ONLINE && !sent) {
			CHK(diginet_session_submit(&S, &fc) == 0);
			sent = 1;
		}
		if (sent && emu_count_cmd(&E, fc.bytes, fc.len) == 1 && !S.inflight)
			break;
	}
	CHK(S.state == DIGINET_S_ONLINE && E.wakes == 1);
	CHK(emu_count_cmd(&E, fc.bytes, fc.len) == 1 && !S.inflight && S.stats.ack_lost == 0);
	/* Our own frames came back on lo; the session saw them and set them aside. */
	CHK(S.stats.rx_ignored > 0);
	if (fails) {
		fprintf(stderr, "test_packet: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_packet: ok (AF_PACKET on a private loopback)\n");
	return 0;
}
