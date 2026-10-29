// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* diginet-packet-helper: open the any-interface DigiNet packet socket and hand it to the
 * process that started this one (docs/diginet-packet-helper.1).
 *
 * It holds cap_net_raw so its caller need not. The contract: descriptor 3 is a connected
 * AF_UNIX socket; the helper opens an AF_PACKET socket bound to EtherType 0x885F on no
 * interface (diginet_packet_open_any), passes it over descriptor 3 with SCM_RIGHTS and exits 0.
 * Without the capability it exits 1 with "needs cap_net_raw" on stderr; with descriptor 3 not a
 * connected Unix socket, or any other failure, it exits 2. It takes no arguments, reads nothing,
 * loops on nothing and keeps no descriptor: the socket it passes is the only thing it makes. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <diginet/diginet.h>
#include <diginet/transport/diginet_io.h>

#define CHANNEL 3

int main(int argc, char **argv)
{
	(void)argv;
	if (argc > 1) {
		fprintf(stderr, "diginet-packet-helper: takes no arguments; see diginet-packet-helper(1)\n");
		return 2;
	}
	int domain = 0, type = 0;
	socklen_t dl = sizeof domain, tl = sizeof type;
	struct sockaddr_storage peer;
	socklen_t pl = sizeof peer;
	if (getsockopt(CHANNEL, SOL_SOCKET, SO_DOMAIN, &domain, &dl) < 0 || domain != AF_UNIX ||
	    getsockopt(CHANNEL, SOL_SOCKET, SO_TYPE, &type, &tl) < 0 ||
	    getpeername(CHANNEL, (struct sockaddr *)&peer, &pl) < 0) {
		fprintf(stderr, "diginet-packet-helper: descriptor 3 is not a connected Unix socket\n");
		return 2;
	}
	int fd = diginet_packet_open_any();
	if (fd == -EPERM || fd == -EACCES) {
		fprintf(stderr, "diginet-packet-helper: needs cap_net_raw (setcap cap_net_raw=ep %s)\n",
			"/usr/bin/diginet-packet-helper");
		return 1;
	}
	if (fd < 0) {
		fprintf(stderr, "diginet-packet-helper: cannot open the packet socket: %s\n", strerror(-fd));
		return 2;
	}
	int r = diginet_packet_send_fd(CHANNEL, fd);
	close(fd);
	if (r < 0) {
		fprintf(stderr, "diginet-packet-helper: cannot pass the socket: %s\n", strerror(-r));
		return 2;
	}
	return 0;
}
