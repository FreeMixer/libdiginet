/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * The desk emulator over a descriptor, on the real clock: read what the host sent, run the
 * desk's timers and announces, write what the desk has to say.
 */
#ifndef DIGINET_EMU_PUMP_H
#define DIGINET_EMU_PUMP_H

#include <errno.h>
#include <sys/socket.h>

#include "desk_emu.h"
#include <diginet/transport/diginet_io.h>

static inline void emu_pump_fd(struct desk_emu *e, int fd, uint64_t *next_announce, uint64_t period_us)
{
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	ssize_t n;
	uint64_t now = diginet_clock_us();
	while ((n = recv(fd, b, sizeof b, MSG_DONTWAIT)) > 0)
		emu_from_host(e, b, (size_t)n, now);
	emu_tick(e, now);
	if (now >= *next_announce) {
		emu_announce(e, now);
		*next_announce = now + period_us;
	}
	size_t m;
	while ((m = emu_pop(e, b, sizeof b)))
		if (send(fd, b, m, 0) < 0 && errno != EAGAIN)
			break;
}

#endif
