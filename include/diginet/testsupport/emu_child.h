/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * A program under test against the desk emulator, end to end and without root: a user and
 * network namespace of the test's own (netns.h) with a veth pair, the emulated desk on one end
 * over its own packet socket, the program on the other as a child whose stdout and stderr the
 * test reads, with a pipe to its stdin when the program takes orders. The test pumps both sides
 * on the real clock, waits on the program's words, counts what the desk was sent, and reaps the
 * program at the end. libsurface's surface-c24 and the console's surface-native addon are tested
 * this way: the scenario stays with each of them, this is the harness under both.
 */
#ifndef DIGINET_EMU_CHILD_H
#define DIGINET_EMU_CHILD_H

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

#include <diginet/diginet_codec.h>
#include <diginet/testsupport/emu_pump.h>
#include <diginet/testsupport/netns.h>

#define EMU_CHILD_OUT_MAX (1 << 18)

struct emu_child {
	struct desk_emu desk;         /* the emulated desk */
	int desk_fd;                  /* its packet socket, on the desk's end of the veth pair */
	uint64_t next_announce_us;
	uint64_t announce_period_us;  /* 2 s, as a desk announces */
	pid_t pid;                    /* the program under test, -1 before emu_child_spawn */
	int out_fd;                   /* its stdout and stderr */
	int in_fd;                    /* its stdin, -1 when it has none */
	char out[EMU_CHILD_OUT_MAX];  /* everything the program has said so far, NUL-terminated */
	size_t outlen;
};

/* The private network and the desk on it: a new user and network namespace, the veth pair
 * host_if <-> desk_if, the desk `mac` named `name` at `version` on desk_if. 0 when all of it is
 * up; 77 where the machine allows none of it, after printing "<who>: <why>: nothing tested"
 * (the test's SKIP); -1 with errno on any other failure. */
static inline int emu_child_net(struct emu_child *c, const char *who, const char *host_if,
				const char *desk_if, const uint8_t mac[6], const char *name,
				const char *version)
{
	memset(c, 0, sizeof *c);
	c->desk_fd = c->out_fd = c->in_fd = -1;
	c->pid = -1;
	c->announce_period_us = 2000000;
	if (ns_enter() < 0) {
		printf("%s: no unprivileged user+net namespace (%s): nothing tested\n", who, strerror(errno));
		return 77;
	}
	if (ns_veth(host_if, desk_if) < 0) {
		printf("%s: cannot make a veth pair in the namespace (%s): nothing tested\n", who, strerror(errno));
		return 77;
	}
	uint8_t own[DIGINET_MAC_LEN];
	c->desk_fd = diginet_packet_open(desk_if, own);
	if (c->desk_fd == -EPERM) {
		printf("%s: no CAP_NET_RAW in the namespace: nothing tested\n", who);
		return 77;
	}
	if (c->desk_fd < 0) {
		errno = -c->desk_fd;
		c->desk_fd = -1;
		return -1;
	}
	emu_init(&c->desk, mac, name, version);
	return 0;
}

/* Start the program under test: argv[0] with the arguments argv (NULL-terminated), its stdout
 * and stderr read into c->out by every emu_child_step, its stdin a pipe the test writes with
 * emu_child_tell when `with_stdin`, /dev/null otherwise. The child keeps the namespace's
 * capabilities unless the test gave them up first (ns_drop_caps). 0, or -1 with errno. */
static inline int emu_child_spawn(struct emu_child *c, char *const argv[], int with_stdin)
{
	int po[2], pi[2] = { -1, -1 };
	if (pipe(po) < 0)
		return -1;
	if (with_stdin && pipe(pi) < 0) {
		close(po[0]);
		close(po[1]);
		return -1;
	}
	c->pid = fork();
	if (c->pid < 0) {
		close(po[0]);
		close(po[1]);
		if (with_stdin) {
			close(pi[0]);
			close(pi[1]);
		}
		return -1;
	}
	if (c->pid == 0) {
		int in = with_stdin ? pi[0] : open("/dev/null", O_RDONLY);
		dup2(in, 0);
		dup2(po[1], 1);
		dup2(po[1], 2);
		for (int fd = 3; fd < 64; fd++)
			close(fd);
		execv(argv[0], argv);
		_exit(127);
	}
	close(po[1]);
	c->out_fd = po[0];
	fcntl(c->out_fd, F_SETFL, O_NONBLOCK);
	if (with_stdin) {
		close(pi[0]);
		c->in_fd = pi[1];
	}
	c->next_announce_us = diginet_clock_us() + 300000;
	return 0;
}

/* One turn: take what the program said, run the desk (frames from the host, its timers and
 * announces, its frames back), and nap a millisecond. */
static inline void emu_child_step(struct emu_child *c)
{
	ssize_t k;
	while (c->outlen < sizeof c->out - 1 &&
	       (k = read(c->out_fd, c->out + c->outlen, sizeof c->out - 1 - c->outlen)) > 0)
		c->outlen += (size_t)k;
	c->out[c->outlen] = '\0';
	emu_pump_fd(&c->desk, c->desk_fd, &c->next_announce_us, c->announce_period_us);
	struct timespec ts = { 0, 1000000 };
	nanosleep(&ts, NULL);
}

/* Pump until the program has said `text`, at most `ms`: 1 when it did, 0 when the time ran out. */
static inline int emu_child_wait_for(struct emu_child *c, const char *text, int ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000;
	while (diginet_clock_us() < end) {
		emu_child_step(c);
		if (strstr(c->out, text))
			return 1;
	}
	return 0;
}

/* Pump for `ms`. */
static inline void emu_child_pump_ms(struct emu_child *c, int ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000;
	while (diginet_clock_us() < end)
		emu_child_step(c);
}

/* A line to the program's stdin. 0, or -1 (also when the program has no stdin). */
static inline int emu_child_tell(struct emu_child *c, const char *line)
{
	size_t n = strlen(line);
	if (c->in_fd < 0)
		return -1;
	return write(c->in_fd, line, n) == (ssize_t)n ? 0 : -1;
}

/* What the desk was sent: how many commands of the host's data frames (first sends only, as
 * `p` decodes them) `match` with `arg`. */
static inline int emu_child_got(const struct emu_child *c, const struct diginet_personality *p,
				int (*match)(const struct diginet_event *ev, const void *arg),
				const void *arg)
{
	int n = 0;
	for (unsigned i = 0; i < c->desk.nlog; i++) {
		const struct emu_rx *r = &c->desk.log[i];
		if (r->cmd != DIGINET_CMD_DATA || r->retry)
			continue;
		struct diginet_decoder dec;
		struct diginet_event ev;
		diginet_decoder_init(&dec, p, r->body, r->body_len);
		for (int rc; (rc = diginet_decoder_next(&dec, &ev)) != 0; )
			if (rc > 0 && match(&ev, arg))
				n++;
	}
	return n;
}

/* Predicates for emu_child_got: a scribble reading `arg` (a string) at any address; a fader
 * set-point, arg = { strip, value }; a left meter, arg = { address, segments }. */
static inline int emu_ev_text(const struct diginet_event *ev, const void *arg)
{
	return ev->kind == DIGINET_EV_SCRIBBLE && !strcmp(ev->text, arg);
}

static inline int emu_ev_fader(const struct diginet_event *ev, const void *arg)
{
	const unsigned *sv = arg;
	return ev->kind == DIGINET_EV_FADER && ev->strip == sv[0] && ev->value == sv[1];
}

static inline int emu_ev_meter(const struct diginet_event *ev, const void *arg)
{
	const unsigned *sv = arg;
	return ev->kind == DIGINET_EV_METER && !ev->right && ev->addr == sv[0] && ev->segments == (int)sv[1];
}

/* Wait for the program to exit, pumping, at most `ms`; past that it is killed. One last turn
 * takes its parting words and frames. Returns the wait status (WIFEXITED, WEXITSTATUS) and
 * closes the pipes; c->out keeps everything the program said. */
static inline int emu_child_reap(struct emu_child *c, int ms)
{
	int st = -1, done = 0;
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000;
	while (!done && diginet_clock_us() < end) {
		emu_child_step(c);
		done = waitpid(c->pid, &st, WNOHANG) == c->pid;
	}
	if (!done) {
		kill(c->pid, SIGKILL);
		waitpid(c->pid, &st, 0);
	}
	emu_child_step(c);
	if (c->in_fd >= 0)
		close(c->in_fd);
	close(c->out_fd);
	c->in_fd = c->out_fd = -1;
	c->pid = -1;
	return st;
}

#endif
