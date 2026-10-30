// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* diginet-probe: the first test on a real desk (docs/probe.md). */
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>
#include <diginet/transport/diginet_io.h>
#include <diginet/transport/diginet_mux.h>
#include <diginet/transport/diginet_session.h>

enum { EXIT_OK = 0, EXIT_USAGE = 2, EXIT_FOREIGN = 3, EXIT_NO_DESK = 4, EXIT_NO_ACK = 5 };

static volatile sig_atomic_t stop;
static void on_signal(int sig) { (void)sig; stop = 1; }

/* The session the steps drive: the probe's own over one interface or a descriptor, or with --any
 * the session of the desk the mux attached (S0, idle and empty, while there is none). */
static struct diginet_session S0, *S = &S0;
static uint64_t t0;
static const struct diginet_personality *P;

/* What the run found. */
static struct {
	int desk_seen, foreign, online, acked_wake, e1_offset, e1_before_ack;
	char name[10], version[10];
	uint8_t desk_mac[6];
	unsigned frames, cmds, running, keys, touches, fader_moves, vpot_turns, jog_turns, other;
	unsigned acked, lost;
	int vpot1_sum, jog_sum;
	int fader1_min, fader1_max, fader1_last;
	unsigned lost_online;          /* sessions that ended while online, not by us */
	enum diginet_reason lost_why;
	uint64_t last_keepalive_us, max_ka_gap_at_e0;
	/* touch test */
	int touch_test, touched, touch_seen, release_seen;
	int held_min, held_max, at_release, after_release_last;
	unsigned held_moves, after_moves;
} R = { .e1_offset = -1, .fader1_min = -1, .fader1_max = -1, .fader1_last = -1,
	.held_min = -1, .held_max = -1, .at_release = -1, .after_release_last = -1 };

static double secs(void) { return (double)(diginet_clock_us() - t0) / 1e6; }

static void say(const char *fmt, ...)
{
	va_list ap;
	printf("[%7.3f] ", secs());
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static const char *strip_button_name(unsigned b)
{
	static const char *n[] = { "REC", "PAN/SEND", "EQ", "DYN", "ACTIVE", "AUTO", "SELECT",
				   "SOLO", "MUTE", "TOUCH", "INSERTS", "PEAK", "SOURCE", "ROLL-OFF" };
	return b < sizeof n / sizeof n[0] ? n[b] : "?";
}

static void log_event(const struct diginet_event *ev)
{
	R.cmds++;
	if (ev->msg.running)
		R.running++;
	switch (ev->kind) {
	case DIGINET_EV_FADER:
		R.fader_moves++;
		if (ev->strip == 0) {
			if (R.fader1_min < 0 || ev->value < R.fader1_min) R.fader1_min = ev->value;
			if (ev->value > R.fader1_max) R.fader1_max = ev->value;
			R.fader1_last = ev->value;
			if (R.touch_test && R.touched) {
				R.held_moves++;
				if (R.held_min < 0 || ev->value < R.held_min) R.held_min = ev->value;
				if (ev->value > R.held_max) R.held_max = ev->value;
			} else if (R.touch_test && R.release_seen) {
				R.after_moves++;
				R.after_release_last = ev->value;
			}
		}
		say("fader %u at %u%s", ev->strip + 1, ev->value, ev->lsb_missing ? " (no LSB)" : "");
		break;
	case DIGINET_EV_TOUCH:
		R.touches++;
		if (ev->strip == 0 && R.touch_test) {
			if (ev->on) {
				R.touched = 1;
				R.touch_seen = 1;
			} else if (R.touched) {
				R.touched = 0;
				R.release_seen = 1;
				R.at_release = R.fader1_last;
			}
		}
		say("fader %u %s", ev->strip + 1, ev->on ? "touched" : "released");
		break;
	case DIGINET_EV_STRIP_BUTTON:
		R.keys++;
		say("key: strip %u %s %s", ev->strip + 1, strip_button_name(ev->button),
		    ev->on ? "pressed" : "released");
		break;
	case DIGINET_EV_SECTION_BUTTON:
		R.keys++;
		say("key: zone 0x%02X button 0x%02X %s", ev->zone, ev->button, ev->on ? "pressed" : "released");
		break;
	case DIGINET_EV_VPOT:
		R.vpot_turns++;
		if (ev->strip == 0)
			R.vpot1_sum += ev->delta;
		say("V-Pot %u %+d", ev->strip + 1, ev->delta);
		break;
	case DIGINET_EV_JOG:
		R.jog_turns++;
		R.jog_sum += ev->delta;
		say("jog %+d", ev->delta);
		break;
	default: {
		R.other++;
		char hex[3 * 64 + 1] = "";
		const uint8_t *p = ev->msg.status == 0xf0 ? ev->msg.sysex - 1 : NULL;
		size_t n = p ? ev->msg.sysex_len + 2 : 0;
		for (size_t i = 0; i < n && i < 64; i++)
			sprintf(hex + 3 * i, "%02x ", p[i]);
		if (!p)
			sprintf(hex, "%02x %02x %02x", ev->msg.status, ev->msg.d1, ev->msg.d2);
		say("other: %s", hex);
		break;
	}
	}
}

static void on_notice(void *ctx, const struct diginet_notice *n)
{
	(void)ctx;
	switch (n->kind) {
	case DIGINET_N_DESK:
		if (!R.desk_seen) {
			R.desk_seen = 1;
			memcpy(R.desk_mac, n->frame->src, 6);
			snprintf(R.name, sizeof R.name, "%s", n->announce->name);
			snprintf(R.version, sizeof R.version, "%s", n->announce->version);
			if (n->personality)
				P = n->personality;
			const uint8_t *m = n->frame->src;
			say("desk: %02x:%02x:%02x:%02x:%02x:%02x name \"%s\" version \"%s\" (%s)",
			    m[0], m[1], m[2], m[3], m[4], m[5], R.name, R.version,
			    !n->personality ? "unknown personality" :
			    n->personality->desk == DIGINET_DESK_CONTROL24 ? "Control|24" : "ProControl");
		}
		if (n->frame->h.cmd == DIGINET_CMD_ANNOUNCE_SESSION && n->mac_offset >= 0) {
			if (R.e1_offset < 0) {
				R.e1_offset = n->mac_offset;
				R.e1_before_ack = !R.acked_wake;
				say("e1 names this host at body offset %d", n->mac_offset);
			}
		}
		if (n->frame->h.cmd == DIGINET_CMD_ANNOUNCE && R.online && P->announces_session)
			say("desk announced e0 while in session, %.1f s after our last keepalive",
			    (double)(diginet_clock_us() - R.last_keepalive_us) / 1e6);
		break;
	case DIGINET_N_FOREIGN:
		if (!R.foreign)
			say("desk is in a session with another host: not waking it");
		R.foreign = 1;
		break;
	case DIGINET_N_DESK_DEAF:
		say("desk announces but let %u wakes in a row time out: it likely booted with large "
		    "broadcasts on its link; power-cycle it with the link quiet", n->counter);
		break;
	case DIGINET_N_STATE:
		say("session %s -> %s (%s)", diginet_state_name(n->old_state), diginet_state_name(n->state),
		    diginet_reason_name(n->reason));
		if (n->state == DIGINET_S_ONLINE) {
			R.online = 1;
			R.last_keepalive_us = diginet_clock_us();
		} else if (n->old_state == DIGINET_S_ONLINE) {
			R.online = 0;
			if (n->reason != DIGINET_R_CLOSED) {
				R.lost_online++;
				R.lost_why = n->reason;
				say("session lost while online (%s), %.1f s after our last keepalive",
				    diginet_reason_name(n->reason),
				    (double)(diginet_clock_us() - R.last_keepalive_us) / 1e6);
			}
		}
		break;
	case DIGINET_N_ACKED:
		if (S->state == DIGINET_S_WAKING)
			R.acked_wake = 1;
		else
			R.acked++;
		break;
	case DIGINET_N_ACK_LOST:
		R.lost++;
		say("no ACK for our frame %u after %u retries", n->counter, n->retry);
		break;
	case DIGINET_N_DATA: {
		R.frames++;
		struct diginet_decoder d;
		struct diginet_event ev;
		int r;
		diginet_decoder_init(&d, P, n->body, n->body_len);
		while ((r = diginet_decoder_next(&d, &ev)) != 0) {
			if (r < 0) {
				say("undecodable bytes in desk frame %u: %s", n->counter, diginet_strerror(r));
				continue;
			}
			log_event(&ev);
		}
		break;
	}
	}
}

/* --any: one socket for every interface, and the desk mux over it. */
static struct diginet_mux MUX;
static int any_mode, our_desk = -1;
static struct diginet_session_config any_cfg;
static const uint8_t *desk_filter;
static int heard_if[16], nheard_if;

static const char *if_name(int ifindex, char *buf)
{
	if (!if_indextoname((unsigned)ifindex, buf))
		snprintf(buf, IF_NAMESIZE, "#%d", ifindex);
	return buf;
}

static void on_mux_notice(void *ctx, const struct diginet_mux_notice *n)
{
	(void)ctx;
	char name[IF_NAMESIZE];
	const uint8_t *m = n->mac;
	switch (n->kind) {
	case DIGINET_MUX_N_APPEARED: {
		say("desk %02x:%02x:%02x:%02x:%02x:%02x appeared on %s (\"%s\")", m[0], m[1], m[2], m[3], m[4],
		    m[5], if_name(n->ifindex, name), n->announce->name);
		int seen = 0;
		for (int i = 0; i < nheard_if; i++)
			seen |= heard_if[i] == n->ifindex;
		if (!seen && nheard_if < 16)
			heard_if[nheard_if++] = n->ifindex;
		if (our_desk >= 0 || (desk_filter && memcmp(desk_filter, m, 6)))
			break;
		/* the desk the run is about; one that comes back after it was gone is woken again */
		struct diginet_session_config c = any_cfg;
		c.auto_wake = R.desk_seen;
		int r = diginet_mux_attach(&MUX, n->desk, &c);
		if (r != DIGINET_OK) {
			say("cannot attach the desk on %s: %s", name, r < 0 ? strerror(-r) : diginet_strerror(r));
			break;
		}
		our_desk = (int)n->desk;
		S = diginet_mux_session(&MUX, n->desk);
		const uint8_t *h = S->cfg.host_mac;
		say("attached: host %02x:%02x:%02x:%02x:%02x:%02x on %s", h[0], h[1], h[2], h[3], h[4], h[5], name);
		break;
	}
	case DIGINET_MUX_N_GONE:
		say("desk %02x:%02x:%02x:%02x:%02x:%02x gone from %s", m[0], m[1], m[2], m[3], m[4], m[5],
		    if_name(n->ifindex, name));
		if ((int)n->desk == our_desk) {
			our_desk = -1;
			S = &S0;
		}
		break;
	case DIGINET_MUX_N_SESSION:
		if ((int)n->desk == our_desk)
			on_notice(NULL, n->session);
		break;
	}
}

static int send_nowhere(void *ctx, const uint8_t *frame, size_t len)
{
	(void)ctx;
	(void)frame;
	(void)len;
	return -ENOTCONN;
}

static int poll_wire(int ms)
{
	return any_mode ? diginet_mux_poll(&MUX, ms) : diginet_session_poll(S, ms);
}

/* Run the session for `ms` milliseconds (or until stop). */
static void run_for(unsigned ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	uint64_t ka = S->stats.tx_keepalives;
	while (!stop && diginet_clock_us() < end) {
		int r = poll_wire(20);
		if (r < 0) {
			say("io error: %s", strerror(-r));
			stop = 1;
		}
		if (S->stats.tx_keepalives != ka) {
			ka = S->stats.tx_keepalives;
			R.last_keepalive_us = diginet_clock_us();
		}
	}
}

/* Run until cond() or timeout; returns cond(). */
static int run_until(int (*cond)(void), unsigned ms)
{
	uint64_t end = diginet_clock_us() + (uint64_t)ms * 1000u;
	while (!stop && !cond() && diginet_clock_us() < end)
		run_for(10);
	return cond();
}

/* How the session came online: the e1 is reported only when the desk sent one. */
static const char *online_how(void)
{
	if (R.e1_offset < 0)
		return "a0 alone, no e1";
	return R.e1_before_ack ? "e1 before a0" : "a0 then e1";
}

static int c_desk(void) { return R.desk_seen && (R.foreign || S->state != DIGINET_S_IDLE || !S->cfg.auto_wake); }
static int c_online(void) { return S->state == DIGINET_S_ONLINE || R.foreign; }
static int c_drained(void) { return !S->inflight && !S->queued; }

static void send_cmd(const struct diginet_cmd *c, const char *what)
{
	unsigned acked = R.acked, lost = R.lost;
	char hex[3 * DIGINET_CMD_MAX_LEN + 1] = "";
	for (int i = 0; i < c->len; i++)
		sprintf(hex + 3 * i, "%02x%s", c->bytes[i], i + 1 < c->len ? " " : "");
	int r = diginet_session_submit(S, c);
	if (r) {
		say("%s: refused (%s)", what, diginet_strerror(r));
		return;
	}
	run_until(c_drained, 2000);
	say("%s: sent %s, %s", what, hex, R.acked > acked ? "ACKed" : R.lost > lost ? "NOT ACKed" : "no answer yet");
}

/* Ask the operator; keeps the session alive while waiting. Returns the answer or "". */
static void ask(const char *question, char *answer, size_t n, unsigned timeout_ms)
{
	answer[0] = '\0';
	say("QUESTION: %s (type a word and Enter)", question);
	uint64_t end = diginet_clock_us() + (uint64_t)timeout_ms * 1000u;
	size_t len = 0;
	while (!stop && diginet_clock_us() < end) {
		struct pollfd p = { .fd = 0, .events = POLLIN };
		if (poll(&p, 1, 0) > 0) {
			char c;
			ssize_t k = read(0, &c, 1);
			if (k <= 0)
				break;          /* EOF: nobody to answer */
			if (c == '\n')
				break;
			if (len + 1 < n)
				answer[len++] = c;
			answer[len] = '\0';
			continue;
		}
		run_for(20);
	}
	say("answer: %s", answer[0] ? answer : "(none)");
}

static int parse_mac(const char *s, uint8_t mac[6])
{
	unsigned v[6];
	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (v[i] > 0xff)
			return -1;
		mac[i] = (uint8_t)v[i];
	}
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f,
		"usage: diginet-probe -i <interface> [options]\n"
		"       diginet-probe --fd <n> --mac <host-mac> [options]\n"
		"       diginet-probe --any [--helper <path>] [options]\n"
		"\n"
		"  -i, --interface <if>    the interface the desk is cabled to (needs cap_net_raw:\n"
		"                          sudo setcap cap_net_raw=ep ./diginet-probe)\n"
		"      --fd <n>            use an open descriptor carrying whole frames instead\n"
		"      --mac <mac>         this host's MAC (with --fd)\n"
		"      --any               every interface at once: the first desk heard on any of them\n"
		"                          (or --desk), its host MAC that interface's; without\n"
		"                          cap_net_raw the socket comes from diginet-packet-helper\n"
		"      --helper <path>     with --any, always take the socket from this helper\n"
		"      --desk <mac>        talk to this desk only\n"
		"      --checksum zero|sum header sum of our frames (default sum)\n"
		"      --keepalive <s>     keepalive interval (default 10)\n"
		"      --listen <s>        how long to log the desk (default 60)\n"
		"      --wait <s>          how long to wait for the desk's announce (default 30)\n"
		"      --answer <s>        how long to wait for each answer (default 60)\n"
		"      --touch-test        command fader 1 to 25%%, report what it does while held\n"
		"  -h, --help\n"
		"\nSee docs/probe.md.\n");
}

int main(int argc, char **argv)
{
	const char *ifname = NULL, *helper = NULL;
	int fd = -1, have_mac = 0;
	struct diginet_session_config cfg;
	diginet_session_config_default(&cfg);
	cfg.auto_wake = 0;
	unsigned listen_s = 60, wait_s = 30, answer_s = 60, keepalive_s = 10;
	static const struct option opts[] = {
		{ "interface", required_argument, 0, 'i' }, { "fd", required_argument, 0, 'F' },
		{ "mac", required_argument, 0, 'M' }, { "desk", required_argument, 0, 'D' },
		{ "checksum", required_argument, 0, 'C' }, { "keepalive", required_argument, 0, 'K' },
		{ "listen", required_argument, 0, 'L' }, { "wait", required_argument, 0, 'W' },
		{ "answer", required_argument, 0, 'A' }, { "touch-test", no_argument, 0, 'T' },
		{ "any", no_argument, 0, 'Y' }, { "helper", required_argument, 0, 'H' },
		{ "help", no_argument, 0, 'h' }, { 0, 0, 0, 0 },
	};
	int o;
	while ((o = getopt_long(argc, argv, "i:h", opts, NULL)) != -1) {
		char *end = NULL;
		switch (o) {
		case 'i': ifname = optarg; break;
		case 'F': fd = (int)strtol(optarg, &end, 10); if (*end || fd < 0) goto bad; break;
		case 'M': if (parse_mac(optarg, cfg.host_mac)) goto bad; have_mac = 1; break;
		case 'D': if (parse_mac(optarg, cfg.desk_mac)) goto bad; cfg.desk_mac_set = 1; break;
		case 'C':
			if (!strcmp(optarg, "zero")) cfg.sum_mode = DIGINET_SUM_ZERO;
			else if (!strcmp(optarg, "sum")) cfg.sum_mode = DIGINET_SUM_BODY;
			else goto bad;
			break;
		case 'K': keepalive_s = (unsigned)strtoul(optarg, &end, 10); if (*end || !keepalive_s) goto bad; break;
		case 'L': listen_s = (unsigned)strtoul(optarg, &end, 10); if (*end) goto bad; break;
		case 'W': wait_s = (unsigned)strtoul(optarg, &end, 10); if (*end || !wait_s) goto bad; break;
		case 'A': answer_s = (unsigned)strtoul(optarg, &end, 10); if (*end) goto bad; break;
		case 'T': R.touch_test = 1; break;
		case 'Y': any_mode = 1; break;
		case 'H': helper = optarg; break;
		case 'h': usage(stdout); return EXIT_OK;
		default: goto bad;
		}
	}
	if (optind != argc || (!!ifname + (fd >= 0) + any_mode) != 1 || (fd >= 0 && !have_mac) ||
	    (helper && !any_mode) || (any_mode && have_mac))
		goto bad;
	cfg.keepalive_ms = keepalive_s * 1000u;
	/* The offline timeout must outlast a stretched keepalive, or R5 cannot be measured. */
	if (cfg.offline_ms < 3 * cfg.keepalive_ms)
		cfg.offline_ms = 3 * cfg.keepalive_ms;

	if (any_mode) {
		fd = helper ? -EPERM : diginet_packet_open_any();
		if (fd == -EPERM || fd == -EACCES) {
			fd = diginet_packet_open_by_helper(helper);
			if (fd < 0) {
				fprintf(stderr, "diginet-probe: no socket from %s: %s\n",
					helper ? helper : "diginet-packet-helper", strerror(-fd));
				return EXIT_USAGE;
			}
			fprintf(stderr, "diginet-probe: the socket came from %s; this process holds no capability for it\n",
				helper ? helper : "diginet-packet-helper");
		} else if (fd < 0) {
			fprintf(stderr, "diginet-probe: cannot open the any-interface socket: %s\n", strerror(-fd));
			return EXIT_USAGE;
		}
	} else if (ifname) {
		fd = diginet_packet_open(ifname, cfg.host_mac);
		if (fd < 0) {
			fprintf(stderr, "diginet-probe: cannot open %s: %s%s\n", ifname, strerror(-fd),
				fd == -EPERM ? " (run: sudo setcap cap_net_raw=ep ./diginet-probe)" : "");
			return EXIT_USAGE;
		}
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	struct diginet_fd_io st;
	if (any_mode) {
		struct diginet_mux_io mio;
		diginet_mux_io_packet(&mio, &st, fd);
		any_cfg = cfg;
		desk_filter = cfg.desk_mac_set ? any_cfg.desk_mac : NULL;
		/* S0 stands while no desk is attached: it knows no desk and sends nothing */
		struct diginet_io none = { .ctx = NULL, .send = send_nowhere, .recv = NULL, .now_us = NULL };
		if (diginet_session_init(&S0, &cfg, &none, on_notice, NULL) != DIGINET_OK ||
		    diginet_mux_init(&MUX, NULL, &mio, on_mux_notice, NULL) != DIGINET_OK) {
			fprintf(stderr, "diginet-probe: bad session settings\n");
			return EXIT_USAGE;
		}
		S0.desk_known = 0;
	} else {
		struct diginet_io io;
		diginet_io_fd(&io, &st, fd);
		if (diginet_session_init(S, &cfg, &io, on_notice, NULL) != DIGINET_OK) {
			fprintf(stderr, "diginet-probe: bad session settings\n");
			return EXIT_USAGE;
		}
	}
	t0 = diginet_clock_us();
	P = diginet_personality_of(DIGINET_DESK_CONTROL24);
	const uint8_t *hm = cfg.host_mac;
	if (any_mode)
		say("diginet-probe %s: every interface, the host MAC the desk's interface's, checksum %s, keepalive %u s",
		    DIGINET_VERSION_STRING, cfg.sum_mode == DIGINET_SUM_ZERO ? "zero" : "sum", keepalive_s);
	else
		say("diginet-probe %s: host %02x:%02x:%02x:%02x:%02x:%02x, checksum %s, keepalive %u s",
		    DIGINET_VERSION_STRING, hm[0], hm[1], hm[2], hm[3], hm[4], hm[5],
		    cfg.sum_mode == DIGINET_SUM_ZERO ? "zero" : "sum", keepalive_s);

	/* 1. the announce */
	say("step 1: waiting up to %u s for the desk's announce", wait_s);
	run_until(c_desk, wait_s * 1000u);
	if (!R.desk_seen) {
		say("RESULT: no desk announced on the wire");
		return EXIT_NO_DESK;
	}
	if (R.foreign) {
		say("RESULT: the desk is in another host's session; nothing was sent");
		return EXIT_FOREIGN;
	}

	/* 2-3. wake */
	say("step 2: sending e2");
	if (diginet_session_wake(S, diginet_clock_us()) != DIGINET_OK) {
		say("RESULT: e2 refused");
		return R.foreign ? EXIT_FOREIGN : EXIT_NO_DESK;
	}
	say("step 3: waiting for the desk to take the session (a0, and an e1 where it announces one)");
	if (!run_until(c_online, 5000) || R.foreign) {
		say("RESULT: the desk did not come online (a0 %s, e1 naming us %s)",
		    R.acked_wake ? "seen" : "missing", R.e1_offset >= 0 ? "seen" : "missing");
		diginet_session_close(S, diginet_clock_us());
		return R.foreign ? EXIT_FOREIGN : EXIT_NO_DESK;
	}
	say("online: %s, host MAC at e1 body offset %d", online_how(), R.e1_offset);
	say("step 4: keepalive every %u s, independent of ACKs", keepalive_s);

	struct diginet_cmd c;
	int exit_code = EXIT_OK;
	char ans00[64], ans20[64];

	/* 5. fader 1 */
	diginet_fader_encode(P, 0, R.touch_test ? 256 : 512, &c);
	unsigned lost0 = R.lost;
	send_cmd(&c, R.touch_test ? "step 5: fader 1 to 25 %" : "step 5: fader 1 to mid-travel");
	int fader_acked = R.lost == lost0;

	/* 6. MUTE LED */
	diginet_button_encode(DIGINET_BTN_MUTE, 0, 1, &c);
	send_cmd(&c, "step 6: strip 1 MUTE on");
	run_for(1000);
	diginet_button_encode(DIGINET_BTN_MUTE, 0, 0, &c);
	send_cmd(&c, "step 6: strip 1 MUTE off");

	/* 7. scribble at 0x00, then 0x20 */
	uint8_t text[DIGINET_SCRIBBLE_MAX];
	diginet_scribble_text("OMX1", text, P->scribble_chars);
	diginet_scribble_encode(P, 0x00, text, &c);
	send_cmd(&c, "step 7: OMX1 at scribble 0x00");
	ask("What does strip 1's scribble show now (where, which row)?", ans00, sizeof ans00, answer_s * 1000u);
	diginet_scribble_encode(P, 0x20, text, &c);
	send_cmd(&c, "step 7: OMX1 at scribble 0x20");
	ask("And now, after the write at 0x20?", ans20, sizeof ans20, answer_s * 1000u);

	/* 8. listen */
	if (R.touch_test)
		say("step 8 (touch test): grab fader 1, move it, hold it, let go; no echo is sent");
	say("step 8: logging the desk for %u s: press keys, touch and move fader 1, turn V-Pot 1 and the jog wheel",
	    listen_s);
	run_for(listen_s * 1000u);

	/* 9. e3 */
	say("step 9: sending e3");
	diginet_session_close(S, diginet_clock_us());

	say("SUMMARY desk: \"%s\" version \"%s\" (R1)", R.name, R.version);
	if (any_mode) {
		char list[16 * (IF_NAMESIZE + 1)] = "", name[IF_NAMESIZE];
		for (int i = 0; i < nheard_if; i++) {
			strcat(list, i ? " " : "");
			strcat(list, if_name(heard_if[i], name));
		}
		say("SUMMARY any interface: desks appeared on %s; %llu frames set aside from another interface",
		    nheard_if ? list : "(none)", (unsigned long long)MUX.stats.rx_other_if);
	}
	say("SUMMARY online: %s, host MAC at e1 body offset %d (A6)", online_how(), R.e1_offset);
	say("SUMMARY checksum %s: fader frame %s (R3)", cfg.sum_mode == DIGINET_SUM_ZERO ? "zero" : "sum",
	    fader_acked ? "ACKed" : "NOT ACKed");
	say("SUMMARY scribble 0x00: %s; 0x20: %s (R6)", ans00[0] ? ans00 : "(not answered)",
	    ans20[0] ? ans20 : "(not answered)");
	say("SUMMARY desk frames %u, commands %u (%u under running status), keys %u, touches %u, "
	    "fader moves %u, V-Pot turns %u, jog turns %u, other %u (R9, R10)",
	    R.frames, R.cmds, R.running, R.keys, R.touches, R.fader_moves, R.vpot_turns, R.jog_turns, R.other);
	say("SUMMARY fader 1 range %d..%d, V-Pot 1 net %+d, jog net %+d", R.fader1_min, R.fader1_max,
	    R.vpot1_sum, R.jog_sum);
	say("SUMMARY keepalive %u s: session lost %u time(s) while online%s%s%s (R5)", keepalive_s,
	    R.lost_online, R.lost_online ? " (last: " : "",
	    R.lost_online ? diginet_reason_name(R.lost_why) : "", R.lost_online ? ")" : "");
	say("SUMMARY our frames ACKed %u, lost %u, retransmits %llu, desk retries %llu (R8)", R.acked, R.lost,
	    (unsigned long long)S->stats.tx_retransmits, (unsigned long long)S->stats.rx_desk_retries);
	if (R.touch_test) {
		if (!R.release_seen)
			say("SUMMARY touch test: no touch and release of fader 1 was seen (R4)");
		else
			say("SUMMARY touch test: set-point 256; while held %u moves, %d..%d; released at %d; "
			    "after release %u moves, last %d: %s (R4)",
			    R.held_moves, R.held_min, R.held_max, R.at_release, R.after_moves, R.after_release_last,
			    R.after_moves == 0 ? "the desk reported no motion after release" :
			    (R.after_release_last >= 248 && R.after_release_last <= 264) ?
			    "the motor went back to the set-point" : "the fader stayed away from the set-point");
	}
	if (!fader_acked || R.lost)
		exit_code = EXIT_NO_ACK;
	return exit_code;
bad:
	usage(stderr);
	return EXIT_USAGE;
}
