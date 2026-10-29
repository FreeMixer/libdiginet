// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* diginet-probe against the desk emulator: the probe runs as its own process with the wire
 * on descriptor 3 (one end of a SOCK_SEQPACKET socketpair), the emulator holds the other end,
 * the operator's answers come on stdin. Each run checks the probe's output and what the
 * desk received.
 *
 *   tests/test_probe <path to diginet-probe>
 *
 *  A. the M1 run: announce, e2, a0 + e1, fader 1 to mid-travel, MUTE on and off, OMX1 at 0x00
 *     and 0x20 with the answers recorded, every desk command decoded, keepalives, e3;
 *  B. --checksum zero against a desk that checks the sum: the fader is not ACKed, exit 5;
 *  C. a desk in another host's session: nothing sent, exit 3;
 *  D. --touch-test: 25 %, no echo while the cap is held, the motion after release reported;
 *  E. --keepalive stretched past the desk's timeout: the fall back to e0 is reported;
 *  F. no desk: exit 4; bad usage: exit 2, --any with another wire or --mac, --helper without
 *     --any, a helper that is not there.
 */
#include "golden.h"
#include "emu_pump.h"

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

static const uint8_t DESK_MAC[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x01 };
static const uint8_t OTHER_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x99 };
#define HOST "02:00:00:00:00:01"

static const char *probe;
static struct desk_emu E;
static char out[1 << 16];
static size_t outlen;

/* The desk's side of a scenario, called on every loop with the time since the start. */
typedef void (*hook_fn)(uint64_t t_us);

static int run_probe(const char *const *args, const char *answers, hook_fn hook)
{
	int sv[2], in[2], po[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0 || pipe(in) < 0 || pipe(po) < 0) {
		perror("pipe");
		exit(2);
	}
	pid_t pid = fork();
	if (pid == 0) {
		dup2(in[0], 0);
		dup2(po[1], 1);
		dup2(po[1], 2);
		dup2(sv[1], 3);
		for (int fd = 4; fd < 64; fd++)
			close(fd);
		const char *argv[32] = { probe };
		int n = 1;
		for (; args[n - 1] && n < 31; n++)
			argv[n] = args[n - 1];
		argv[n] = NULL;
		execv(probe, (char *const *)argv);
		_exit(127);
	}
	close(in[0]);
	close(po[1]);
	close(sv[1]);
	if (answers && write(in[1], answers, strlen(answers)) < 0)
		perror("write");
	close(in[1]);   /* EOF after the answers */
	fcntl(po[0], F_SETFL, O_NONBLOCK);
	outlen = 0;
	uint64_t t0 = diginet_clock_us(), next_ann = t0;
	int status = -1;
	for (;;) {
		ssize_t k;
		while ((k = read(po[0], out + outlen, sizeof out - 1 - outlen)) > 0)
			outlen += (size_t)k;
		out[outlen] = '\0';
		emu_pump_fd(&E, sv[0], &next_ann, 500000);
		if (hook)
			hook(diginet_clock_us() - t0);
		emu_pump_fd(&E, sv[0], &next_ann, 500000);
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid)
			break;
		if (diginet_clock_us() - t0 > 40000000) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			fprintf(stderr, "probe did not finish in 40 s\n");
			status = -1;
			break;
		}
		usleep(500);
	}
	ssize_t k;
	while ((k = read(po[0], out + outlen, sizeof out - 1 - outlen)) > 0)
		outlen += (size_t)k;
	out[outlen] = '\0';
	/* What the probe sent last, after its output ended. */
	uint8_t b[DIGINET_MAX_FRAME_LEN];
	while ((k = recv(sv[0], b, sizeof b, MSG_DONTWAIT)) > 0)
		emu_from_host(&E, b, (size_t)k, diginet_clock_us());
	close(po[0]);
	close(sv[0]);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int has(const char *s)
{
	if (strstr(out, s))
		return 1;
	fprintf(stderr, "probe output lacks: %s\n", s);
	return 0;
}

static void emu_fresh(void)
{
	emu_init(&E, DESK_MAC, "CNTRL|24", "1.37");
}

static const uint8_t SCRIB20[] = { 0xf0, 0x13, 0x01, 0x40, 0x20, 0x00, 'O', 'M', 'X', '1', 0xf7 };

/* The operator during step 8: keys, touch and fader 1, V-Pot 1, jog, a transport key. */
static int fired;
static uint64_t seen_at;
static void operator_plays(uint64_t t)
{
	if (fired || !emu_count_cmd(&E, SCRIB20, sizeof SCRIB20))
		return;
	if (!seen_at) {
		seen_at = t;
		return;
	}
	if (t - seen_at < 300000)
		return;
	fired = 1;
	static const uint8_t keys[] = { 0x90, 0x08, 0x40, 0x08, 0x00 };          /* MUTE 1 press, release */
	static const uint8_t touch[] = { 0x90, 0x09, 0x40, 0xb0, 0x00, 0x25, 0x20, 0x40, 0x90, 0x09, 0x00 };
	static const uint8_t turns[] = { 0xb0, 0x40, 0x41, 0x40, 0x41, 0x40, 0x41, 0x5c, 0x3e };
	static const uint8_t transport[] = { 0x90, 0x0c, 0x5c };
	emu_send_data(&E, keys, sizeof keys, 2, 0, 0);
	emu_send_data(&E, touch, sizeof touch, 3, 0, 0);
	emu_send_data(&E, turns, sizeof turns, 4, 0, 0);
	emu_send_data(&E, transport, sizeof transport, 1, 0, 0);
}

static void test_m1(void)
{
	const char *args[] = { "--fd", "3", "--mac", HOST, "--listen", "2", "--keepalive", "1", "--wait", "5", NULL };
	emu_fresh();
	fired = 0;
	seen_at = 0;
	int rc = run_probe(args, "top\nbottom\n", operator_plays);
	CHK(rc == 0);
	CHK(has("desk: 00:a0:7e:24:00:01 name \"CNTRL|24\" version \"1.37\" (Control|24)"));
	CHK(has("online: a0 alone, no e1, host MAC at e1 body offset -1"));
	CHK(has("step 5: fader 1 to mid-travel: sent b0 00 40 20 00, ACKed"));
	CHK(has("step 6: strip 1 MUTE on: sent 90 08 40, ACKed"));
	CHK(has("step 6: strip 1 MUTE off: sent 90 08 00, ACKed"));
	CHK(has("step 7: OMX1 at scribble 0x00: sent f0 13 01 40 00 00 4f 4d 58 31 f7, ACKed"));
	CHK(has("step 7: OMX1 at scribble 0x20: sent f0 13 01 40 20 00 4f 4d 58 31 f7, ACKed"));
	CHK(has("answer: top") && has("answer: bottom"));
	CHK(has("key: strip 1 MUTE pressed") && has("key: strip 1 MUTE released"));
	CHK(has("fader 1 touched") && has("fader 1 at 300") && has("fader 1 released"));
	CHK(has("V-Pot 1 +1") && has("jog -2"));
	CHK(has("key: zone 0x1C button 0x0C pressed"));
	CHK(has("step 9: sending e3"));
	CHK(has("SUMMARY desk: \"CNTRL|24\" version \"1.37\" (R1)"));
	CHK(has("SUMMARY checksum sum: fader frame ACKed (R3)"));
	CHK(has("SUMMARY scribble 0x00: top; 0x20: bottom (R6)"));
	CHK(has("SUMMARY desk frames 4, commands 10 (4 under running status), keys 3, touches 2, fader moves 1, V-Pot turns 3, jog turns 1, other 0"));
	CHK(has("SUMMARY fader 1 range 300..300, V-Pot 1 net +3, jog net -2"));
	CHK(has("SUMMARY keepalive 1 s: session lost 0 time(s) while online (R5)"));
	CHK(has("lost 0"));

	static const uint8_t fad[] = { 0xb0, 0x00, 0x40, 0x20, 0x00 };
	static const uint8_t on[] = { 0x90, 0x08, 0x40 }, off[] = { 0x90, 0x08, 0x00 };
	static const uint8_t s00[] = { 0xf0, 0x13, 0x01, 0x40, 0x00, 0x00, 'O', 'M', 'X', '1', 0xf7 };
	CHK(E.wakes == 1 && E.disconnects == 1 && !E.in_session);
	CHK(emu_count_cmd(&E, fad, 5) == 1 && emu_count_cmd(&E, on, 3) == 1 && emu_count_cmd(&E, off, 3) == 1);
	CHK(emu_count_cmd(&E, s00, sizeof s00) == 1 && emu_count_cmd(&E, SCRIB20, sizeof SCRIB20) == 1);
	CHK(E.keepalives >= 2);
	CHK(E.acks_from_host >= 4);
	if (fails)
		fprintf(stderr, "---- probe output ----\n%s----\n", out);
}

static void test_checksum_zero(void)
{
	const char *args[] = { "--fd", "3", "--mac", HOST, "--listen", "0", "--checksum", "zero", "--answer", "0", NULL };
	emu_fresh();
	E.require_sum = 1;
	int f0 = fails;
	int rc = run_probe(args, "", NULL);
	CHK(rc == 5);
	CHK(has("checksum zero"));
	CHK(has("SUMMARY checksum zero: fader frame NOT ACKed (R3)"));
	CHK(has("no ACK for our frame"));
	CHK(E.log[1].cmd == DIGINET_CMD_DATA && E.log[1].sum == 0);
	if (fails > f0)
		fprintf(stderr, "---- probe output ----\n%s----\n", out);
}

static void test_foreign(void)
{
	const char *args[] = { "--fd", "3", "--mac", HOST, "--wait", "3", NULL };
	emu_fresh();
	E.foreign = 1;
	memcpy(E.session_mac, OTHER_MAC, 6);
	int rc = run_probe(args, "", NULL);
	CHK(rc == 3);
	CHK(has("RESULT: the desk is in another host's session; nothing was sent"));
	CHK(E.wakes == 0 && E.nlog == 0);
}

/* The operator during the touch test: grab, move to 280 and 320, let go; the motor drives
 * back through 300 and 270 to the 256 set-point. */
static void operator_touches(uint64_t t)
{
	static const uint8_t SCRIB20B[] = { 0xf0, 0x13, 0x01, 0x40, 0x20, 0x00, 'O', 'M', 'X', '1', 0xf7 };
	if (fired || !emu_count_cmd(&E, SCRIB20B, sizeof SCRIB20B))
		return;
	if (!seen_at) {
		seen_at = t;
		return;
	}
	if (t - seen_at < 300000)
		return;
	fired = 1;
	static const uint8_t held[] = { 0x90, 0x09, 0x40, 0xb0, 0x00, 0x23, 0x20, 0x00, 0x00, 0x28, 0x20, 0x00,
					0x90, 0x09, 0x00 };
	static const uint8_t back[] = { 0xb0, 0x00, 0x25, 0x20, 0x40, 0x00, 0x21, 0x20, 0x60, 0x00, 0x20, 0x20, 0x00 };
	emu_send_data(&E, held, sizeof held, 4, 0, 0);
	emu_send_data(&E, back, sizeof back, 3, 0, 0);
}

static void test_touch(void)
{
	const char *args[] = { "--fd", "3", "--mac", HOST, "--listen", "2", "--touch-test", "--answer", "0", NULL };
	emu_fresh();
	fired = 0;
	seen_at = 0;
	int f0 = fails;
	int rc = run_probe(args, "", operator_touches);
	CHK(rc == 0);
	CHK(has("step 5: fader 1 to 25 %: sent b0 00 20 20 00, ACKed"));
	CHK(has("SUMMARY touch test: set-point 256; while held 2 moves, 280..320; released at 320; "
		"after release 3 moves, last 256: the motor went back to the set-point (R4)"));
	/* No echo: the 25 % command is the only fader command the desk ever got. */
	unsigned faders = 0;
	for (unsigned i = 0; i < E.nlog; i++)
		for (size_t k = 0; k + 1 < E.log[i].body_len; k++)
			if (E.log[i].cmd == DIGINET_CMD_DATA && E.log[i].body[k] == 0xb0)
				faders++;
	static const uint8_t q[] = { 0xb0, 0x00, 0x20, 0x20, 0x00 };
	CHK(faders == 1 && emu_count_cmd(&E, q, 5) == 1);
	if (fails > f0)
		fprintf(stderr, "---- probe output ----\n%s----\n", out);
}

static void test_keepalive_stretch(void)
{
	const char *args[] = { "--fd", "3", "--mac", HOST, "--listen", "4", "--keepalive", "3", "--answer", "0", NULL };
	emu_fresh();
	E.host_timeout_us = 1500000;   /* this desk gives up 1.5 s after the last host frame */
	int f0 = fails;
	run_probe(args, "", NULL);
	CHK(has("session lost while online (desk stopped ACKing)"));
	CHK(has("SUMMARY keepalive 3 s: session lost 1 time(s) while online (last: desk stopped ACKing) (R5)"));
	if (fails > f0)
		fprintf(stderr, "---- probe output ----\n%s----\n", out);
}

static void test_refusals(void)
{
	const char *nodesk[] = { "--fd", "3", "--mac", HOST, "--wait", "1", NULL };
	emu_fresh();
	E.mute = 1;
	CHK(run_probe(nodesk, "", NULL) == 4 && has("RESULT: no desk announced on the wire"));
	const char *none[] = { NULL };
	CHK(run_probe(none, "", NULL) == 2);
	const char *both[] = { "-i", "lo", "--fd", "3", "--mac", HOST, NULL };
	CHK(run_probe(both, "", NULL) == 2);
	const char *nomac[] = { "--fd", "3", NULL };
	CHK(run_probe(nomac, "", NULL) == 2);
	const char *badsum[] = { "--fd", "3", "--mac", HOST, "--checksum", "crc", NULL };
	CHK(run_probe(badsum, "", NULL) == 2);
	const char *anyif[] = { "--any", "-i", "lo", NULL };
	CHK(run_probe(anyif, "", NULL) == 2);
	const char *anyfd[] = { "--any", "--fd", "3", "--mac", HOST, NULL };
	CHK(run_probe(anyfd, "", NULL) == 2);
	const char *anymac[] = { "--any", "--mac", HOST, NULL };
	CHK(run_probe(anymac, "", NULL) == 2);
	const char *helperonly[] = { "--fd", "3", "--mac", HOST, "--wait", "1", "--helper", "/bin/true", NULL };
	CHK(run_probe(helperonly, "", NULL) == 2);
	/* a helper that passes no socket: the probe says so and stops */
	const char *nohelper[] = { "--any", "--helper", "/nonexistent/diginet-packet-helper", NULL };
	CHK(run_probe(nohelper, "", NULL) == 2 && has("no socket from /nonexistent/diginet-packet-helper"));
	const char *help[] = { "--help", NULL };
	CHK(run_probe(help, "", NULL) == 0 && has("sudo setcap cap_net_raw=ep") && has("--any"));
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: test_probe <diginet-probe>\n");
		return 2;
	}
	probe = argv[1];
	signal(SIGPIPE, SIG_IGN);
	test_m1();
	test_checksum_zero();
	test_foreign();
	test_touch();
	test_keepalive_stretch();
	test_refusals();
	if (fails) {
		fprintf(stderr, "test_probe: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_probe: ok\n");
	return 0;
}
