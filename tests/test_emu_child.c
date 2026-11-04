// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The child harness (testsupport/emu_child.h) that libsurface's and the console's end-to-end
 * tests run on, proved here on diginet-probe: the private network comes up, the probe on hA
 * finds the desk on dA and takes it through its steps, what it sent is counted from the desk's
 * log, its words are waited on, it is reaped with its exit status. A shell child proves the
 * stdin pipe and the kill past the deadline.
 *
 *   test_emu_child <diginet-probe>
 */
#define _GNU_SOURCE
#include <diginet/testsupport/emu_child.h>

static int fails;
#define CHK(cond) do { \
	if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static const uint8_t DESK[6] = { 0x00, 0xa0, 0x7e, 0x24, 0x00, 0x0a };

static struct emu_child C;

static int is_fader1(const struct diginet_event *ev, const void *arg)
{
	(void)arg;
	return ev->kind == DIGINET_EV_FADER && ev->strip == 0;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: test_emu_child <diginet-probe>\n");
		return 2;
	}
	int rc = emu_child_net(&C, "test_emu_child", "hA", "dA", DESK, "CNTRL|24", "1.08");
	if (rc == 77)
		return 77;
	CHK(rc == 0);
	if (rc != 0)
		return 1;
	CHK(C.desk_fd >= 0 && C.pid == -1 && C.in_fd == -1);

	/* the probe on hA, with the namespace's capabilities: it opens its own packet socket */
	char *const probe[] = { argv[1], "-i", "hA", "--listen", "1", "--wait", "5", "--answer", "0",
				"--keepalive", "1", NULL };
	CHK(emu_child_spawn(&C, probe, 0) == 0);
	CHK(C.pid > 0 && C.out_fd >= 0 && C.in_fd == -1);
	CHK(emu_child_wait_for(&C, "desk: 00:a0:7e:24:00:0a name \"CNTRL|24\" version \"1.08\"", 5000));
	CHK(emu_child_wait_for(&C, "session waking -> online (desk took the session)", 5000));
	CHK(emu_child_wait_for(&C, "fader 1 to mid-travel", 10000));
	emu_child_pump_ms(&C, 300);
	const struct diginet_personality *p = diginet_personality_of(DIGINET_DESK_CONTROL24);
	CHK(emu_child_got(&C, p, is_fader1, NULL) >= 1);
	unsigned mid[2] = { 0, 512 };
	CHK(emu_child_got(&C, p, emu_ev_fader, mid) >= 1);
	CHK(emu_child_got(&C, p, emu_ev_text, "no such scribble") == 0);
	int st = emu_child_reap(&C, 30000);
	CHK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHK(C.pid == -1 && C.out_fd == -1);
	CHK(strstr(C.out, "SUMMARY desk: \"CNTRL|24\"") != NULL);
	CHK(C.desk.wakes >= 1 && C.desk.disconnects == 1);
	if (fails)
		fprintf(stderr, "--- diginet-probe said:\n%s---\n", C.out);

	/* a shell child on the stdin pipe: told a word, it answers; told nothing more, it is
	 * killed at the deadline and reaped with a signal status */
	size_t said = C.outlen;
	char *const sh[] = { "/bin/sh", "-c", "read x; echo \"told $x\"; read y; exit 3", NULL };
	CHK(emu_child_spawn(&C, sh, 1) == 0);
	CHK(C.in_fd >= 0);
	CHK(emu_child_tell(&C, "ping\n") == 0);
	CHK(emu_child_wait_for(&C, "told ping", 3000));
	CHK(strstr(C.out + said, "told ping") != NULL);
	CHK(!emu_child_wait_for(&C, "never said", 100));
	st = emu_child_reap(&C, 200);
	CHK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
	CHK(emu_child_tell(&C, "late\n") == -1);

	/* told to go, it goes, and its status is its own */
	char *const sh2[] = { "/bin/sh", "-c", "read x; exit 3", NULL };
	CHK(emu_child_spawn(&C, sh2, 1) == 0);
	CHK(emu_child_tell(&C, "go\n") == 0);
	st = emu_child_reap(&C, 3000);
	CHK(WIFEXITED(st) && WEXITSTATUS(st) == 3);

	if (fails) {
		fprintf(stderr, "test_emu_child: %d failure(s)\n", fails);
		return 1;
	}
	printf("test_emu_child: ok (diginet-probe and a shell under the child harness, on a veth pair)\n");
	return 0;
}
