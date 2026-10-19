/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
 *
 * The test helpers every suite shares: a CHK macro that counts failures, and the reader for
 * tests/golden/frames.txt (name, space, hex of one whole Ethernet frame).
 */
#ifndef DIGINET_TEST_GOLDEN_H
#define DIGINET_TEST_GOLDEN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int fails;
#define CHK(cond) do { \
	if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

#define GOLDEN_MAX 64

struct golden {
	char name[64];
	uint8_t bytes[1514];
	size_t len;
};

static struct golden golden_set[GOLDEN_MAX];
static int golden_count;

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Loads every frame of `path`; exits 2 (NOT A RESULT) when the file cannot be read. */
static void golden_load(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "NOT A RESULT: cannot open %s\n", path);
		exit(2);
	}
	char line[4096];
	while (fgets(line, sizeof line, fp)) {
		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (golden_count == GOLDEN_MAX) {
			fprintf(stderr, "NOT A RESULT: more than %d golden frames\n", GOLDEN_MAX);
			exit(2);
		}
		struct golden *g = &golden_set[golden_count];
		char *sp = strchr(line, ' ');
		if (!sp || (size_t)(sp - line) >= sizeof g->name) {
			fprintf(stderr, "NOT A RESULT: bad golden line: %s", line);
			exit(2);
		}
		memcpy(g->name, line, (size_t)(sp - line));
		g->name[sp - line] = '\0';
		const char *h = sp + 1;
		g->len = 0;
		while (hexval(h[0]) >= 0 && hexval(h[1]) >= 0 && g->len < sizeof g->bytes) {
			g->bytes[g->len++] = (uint8_t)(hexval(h[0]) << 4 | hexval(h[1]));
			h += 2;
		}
		if (*h != '\n' && *h != '\0') {
			fprintf(stderr, "NOT A RESULT: bad hex in golden frame %s\n", g->name);
			exit(2);
		}
		golden_count++;
	}
	fclose(fp);
}

static const struct golden *golden(const char *name)
{
	for (int i = 0; i < golden_count; i++)
		if (!strcmp(golden_set[i].name, name))
			return &golden_set[i];
	fprintf(stderr, "NOT A RESULT: golden frame %s missing\n", name);
	exit(2);
}

#endif
