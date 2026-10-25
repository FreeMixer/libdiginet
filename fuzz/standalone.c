// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* A driver of a harness without libFuzzer (make fuzz-records, make fuzz-static): each file
 * named runs through LLVMFuzzerTestOneInput once, in an allocation of exactly its size, as
 * libFuzzer's -runs=0 runs a corpus and as the OSS Verify driver runs an input with no config
 * bytes. A harness and the library then link as a plain native program, or a fully static
 * one, with no library beyond libc. A property that fails aborts (exit 134), as it does under
 * libFuzzer; the driver itself exits 0 when every call returned 0 or -1, 78 for any other
 * return, and 2 when a file cannot be read. Usage: fuzz_<harness> <file>... */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t *slurp(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b = NULL;
	size_t cap = 0, got;

	*n = 0;
	if (!f)
		return NULL;
	do {
		if (*n + 65536 > cap) {
			uint8_t *more = realloc(b, cap = (*n + 65536) * 2);
			if (!more) {
				free(b);
				fclose(f);
				return NULL;
			}
			b = more;
		}
		got = fread(b + *n, 1, 65536, f);
		*n += got;
	} while (got == 65536);
	if (ferror(f)) {
		free(b);
		fclose(f);
		return NULL;
	}
	fclose(f);
	/* an exact-size copy, as libFuzzer hands its input */
	uint8_t *exact = malloc(*n ? *n : 1);
	if (exact && *n)
		memcpy(exact, b, *n);
	free(b);
	return exact;
}

int main(int argc, char **argv)
{
	int other = 0;

	for (int i = 1; i < argc; i++) {
		size_t n;
		uint8_t *b = slurp(argv[i], &n);
		if (!b) {
			perror(argv[i]);
			return 2;
		}
		int r = LLVMFuzzerTestOneInput(b, n);
		free(b);
		if (r != 0 && r != -1)
			other = 1;
	}
	printf("%d inputs\n", argc - 1);
	return other ? 78 : 0;
}
