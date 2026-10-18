#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# This repository is public and cites public sources only. Refuse any tracked file or
# commit message that names a private repository, a private host or a local path.
#
#   tests/public-sources-check.sh [repo-dir]
#
# Exit 0 clean, 1 with every offending line printed, 77 when repo-dir is not a git work
# tree (a release tarball: nothing to check). tests/test_public_sources.sh proves it fails.
set -u
dir=${1:-.}
git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
	echo "public-sources-check: $dir is not a git work tree, nothing checked"; exit 77; }

# Matched without regard to case.
names='openmixer|zerosignage|\.local/share/omx|/var/home/|/home/[a-z]+/|claude\.ai|anthropic|co-authored-by'
# Host names, matched as lower-case whole words (R1..R14 in docs/protocol.md stay legal).
hosts='(^|[^A-Za-z0-9_-])(r1|h2|msi)([^A-Za-z0-9_-]|$)'

self='tests/public-sources-check.sh'
bad=0

files=$(git -C "$dir" ls-files | grep -v -x -e "$self")
if [ -n "$files" ]; then
	hits=$(cd "$dir" && printf '%s\n' "$files" | while IFS= read -r f; do
		[ -f "$f" ] || continue
		grep -n -I -i -E -H -e "$names" -- "$f"
		grep -n -I -E -H -e "$hosts" -- "$f"
	done)
	if [ -n "$hits" ]; then
		echo "public-sources-check: private names in tracked files:" >&2
		printf '%s\n' "$hits" >&2
		bad=1
	fi
fi

if git -C "$dir" rev-parse --verify -q HEAD >/dev/null; then
	msgs=$(git -C "$dir" log --format='%h %s%n%b' HEAD)
	hits=$( { printf '%s\n' "$msgs" | grep -i -E -e "$names"; printf '%s\n' "$msgs" | grep -E -e "$hosts"; } )
	if [ -n "$hits" ]; then
		echo "public-sources-check: private names in commit messages:" >&2
		printf '%s\n' "$hits" >&2
		bad=1
	fi
fi

[ $bad -eq 0 ] && echo "public-sources-check: clean"
exit $bad
