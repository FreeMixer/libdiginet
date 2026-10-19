#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The public-sources gate, sabotaged: a scratch repository that is clean must pass, and one
# private name in a tracked file, or in a commit message, must fail it.
set -u
command -v git >/dev/null 2>&1 || { echo "no git: nothing tested"; exit 77; }
check=$(cd "$(dirname "$0")" && pwd)/public-sources-check.sh
tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
fail=0
# The forbidden names are assembled here so that this file passes the gate it tests.
p_repo="open""mixer-ops"; p_host="r""1"; p_org="zero""signage"

mkrepo() {
	git init -q "$tmp/$1" &&
	git -C "$tmp/$1" config user.name t && git -C "$tmp/$1" config user.email t@example.org &&
	git -C "$tmp/$1" config commit.gpgsign false
}
commit() { git -C "$tmp/$1" add -A && git -C "$tmp/$1" commit -q -m "$2"; }
expect() { # name want-rc
	"$check" "$tmp/$1" >/dev/null 2>&1; rc=$?
	if [ "$rc" -ne "$2" ]; then echo "FAIL: $1 gave $rc, want $2"; fail=1; else echo "ok: $1 -> $rc"; fi
}

mkrepo clean; echo "R1 and R14 are open questions" > "$tmp/clean/a.md"; commit clean "Docs (#1)"
expect clean 0

mkrepo file; echo "see $p_repo for the trap" > "$tmp/file/a.md"; commit file "Docs (#1)"
expect file 1

mkrepo host; echo "built on $p_host overnight" > "$tmp/host/a.md"; commit host "Docs (#1)"
expect host 1

mkrepo msg; echo "plain" > "$tmp/msg/a.md"; commit msg "Fix the parser ($p_org#3)"
expect msg 1

mkdir "$tmp/notgit"
expect notgit 77

exit $fail
