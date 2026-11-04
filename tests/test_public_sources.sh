#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The public-sources gate, sabotaged: a scratch repository that is clean must pass, and so must
# one that names the product or its public site; one private name or pointer in a tracked file,
# or in a commit message, must fail it.
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

# The product name and the public site are not pointers: packaging descriptions name the site,
# because the guides are published there.
p_name="open""mixer"; p_site="$p_name.org"

mkrepo site_file
printf 'Its documentation is on %s.\nhttps://www.%s/rpm/%s-release.noarch.rpm\n' "$p_site" "$p_site" "$p_name" > "$tmp/site_file/a.md"
commit site_file "Docs (#1)"
expect site_file 0

mkrepo site_msg; echo "plain" > "$tmp/site_msg/a.md"; commit site_msg "packaging: the descriptions name $p_site"
expect site_msg 0

mkrepo product
printf 'The %s console.\norg.%s.x urn:%s:x @%s/x\n' "OpenMixer" "$p_name" "$p_name" "$p_name" > "$tmp/product/a.md"
commit product "Docs for the OpenMixer console (#1)"
expect product 0

# One line in a tracked file and in a commit message, each of which must fail the gate.
n=0
red() { # text
	n=$((n + 1))
	mkrepo "f$n"; printf '%s\n' "$1" > "$tmp/f$n/a.md"; commit "f$n" "Docs (#1)"
	expect "f$n" 1
	mkrepo "m$n"; echo "plain" > "$tmp/m$n/a.md"; commit "m$n" "Docs: $1"
	expect "m$n" 1
}
p_org2="Free""Mixer"; p_date="20""26-10-09"
# Pointers into a private repository: the repository, its issues, its branches and its paths.
red "$p_org2/$p_name"
red "see $p_org2/$p_name.git for it"
red "see $p_org2/$p_name#12"
red "$p_name""-ops"
red "see $p_name#1580"
red "see $p_name #1580"
red "see omx-dsp""-dev#32"
red "drawn on integ""ration/lean-engine"
red "pack""ages/web-ui"
red "the strip in Foo.v""ue"
red "$p_name's ""spec on this"
red "the notes in docs/""design/specs"
red "har""ness/dsp-check.sh"
red "the layout in $p_date-plugin-from-contract"".md"
red "as laid out in spec"" $p_date"
# Names kept from before: a private organisation, local paths, tool names and host words.
red "$p_org"
red "~/.lo""cal/share/omx/x"
red "/var/""home/x"
red "/ho""me/x/y"
red "claude"".ai/x"
red "anth""ropic"
red "co-auth""ored-by: x"
red "$p_host"
red "h""2"
red "m""si"

exit $fail
