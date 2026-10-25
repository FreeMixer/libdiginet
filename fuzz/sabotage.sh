#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# `make fuzz-sabotage`: A PROPERTY NO MUTANT CAN BREAK CHECKS NOTHING. fuzz/sabotage/
# <harness>-<property>.patch is a bug in the code the harness drives, at least one for each
# property the harness checks, as `git diff` writes it; above its `diff --git` line it names
# the check it breaks and the seed that shows it, as OSS Verify reads a breakage patch
# (docs/project-yaml.md, "mutants", there):
#
#   Breaks the check of fuzz/fuzz_<harness>.c:<abort line> (<what the bug is>).
#   Caught by the seed input "<seed>" of fuzz_<harness>.
#
# This applies each, rebuilds the sanitizer harness, and runs it over every seed of its
# corpus, one at a time; no fuzzing, so the corpus alone must catch it. A patch is found when
# the seed it names aborts inside check_<property> (or a check_<property>_<part>), the function
# that holds that property's checks, and every seed that fails fails by an abort() in some
# check_ function: a bug the harness reads in two ways may stop another seed in another
# property, but a sanitizer report or a crash outside a check makes it red. The optimizer
# merges the abort() calls of a function, so the line is fuzz/records.sh's to prove, in a
# build that keeps them apart. The source is restored with `git checkout --` on every exit
# path, and the sanitizer build is rebuilt as the tree is at the end.
#
# Usage: FUZZ_BUILD=build/fuzz MAKE=make sabotage.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
B=${FUZZ_BUILD:-build/fuzz}
MAKE=${MAKE:-make}
OUT=$B/sabotage
mkdir -p "$OUT"

patched=
restore() {
	[ -n "$patched" ] && git checkout -- $patched
	patched=
}
trap 'restore' EXIT
trap 'restore; exit 130' INT TERM

if ! git diff --quiet -- src include transport/src; then
	echo "fuzz-sabotage: src/, include/ or transport/src/ has uncommitted changes; refusing to patch over them" >&2
	exit 2
fi

missed=
n=0
for p in fuzz/sabotage/*.patch; do
	[ -f "$p" ] || continue
	m=$(basename "$p" .patch)
	h=${m%%-*}
	prop=${m#*-}
	fn=check_$(echo "$prop" | tr - _)
	n=$((n + 1))
	# the check and the seed its header names
	at=$(sed -n "s|^Breaks the check of \(fuzz/fuzz_$h\.c:[0-9]*\) (.*)\.\$|\1|p" "$p" | head -n 1)
	named=$(sed -n "s|^Caught by the seed input \"\([^\"]*\)\" of fuzz_$h\.\$|\1|p" "$p" | head -n 1)
	if [ -z "$at" ] || [ -z "$named" ] || [ ! -f "fuzz/corpus/$h/$named" ]; then
		echo "$m: the header does not name a check of fuzz/fuzz_$h.c and a seed of fuzz/corpus/$h/"
		missed="$missed $m"
		continue
	fi
	files=$(git apply --numstat "$p" | awk '{ print $3 }')
	if ! git apply "$p"; then
		echo "$m: $p no longer applies"
		missed="$missed $m"
		continue
	fi
	patched=$files
	echo "== $m: fuzz_$h against $(grep -m1 '^+[^+]' "$p" | sed 's/^+[[:space:]]*//')"
	if ! $MAKE --no-print-directory "$B/fuzz_$h" >"$OUT/$m.build.log" 2>&1; then
		cat "$OUT/$m.build.log"
		echo "$m: the mutant does not build"
		missed="$missed $m"
		restore
		continue
	fi
	found=0
	own=0
	other=
	for seed in fuzz/corpus/$h/*; do
		log=$OUT/$m.$(basename "$seed").log
		"$B/fuzz_$h" -runs=1 -artifact_prefix="$OUT/$m-" "$seed" >"$log" 2>&1 && { rm -f "$log"; continue; }
		# the innermost check_ function of the abort's stack, and whether it was an abort
		where=$(awk '/ERROR: libFuzzer: deadly signal/ { on = 1 }
			on && match($0, / in check_[a-z_]+/) { print substr($0, RSTART + 4, RLENGTH - 4); exit }' "$log")
		if grep -q 'ERROR: libFuzzer: deadly signal' "$log" && [ -n "$where" ]; then
			found=$((found + 1))
			echo "$where" | grep -qE "^$fn(_[a-z]+)*\$" && own=$((own + 1))
		else
			other="$other $(basename "$seed")(${where:-$(grep -m1 -E '^SUMMARY: ' "$log")})"
		fi
	done
	restore
	log=$OUT/$m.$named.log
	if [ -n "$other" ]; then
		echo "$m: seeds that failed outside a check:$other"
		echo "$m: RED -- the patch is not read as a broken property (logs in $OUT/)"
		missed="$missed $m"
	elif [ ! -f "$log" ] || ! awk '/ERROR: libFuzzer: deadly signal/ { on = 1 }
			on && match($0, / in check_[a-z_]+/) { print substr($0, RSTART + 4, RLENGTH - 4); exit }' "$log" |
			grep -qE "^$fn(_[a-z]+)*\$"; then
		echo "$m: RED -- the seed $named does not abort in $fn"
		missed="$missed $m"
	else
		echo "$m: found by $found seeds, $own in $fn, $named among them"
	fi
done

# leave the sanitizer build as the tree is, not as the last mutant was
$MAKE --no-print-directory fuzz >"$OUT/rebuild.log" 2>&1 || { cat "$OUT/rebuild.log"; exit 1; }

if [ "$n" -eq 0 ]; then
	echo "make fuzz-sabotage: RED -- no patch in fuzz/sabotage/"
	exit 1
fi
if [ -n "$missed" ]; then
	echo "make fuzz-sabotage: RED --$missed"
	exit 1
fi
echo "make fuzz-sabotage: all $n patches found, each in the property its header names"
