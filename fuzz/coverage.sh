#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# THE COVERAGE WITNESS (`make fuzz-coverage`). Each harness, built for llvm-cov without
# sanitizers, runs once over its seed corpus (-runs=0 executes the corpus and nothing else);
# this prints the line coverage of the reader functions the harness exists to drive, and
# every line of them the corpus never reached. A file's other functions (log strings, the
# socket code) are not the harness's job and are not counted.
#
# THE FLOOR. fuzz/coverage-floor.txt holds, per harness, the number of covered lines the
# committed corpus reaches. A harness whose covered lines fall below its floor turns this
# red: a seed lost, a harness that stopped driving a function, or a reader that grew lines
# its corpus never reaches. Raise a floor when coverage rises; lower one only together with
# the change that removed the lines.
#
# THE HARNESS FLOOR. Every property check of the harness itself, each abort() in
# fuzz/fuzz_<harness>.c and the statement that guards it (fuzz/checks.awk), must be executed
# by at least one seed. A check no seed reaches is a property nobody tests, and the
# library's line count cannot see it; this names the harness file and the line of every
# such check and turns red. So does a check whose comment holds no `mutant:` and `input:`
# record and no `not a property:` line (fuzz/records.sh proves the records): a check that
# names no bug it catches is a property nobody showed can fail.
#
# Usage: coverage.sh <cov build dir> <harness>...   (LLVM_COV names llvm-cov)
set -eu
B=$1
shift
LLVM_COV=${LLVM_COV:-llvm-cov}
FLOOR=fuzz/coverage-floor.txt
[ -f "$FLOOR" ] || { echo "coverage.sh: no $FLOOR" >&2; exit 2; }
low=
dead=

# The functions each harness covers: what "every reader line the harness means to cover"
# means, one list per harness. Static functions are matched by bare name.
funcs() {
	case $1 in
	frame) echo src/diginet_frame.c :: \
		rd16 rd32 wr16 wr32 diginet_sum16 diginet_mac_is_digidesign diginet_frame_is_keepalive \
		diginet_frame_parse diginet_frame_build copy_strz diginet_announce_parse ;;
	decode) echo src/diginet_msg.c src/diginet_decode.c src/diginet_codec.c :: \
		diginet_cursor_init channel_data_len diginet_msg_next diginet_decoder_init \
		decode_note decode_sysex diginet_decoder_next diginet_body_check ;;
	codec) echo src/diginet_codec.c :: \
		diginet_personality_from_name diginet_personality_of put3 diginet_sysex_encode \
		diginet_fader_encode diginet_button_encode diginet_touch_encode delta_byte \
		diginet_vpot_encode diginet_jog_encode diginet_ring_dot diginet_ring_fill \
		diginet_ring_encode diginet_meter_mask diginet_meter_segments diginet_meter_encode \
		leds_encode diginet_strip_leds_encode diginet_counter_leds_encode \
		diginet_scribble_text diginet_scribble_encode diginet_seg7 diginet_counter_text \
		diginet_counter_encode ;;
	transport) echo transport/src/diginet_session.c :: \
		diginet_session_config_default diginet_session_init ms set_state send_raw \
		send_control inflight_start diginet_session_wake diginet_session_close session_lost \
		find_mac maybe_online on_announce on_ack on_data diginet_session_rx coalescable \
		diginet_session_submit take send_data retransmit diginet_session_tick min64 \
		diginet_session_deadline diginet_session_poll ;;
	mux) echo transport/src/diginet_mux.c :: \
		diginet_mux_config_default diginet_mux_init ms notify_desk desk_send desk_now desk_notice \
		diginet_mux_find diginet_mux_attach diginet_mux_detach diginet_mux_session diginet_mux_rx \
		gone diginet_mux_tick min64 diginet_mux_deadline diginet_mux_poll ;;
	*) echo "coverage.sh: no function list for harness '$1'" >&2; exit 2 ;;
	esac
}

for h in "$@"; do
	set -- $(funcs "$h")
	files=
	while [ "$1" != "::" ]; do files="$files $1"; shift; done
	shift
	bin=$B/fuzz_$h prof=$B/$h.profdata
	echo "== fuzz_$h: $(ls fuzz/corpus/$h | wc -l) seed inputs"
	# Name Regions Miss Cover Lines Miss Cover ...: keep the listed functions.
	tot=$B/$h.covered
	"$LLVM_COV" report -show-functions "$bin" -instr-profile="$prof" $files |
	awk -v want="$*" -v tot="$tot" '
		BEGIN { n = split(want, w, " "); for (i = 1; i <= n; i++) keep[w[i]] = 1 }
		{ name = $1; sub(/^.*:/, "", name) }
		(name in keep) && NF >= 10 {
			printf "  %-34s lines %4d  missed %3d  %s\n", name, $5, $6, $7
			lines += $5; missed += $6; seen[name] = 1
		}
		END {
			for (k in keep) if (!(k in seen)) printf "  %-34s NOT FOUND in the report\n", k
			printf "  %-34s lines %4d  missed %3d  %.2f%%\n", "TOTAL", lines, missed,
			       lines ? 100 * (lines - missed) / lines : 0
			print lines - missed > tot
		}'
	for f in "$@"; do
		"$LLVM_COV" show "$bin" -instr-profile="$prof" -name-regex="^(.*:)?$f\$" $files \
			2>/dev/null |
		awk -v f="$f" -F'|' '$2 ~ /^ *0$/ {
			sub(/^ */, "", $1); printf "    unreached %s:%s %s\n", f, $1, $3 }'
	done
	src=fuzz/fuzz_$h.c
	"$LLVM_COV" show "$bin" -instr-profile="$prof" "$src" |
		awk -v file="$src" -f fuzz/checks.awk >"$B/$h.checks"
	nchk=$(wc -l <"$B/$h.checks")
	if [ "$nchk" -eq 0 ]; then
		echo "  CHECKS: no property check found in $src"
		dead="$dead $h"
	elif awk -F: '$4 == "0" && $5 != "not-a-property" { n++ } END { exit !n }' "$B/$h.checks"; then
		awk -F: '$4 == "0" && $5 != "not-a-property" { t = $0; sub(/^([^:]*:){5}/, "", t)
			printf "  CHECK: %s:%d no seed reaches (abort at line %d): %s\n", $1, $2, $3, t }' \
			"$B/$h.checks"
		dead="$dead $h"
	elif awk -F: '$5 == "NONE" || $5 == "BAD" { n++ } END { exit !n }' "$B/$h.checks"; then
		awk -F: '$5 == "NONE" || $5 == "BAD" { t = $0; sub(/^([^:]*:){5}/, "", t)
			printf "  RECORD: %s:%d has no mutant: and input: record and is no stop after a failed allocation (%s): %s\n",
			       $1, $3, $5, t }' "$B/$h.checks"
		dead="$dead $h"
	else
		echo "  checks: all $nchk property checks of $src reached"
	fi
	covered=$(cat "$tot")
	floor=$(awk -v h="$h" '$1 == h { print $2 }' "$FLOOR")
	if [ -z "$floor" ]; then
		echo "  FLOOR: fuzz_$h has no line in $FLOOR"
		low="$low $h"
	elif [ "$covered" -lt "$floor" ]; then
		echo "  FLOOR: fuzz_$h covers $covered reader lines, below its floor of $floor"
		low="$low $h"
	else
		echo "  floor $floor: held ($covered covered)"
	fi
done

[ -z "$low" ] || echo "make fuzz-coverage: RED -- below the coverage floor:$low"
[ -z "$dead" ] || echo "make fuzz-coverage: RED -- harness checks no seed reaches, or with no record:$dead"
[ -z "$low$dead" ] || exit 1
echo "make fuzz-coverage: every harness at or above its coverage floor, every check reached"
