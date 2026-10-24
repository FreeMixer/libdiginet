# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# THE HARNESS FLOOR (fuzz/coverage.sh). Reads `llvm-cov show` of one harness source
# (`LINE|COUNT|source`) and prints, for every property check in it, one line
#
#   <file>:<check line>:<abort line>:<count>:<the check's first source line>
#
# A property check is an abort() and the statement that guards it: the `if` whose
# condition ends in the abort, or, for a bare abort() in a block (an `else` arm, a
# switch's `default:`), the statement that opens that block. <count> is how often the
# seed corpus executed that statement's first line; 0 is a property no seed tests.
# Comments are stripped before anything is matched, so an abort() named in prose is
# not a site.
BEGIN { FS = "|" }
{
	ln = $1 + 0
	cnt = $2
	gsub(/[ \t]/, "", cnt)
	src = $0
	sub(/^[^|]*\|[^|]*\|/, "", src)
	code = src
	if (incomment) {
		if (code ~ /\*\//) { sub(/^.*\*\//, "", code); incomment = 0 }
		else code = ""
	}
	while (match(code, /\/\*([^*]|\*+[^*\/])*\*+\//))
		code = substr(code, 1, RSTART - 1) substr(code, RSTART + RLENGTH)
	if (code ~ /\/\*/) { sub(/\/\*.*$/, "", code); incomment = 1 }
	sub(/\/\/.*$/, "", code)
	gsub(/^[ \t]+|[ \t]+$/, "", code)
	C[ln] = code; N[ln] = cnt; S[ln] = src
	if (code ~ /(^|[^A-Za-z0-9_])abort\(\);/) site[++ns] = ln
}

# The first line of the statement that ends on line l.
function stmt_start(l) {
	while (l > 1 && C[l - 1] != "" && C[l - 1] !~ /[;{}:]$/) l--
	return l
}

END {
	for (i = 1; i <= ns; i++) {
		l = site[i]
		s = stmt_start(l)
		if (s == l && C[l] ~ /^abort\(\);/) {
			d = 0
			for (s = l - 1; s >= 1 && d >= 0; s--)
				for (k = length(C[s]); k >= 1; k--) {
					c = substr(C[s], k, 1)
					if (c == "}") d++
					else if (c == "{" && --d < 0) break
				}
			s = stmt_start(s + 1)
		}
		t = S[s]
		gsub(/^[ \t]+/, "", t)
		printf "%s:%d:%d:%s:%s\n", file, s, l, N[s], t
	}
}
