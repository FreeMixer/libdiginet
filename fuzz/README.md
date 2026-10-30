# Fuzzing libdiginet

libdiginet reads raw Ethernet frames a desk sends (EtherType 0x885F): the frame and its header,
the command stream of a data frame, the controls in it, the session those frames drive and the
desk mux that hands each desk its own.
Every function that reads those bytes has a libFuzzer harness here, built with clang under
AddressSanitizer and UndefinedBehaviorSanitizer and run in CI on every push and pull request
(`.github/workflows/fuzz.yml`). The harnesses are written to the build contract of OSS Verify
(its `docs/build-contract.md`, "The checks of a fuzz target"), which proves never-crash and the
declared properties over them.

Each harness is one plain C file defining `LLVMFuzzerTestOneInput`. It reads its input as a
small program: a few bytes that choose what the reader is given (a personality, a config), then
a frame, a body or a sequence of operations, until the input ends. Every input means something,
and the end of the input ends it. No harness reads a clock, the environment, a file or the
network, starts a thread or installs a signal handler; a time the session needs is a time the
input chooses. Every input of 64 MiB or more is refused, and every other outcome an input can
choose returns 0. A frame or body is copied into an allocation of exactly its length, so a read
one byte past it is a sanitizer report.

## The expected values come from the protocol, not from the library

A check that takes its expected value from the code it judges holds for a library that is wrong
the same way. So no check here compares libdiginet with itself. `fuzz/spec.h` is the protocol as
the harnesses hold it, written from `protocol/diginet.ksy` and `docs/protocol.md`: the offsets,
codes, limits and personalities, each with a `contract:` line naming the line it stands on, and
the harnesses' own readers of a frame (`spec_read_frame`), of the command stream
(`spec_msg_step`) and of the controls in it (`spec_event_of`). The few values only the library's
header defines (its return codes, the key of a command, the 24-byte command, the 512-command
queue) are written out there too, so a change to the header is a change a check sees.

Each harness holds the library to that reading: the parser to the grammar's reading of the same
bytes, the builder to the frame the grammar makes of its fields, the cursor and the decoder to
the grammar's steps and the controls `docs/protocol.md` makes of them, each encoder to the bytes
`docs/protocol.md` gives for its control and to the range `diginet_codec.h` gives it, and the
session to a model of `diginet_session.h` that the harness runs itself (below). A frame the
session sends is read with the harness's own reader.

## The checks and their records

Every property is an `if (...) abort();`, never `assert()`, inside a `noinline` function
`check_<property>` (or `check_<property>_<part>`). The comment of each check says what it checks,
names its `contract:`, and carries one or more records, as OSS Verify's `tools/check` reads them:

```
/* Each header field is the big-endian value at its offset.
 * contract: docs/protocol.md:37-43; protocol/diginet.ksy `header`
 * mutant: src/diginet_frame.c:81 `rd32(h + 8)` -> `rd32(h + 4)`
 * input: ack */
```

A record is a one-line change of `src/`, `include/` or `transport/src/` and the seed it shows
on: with the change, that seed makes THAT check abort; without it, the seed passes. The one
stop that is not a property, the harness's own failed allocation in `fuzz_alloc()`
(`fuzz/fuzz.h`), carries the line `not a property: the harness's own allocation failed` in place
of a record.

`make fuzz-records` (`fuzz/records.sh`) proves every record at this commit. First the ratchet:
`fuzz/checks.awk` reads every `abort()` of `fuzz/` and its comment, and a check with no record
and no `not a property:` line, or a record not of the form, is red before anything is built.
Then, for each record alone, it makes the change (the old text must occur once on that line),
builds the plain native harness against the library compiled the same way (no sanitizer,
`fuzz/standalone.c` as the driver, every `abort()` of the harness naming its own line), runs the
named seed, requires exit 134 from the record's own check, and puts the file back. Every named
seed must exit 0 on the unchanged tree. The count of records met is the proof:

```
make fuzz-records: all 190 records and 28 patches met, each by its own check on its own seed (122 checks)
```

| Harness | Checks | Records | Sabotage patches |
| --- | ---: | ---: | ---: |
| frame | 23 | 29 | 4 |
| decode | 23 | 33 | 3 |
| codec | 17 | 27 | 6 |
| transport | 43 | 72 | 9 |
| mux | 16 | 29 | 6 |

### What each harness checks

The header comment of each harness states its properties in full; in short:

| Harness | Readers it feeds | Properties |
| --- | --- | --- |
| `fuzz_frame` | `diginet_frame_parse`, `diginet_frame_build`, `diginet_frame_is_keepalive`, `diginet_mac_is_digidesign`, `diginet_announce_parse`, `diginet_sum16` | parse: each refusal with its code, every field where the grammar puts it; round-trip: the builder makes the grammar's frame of those fields and refuses a body past 1484 bytes, the system family and a buffer one byte short; announce: only an e0 or e1 of 33 bytes, `unknown`, version and name at 0, 15 and 24 |
| `fuzz_decode` | `diginet_msg_next`, `diginet_decoder_next`, `diginet_body_check` | cursor: each step of the grammar, message or refusal, with its place, bytes, cursor and running status; events: each step as the control `docs/protocol.md` makes of it, every field; refusal: a body refused exactly when it holds F0 13 xx 70 |
| `fuzz_codec` | every encoder of `src/diginet_codec.c`, the personalities, `diginet_scribble_text`, `diginet_seg7`, `diginet_counter_text`, the meter and ring helpers | personality, refusal of function 0x70, range (success exactly in range, the code otherwise, the command untouched on failure), bytes (the control's message, its key, the display flag), text |
| `fuzz_transport` | `diginet_session_rx`, `_tick`, `_submit`, `_wake`, `_close`, `_poll`, `_deadline` | sent, ack, inflight, state, keepalive, latest, refusal (below) |
| `fuzz_mux` | `diginet_mux_rx`, `_tick`, `_attach`, `_detach`, `_poll`, `_deadline`, `_find`, `_session` | appear, route, send, gone, attach, deadline (below) |

`fuzz_transport` is the session's io: its send reads and records every frame the session sends
(and fails one when the input asks), its recv hands `diginet_session_poll()` a frame the input
chose. It runs the session the header describes on its own: the desk it learns, its state and
the reason of each change, the handshake since the last e2, the desk's latest announce, the frame
in flight and its retransmissions, the keepalive clock, the back-off after a desk retry, the
display pacing, the host's counter and the queue of commands. Before each operation, and in a
poll before each frame its recv hands over, it works out what the operation owes; every frame
and notice the library then gives is held to the model as it happens, and the state, the timers
and the queue after it. Its properties: every frame sent is
the grammar's, to the known desk, padded, with the sum its mode asks and no system family; every
desk data frame ACKed once with its counter; one frame in flight, retransmitted never early, never
past `max_retries`, always once due; ONLINE only after the a0 and an e1 naming this host; an e2
exactly when the host wakes and never into another host's session; a desk that announces but
lets `deaf_wakes` wakes in a row time out reported once, at that wake, with that count, and
never after an a0, another host's e1 or a timeout with no recent announce; the keepalive on its own
clock, never early, never skipped; frames within `max_cmds` and `max_body`, their count and
counter right, display writes paced; the queue exactly the pending commands, latest in place,
and a command that may go gone after each tick; a command holding F0 13 xx 70 refused. Each
timer has a seed that reaches it exactly, so a bound moved by one shows.

`fuzz_mux` is the desk mux's io: its send reads every frame a desk's session sends and the
interface it goes out of, its recv hands `diginet_mux_poll()` a frame and an interface the input
chose, and its `if_mac` gives interfaces 1 and 2 a MAC and 3 none. Ten MACs, nine of them
Digidesign's, announce and send on three interfaces; desks are attached as they appear or by
hand, detached, given a command, and time passes. The harness keeps the table on its own: which
desk is in which slot, on which interface, attached or not, when its last frame came, and
whether its session ended on silence (read from that session's own notice; the session itself
is `fuzz_transport`'s). Its properties: APPEARED exactly for the announce of a Digidesign MAC no
desk holds while a slot is free, in the lowest free slot, with its MAC, interface, announce and
personality; a present desk's frame on its interface to its attached session and to no other,
on another interface to none, and every session notice under its own desk with its desk's
frames only; every frame a session sends out of its desk's interface, to that desk, from that
interface's MAC; GONE exactly for a desk silent for `gone_ms` or whose session ended on
silence, on a tick, and the slot forgotten; attach and detach answering as the header says; the
deadline never past a desk's gone time or a session's own deadline.

## The sabotage patches

`fuzz/sabotage/<harness>-<property>.patch` is a bug in the code a harness drives, at least one
for each property, as `git diff` writes it; a further bug of the same property is
`<harness>-<property>.<what>.patch`. Above its `diff --git` line it names the check it
breaks and the seed that shows it, the two lines OSS Verify reads (its `docs/project-yaml.md`,
"mutants"):

```
Breaks the check of fuzz/fuzz_frame.c:46 (the EtherType refusal tests for 0, not for 0x885F).
Caught by the seed input "wrong-ethertype" of fuzz_frame.
```

`make fuzz-sabotage` applies each, rebuilds the sanitizer harness and runs every seed of its
corpus once, without fuzzing: the named seed must abort inside that property's `check_`
function, and every seed that fails must fail by an abort in some check, not a sanitizer report.
`make fuzz-records` proves the line the header names. One patch, `transport-sent`, is two lines:
the session's queue and the frame builder each refuse F0 13 xx 70, so no one-line change makes
the session send it.

## The seed corpus and the coverage witness

`fuzz/corpus/<harness>/` is written by `fuzz/gen-corpus.c` (`make fuzz-corpus`) from what the
repository already holds: the golden frames of `tests/golden/frames.txt`, and commands the
library's own encoders make. Beside them it writes one input per refusal a reader makes, each
range at its last accepted and first refused value, and sessions that reach every state and
timer. Nothing is fetched and nothing is random; the corpus is committed, and
`make fuzz-corpus-check` is red when it is not what the generator writes. Together the seeds run
every check of every harness.

`make fuzz-coverage` builds each harness for `llvm-cov` (no sanitizers), runs it once over its
corpus and prints the line coverage of the reader functions it drives (`fuzz/coverage.sh`), then
every line of them no seed reached. `fuzz/coverage-floor.txt` holds the covered lines each
harness reaches today, and the target is red when one falls below it. Every check of a harness
must be reached by a seed, and must carry a record or a `not a property:` line; a check that
misses either is named by file and line and turns the target red.

`make fuzz-static` builds each harness with `fuzz/standalone.c` for its driver and the library
sources, fully static, checks that the program has no interpreter and no dynamic section, and
runs it over its corpus: the build a verifier that brings its own driver takes.

## What has no harness, and why

- **Dante.** libdiginet holds no Dante code: the desks it drives speak DigiNet only.
- **A file or config reader.** There is none. The session config
  (`struct diginet_session_config`) is a struct the caller fills, not bytes from outside; the
  harness fills it from its input, every field in the range the session takes.
- **The packet socket and the descriptor io** (`transport/src/diginet_io.c`). They read no bytes
  of their own: they hand a whole frame to the session or the mux, which `fuzz_transport` and
  `fuzz_mux` drive with the frame the input chose, through their own recv. What is left is
  system calls (`socket`, `bind`, `poll`, `recvfrom`, `sendto`, `ioctl`, `sendmsg`, `recvmsg`,
  `posix_spawn`, `clock_gettime`), which a harness may not make; `test_fdio` and `test_anyif`
  test them on real descriptors.
- **`diginet-packet-helper`** (`tools/diginet-packet-helper.c`) reads nothing: it opens a socket
  and passes it on.
- **`diginet-probe`** (`tools/diginet-probe.c`) reads its arguments and drives the library over
  a packet socket; the bytes it reads go through the readers above.
- **The name tables** (`diginet_strerror`, `diginet_state_name`, `diginet_reason_name`) map a
  code to a constant string and read no input bytes.

## Running

```
make fuzz                    # build every harness into build/fuzz/
make fuzz-run FUZZ_TIME=60   # fuzz each for 60 s; red on any crash
make fuzz-sabotage           # every patch found, each in its own property
make fuzz-records            # every record met, each at its own check
make fuzz-coverage           # the coverage witness and its floors
make fuzz-static             # each harness linked fully static, over its corpus
make fuzz-corpus             # write fuzz/corpus/ again
make fuzz-corpus-check       # red when fuzz/corpus/ is not what fuzz-corpus writes
```

They need clang with libFuzzer, `llvm-profdata` and `llvm-cov` for `fuzz-coverage`, and the
static libc for `fuzz-static`; on Fedora `dnf install clang compiler-rt llvm glibc-static`. The
harnesses link a library of their own, compiled from the same sources into `build/fuzz/`, so the
ordinary `make` and `make test` builds are never touched.

One harness by hand, with its corpus and a scratch directory for what it finds:

```
mkdir -p /tmp/new && build/fuzz/fuzz_transport -max_total_time=60 /tmp/new fuzz/corpus/transport
```

## Reproducing a finding

`make fuzz-run` writes the input that crashed a harness to
`fuzz/findings/<harness>-crash-<sha1>` (or `leak-`, `timeout-`, `oom-`), with the harness's log
beside it as `fuzz/findings/<harness>.log`; CI uploads the directory as the `fuzz-findings`
artifact. To replay it:

```
make fuzz
build/fuzz/fuzz_<harness> fuzz/findings/<harness>-crash-<sha1>
```

prints the sanitizer report or the aborted property with its stack. Once the bug is fixed, the
input, or a seed in `fuzz/gen-corpus.c` that reaches the same path, goes into the corpus so
every later run replays it first. Three are there now: two from bugs `fuzz_transport` found in
the session, one from a bug in `fuzz_transport` itself:

- `transport/wake-fails-in-flight`: a `diginet_session_wake()` whose send failed had already
  written its e2 over the frame in flight, so the next retransmission sent that e2, with a
  retry count, in place of the data frame (`check_inflight_retry`).
- `transport/split-system`: two commands each whole alone, the first ending `F0 13` and the
  second starting `A0 70`, made F0 13 A0 70 side by side; the builder refused the frame and
  every command taken for it was dropped without a notice (`check_latest_sent`).
- `transport/poll-twice-ack-new-frame`: when poll's recv handed a frame over twice, the model
  judged both copies before the poll ran, but the tick between them can send a queued command;
  a second copy that was the desk's a0 for that command stopped a session that did nothing
  wrong (`check_inflight_acked`).
