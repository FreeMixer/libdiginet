# Fuzzing libdiginet

libdiginet reads raw Ethernet frames a desk sends (EtherType 0x885F): the frame and its header,
the command stream of a data frame, the controls in it, and the session those frames drive.
Every function that reads those bytes has a libFuzzer harness here, built with clang under
AddressSanitizer and UndefinedBehaviorSanitizer and run in CI on every push and pull request
(`.github/workflows/fuzz.yml`).

Each harness is one plain C file defining `LLVMFuzzerTestOneInput`. It reads its input as a
small program: a few bytes that choose what the reader is given (a personality, a config), then
a frame, a body or a sequence of operations, until the input ends. Every input means something,
and the end of the input ends it. No harness reads a clock, the environment, a file or the
network, starts a thread or installs a signal handler; a time the session needs is a time the
input chooses. Properties are checked with `if (!cond) abort();`, never `assert()`, every
outcome an input can choose returns 0, and an input of 64 MiB or more is refused. A frame or
body is copied into an allocation of exactly its length, so a read one byte past it is a
sanitizer report.

The harnesses call the library as it is. They do not carry a grammar of their own: the
protocol is `protocol/diginet.ksy` and the library's reading of it. Where a property needs to
know what bytes should say, it asks a second libdiginet function (the builder for the parser,
the encoder for the decoder, the cursor for the decoder, `diginet_body_check()` for the
refusal) and requires the two to agree; the offsets and limits it uses are the constants of
`include/diginet/`.

## The harnesses

| Harness | Readers it feeds | Input |
| --- | --- | --- |
| `fuzz_frame` | `diginet_frame_parse`, `diginet_frame_build`, `diginet_frame_is_keepalive`, `diginet_announce_parse`, `diginet_sum16` (`src/diginet_frame.c`) | one Ethernet frame of any length |
| `fuzz_decode` | `diginet_msg_next` (`src/diginet_msg.c`); `diginet_decoder_next` (`src/diginet_decode.c`); `diginet_body_check` (`src/diginet_codec.c`) | a personality and a body, or a whole frame whose body is decoded |
| `fuzz_codec` | every encoder of `src/diginet_codec.c`, the scribble and counter text helpers, the meter and ring masks; the decoder reading back what they make | up to 256 encoder calls with their arguments and personality |
| `fuzz_transport` | `diginet_session_rx`, `_tick`, `_submit`, `_wake`, `_close`, `_poll`, `_deadline` (`transport/src/diginet_session.c`) | a config, then up to 1024 operations: a raw or built desk frame, an announce, time passing, a command, a wake, a close, a failed send, a poll |

The packet socket and the descriptor io (`transport/src/diginet_io.c`) read no bytes of their
own: they hand a whole frame to the session, which `fuzz_transport` drives with the frame the
input chose. `fuzz_transport` is the session's io: its send records every frame the session
sends, and its recv hands `diginet_session_poll()` a frame the input chose.

### What each harness checks, and the mutant that breaks it

Every property is the checks of one `check_<property>` function (or `check_<property>_<part>`),
and has one recorded mutant, `fuzz/mutants/<harness>-<property>.patch`: a one-line change to the
library that the seed corpus alone catches, in that function and no other. The header comment
of every harness states its properties in full.

| Harness | Property | What must hold | Mutant | Seed that finds it |
| --- | --- | --- | --- | --- |
| frame | parse | the parser refuses exactly what diginet.h says, each with its code, and reads what it accepts inside the buffer: body, length, padding, sum, keepalive | the EtherType refusal tests for 0 | `wrong-ethertype` |
| frame | round-trip | an accepted frame is what the builder makes of its fields, byte for byte, and parses back the same; the builder refuses exactly the system family and an oversized body | the ack counter written from the send counter | `ack` |
| frame | announce | only an e0 or e1 of 33 body bytes or more is an announce; version and name are the bytes at 15 and 24, up to a NUL, at most 9, terminated | the name read one byte early | `announce_cntrl24` |
| decode | cursor | every call moves forward and ends; a message lies where diginet.ksy puts it (F0 to its first F7; a status, or running status, then one data byte for C0/D0 and two otherwise, each under 0x80); each refusal steps where diginet.h says | the first data byte of a channel message not checked for bit 7 | `status-for-data` |
| decode | events | the decoder returns the cursor's messages in order, each event of its message's family; a fader MSB takes the next message as its LSB exactly when it is B0 (20+tt) | the LSB read but not stepped past | `fader_move` |
| decode | refusal | a body holding F0 13 xx 70, whole or cut short, is refused by `diginet_body_check` and the builder, the decoder names it and nothing else `DIGINET_EV_SYSTEM`, and a body is refused only when one is in it | the cut-short scan misses one that ends the body | `system-cut-short` |
| codec | refusal | `diginet_sysex_encode` never makes function 0x70 and leaves its output untouched; no encoder output holds the system family | only an empty 0x70 message refused | `sysex-system` |
| codec | range | each encoder succeeds exactly in the range its comment gives, `DIGINET_E_ARG` without a personality, output untouched on failure | the fader takes the strip one past the last | `fader-past-last-strip` |
| codec | round-trip | what an encoder makes decodes as one event of its kind with the values encoded, every byte used; its key names its address, display writes only for scribble and counter | the fader LSB shifted by 3 instead of 4 | `fader-full` |
| codec | text | what the text helpers accept, the encoders take; the meter mask and segment count invert each other; the ring helpers light what they name | the counter text accepts a dot on the rightmost digit | `counter-text-last-dot` |
| transport | ack | every desk data frame to this host is ACKed at once with its send counter, while the session is not closed, and no other frame is | the ACK echoes the frame's ack counter | `data-acked` |
| transport | inflight | one host frame in flight; a retransmission is that frame with retry 1, 2, ... never past `max_retries`; `ACK_LOST` after exactly `max_retries`, `ACKED` only for the frame in flight | one retransmission past `max_retries` | `wake-unanswered` |
| transport | latest | a sent body is commands submitted, not sent before and not replaced for their key; the queue holds exactly what is pending; a queued key never lacks room | a newer command takes the old one's key but not its bytes | `coalesce` |
| transport | refusal | a command `diginet_body_check` refuses is refused by submit and not queued; every frame sent parses and carries no system message | submit checks all but the last byte | `submit-system-cut-short` |
| transport | state | ONLINE only after an a0 for the e2 and an e1 naming this host since it; never an e2 while another host's session is the desk's latest announce | a foreign session refuses a wake only while online | `wake-foreign` |

`make fuzz-sabotage` applies each mutant, rebuilds its harness and runs every seed of the
harness's corpus once, without fuzzing. A mutant passes when at least one seed aborts and every
seed that aborts does so in that property's own `check_` function; a sanitizer report, or an
abort in another property, makes it red, since the mutant then breaks a property it does not
name. All 15 are found today.

## The seed corpus

`fuzz/corpus/<harness>/` is written by `fuzz/gen-corpus.c` (`make fuzz-corpus`) from what the
repository already holds: the golden frames of `tests/golden/frames.txt`, and commands the
library's own encoders make. Beside them it writes one input per refusal a reader makes (a
short frame, a wrong EtherType, a numbytes past the buffer, an announce one byte short, a
status byte where a data byte is due, a sysex with no F7, F0 13 xx 70 whole, cut short and
inside another sysex, each encoder past its range ...), and sessions that reach every state:
the handshake, desk data and retries, an e2 nobody answers, keepalives and silence, the ways a
session ends, a foreign session, coalescing, full frames, paced display writes, a full queue.
Nothing is fetched and nothing is random; the corpus is committed, and `make fuzz-corpus-check`
is red when it is not what the generator writes.

## The coverage witness

`make fuzz-cov` builds each harness for `llvm-cov` (no sanitizers,
`-fprofile-instr-generate -fcoverage-mapping`), runs it once over its corpus (`-runs=0`) and
prints the line coverage of the reader functions it drives (the lists are in
`fuzz/coverage.sh`), then every line of them no seed reached. `fuzz/coverage-floor.txt` holds
the number of covered lines each harness reaches today, and `make fuzz-cov` is red when one
falls below it. Every property check in `fuzz/fuzz_*.c`, an `abort()` and the statement that
guards it, must be executed by at least one seed (`fuzz/checks.awk`); one that no seed reaches
turns it red, naming the file and the line:

```
  CHECK: fuzz/fuzz_frame.c:52 no seed reaches (abort at line 53): if (r != DIGINET_E_ETHERTYPE)
  FLOOR: fuzz_frame covers 90 reader lines, below its floor of 91
make fuzz-cov: RED -- below the coverage floor: frame
make fuzz-cov: RED -- harness checks no seed reaches: frame
```

| Harness | Reader lines | Covered | Lines no seed reaches |
| --- | ---: | ---: | --- |
| frame | 95 | 95.79% | the four `DIGINET_E_ARG` returns for a NULL pointer or an unknown sum mode |
| decode | 233 | 98.28% | the four NULL-pointer guards of the cursor and the decoder |
| codec | 269 | 97.03% | the eight NULL-pointer guards (`out`, `text`) of the encoders and text helpers |
| transport | 417 | 97.60% | the NULL-session and invalid-config guards; `send_control` and `send_data` returning a builder refusal, which cannot happen: a control frame has no body, and `take()` stops before a command that would make the body one the builder refuses |

The argument guards are the library's answer to a caller's NULL pointer, not to desk bytes;
no input reaches them because no harness passes a NULL.

## Running

```
make fuzz                    # build every harness into build/fuzz/
make fuzz-run FUZZ_TIME=60   # fuzz each for 60 s; red on any crash
make fuzz-sabotage           # every mutant found, each by its own property
make fuzz-cov                # the coverage witness and its floors
make fuzz-corpus             # write fuzz/corpus/ again
make fuzz-corpus-check       # red when fuzz/corpus/ is not what fuzz-corpus writes
```

They need clang with libFuzzer and, for `fuzz-cov`, `llvm-profdata` and `llvm-cov`; on Fedora
`dnf install clang compiler-rt llvm`. The harnesses link a library of their own, compiled from
the same sources with the sanitizers into `build/fuzz/obj/`, so the ordinary `make` and
`make test` builds are never touched.

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
every later run replays it first. Two are there now, each from a bug `fuzz_transport` found:

- `transport/wake-fails-in-flight`: a `diginet_session_wake()` whose send failed had already
  written its e2 over the frame in flight, so the next retransmission sent that e2, with a
  retry count, in place of the data frame (`check_inflight_retry`).
- `transport/split-system`: two commands each whole alone, the first ending `F0 13` and the
  second starting `A0 70`, made F0 13 A0 70 side by side; the builder refused the frame and
  every command taken for it was dropped without a notice (`check_latest_queue`).
