# Building libdiginet

A hand-kept Makefile, no build system to configure. You need a C11 compiler and `make`.
Nothing else: no library outside libc.

```
make                          # libdiginet.a, libdiginet-transport.a and tools/diginet-probe
make test                     # the unit suite, the same command CI runs
make install PREFIX=/usr/local [DESTDIR=...]
make clean
```

The code is plain C11 built with `-Wall -Wextra -Werror`, so a warning is a build failure.
`CC` and `CFLAGS` can be overridden on the command line; the warning flags are kept even then.

Two libraries come out of one tree:

- `libdiginet`: the protocol. Frame grammar, codecs, personalities. No socket, no clock.
- `libdiginet-transport`: the wire. The packet socket and the session (discovery, wake,
  ACKs, retransmit, keepalive, coalescing, pacing). It links `libdiginet`.

`make install` copies the headers to `$(PREFIX)/include/diginet/`, the archives to
`$(PREFIX)/lib` (`LIBDIR=` to change it) and two pkg-config files, so a consumer builds with:

```
cc app.c $(pkg-config --cflags --libs libdiginet-transport)
```

## Tests

Every test runs through `tests/run-test.sh`, which gives it a timeout: a hang is a failure,
never a stalled build. A test that exits 77 proved this machine cannot host it and is reported
as SKIP, never as a pass.

The golden frames are in `tests/golden/frames.txt`, one whole Ethernet frame per line in hex.
The C suite reads that file and checks every frame against the values `docs/protocol.md`
gives. The same file feeds the Kaitai check below, so the two readings of the grammar cannot
drift apart.

The transport suite needs no desk and no privileges. `tests/desk_emu.c` is a desk emulator
that speaks the protocol; `test_transport` drives a session against it on a virtual clock
(minutes of desk time in milliseconds), `test_fdio` does the same on the real clock over a
socketpair. `test_packet` runs the real `AF_PACKET` path: it enters a user and network
namespace of its own, where it may open packet sockets on a private loopback; where
unprivileged namespaces are not allowed it exits 77 and reports SKIP.

`test_probe` runs `tools/diginet-probe` as its own process against the emulator, with the
wire on descriptor 3 and the operator's answers on stdin, and checks both the probe's output
and what the desk received.

## diginet-probe

`make install` puts `diginet-probe` in `$(PREFIX)/bin`. It opens a packet socket, which needs
`cap_net_raw`:

```
sudo setcap cap_net_raw=ep ./tools/diginet-probe
```

Every rebuild or copy makes a binary without the capability, so run `setcap` again after it.
How to run it on a desk is in [docs/probe.md](docs/probe.md).

## The Kaitai grammar

`protocol/diginet.ksy` is the formal byte grammar. To check that it compiles and that the
parser it generates reads the golden frames as the C library does:

```
make ksy-check
```

This needs `kaitai-struct-compiler` (0.11, from https://github.com/kaitai-io/kaitai_struct_compiler/releases)
and the Python runtime (`pip install kaitaistruct==0.11`). CI runs it in a Debian container.

## Fuzzing

Every reader of desk bytes has a libFuzzer harness in `fuzz/`, with a seed corpus, a coverage
floor and one mutant per property; [fuzz/README.md](fuzz/README.md) says what each checks.
They need clang with libFuzzer, and `llvm-cov` for the coverage witness:

```
make fuzz fuzz-run FUZZ_TIME=60 fuzz-sabotage fuzz-cov
```

## CI

`.github/workflows/ci.yml` runs `make`, `make test` and `make install` in fedora:44,
debian:bookworm and debian:trixie containers, `make test` once more on the bare runner (where
the namespace test can run), and `make ksy-check` in a Debian container with the compiler
installed. `.github/workflows/fuzz.yml` builds the harnesses in fedora:44, fuzzes each for 60 s
and runs `make fuzz-corpus-check`, `make fuzz-sabotage` and `make fuzz-cov`.

## Packages

One source builds two shared libraries and a tool:

| | Fedora | Debian |
| --- | --- | --- |
| libdiginet, libdiginet-transport | `libdiginet` | `libdiginet0`, `libdiginet-transport0` |
| headers, pkg-config, `diginet.ksy` | `libdiginet-devel` | `libdiginet-dev` |
| `diginet-probe` | `diginet-tools` | `diginet-tools` |

`packaging/libdiginet.spec` and `debian/` describe them; both run `make shared` and
`make install-shared`, and `make test` against the result. The RPM gives `diginet-probe`
`cap_net_raw` with `%caps`; the DEB sets it in `diginet-tools.postinst` with `setcap`.

The version is the `VERSION` file; the sonames' majors are `DIGINET_ABI` and
`DIGINET_TRANSPORT_ABI` in `include/diginet/diginet.h`. `tests/conformance-packaging.sh` (part of
`make test`) refuses a header, spec or `debian/` that disagrees with them.

### Releasing

Set the version in `VERSION`, `include/diginet/diginet.h`, `Version:` in the spec and the top
entry of `debian/changelog`, then tag `vX.Y.Z`. The tag runs `.github/workflows/release.yml`,
which calls the shared `build-rpm.yml` and `build-deb.yml` workflows of FreeMixer/.github: signed
RPMs for Fedora 44 (x86_64, aarch64) and DEBs for Debian bookworm and trixie (amd64, arm64) are
published to the FreeMixer channel and attached to the GitHub release. A pull request runs the
same workflows as a dry run that builds, lints and publishes nothing, then installs the packages
it built in clean containers and builds a consumer against the development package. Git history
is the changelog; no changelog file is kept.
