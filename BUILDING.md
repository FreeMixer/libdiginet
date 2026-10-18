# Building libdiginet

A hand-kept Makefile, no build system to configure. You need a C11 compiler and `make`.
Nothing else: no library outside libc.

```
make                          # libdiginet.a
make test                     # the unit suite, the same command CI runs
make install PREFIX=/usr/local [DESTDIR=...]
make clean
```

The code is plain C11 built with `-Wall -Wextra -Werror`, so a warning is a build failure.
`CC` and `CFLAGS` can be overridden on the command line; the warning flags are kept even then.

`make install` copies the headers to `$(PREFIX)/include/diginet/`, the archive to
`$(PREFIX)/lib` (`LIBDIR=` to change it) and a pkg-config file, so a consumer builds with:

```
cc app.c $(pkg-config --cflags --libs libdiginet)
```

## Tests

Every test runs through `tests/run-test.sh`, which gives it a timeout: a hang is a failure,
never a stalled build. A test that exits 77 proved this machine cannot host it and is reported
as SKIP, never as a pass.

The golden frames are in `tests/golden/frames.txt`, one whole Ethernet frame per line in hex.
The C suite reads that file and checks every frame against the values `docs/protocol.md`
gives. The same file feeds the Kaitai check below, so the two readings of the grammar cannot
drift apart.

## The Kaitai grammar

`protocol/diginet.ksy` is the formal byte grammar. To check that it compiles and that the
parser it generates reads the golden frames as the C library does:

```
make ksy-check
```

This needs `kaitai-struct-compiler` (0.11, from https://github.com/kaitai-io/kaitai_struct_compiler/releases)
and the Python runtime (`pip install kaitaistruct==0.11`). CI runs it in a Debian container.

## CI

`.github/workflows/ci.yml` runs `make`, `make test` and `make install` in fedora:44,
debian:bookworm and debian:trixie containers, and `make ksy-check` in a Debian container with
the compiler installed.
