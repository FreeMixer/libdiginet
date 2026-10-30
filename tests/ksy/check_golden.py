# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
"""The second reading of the grammar: the parser kaitai-struct-compiler generates from
protocol/diginet.ksy reads every golden frame with the values the C suite asserts.

    python3 tests/ksy/check_golden.py <dir holding the generated diginet.py> <frames.txt>
"""
import sys

sys.path.insert(0, sys.argv[1])
from diginet import Diginet  # noqa: E402  (generated)

C = Diginet.Command
F = Diginet.SysexFunction
DESK = bytes.fromhex("00a07e240001")
HOST = bytes.fromhex("020000000001")

# name: (numbytes, sum, send, ack, retry, cmd, ncmds, messages)
# a message is (status, running, d1, d2) or (0xf0, device, function, payload hex)
EXPECT = {
    "announce_cntrl24": (50, 0x032E, 0, 0, 0, C.announce_offline, 0, None),
    "announce_session_cntrl24": (50, 0x0331, 0, 0, 0, C.announce_session, 0, None),
    "announce_mainunit": (50, 0x0326, 0, 0, 0, C.announce_offline, 0, None),
    "wake": (16, 0, 0, 0, 0, C.wake, 0, None),
    "disconnect": (16, 0, 0, 0, 0, C.disconnect, 0, None),
    "keepalive": (17, 0, 0x2A, 0, 0, C.data, 1, [(0, True, 0, None)]),
    "ack": (16, 0, 0x2A, 0x105, 0, C.ack, 0, None),
    "fader_move": (21, 0x0110, 0x105, 0, 0, C.data, 1,
                   [(0xB0, False, 0x00, 0x40), (0xB0, True, 0x20, 0x00)]),
    "button_mute": (19, 0x00D8, 0x106, 0, 0, C.data, 1, [(0x90, False, 0x08, 0x40)]),
    "scribble_write": (27, 0x0360, 0x2B, 0, 0, C.data, 1,
                       [(0xF0, 0x01, F.scribble, "0000" "4f4d5831")]),
    "meter": (24, 0x0291, 0x2C, 0, 0, C.data, 1, [(0xF0, 0x01, F.meter, "00077f")]),
    "clock_init": (30, 0x0244, 1, 0, 0, C.data, 1,
                   [(0xF0, 0x01, F.counter, "19" + "00" * 8)]),
    "running_status": (30, 0x03FD, 0x107, 0, 0, C.data, 5,
                       [(0x90, False, 0x08, 0x40), (0x90, True, 0x07, 0x41),
                        (0xB0, False, 0x01, 0x7F), (0xB0, True, 0x21, 0x70),
                        (0xB0, True, 0x40, 0x41), (0xB0, True, 0x5C, 0x3F)]),
    "desk_retry": (19, 0x0098, 0x108, 0, 1, C.data, 1, [(0x90, False, 0x08, 0x00)]),
    "counter_write": (31, 0x037C, 0x2D, 0, 0, C.data, 1,
                      [(0xF0, 0x01, F.counter, "1940" "5b6d300000000000")]),
}

ANNOUNCE = {
    "announce_cntrl24": ("1.37", "CNTRL|24"),
    "announce_session_cntrl24": ("1.37", "CNTRL|24"),
    "announce_mainunit": ("2.10", "MAINUNIT"),
}


def frames(path):
    with open(path) as fp:
        for line in fp:
            if line.startswith("#") or not line.strip():
                continue
            name, hexs = line.split()
            yield name, bytes.fromhex(hexs)


def check(name, raw, fails):
    def chk(cond, what):
        if not cond:
            fails.append(f"{name}: {what}")

    d = Diginet.from_bytes(raw)
    numbytes, csum, send, ack, retry, cmd, ncmds, msgs = EXPECT[name]
    h = d.header
    chk(d.ethertype == 0x885F, "ethertype")
    chk(h.numbytes == numbytes, f"numbytes {h.numbytes}")
    chk(h.sum == csum, f"sum {h.sum:#x}")
    chk(h.send_counter == send and h.ack_counter == ack, "counters")
    chk(h.retry == retry and h.cmd == cmd and h.num_commands == ncmds, "retry/cmd/ncmds")
    body_len = numbytes - 16
    chk(sum(raw[30:30 + body_len]) & 0xFFFF == csum, "sum is the body byte sum")
    chk(len(d.padding) == len(raw) - 30 - body_len, "padding length")
    if name in ANNOUNCE:
        ver, dev = ANNOUNCE[name]
        chk(d.body.version.text == ver and d.body.name.text == dev, f"announce {d.body.version.text!r} {d.body.name.text!r}")
        chk(d.src[:3] == DESK[:3], "Digidesign OUI")
    if msgs is not None:
        got = d.body.messages
        chk(len(got) == len(msgs), f"{len(got)} messages")
        for m, x in zip(got, msgs):
            if x[0] == 0xF0:
                chk(m.status == 0xF0 and m.sysex.maker == 0x13, "sysex")
                chk(m.sysex.device == x[1] and m.sysex.function == x[2], "sysex device/function")
                chk(m.sysex._raw_payload == bytes.fromhex(x[3]), f"sysex payload {m.sysex._raw_payload.hex()}")
            elif x[0] == 0:
                chk(m.status == 0 and m.running, "keepalive 00 is a data byte with no status")
            else:
                chk((m.status, m.running, m.data1, m.data2) == x,
                    f"message {(m.status, m.running, m.data1, m.data2)} != {x}")


def main():
    fails = []
    seen = set()
    for name, raw in frames(sys.argv[2]):
        if name not in EXPECT:
            fails.append(f"{name}: no expectation")
            continue
        seen.add(name)
        check(name, raw, fails)
        # One changed byte before the padding must change what the grammar reads.
        logical = 30 + EXPECT[name][0] - 16
        for i in range(logical):
            mutated = bytearray(raw)
            mutated[i] ^= 0x01
            sub = []
            try:
                check(name, bytes(mutated), sub)
            except Exception:
                sub.append("parse error")
            if not sub and i not in range(0, 12):  # MACs are not part of EXPECT
                fails.append(f"{name}: byte {i} changed and the grammar read the same values")
    for name in set(EXPECT) - seen:
        fails.append(f"{name}: missing from the golden file")
    for f in fails:
        print("FAIL", f, file=sys.stderr)
    if fails:
        sys.exit(1)
    print(f"check_golden: ok ({len(seen)} golden frames)")


if __name__ == "__main__":
    main()
