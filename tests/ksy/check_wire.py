# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
"""The third reading of the grammar: the parser kaitai-struct-compiler generates from
protocol/diginet.ksy reads frames captured from a real Control|24 (tests/ksy/wire_frames.txt),
and every value must be the one the wire holds. The expectations below were taken from the
frames' bytes and from libdiginet's C decoder, not from the grammar.

    python3 tests/ksy/check_wire.py <dir holding the generated diginet.py> <wire_frames.txt>

Per frame: (sent by the desk, command, num_commands, numbytes, sum, send counter,
ack counter, retry, padding bytes, events). An event is what the C decoder reports for a
message: FADER strip value lsb_missing, VPOT strip delta, JOG delta, TOUCH strip on, SBTN strip button on, ZBTN zone
button on, RING strip mask, METER address mask, SCRIB address text, CTR address dots
digits (leftmost first), SYS.
"""
import sys

sys.path.insert(0, sys.argv[1])
from diginet import Diginet  # noqa: E402  (generated)

C = Diginet.Command
F = Diginet.SysexFunction
DESK_OUI = bytes.fromhex("00a07e")

EXPECT = {
    'desk_e0_cold': (True, 224, 1, 50, 937, 245, 0, 0, 0, []),
    'desk_e0_last_host': (True, 224, 1, 50, 1682, 94, 0, 0, 0, []),
    'desk_e1_host': (True, 225, 1, 50, 1289, 828, 0, 0, 0, []),
    'desk_ack': (True, 160, 0, 16, 0, 0, 119643, 0, 30, []),
    'desk_ack_of_e2': (True, 160, 0, 16, 0, 0, 0, 0, 30, []),
    'desk_fader': (True, 0, 1, 21, 311, 329, 0, 0, 25, ['FADER 0 570 0']),
    'desk_touch_on': (True, 0, 1, 19, 217, 328, 0, 0, 27, ['TOUCH 0 1']),
    'desk_touch_off': (True, 0, 1, 19, 153, 331, 0, 0, 27, ['TOUCH 0 0']),
    'desk_button': (True, 0, 1, 19, 218, 135, 0, 0, 27, ['SBTN 0 10 1']),
    'desk_two_faders': (True, 0, 2, 26, 670, 5, 0, 0, 20, ['FADER 23 254 0', 'FADER 23 280 0']),
    'desk_five_faders': (True, 0, 5, 41, 1724, 8, 0, 0, 5, ['FADER 23 329 0', 'FADER 23 352 0', 'FADER 23 375 0', 'FADER 23 394 0', 'FADER 23 404 0']),
    'desk_system_ok': (True, 0, 1, 24, 774, 39, 0, 0, 22, ['SYS']),
    'desk_system_lf_cr': (True, 0, 1, 24, 643, 40, 0, 0, 22, ['SYS']),
    'desk_retry': (True, 0, 1, 21, 324, 7, 0, 3, 25, ['FADER 23 306 0']),
    'desk_stale_padding': (True, 0, 1, 21, 311, 330, 0, 0, 25, ['FADER 0 570 0']),
    'host_e2': (False, 226, 0, 16, 0, 0, 0, 0, 30, []),
    'host_e2_retry3': (False, 226, 0, 16, 0, 0, 0, 3, 30, []),
    'host_e2_counter': (False, 226, 0, 16, 0, 5909, 0, 0, 30, []),
    'host_e3': (False, 227, 0, 16, 0, 5, 0, 0, 30, []),
    'host_ack': (False, 160, 0, 16, 0, 120046, 328, 0, 30, []),
    'host_keepalive': (False, 0, 1, 17, 0, 119751, 0, 0, 29, []),
    'host_meter': (False, 0, 1, 24, 651, 119676, 0, 0, 22, ['METER 0 255']),
    'host_ring': (False, 0, 5, 36, 1103, 38151, 0, 0, 10, ['RING 0 128', 'SBTN 0 4 0', 'SBTN 0 2 0', 'SBTN 0 3 0', 'SBTN 0 10 0']),
    'host_scribble': (False, 0, 1, 27, 864, 4, 0, 0, 19, ['SCRIB 0 OMX1']),
    'host_counter': (False, 0, 1, 31, 580, 2, 0, 0, 15, ['CTR 25 0 0000000000000000']),
    'host_fader': (False, 0, 1, 21, 311, 120047, 0, 0, 25, ['FADER 0 570 0']),
    'host_batch': (False, 0, 48, 160, 7471, 48, 0, 0, 0, ['ZBTN 24 40 0', 'ZBTN 24 13 0', 'SBTN 0 8 0', 'SBTN 0 7 0', 'SBTN 0 6 0', 'SBTN 0 4 0', 'SBTN 0 2 0', 'SBTN 0 3 0', 'SBTN 0 10 0', 'SBTN 1 8 0', 'SBTN 1 7 0', 'SBTN 1 6 0', 'SBTN 1 4 0', 'SBTN 1 2 0', 'SBTN 1 3 0', 'SBTN 1 10 0', 'SBTN 2 8 0', 'SBTN 2 7 0', 'SBTN 2 6 0', 'SBTN 2 4 0', 'SBTN 2 2 0', 'SBTN 2 3 0', 'SBTN 2 10 0', 'SBTN 3 8 0', 'SBTN 3 7 0', 'SBTN 3 6 0', 'SBTN 3 4 0', 'SBTN 3 2 0', 'SBTN 3 3 0', 'SBTN 3 10 0', 'SBTN 4 8 0', 'SBTN 4 7 0', 'SBTN 4 6 0', 'SBTN 4 4 0', 'SBTN 4 2 0', 'SBTN 4 3 0', 'SBTN 4 10 0', 'SBTN 5 8 0', 'SBTN 5 7 0', 'SBTN 5 6 0', 'SBTN 5 4 0', 'SBTN 5 2 0', 'SBTN 5 3 0', 'SBTN 5 10 0', 'SBTN 6 8 1', 'SBTN 6 7 0', 'SBTN 6 6 0', 'SBTN 6 4 0']),
    'desk_vpot_strip1': (True, 0, 1, 19, 305, 3, 0, 0, 27, ['VPOT 0 1']),
    'desk_vpot_strip8': (True, 0, 1, 19, 310, 1548, 0, 0, 27, ['VPOT 7 -1']),
    'desk_jog_left': (True, 0, 1, 19, 331, 246, 0, 0, 27, ['JOG -1']),
    'desk_jog_right': (True, 0, 1, 19, 333, 300, 0, 0, 27, ['JOG 1']),
    'desk_key_af_on': (True, 0, 1, 19, 248, 1, 0, 0, 27, ['ZBTN 29 11 1']),
    'desk_key_af_off': (True, 0, 1, 19, 184, 2, 0, 0, 27, ['ZBTN 29 11 0']),
    'desk_high_padding': (True, 0, 1, 19, 305, 19, 0, 0, 27, ['VPOT 0 1']),
}


ANNOUNCE = {
    # name: (host_mac, unknown_a, unknown_b, prefix, version, name)
    "desk_e0_cold": ("000000000000", 1, 6, 0x76, "1.08", "CNTRL|24"),
    "desk_e0_last_host": ("345a609f9ebe", 1, 6, 0x76, "1.08", "CNTRL|24"),
    "desk_e1_host": ("00145c9b282d", 1, 6, 0x76, "1.08", "CNTRL|24"),
}
SYSTEM = {"desk_system_ok": (0x01, "4f4b"), "desk_system_lf_cr": (0x01, "0a0d")}


def frames(path):
    with open(path) as fp:
        for line in fp:
            if line.startswith("#") or not line.strip():
                continue
            name, hexs = line.split()
            yield name, bytes.fromhex(hexs)


def events(d):
    """The messages of a data frame as the C decoder reports them."""
    out = []
    ms = d.body.messages
    i = 0
    while i < len(ms):
        m = ms[i]
        i += 1
        if m.status == 0:
            continue  # a keepalive's 00: a data byte with no status in force
        if m.status == 0xF0:
            s = m.sysex
            p = s.payload
            if s.function == F.vpot_ring:
                mask = 1 if p.address & 0x40 else 0
                for k in range(7):
                    if p.left & (1 << (6 - k)):
                        mask |= 1 << (1 + k)
                    if p.right & (1 << (6 - k)):
                        mask |= 1 << (8 + k)
                out.append(f"RING {p.address & 0x3f} {mask}")
            elif s.function == F.meter:
                out.append(f"METER {p.address} {(p.hi & 0x7f) << 7 | (p.lo & 0x7f)}")
            elif s.function == F.scribble:
                out.append(f"SCRIB {p.address} {p.text.decode('latin1')}")
            elif s.function == F.counter:
                out.append(f"CTR {p.address} {p.dots} {p.digits[::-1].hex()}")
            elif s.function == F.system:
                out.append("SYS")
            else:
                out.append(f"OTHER {s.function}")
            continue
        kind = m.status & 0xF0
        if kind == 0x90:
            ident = m.data2 & 0x3F
            on = int(bool(m.data2 & 0x40))
            if 0x18 <= ident <= 0x1D:
                out.append(f"ZBTN {ident} {m.data1} {on}")
            elif m.data1 == 9:
                out.append(f"TOUCH {ident} {on}")
            else:
                out.append(f"SBTN {ident} {m.data1} {on}")
        elif kind == 0xB0 and m.data1 < 0x20:
            value = m.data2 << 3
            missing = 1
            if i < len(ms) and ms[i].status & 0xF0 == 0xB0 and ms[i].data1 == 0x20 + m.data1:
                value |= (ms[i].data2 >> 4) & 7
                i += 1
                missing = 0
            out.append(f"FADER {m.data1} {value} {missing}")
        elif kind == 0xB0 and m.data1 == 0x5C:
            out.append(f"JOG {m.data2 - 64}")
        elif kind == 0xB0 and 0x40 <= m.data1 < 0x58:
            out.append(f"VPOT {m.data1 - 0x40} {m.data2 - 64}")
        else:
            out.append(f"OTHER {m.status:02x}")
    return out


def commands_counted(d):
    """num_commands as the desk counts: a fader's MSB and LSB are one command."""
    n = 0
    ms = d.body.messages
    i = 0
    while i < len(ms):
        m = ms[i]
        i += 1
        if m.status == 0xB0 and m.data1 < 0x20:
            if i < len(ms) and ms[i].status == 0xB0 and ms[i].data1 == 0x20 + m.data1:
                i += 1
        n += 1
    return n


def fingerprint(d):
    h = d.header
    fp = [d.dst, d.src, d.ethertype, h.numbytes, h.sum, h.send_counter, h.ack_counter, h.retry,
          int(h.cmd.value if isinstance(h.cmd, C) else h.cmd), h.num_commands]
    if h.cmd in (C.announce_offline, C.announce_session):
        b = d.body
        fp += [b.host_mac, b.unknown_a, b.unknown_b, b.version_prefix, b.version.text, b.version.rest,
               b.name.text, b.name.rest, b.tail]
    elif h.cmd == C.data:
        fp += events(d)
        fp += [(m.status, m.running, m.data1, getattr(m, 'data2', None)) for m in d.body.messages if m.status != 0xF0]
        fp += [(m.sysex.maker, m.sysex.device, m.sysex.function.value) for m in d.body.messages if m.status == 0xF0]
        fp += [m.sysex._raw_payload for m in d.body.messages if m.status == 0xF0]
    return fp


def check(name, raw, fails):
    def chk(cond, what):
        if not cond:
            fails.append(f"{name}: {what}")

    d = Diginet.from_bytes(raw)
    desk, cmd, ncmds, numbytes, csum, send, ack, retry, pad, evs = EXPECT[name]
    h = d.header
    chk(d.ethertype == 0x885F, "ethertype")
    chk((d.src[:3] == DESK_OUI) == desk, "who sent it")
    chk(isinstance(h.cmd, C) and h.cmd.value == cmd, f"cmd {h.cmd}")
    chk(h.num_commands == ncmds, f"num_commands {h.num_commands}")
    chk(h.numbytes == numbytes, f"numbytes {h.numbytes}")
    chk(h.sum == csum, f"sum {h.sum:#x}")
    chk(sum(raw[30:14 + numbytes]) & 0xFFFF == csum, "sum is the body byte sum")
    chk((h.send_counter, h.ack_counter, h.retry) == (send, ack, retry),
        f"counters {(h.send_counter, h.ack_counter, h.retry)}")
    chk(len(d.padding) == pad, f"padding {len(d.padding)}")
    chk(len(raw) == 14 + numbytes + pad, "frame length")
    if cmd == 0:
        chk(events(d) == evs, f"events {events(d)}")
        if raw[30:14 + numbytes] != b"\x00":
            chk(commands_counted(d) == ncmds, f"commands counted {commands_counted(d)}")
        for m in d.body.messages:
            if m.status == 0xF0:
                chk(m.sysex.device == 0x01, "device byte")
    if name in ANNOUNCE:
        mac, ua, ub, pre, ver, dev = ANNOUNCE[name]
        b = d.body
        chk((b.host_mac.hex(), b.unknown_a, b.unknown_b, b.version_prefix, b.version.text, b.name.text)
            == (mac, ua, ub, pre, ver, dev), f"announce {b.host_mac.hex()} {b.version.text!r} {b.name.text!r}")
        chk(b.tail == b"\x00" and b.version.rest == bytes(4) and b.name.rest == b"", "announce tail")
        chk(d.dst == b"\xff" * 6, "announce is broadcast")
    if name == "desk_high_padding":
        chk(d.padding[0] >= 0x80, "stale padding byte at or above 0x80 sits after the body")
    if name in SYSTEM:
        sel, data = SYSTEM[name]
        p = d.body.messages[0].sysex.payload
        chk(p.selector == sel and p.data.hex() == data, "system payload")


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
        logical = 30 + EXPECT[name][3] - 16
        base = fingerprint(Diginet.from_bytes(raw))
        for i in range(logical):
            mutated = bytearray(raw)
            mutated[i] ^= 0x01
            try:
                same = fingerprint(Diginet.from_bytes(bytes(mutated))) == base
            except Exception:
                same = False  # a parse error is a change
            if same:
                fails.append(f"{name}: byte {i} changed and the grammar read the same values")
    for name in set(EXPECT) - seen:
        fails.append(f"{name}: missing from the wire file")
    for f in fails:
        print("FAIL", f, file=sys.stderr)
    if fails:
        sys.exit(1)
    print(f"check_wire: ok ({len(seen)} frames from a Control|24)")


if __name__ == "__main__":
    main()
