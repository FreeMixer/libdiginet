# The DigiNet surface protocol (Control|24, ProControl)

What is known about the protocol the Digidesign Control|24 and ProControl speak over Ethernet, gathered from the projects listed below. Every claim names its source. Nothing here was taken from a vendor document. Items marked unknown are settled by captures on a real unit (see the end of this file).

## Sources

Line citations below are to these commits.

| Source | URL | What it covers | What here rests on it |
|---|---|---|---|
| ReaControl24, branch `Release`, commit `2a963e9` (2020-06-26). GPL-3.0-or-later | https://github.com/phunkyg/ReaControl24 | A Control\|24 daemon and OSC client for Reaper: daemon `control24d.py`, control map `control24map.py`, client `control24osc.py` | The header fields and their names, `e2` and `a0`, the counters, stop-and-wait and back-off, the batching limits, the 10 s keepalive and its bug, the button and LED map, and the fader, V-Pot, ring, meter, scribble, automation-LED and counter encodings |
| ReaControl24, branch `Ftr_Version2`, commit `440f29a` (2024-11-19) | https://github.com/phunkyg/ReaControl24/tree/Ftr_Version2 | The newer multi-device daemon `ReaControl.py`, `ReaCommon.py`, the ProControl client `procontrolosc.py`, `pro_control_map.csv`, `test/emulator.py` | The announce layout, broadcast and unicast, the ProControl's name, the stale fourth V-Pot byte |
| ReaControl24 issues #2 to #22 | https://github.com/phunkyg/ReaControl24/issues | Problems users reported | ProControl display addressing (#12, #22) and its device byte |
| procontrol-linux, commit `ecf1da8` (2026-09-27). GPL-3.0-or-later; the documents are in French | https://github.com/julienfernandez/procontrol-linux | A ProControl driver for Linux, with captures and measurements from a real unit. It carries lazlooose's ProControl display fixes (`docs/displays.md`) | The header sum, `e0`/`e1` and the host MAC in `e1`, the keepalive bug and its fix, the fader echo, the 10 Mbit/s half-duplex link, the ProControl counter and display addresses, the dangers of the `0x70` family |
| C24-Engine-Renewed, commit `94d7a3b` (2026-08-16). No licence | https://github.com/Davitekk/C24-Engine-Renewed | Control\|24 tools for macOS that drive a real desk: a Pro Tools HUI bridge (`Control24-Engine/motore.py`), CamillaDSP and media modes (`Camilla24/`, `HUI-OS/`), a calculator on the keypad and counter (`Calculator24/`), an LED finder (`Control24-LED-Finder/`) | The header as a host fills it, `e3`, the minimum frame, the ping and watchdog timings, running status, display pacing, the 14-bit fader, the ring bits (A1), the meter bits (A2), the seven-segment bits (A3), the counter's digit and dot order (A4, A5), the centre displays, the automation and counter-mode LED values, the device-name write. Every point is compared with this library in "Checked against C24-Engine-Renewed" below |
| Neyrinck, legacy control surface research | https://neyrinck.com/v-control-pro/legacy-control-surface-research/ | Neyrinck's one-line description of the surfaces' link: "low level ethernet communications, cryptography, CRC error detection" | R3 and R11 |

---

## The protocol

### Transport

| Property | Finding | Status | Citation |
|---|---|---|---|
| Framing | Raw Ethernet II, EtherType **0x885F**, no IP | Decoded, confirmed by three projects | `control24d.py:42`, `:123`; procontrol-linux `docs/protocol.md` (frame offset table) |
| Vendor | Source OUI **00:a0:7e** (Digidesign) | Decoded | `control24d.py:101`, `:403` |
| Capture filter used | `(ether dst <host-mac> or broadcast) and ether[12:2]=0x885f` | — | `control24d.py:69`, `:261` |
| Link | The ProControl showed **10 Mbit/s half duplex** on a direct link. The Control|24's port is of the same generation | Observed (ProControl); **to verify** on the C24 | procontrol-linux `docs/protocol.md` ("10 Mbit/s half-duplex"), `docs/capture-linux.md:14-26` |
| Minimum frame | Bodies are padded to the Ethernet minimum (46-byte payload). Bytes after the logical length are padding | Decoded | C24-Engine `motore.py:520`, `:538`; ReaControl's 30-byte receive logs in `pro_control_map.csv` (stale bytes after a 3-byte command) |
| Broadcast and unicast | The desk **broadcasts** its announce to ff:ff:ff:ff:ff:ff. Everything else is unicast between the desk MAC and the host MAC | Decoded | `control24d.py:396-418`; `ReaControl.py:418-436` (Ftr_Version2) |

**The header** (16 bytes after the 14-byte Ethernet header, big-endian; `control24d.py:137-150`):

| Frame offset | Size | Field (ReaControl name) | Meaning | Status |
|---|---|---|---|---|
| 14 | 2 | `numbytes` | 16 + body length (keepalive = 17, bare control frame = 16, announce = 50) | Decoded (`control24d.py:198`, `:221`) |
| 16 | 2 | `unknown1` / "parity" | **16-bit additive sum of the body.** All 418 of 418 ProControl→host frames matched (procontrol-linux `tools/audit_diginet.py:26-27`, `docs/protocol.md` §Mise à jour). ReaControl's one non-zero value, `0x0244` on the clock-init frame (`control24d.py:415-416`), is exactly the byte sum of that body. ReaControl and C24-Engine send **zero** everywhere else, and the Control|24 accepts it | Strongly supported; whether the C24 verifies host→desk is **unknown** |
| 18 | 4 | `sendcounter` | The sender's own sequence. ReaControl advances it by the number of commands in the frame; C24-Engine by one per frame, ACKs and pings included. The desk works with both | Decoded (`control24d.py:502-504`; `motore.py:516-545`, `:940-960`) |
| 22 | 4 | `cmdcounter` | In an ACK: the peer's sequence being acknowledged | Decoded (`control24d.py:439-447`, `:499-500`) |
| 26 | 2 | `retry` | Non-zero = the desk is retransmitting because it did not get our ACK in time | Partly decoded (`control24d.py:430-437`) |
| 28 | 1 | `c24cmd` | `0x00` = data, `0xA0` = ACK, `0xE2` = online/wake, `0xE0` = announce (offline), `0xE1` = announce (in session), `0xE3` = disconnect | `a0`/`e2` in `control24common.py:48-51`; `e0`/`e1` in procontrol-linux `tools/procontrold.py:102-115` and `docs/session-reference.md`; `e3` in C24-Engine `motore.py:1069-1079` |
| 29 | 1 | `numcommands` | Number of commands in the body. A fader move `B0 tt MSB (20+tt) LSB` counts as one | Decoded (`control24d.py:438`, `:498`; `motore.py:585-590`) |

**Discovery and handshake:**

1. The desk broadcasts an `e0` announce about every 7 s when idle (ProControl: 4 in 30 s, 104 in 740 s; procontrol-linux `docs/observations-2026-09-13.md:60,73`). The body is 15 unknown bytes, then a 9-character version (`1.37`), then a 9-character device name: **`CNTRL|24`** for a Control|24, `MAINUNIT` for a ProControl (`control24d.py:168-176`; `ReaControl.py:624-636`; `test/emulator.py:14-17`). C24-Engine reads the version at body bytes 14–24 and the name at 24–32 (`motore.py:1191-1198`).
2. The host sends `e2` with no body (`control24d.py:414`). ReaControl then sends a clock-clear frame `F0 13 01 30 19 00 ×8 F7` with checksum `02 44` (`control24d.py:415-418`). procontrol-linux showed the clock frame is not needed (`docs/session-reference.md`, "Essai local").
3. The desk ACKs (`a0`, ack counter = our sequence). A ProControl then switches its broadcasts to **`e1`, which carries the host MAC**, so on a ProControl an `e1` announce is the "online" proof and an ACK alone is not (procontrol-linux `docs/online-2026-09-13.md:35-36`). **A Control|24 announces its session in `e0` or in `e1`, and can change from one to the other without a reboot** (firmware 1.08, measured 2026-10-29, libdiginet #29, #30). After each boot it took the session on the `a0` and kept broadcasting `e0`, the bytes of its idle announce but for the counter, while it carried out what it ACKed (a fader moved). Without a reboot it then began answering `e2` with `a0` and, at once and on every announce, `e1` naming the host, each time after its front panel had been used: the Utility page opened and closed, or faders moved by hand (seen three times). That front-panel use is what switches it is likely, not proven. On a Control|24 the `a0` is the online proof; an `e0` ends the session only once an `e1` has named the host, and before that a host frame the desk stops ACKing is the only sign that the session is gone. **A Control|24 that boots while large unknown broadcasts reach it ignores every host:** booted with reac-pw sending about 32 REAC frames of 1492 bytes a second on its link, it ACKed no `e2`, ours nor ReaControl24's, and stopping the traffic did not bring it back; booted on a quiet link it took the session at once. Such a desk keeps announcing and lets every `e2` time out, and nothing on the wire names the cause, so the session reports it on its own: after `deaf_wakes` (3) wakes in a row that time out while the desk still announces (an announce within `offline_ms`), it gives `DIGINET_N_DESK_DEAF` once (#35). An `a0` for an `e2`, an `e1` naming another host (`DIGINET_N_FOREIGN`, a different notice: that desk hears hosts) or a timeout with no recent announce ends the count.
4. Disconnect is `e3` with no body. It drops the session (C24-Engine `motore.py:1069-1079`, "the CORRECT way to disconnect"). A Control|24 (firmware 1.08, measured 2026-10-29, #33) then keeps announcing `e1` naming that host for about 30 s (34 s and 30 s), until its own timeout, before it falls back to `e0`. With `auto_wake` the session therefore sends `e2` on an `e1` naming its own host as it does on an `e0`, so a restarted host need not wait for the desk to time out.

C24-Engine sends `e2` five times 5 ms apart, waits 200 ms and then drives the desk without waiting for an ACK or an `e1` (`motore.py:1172-1189`). It treats any frame from the desk as the desk being there.

**Acks, sequencing, retransmit:**

- Every desk data frame gets a host ACK. ReaControl sends it about 0.8 ms after receipt (`TIMING_BEFORE_ACKT`, `control24d.py:48`, `:445-447`), with the desk's `sendcounter` in our `cmdcounter` field (`:499-500`). ReaControl does not advance its own counter on an ACK; C24-Engine does (`motore.py:940-948`). Both work, so the desk tolerates either.
- **Host→desk is stop-and-wait: one frame in flight.** `receive_handler` blocks on `sendlock` until the desk's `a0` arrives (`control24d.py:460-468`). It logs every 100 ms and never gives up or retransmits: `#TODO implement daw-desk retry packets` (`:463`). procontrol-linux kept the same one-frame window (`docs/fader-echo-2026-09-14.md`, "une seule trame en attente d'ACK").
- When the desk sends a retry frame, ReaControl pauses its own sending for 300 ms (`TIMING_BACKOFF`, `control24d.py:53`, `:433-437`).
- C24-Engine does not wait for ACKs at all: it sends frame after frame, never retransmits, and never sets or reads the retry field (`motore.py:516-550`). So the desk accepts more than one host frame in flight.
- Batching: up to 48 commands or 314 bytes per frame (`control24d.py:298-299`, `:333-341`). C24-Engine packs whole display batches into one frame, up to 51 commands and 461 bytes when it initialises the scribble strips (`motore.py:962-984`) and 100 LED commands when it blanks the desk (`:1036-1067`), and paces display batches about 2 ms apart, "so the desk's controller renders cleanly (no datamoshing)" (`motore.py:531-550`).

**Keepalive (a real bug in the reference):**

- ReaControl sends a keepalive frame (body `00`, ncmds 1) when nothing has been sent for 10 s (`control24d.py:46`, `:285-293`, `:507-511`). But every ACK counts as "sent" (`pcap_last_sent`, `:484`), so a busy surface never sends one.
- procontrol-linux measured a 48 s gap between keepalives with 225 ACKs in between, and the desk fell back to `e0` (offline). Their fix is a keepalive every 10 s **regardless of ACKs** (`docs/online-2026-09-13.md:136-160`). After the fix the longest gap was 10.048 s and the desk stayed online.
- C24-Engine pings every 1 s with an empty 16-byte data frame (count 0, no body), and declares the desk offline after 4 s with no traffic (`motore.py:404`, `:951-960`, `:1023-1034`). Its calculator pings every 2.5 s (`Calculator24/Calculator24.py:78-81`). The desk accepts both keepalive forms, the empty frame and the body `00`.
- The desk-side timeout is **not measured**; "about 45 s" is an upper bound on the ProControl.

**One socket, every interface (libdiginet's own, #35):**

Nothing in the protocol ties a desk to an interface: it broadcasts its announce on whatever link it is cabled to, and a host answers from that link's MAC. So one `AF_PACKET` socket bound to EtherType 0x885F on no interface (`diginet_packet_open_any()`) hears every desk on every interface, interfaces that come up later included (a USB adapter plugged in afterwards). Each frame comes with the index of the interface it arrived on (`diginet_packet_recvfrom()`), and a frame goes out of one named interface (`diginet_packet_sendto()`); a host MAC is the MAC of the desk's interface (`diginet_if_mac()`).

- **The desk mux** (`diginet_mux.h`) runs one session per desk over that socket. A desk is keyed by its MAC. Its first valid announce, from a Digidesign MAC, makes it present on the interface it came in on (`DIGINET_MUX_N_APPEARED`); from then on its frames come from that interface only, and the same MAC on another interface while it is present (a bridge and its port both show a frame) is set aside. An attached desk's session sends out of the desk's interface, from that interface's MAC.
- **Gone:** nothing from the desk for `gone_ms` (30 s), or its session ended on silence (`DIGINET_R_SILENCE`, nothing for `offline_ms`, 25 s): `DIGINET_MUX_N_GONE`. 30 s is more than three announce periods (6.0-9.4 s, #29) and more than `offline_ms`, so an attached session gives up first. A Control|24 in an `e0` session loses it sooner, on its first unACKed keepalive (`DIGINET_R_ACK_LOST`), and is then gone at `gone_ms`.
- **The capability:** `cap_net_raw` is checked when the socket is opened, never after. `diginet-packet-helper` holds it, opens the socket, passes it over a Unix socket (`SCM_RIGHTS`) and exits; `diginet_packet_open_by_helper()` starts it and takes the socket, and `diginet_packet_receive_fd()` takes only an `AF_PACKET` socket. The program that drives the desks holds no capability.
- **What the socket also hears.** It hears 0x885F on every interface, a REAC trunk included, and the mux would answer a desk there. The mux reports each desk's interface; whether a host should refuse a desk on an interface that carries REAC is the host's to rule, from that interface.

### The command set (body)

The body is a byte stream of MIDI-shaped messages. **Running status occurs**: C24-Engine expands it before parsing (`motore.py:1100-1137`, `:1209`), and says a desk fader move arrives as `B0 tt MSB (20+tt) LSB` with the second `B0` left out. ReaControl instead splits on known status bytes and `F7` (`control24osc.py:1175-1200`), which mis-parses running status. The desk uses the same encoding in both directions for faders, buttons and LEDs.

**Faders (24 motor faders)** — decoded:

- Desk→host and host→desk: `B0 tt MSB (20+tt) LSB`, a 14-bit MIDI CC pair carrying a **10-bit** position: MSB = v>>3, LSB = (v&7)<<4 (`control24osc.py:166-176`, `:916-920`, `:986-1001`).
  - Example: v = 512 gives `B0 tt 40 (20+tt) 00`.
  - C24-Engine writes and reads plain 14-bit values, MSB = v>>7, LSB = v&0x7F (`motore.py:585-590`, `:1345-1372`). These are the same bytes with the low 4 bits used.
- procontrol-linux confirmed raw travel of 0–1023 on fader 1 (`docs/protocol.md`, register row "Fader 1 et contact").
- **Touch:** a strip button `90 09 (40|tt)` on touch, `90 09 tt` on release (`control24map.py:942-946`).
- **The motor holds a set-point.** ReaControl echoes the hand's position back to the desk at most every 100 ms during a move (`control24osc.py:974-976`, `TIMING_FADER_ECHO :50`), and re-sends the last position on release (`:978-983`).
  - procontrol-linux filmed the consequence of a late echo: on release the motor drove back to the old set-point, then to the new one (`docs/fader-echo-2026-09-14.md`).
  - Their fix: echo the exact physical value immediately on release, and refuse any other host value while the cap is touched.
  - **Status:** encoding decoded. Whether the motor pushes against a touched cap is **unknown** on the C24.

**V-Pots (24) and jog wheel** — decoded:

- Turn: `B0 (40|tt) dd` with delta = dd − 64 (`control24map.py:20-36`; `control24osc.py:890-906`).
- ReaControl reads a 4th "velocity" byte (`control24osc.py:893`). The ProControl logs show that byte is stale buffer content (`pro_control_map.csv`, rows 5/15/25: arbitrary values), so treat V-Pot input as 3 bytes.
- The jog wheel is "virtual track 28": `B0 5C dd`, delta = dd − 64 (`control24osc.py:369-373`, `:746-775`; procontrol-linux `docs/protocol.md`, "Le jog `b0 5c valeur`"). C24-Engine reads V-Pots and jog the same way, three bytes each (`motore.py:1374-1391`), and hands the jog on with its sign inverted relative to the V-Pots. Which way of turning gives dd > 64 on each control is **unknown**.
- Scrub and Shuttle are buttons in zone `0x1C`, ids 0x12/0x13 (`control24map.py:746-756`).

**V-Pot LED rings (15 LEDs)** — decoded:

- `F0 13 01 00 (tt | 0x40·LED1) b1 b2 F7`: bit 6 of the address byte lights LED 1, `b1` bits 6..0 are LEDs 2..8, `b2` bits 6..0 are LEDs 9..15.
- ReaControl ships dot and fill tables (`control24osc.py:783-816`, `:864-882`). C24-Engine computes the same, LED 1 in the address byte and LED 2 at bit 6 of `b1` (`motore.py:633-643`).

**Buttons and LEDs** — decoded, about 200 controls mapped:

- **Strip buttons:** `90 bb (40·pressed | tt)`, where `bb` is the button: 00 RecArm, 01 Pan/Send, 02 EQ, 03 Dynamics, 04 Switch/Active, 05 auto-mode, 06 Select, 07 Solo, 08 Mute, 09 fader Touch, 0A Inserts, 0B Peak, 0C SourceToggle, 0D RollOff (`control24map.py:886-962`).
- **Section buttons:** `90 bb (40·pressed | zone)`, zone 0x18..0x1D (`control24map.py:37-48`, `ChildByteMatch 0x18`):

| Zone | What it holds | Citation |
|---|---|---|
| 0x18 | F1–F10, automation enable and mode, Shift/Option/Control/Command modifiers, Show Values/Group/Names/Info, Solo Clear, meter select | `control24map.py:49-330` |
| 0x19 | Window, zoom presets, Nav/Zoom/SelAdj, cursor keys, Counter Mode | `control24map.py:331-446` |
| 0x1A | Numeric keypad | `control24map.py:447-505` |
| 0x1B | Edit mode/function/tools, Bank Left/Nudge/Right, Master Faders, Undo/Save/Esc, Groups | `control24map.py:506-668` |
| 0x1C | Transport and Talkback | `control24map.py:669-757` |
| 0x1D | Monitor, inserts, assignment, Sends Flip and A/F–E/J, pans, channel-bar scroll | `control24map.py:758-880` |

- **LEDs** use the same 3-byte message: `90 bb (40·on | zone-or-track)`. ReaControl builds its LED table by walking the input map (`control24osc.py:178-208`, `:1005-1062`). C24-Engine: `send_native_button_led` (`motore.py:552-556`) and a separately discovered LED dictionary (`Control24-LED-Finder/c24_led_dictionary.json`, 1149 lines, facts only).
- **Per-strip automation LEDs:** `F0 13 01 20 tt bits F7` with write 0x40, touch 0x20, latch 0x10, trim 0x08, read 0x04 (`control24osc.py:1082-1098`). C24-Engine uses the same values (`motore.py:777-779`), noting that its first version had touch and trim swapped; its docstring at `:438-440` still shows the swapped pair.
- **Counter-mode LEDs:** `F0 13 01 20 19 xx F7` (`control24osc.py:429-456`), with timecode 0x20, feet+frames 0x10, bars\|beats 0x08, min:sec 0x40, all off 0x00 (`motore.py:339-343`, `:449-470`).
- **Status:** the map covers what a mixing console needs. Some zone assignments are ReaControl's names and are unverified on a C24.

**Scribble strips** — decoded, with one open point:

- `F0 13 01 40 aa 00 c1 c2 c3 c4 F7`: **4 characters**, plain ASCII, padded with spaces (`control24osc.py:609-673`).
- Special glyphs: a "dot plus small digit" glyph for `.1`..`.9` is `chr(ord(d) − 26)`, i.e. 0x17..0x1F (`control24osc.py:662-671`).
- Addresses:
  - ReaControl writes strip n at `aa = n` (0x00..0x17), plus virtual 24..31 (`control24osc.py:375-376`, `:631`).
  - C24-Engine writes names at `aa = 0x20+n` (`motore.py:962-975`) and the two centre "channel bar" displays at `0x1D`/`0x1E` (`motore.py:558-565`).
  - On the ProControl, `00..07` is the top row and `20..27` the bottom row, 8 characters each (issue #12; procontrol-linux `docs/displays.md`).
  - **What `0x00+n` versus `0x20+n` means on a Control|24 (two layers, two rows, or aliases) is unknown.**
- `long_scribble` spreads a 96-character message over all strips (`control24osc.py:338-345`).

**Meters** — encoding decoded, physical segment count unknown:

- `F0 13 01 10 ch hi lo F7`, with ch 0..23 left and 0x20+ch right; bus meters start at 24/56 (`control24osc.py:540-606`).
- The value is a **thermometer bitmask** over 14 bits (two 7-bit bytes): n segments lit is the n lowest bits, `hi` = mask>>7, `lo` = mask&0x7F. ReaControl's 15-step table is at `:552-568`; C24-Engine builds the mask the same way, at most 14 bits, and refreshes at 25 Hz (`motore.py:913-928`; `Camilla24/camilla_engine.py:92`, "the C24 bitmask holds up to 14").
- Whether the desk decays a lit meter on its own (as the X-Touch does) is unknown.

**Counter / timecode** — decoded:

- `F0 13 01 30 19 dots d8 … d1 F7`: 8 seven-segment digits, the **rightmost first** (d8 … d1 with d1 the leftmost), then F7 (`control24osc.py:382-425`, `:459-520`; `motore.py:616-631`; `HUI-OS/HUI_OS.py:612-626`; `Calculator24/Calculator24.py:83-112`).
- A segment byte has **bit 6 = a, 5 = b, 4 = c, 3 = d, 2 = e, 1 = f, 0 = g**: C24-Engine draws `0` as 0x7E, `1` as 0x30, `-` as 0x01, `E` as 0x4F and `r` as 0x05 (`motore.py:616-619`; `Calculator24/Calculator24.py:27-31`). The library's table covers 0–9 and A b C d E F H h J L o P r S U Y Z -.
- The `dots` byte: **bit k lights the dot after the k-th digit from the left** (bit 0 the leftmost). The rightmost digit has no dot bit. C24-Engine's calculator shows "12.5" with dots = 0x40, and its clock puts the minutes dot at bit 5 (`Calculator24/Calculator24.py:83-93`; `HUI-OS/HUI_OS.py:612-621`; `motore.py:621-626`).
- The ProControl uses address `0x09` and device byte `00` instead of `0x19` and `01` (procontrol-linux `docs/displays.md`).

**System and diagnostic family `F0 13 xx 70 …`** — dangerous:

- Device-name write to the desk's memory: `F0 13 01 70 00 6E <8 chars> F7` (C24-Engine `motore.py:566-574`).
- On the ProControl the same family reads firmware memory (`70 00` comm processor, `70 01` faders) and produced spurious touch events (procontrol-linux `docs/protocol.md`, top section; `docs/fader-touch-recovery-2026-09-21.md`).
- A host must never send this family; the library refuses to encode it.

**The device byte** after `F0 13` is `01` for the Control|24 and `00` for the ProControl main unit (issue #22 trace `f0 13 00 40 …`; procontrol-linux `docs/protocol.md`). This is a per-device personality, not a constant.

### Sources and licences

ReaControl24 and procontrol-linux are GPL-3.0-or-later, like this library. C24-Engine-Renewed carries no licence, so only facts come from it (byte layouts, bit orders, timings), never code or tables. libdiginet is a new implementation written from this description, not a port: the byte grammar lives in `diginet.ksy`, each field cited to the sources above.

---

## Checked against C24-Engine-Renewed

C24-Engine-Renewed drives a real Control|24 from a working host, so each point it touches is
compared here with what this library does. Citations are to its files at commit `94d7a3b`.

| Point | This library | C24-Engine-Renewed | Result |
|---|---|---|---|
| Header layout | 16 bytes: `numbytes`, sum, send counter, ack counter, retry, command, count | The same offsets: length at 0, counter at 4, ack counter at 8, command at 14, count at 15, the rest zero (`motore.py:516-545`, `:930-960`) | Agrees |
| Minimum frame | Padded to a 46-byte payload | `bytearray(max(46, length))` (`motore.py:520`, `:538`) | Agrees |
| Command codes | `00` data, `a0` ACK, `e2` wake, `e3` disconnect, `e0`/`e1` announce | `00`, `a0`, `e2`, `e3`; the announce is told apart by its length 0x32 (`motore.py:930-960`, `:1069-1079`, `:1191-1198`) | Agrees |
| Header sum | Body sum by default, zero selectable | Always zero, and the desk works (`motore.py:516-545`) | Agrees that zero is accepted. Whether the desk checks a non-zero sum (R3) stays open |
| Send counter | Advanced by the number of commands in a data frame; ACK, `e2` and `e3` do not advance it (as ReaControl does) | Advanced by one for every frame, ACKs and pings included (`motore.py:516-545`, `:940-960`) | The desk works with both, so it does not check the step (A8) |
| ACK | Every desk data frame is ACKed at once, with the desk's send counter in the ack counter | The same, for every desk frame other than an announce (`motore.py:1200-1201`, `:940-948`) | Agrees |
| Command count | A fader move `B0 tt MSB (20+tt) LSB` counts one; a frame's count is its commands | A fader move is sent with count 1, a batch with the number of its messages (`motore.py:585-590`, `:531-545`). Its calculator sends single messages with count 0x23 (`Calculator24/Calculator24.py:112`, `:155`) | Agrees (A7). The desk seems not to check the count against the body |
| Frames in flight | One host data frame in flight, retransmitted with the retry field after 100 ms | No wait for ACKs, no retransmission, the retry field never set or read (`motore.py:516-550`) | No conflict: the desk takes more than one frame in flight (R8) |
| Frame size | At most 48 commands and 314 bytes | Up to 51 commands and 461 bytes (`motore.py:962-984`), and 100 commands (`:1036-1067`) | No conflict: the library's limits are inside what the desk takes (R8) |
| Display pacing | 2 ms between frames that carry display writes | 2 ms after each display batch (`motore.py:546-550`) | Agrees |
| Keepalive | Body `00`, count 1, every 10 s on its own clock | An empty data frame, count 0, every 1 s (`motore.py:951-960`, `:1023-1034`); every 2.5 s in the calculator (`Calculator24/Calculator24.py:78-81`) | Both forms work. The desk's own timeout (R5) stays open |
| Offline detection | 25 s with no frame from the desk | 4 s, with its 1 s pings keeping the desk talking (`motore.py:404`, `:1028-1033`) | No conflict: each interval is longer than that host's keepalive |
| Wake | One `e2`, then wait for an `a0` and an `e1` naming this host | `e2` five times 5 ms apart, then 200 ms, then drive the desk (`motore.py:1172-1189`) | No conflict |
| Announce | Version from body byte 15, name from byte 24, 9 bytes each (ReaControl's layout) | Version from byte 14 (10 bytes, cut at the first NUL), name from byte 24 (8 bytes) (`motore.py:1191-1198`) | The name agrees. Whether byte 14 belongs to the version stays open (M0 capture) |
| Host MAC in `e1` | Searched for in the leading bytes (A6) | Not read | Open (A6) |
| Running status | Expanded; a data byte with no status in force is reported and skipped | Expanded; such a byte is skipped (`motore.py:1100-1137`) | Agrees |
| Fader | 10-bit position, MSB = v>>3, LSB = (v&7)<<4 | 14-bit, MSB = v>>7, LSB = v&0x7F, both ways (`motore.py:585-590`, `:1345-1372`) | Agrees: the same bytes, with the low 4 bits used |
| Touch | `90 09 (40\|tt)` touched, `90 09 tt` released | The same (`motore.py:1249-1259`) | Agrees |
| V-Pot and jog | `B0 (40\|tt) dd` and `B0 5C dd`, three bytes, delta = dd − 64 | The same (`motore.py:1374-1391`); the jog is handed on with its sign inverted relative to the V-Pots | Agrees on the bytes. Which way of turning is dd > 64 stays open (M1) |
| Ring LEDs | LED 1 = bit 6 of the address byte; `b1` bits 6..0 = LEDs 2..8; `b2` bits 6..0 = LEDs 9..15 | The same (`motore.py:633-643`) | Agrees (A1) |
| Meter bits | n segments = the n lowest of 14 bits; `hi` = mask>>7, `lo` = mask&0x7F | The same, at most 14 bits (`motore.py:913-926`; `Camilla24/camilla_engine.py:92`) | Agrees (A2). The number of LEDs (R7) stays open |
| Seven-segment bits | Was bit 0 = a ... bit 6 = g | Bit 6 = a ... bit 0 = g: `0` = 0x7E, `1` = 0x30, `-` = 0x01, `E` = 0x4F (`motore.py:616-619`; `Calculator24/Calculator24.py:27-31`) | **Contradicted; fixed.** `diginet_seg7` now gives bit 6 = a (A3) |
| Counter digit order | Rightmost digit first on the wire | The same (`motore.py:621-631`; `HUI-OS/HUI_OS.py:612-626`; `Calculator24/Calculator24.py:99-112`) | Agrees (A4) |
| Counter dots | Was bit k = the k-th digit on the wire, the leftmost dot refused | Bit k = the k-th digit from the left, the rightmost digit with no bit: "12.5" is dots 0x40 (`Calculator24/Calculator24.py:83-93`; `HUI-OS/HUI_OS.py:612-621`; `motore.py:621-626`) | **Contradicted; fixed.** `DIGINET_COUNTER_DOT(d)` is now bit d, and a dot on the rightmost digit is refused (A5) |
| Automation LEDs | write 0x40, touch 0x20, latch 0x10, trim 0x08, read 0x04 | The same values in use (`motore.py:777-779`); the docstring at `:438-440` still has touch and trim swapped, as its code comment explains | Agrees |
| Counter-mode LEDs | `F0 13 01 20 19 bits F7`, bits passed through | timecode 0x20, feet+frames 0x10, bars\|beats 0x08, min:sec 0x40 (`motore.py:339-343`, `:449-470`) | Agrees; the values are now in "Buttons and LEDs" |
| Scribble strips | 4 characters at any address the caller names | Names at `0x20+n`, the centre displays at `0x1D`/`0x1E` (`motore.py:558-564`, `:962-978`) | Agrees. What `0x00+n` is beside `0x20+n` (R6) stays open |
| `0x70` family | Refused by the encoder, the body check and the frame builder | Writes the desk's name with `F0 13 01 70 00 6E <8 chars> F7`, taken from a Pro Tools capture (`motore.py:566-573`) | Agrees that the family writes the desk's memory |

## Assumptions

Each point below is a choice libdiginet makes in one constant or one function, so a capture
that contradicts it is a one-line change. Where C24-Engine-Renewed decides the point, the
library follows it; a capture on our own unit is still the last word.

| # | Point | What the library does | Evidence | Still to check on the desk |
|---|---|---|---|---|
| A1 | Ring LED order inside `b1`/`b2` | Bit 6 = LED 2 ... bit 0 = LED 8 in `b1`; bit 6 = LED 9 ... bit 0 = LED 15 in `b2` | C24-Engine-Renewed (`motore.py:633-643`) | Light LED 2 alone on strip 1 **Measured 2026-10-29 (Control|24 1.08, #29):** mask bit 0 lights the leftmost of the ring's 15 LEDs; all 15 light with 0x7FFF. |
| A2 | Meter bit order | Bit 0 of `lo` is the bottom segment; n segments lit = the n lowest bits of the 14 | C24-Engine-Renewed (`motore.py:913-926`) | R7 **Measured 2026-10-29 (Control|24 1.08, #29):** n segments light from the bottom; 7 reach the -18 mark; the meter has 14 (9 green, 4 orange, 1 red). |
| A3 | Seven-segment bits | Bit 6 = a, 5 = b, 4 = c, 3 = d, 2 = e, 1 = f, 0 = g | C24-Engine-Renewed (`motore.py:616-619`; `Calculator24/Calculator24.py:27-31`) | Write `8` with one bit cleared at a time |
| A4 | Counter digit order | The API takes the digits left to right as shown; the wire carries them right to left (`d8 … d1`) | C24-Engine-Renewed (`motore.py:621-631`; `Calculator24/Calculator24.py:99-112`) | Write `12345678` **Measured 2026-10-29 (Control|24 1.08, #29):** `12345678` reads left to right as written. |
| A5 | Counter dots | Bit k lights the dot after the k-th digit from the left (k = 0 the leftmost). A data byte holds 7 bits, so the rightmost digit has no dot and a dot there is refused | C24-Engine-Renewed (`Calculator24/Calculator24.py:83-93`; `HUI-OS/HUI_OS.py:612-621`) | Write `12.5`, then each dot bit alone **Measured 2026-10-29 (Control|24 1.08, #29):** `12.5` shows its dot between the 2 and the 5. |
| A6 | Host MAC in the `e1` body | Searched for anywhere in the 15 unknown leading bytes; the probe prints the offset where it was found | None: no source reads it | M1 **Measured 2026-10-29 (Control|24 1.08, #29):** body offset 0, when the desk sends e1 (it may announce e0 instead, step 3 above). |
| A7 | `numcommands` | Counts commands as the encoders make them: a fader move (`B0 tt MSB (20+tt) LSB`) is one command | ReaControl24 and C24-Engine-Renewed send it so (`motore.py:585-590`); the desk also accepts a count that does not match (`Calculator24/Calculator24.py:112`) | M1 logs of desk frames: what the desk puts there **Measured 2026-10-29 (Control|24 1.08, #29):** every desk frame carried one command, count 1. |
| A8 | Counter sequence | A data frame carries the sender's counter after adding its own commands; ACK, `e2` and `e3` carry it unchanged; an ACK echoes the peer's counter | ReaControl24 steps by commands, C24-Engine-Renewed by frames, and the desk works with both, so the step is not checked | M1: whether the desk's ACK echoes our counter exactly, which the transport matches on **Measured 2026-10-29 (Control|24 1.08, #29):** every ACK echoed our counter exactly; e2 and e3 carry it unchanged. |

## Open questions and how to settle them on a unit

| # | Unknown | Resolve by |
|---|---|---|
| R1 | Which desk it is. The **Control|24** (2001, 10BASE-T, Focusrite preamps) or the **C|24** (2007, the successor; protocol unverified)? The announce name settles it | M0: read the device name in the announce (`CNTRL|24` expected) and the version |
| R2 | Link speed and duplex. A modern NIC may not negotiate 10/half | M0: `/sys/class/net/*/speed,duplex`; if bad, use a cheap 10/100 unmanaged switch. Keep it off the REAC interfaces |
| R3 | Checksum: does the C24 verify host→desk? (Neyrinck mentions "CRC") | M1: send the sum, and if no ACK, retry with zero. Also check that desk frames in the M0 pcap match sum16 |
| R4 | Does the motor fight a touched cap? Does it go back to its set-point on release? | M1 extension: command 25 %, grab the cap, move it, release, with no echo. Feel and film. Then repeat with an echo on release **Measured 2026-10-29 (Control|24 1.08, #29):** the motor holds a set-point and drives back to it when the cap is let go; it does not report its own moves. A host must echo the hand's value on release, or every fader snaps back. Touch chatters during a move (off for 30-240 ms every few positions): debounce a release for about 250 ms. |
| R5 | Keepalive and offline timeout. Hosts that work send one every 1 s (C24-Engine-Renewed) or 10 s with the fix above (procontrol-linux) | M1: stretch the keepalive interval 10 → 20 → 40 s and watch `e1`→`e0` and the "Offline" display **Measured 2026-10-29 (Control|24 1.08, #29):** a 10 s and a 20 s keepalive held; once the desk ended the session after 38 s without one, once it held 63 s. The cause of the difference is open; 10 s keeps a wide margin. |
| R6 | Scribble `0x00+n` versus `0x20+n`: layers, rows or aliases; the glyph set beyond ASCII | M1: write different text to both, then sweep bytes 0x00–0x7F onto one strip **Measured 2026-10-29 (Control|24 1.08, #29):** `0x00+n` and `0x20+n` write the same 4-character display, the last write showing; strip n is address n. The glyph set beyond ASCII is not yet swept. |
| R7 | Meter segment count (the mask holds 14), and whether a lit meter decays on its own | Send each bitmask step to strip 1 and count the LEDs; hold a value for 10 s **Measured 2026-10-29 (Control|24 1.08, #29):** 14 segments, and a lit meter holds with no decay for at least 10 s: ballistics are the host's. |
| R8 | ACK window and frame size. C24-Engine-Renewed sends without waiting for ACKs and up to 461-byte bodies, so a burst is accepted; whether the desk retries or drops frames under such a burst is not known | Load test in the probe: N commands per frame, measure retries and display garbling **Measured 2026-10-29 (Control|24 1.08, #29):** 100 fader commands, then 24 scribbles, the counter and 24 faders in one go: every frame ACKed, no retry, no garbling. |
| R9 | Running status and multi-command frames from the desk | The M1 logs; the parser handles both **Measured 2026-10-29 (Control|24 1.08, #29):** one command per desk frame in every frame seen; no running status. |
| R10 | Gaps in the button map, and which keys light | Press every key during M1 (decode log); walk LEDs over zones 0x18–0x1D (Davitekk's LED-finder approach, reimplemented) **Measured 2026-10-29 (Control|24 1.08, #29):** strip keys 01 PAN/SEND, 02 EQ, 03 DYN, 0A INSERTS, 05 AUTO, 06 CHANNEL SELECT, 07 SOLO, 08 MUTE (no REC on a strip); every one lights from the host but AUTO, whose mode shows on the automation LEDs (F0 13 dd 20, all five lit); 04 lights SWITCH ACTIVE above the strip. Jog: B0 5C dd, delta dd-64, +-1 to +-7 with speed. The keys outside the strips are not yet mapped. |
| R11 | Does Pro Tools do anything we skip (the "cryptography" in Neyrinck's note)? | **Optional:** capture ReaControl24 driving the desk once, on a separate test machine, never a production one. That is the only way to see a known-working host conversation; Pro Tools on any machine would be even better |
| R12 | Analogue section: which buttons reach the preamps, and whether they are safe | A physical check on the unit; never inferred from LEDs |
| R13 | Two hosts on one desk (a shadow console, or a second daemon) | One daemon owning each desk, plus the transport refusing to send `e2` when it sees a foreign `e1` |
| R14 | The daemon binary loses `cap_net_raw` on reinstall (`install` does not keep file capabilities) | `getcap` check in `ExecStartPre`; `%caps` in the RPM. **The packages (#35):** `diginet-probe` and `diginet-packet-helper` carry `%caps(cap_net_raw=ep)` in the RPM and get `setcap` in the Debian postinst, and `tests/package-check.sh` asks `getcap` for both after a clean install. A host that should hold no capability takes its socket from `diginet-packet-helper` instead (`diginet_packet_open_by_helper()`, "One socket, every interface" above) |
| R15 | What a desk keeps across sessions | **Measured 2026-10-29:** a new session (e2 taken) blanks every scribble, LED, ring, meter and the counter; an e3 leaves all of it shown under "Offline"; faders stay where they are either way. A host repaints everything each time the session comes online, faders included |
| R16 | Motor faders on an old desk | **Measured 2026-10-29:** on one unit, most motors climbed when the desk was cold and up to nine stopped climbing (still pulling down) after an hour on, while every position sensor and touch read true; one fader's sensor jumped (13 -> 1023 within 30 ms) and its motor hunted at full speed. The hardware wants its tracks cleaned and its motor supply checked; a host treats every fader the same |

