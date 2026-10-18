# libdiginet

A C library for the Ethernet protocol of the Digidesign **Control|24** and **ProControl** control surfaces, so that any Linux mixer or DAW can drive one again: motor faders, V-Pots and their LED rings, buttons and lamps, scribble strips, meters, the counter and the jog wheel.

The surfaces talk raw Ethernet (EtherType `0x885F`), not MIDI or IP. libdiginet holds the protocol: frame and session grammar, encoders and decoders for every control, and one personality per desk. A small transport layer holds the wire: the packet socket, discovery, the online handshake, acknowledgements, keepalive, retransmit and pacing. A host links the library, or runs a thin daemon that holds the one capability raw sockets need (`cap_net_raw`) and hands the desk's commands to an unprivileged application.

What is known about the protocol, and what is still open, is in [docs/protocol.md](docs/protocol.md), every claim cited to its source.

## Status

Early: the protocol is described; the code follows in this order.

1. `diginet.ksy`, the formal byte grammar, with golden-frame tests.
2. The codecs and the Control|24 / ProControl personalities.
3. The transport: session state machine, ack window, keepalive, retransmit, latest-wins coalescing.
4. `diginet-probe`, a command-line tool for a first test on a real desk: wake it, move a fader, light a lamp, write a scribble strip, log every press.

## Safety

The desk's system and diagnostic message family (`F0 13 xx 70 …`) can write to the desk's own memory. The library refuses to encode it.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
