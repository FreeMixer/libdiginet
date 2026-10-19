# libdiginet

A C library for the Ethernet protocol of the Digidesign **Control|24** and **ProControl** control surfaces, so that any Linux mixer or DAW can drive one again: motor faders, V-Pots and their LED rings, buttons and lamps, scribble strips, meters, the counter and the jog wheel.

The surfaces talk raw Ethernet (EtherType `0x885F`), not MIDI or IP. libdiginet holds the protocol: frame and session grammar, encoders and decoders for every control, and one personality per desk. A small transport layer holds the wire: the packet socket, discovery, the online handshake, acknowledgements, keepalive, retransmit and pacing. A host links the library, or runs a thin daemon that holds the one capability raw sockets need (`cap_net_raw`) and hands the desk's commands to an unprivileged application.

What is known about the protocol, and what is still open, is in [docs/protocol.md](docs/protocol.md), every claim cited to its source.

## Network

The desk broadcasts its announce (about every 7 s while idle, measured on a ProControl); after that every frame is unicast between the desk's MAC and the host's MAC. A switch forwards these frames like any other, and machines that speak only IP ignore them, so the desk can share a segment with ordinary IP clients. What the link needs:

- The desk and the host on the same layer-2 segment. There is no IP header, so no router can sit between them.
- The desk on the untagged (native) VLAN of the host's port: it sends no VLAN tag.
- A wired path from the desk to the host. Some Wi-Fi bridges drop an EtherType they do not know; IP clients on Wi-Fi are not affected.
- Not on an interface that carries other real-time traffic, such as a REAC stagebox link.
- The ProControl's port runs at 10 Mbit/s half duplex. If a modern NIC will not settle on that, put a small unmanaged 10/100 switch between them.

DigiNet has no authentication: the desk takes a session with whichever host answers its announce. On a LAN shared with other people, give the desk and its host a segment of their own.

## Status

Early, and not yet tried on a desk. In the tree:

1. `protocol/diginet.ksy`, the formal byte grammar, with golden-frame tests.
2. The codecs and the Control|24 / ProControl personalities.
3. The transport: session state machine, ack window, keepalive, retransmit, latest-wins coalescing, all tested against a desk emulator.
4. `diginet-probe`, a command-line tool for a first test on a real desk: wake it, move a fader, light a lamp, write a scribble strip, log every press. See [docs/probe.md](docs/probe.md).

Building and testing: [BUILDING.md](BUILDING.md).

## Safety

The desk's system and diagnostic message family (`F0 13 xx 70 …`) can write to the desk's own memory. The library refuses to encode it.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).
