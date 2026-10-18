# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
#
# The DigiNet surface protocol, one Ethernet frame. Every field below names the line of
# docs/protocol.md it comes from; that file in turn names the source of each fact.
meta:
  id: diginet
  title: DigiNet surface protocol (Digidesign Control|24, ProControl)
  license: GPL-3.0-or-later
  ks-version: 0.11
  endian: be
doc: |
  One raw Ethernet II frame of the DigiNet protocol: EtherType 0x885F, no IP. A 16-byte
  big-endian header follows the Ethernet header, then a body of (numbytes - 16) bytes. The
  frame is padded to the Ethernet minimum; bytes after the body are padding and carry no
  meaning (docs/protocol.md, Transport: "Minimum frame").
doc-ref: docs/protocol.md

seq:
  - id: dst
    size: 6
    doc: Destination MAC. ff:ff:ff:ff:ff:ff for the desk's announce, else the peer (Transport, "Broadcast and unicast").
  - id: src
    size: 6
    doc: Source MAC. A desk sends from the Digidesign OUI 00:a0:7e (Transport, "Vendor").
  - id: ethertype
    type: u2
    valid: 0x885f
    doc: Transport, "Framing".
  - id: header
    type: header
  - id: body
    size: header.numbytes - 16
    type:
      switch-on: header.cmd
      cases:
        'command::data': commands
        'command::announce_offline': announce
        'command::announce_session': announce
  - id: padding
    size-eos: true
    doc: Ethernet minimum-size padding; may hold stale bytes (Transport, "Minimum frame").

enums:
  command:
    0x00: data
    0xa0: ack
    0xe0: announce_offline
    0xe1: announce_session
    0xe2: wake
    0xe3: disconnect
  sysex_function:
    0x00: vpot_ring
    0x10: meter
    0x20: led_strip
    0x30: counter
    0x40: scribble
    0x70: system

types:
  header:
    doc: The 16-byte header at frame offset 14 (docs/protocol.md, "The header").
    seq:
      - id: numbytes
        type: u2
        valid:
          min: 16
        doc: 16 + body length. Keepalive 17, bare control frame 16, announce 50.
      - id: sum
        type: u2
        doc: |
          16-bit additive sum of the body bytes (padding excluded). Zero is also sent by
          hosts and accepted by the Control|24.
      - id: send_counter
        type: u4
        doc: The sender's own sequence, advanced by the number of commands in the frame.
      - id: ack_counter
        type: u4
        doc: In an ACK, the peer's send_counter being acknowledged.
      - id: retry
        type: u2
        doc: Non-zero when the sender is retransmitting a frame that was not acknowledged.
      - id: cmd
        type: u1
        enum: command
      - id: num_commands
        type: u1
        doc: Number of commands in the body.

  announce:
    doc: |
      The desk's broadcast announce, e0 when idle and e1 while in session (docs/protocol.md,
      "Discovery and handshake", step 1). 15 unknown bytes, a 9-byte version, a 9-byte
      device name. One sentence names the e1 body as carrying the host MAC; where it sits
      is not documented, so it is left inside `unknown`.
    seq:
      - id: unknown
        size: 15
      - id: version
        type: strz
        size: 9
        encoding: ASCII
        doc: Firmware version, e.g. "1.37".
      - id: name
        type: strz
        size: 9
        encoding: ASCII
        doc: '"CNTRL|24" for a Control|24, "MAINUNIT" for a ProControl.'
      - id: tail
        size-eos: true
        doc: The rest of the 34-byte body, not described by any source.

  commands:
    doc: |
      The body of a data frame: a stream of MIDI-shaped messages ("The command set").
      Running status occurs: a data byte where a status byte is due repeats the previous
      channel status. A fader position is two control changes, the second one usually under
      running status: B0 tt MSB (20+tt) LSB.
    seq:
      - id: messages
        type: 'message(_index == 0 ? 0 : messages[_index - 1].running_status_out)'
        repeat: eos

  message:
    params:
      - id: running_status_in
        type: u1
        doc: The channel status in force before this message; 0 when there is none.
    seq:
      - id: lead
        type: u1
      - id: data1_explicit
        type: u1
        if: lead >= 0x80 and lead != 0xf0
      - id: data2
        type: u1
        if: status != 0xf0 and status != 0 and (status & 0xe0) != 0xc0
        doc: Every channel status but C0 and D0 carries two data bytes.
      - id: sysex
        type: sysex
        if: lead == 0xf0
    instances:
      running:
        value: lead < 0x80
        doc: True when the status byte was implied by running status.
      status:
        value: 'lead >= 0x80 ? lead : running_status_in'
        doc: The effective status. 0 marks a data byte with no running status in force.
      data1:
        value: 'lead < 0x80 ? lead : data1_explicit'
      running_status_out:
        value: 'status == 0xf0 ? 0 : status'
        doc: A system-exclusive message cancels running status, as in MIDI.

  sysex:
    doc: |
      F0 13 dd ff ... F7. dd is the device byte (01 Control|24, 00 ProControl main unit),
      ff the function. The 0x70 family writes and reads the desk's memory and is never
      sent by a host ("System and diagnostic family").
    seq:
      - id: maker
        type: u1
        valid: 0x13
      - id: device
        type: u1
      - id: function
        type: u1
        enum: sysex_function
      - id: payload
        terminator: 0xf7
        doc: The bytes up to the closing F7, which is consumed.
