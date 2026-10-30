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
          16-bit additive sum of the body bytes (padding excluded). The desk fills it on every
          frame it sends (all 26 811 desk frames of the captures); hosts may send zero and the
          Control|24 accepts it.
      - id: send_counter
        type: u4
        doc: |
          The sender's own sequence. A data frame carries it before its own commands are added;
          the next data frame carries it plus num_commands. The desk's ack frames carry 0, an
          announce carries the count of announces the desk has sent, an e2 or e3 the host's
          counter unchanged.
      - id: ack_counter
        type: u4
        doc: In an ACK, the peer's send_counter being acknowledged.
      - id: retry
        type: u2
        doc: |
          Non-zero when the sender is retransmitting a frame that was not acknowledged; it
          counts the retransmissions (the desk's data frames reach 16, a host's e2 reaches 5).
      - id: cmd
        type: u1
        enum: command
      - id: num_commands
        type: u1
        doc: |
          Number of commands in the body: every message counts one, except that a fader
          position (B0 tt MSB, then (20+tt) LSB) counts one for the pair. Held by every data
          frame of the captures. An announce carries 1, an ack, e2 and e3 carry 0. A keepalive
          (body 00) carries 1.

  announce:
    doc: |
      The desk's broadcast announce, e0 when idle and e1 while in session (docs/protocol.md,
      "Discovery and handshake", step 1). 34 bytes, read from Control|24 firmware 1.08 captures:
      the MAC of the host the desk is, or was last, in session with, two constants, a "v" and
      the version, the name. Every announce seen names the same layout.
    seq:
      - id: host_mac
        size: 6
        doc: |
          The host the desk is in session with. e1 carries it (the proof of a session, step 3).
          e0 carries zeros after a cold start, and the last host's MAC for a while after a
          session ended.
      - id: unknown_a
        type: u4
        doc: 1 in every announce seen.
      - id: unknown_b
        type: u4
        doc: 6 in every announce seen.
      - id: version_prefix
        type: u1
        doc: 0x76, the letter "v", in every announce seen. It stands before the version digits.
      - id: version
        type: padded_text
        size: 9
        doc: Firmware version after its "v", e.g. "1.08" (seen), padded with NULs.
      - id: name
        type: padded_text
        size: 9
        doc: '"CNTRL|24" for a Control|24 (seen), "MAINUNIT" for a ProControl.'
      - id: tail
        size-eos: true
        doc: One byte, 0 in every announce seen. Not described by any source.

  padded_text:
    doc: A text field in a fixed-size slot, closed by a NUL; the slot's remaining bytes are kept.
    seq:
      - id: text
        type: strz
        encoding: ASCII
        eos-error: false
      - id: rest
        size-eos: true

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
      sent by a host ("System and diagnostic family"); the desk itself sends it, twice in
      the captures. Payloads that the captures carry are typed; the sizes seen are in each type.
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
        type:
          switch-on: function
          cases:
            'sysex_function::vpot_ring': ring
            'sysex_function::meter': meter
            'sysex_function::led_strip': led_strip
            'sysex_function::counter': counter
            'sysex_function::scribble': scribble
            'sysex_function::system': system
            _: rest
        doc: The bytes up to the closing F7, which is consumed.

  ring:
    doc: Three bytes on the wire. Address bits 0..5 are the strip, bit 6 is LED 1.
    seq:
      - id: address
        type: u1
      - id: left
        type: u1
        doc: Bits 6..0 are LEDs 2..8.
      - id: right
        type: u1
        doc: Bits 6..0 are LEDs 9..15.

  meter:
    doc: Three bytes on the wire. A thermometer mask of 14 bits, hi = mask >> 7, lo = mask & 0x7f.
    seq:
      - id: address
        type: u1
        doc: Bits 0..4 the strip, bit 5 the right channel.
      - id: hi
        type: u1
      - id: lo
        type: u1

  led_strip:
    doc: |
      Two bytes: the strip's automation LEDs (docs/protocol.md, "Buttons and LEDs"). No
      capture carries this function yet.
    seq:
      - id: address
        type: u1
      - id: bits
        type: u1

  counter:
    doc: |
      Ten bytes in the frames libdiginet sent, the desk answering them: the address, the dots
      and eight digits, rightmost first. ReaControl's clock clear carries one byte fewer.
    seq:
      - id: address
        type: u1
        doc: 0x19 on a Control|24.
      - id: dots
        type: u1
      - id: digits
        size-eos: true
        doc: Seven-segment bytes, rightmost digit first; eight when the frame is whole.

  scribble:
    doc: Six bytes on the wire, an address, a zero and four characters.
    seq:
      - id: address
        type: u1
      - id: zero
        type: u1
        doc: 0 in every message seen.
      - id: text
        size-eos: true
        doc: Four ASCII characters on the wire.

  system:
    doc: |
      The 0x70 family. Seen only from the desk: 01 4f 4b ("OK") and 01 0a 0d, one frame
      each, after a fader move. Its meaning is not known.
    seq:
      - id: selector
        type: u1
      - id: data
        size-eos: true

  rest:
    seq:
      - id: data
        size-eos: true
