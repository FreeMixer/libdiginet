// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>

/* The Ethernet envelope, the 16-byte header and the announce body (protocol/diginet.ksy:
 * the top-level seq, `header`, `announce`). */
#include <string.h>

#include <diginet/diginet.h>
#include <diginet/diginet_codec.h>

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

const char *diginet_strerror(int code)
{
	switch (code) {
	case DIGINET_OK:             return "ok";
	case DIGINET_E_ARG:          return "invalid argument";
	case DIGINET_E_SHORT:        return "frame shorter than the header";
	case DIGINET_E_ETHERTYPE:    return "not EtherType 0x885F";
	case DIGINET_E_LENGTH:       return "header length out of range";
	case DIGINET_E_SPACE:        return "output buffer too small";
	case DIGINET_E_TRUNCATED:    return "message runs past the body";
	case DIGINET_E_NO_STATUS:    return "data byte without running status";
	case DIGINET_E_STATUS:       return "unsupported status byte";
	case DIGINET_E_NOT_ANNOUNCE: return "not an announce";
	case DIGINET_E_REFUSED:      return "refused: the library does not send this message";
	case DIGINET_E_RANGE:        return "value out of range";
	case DIGINET_E_NOT_MINE:     return "message of another kind";
	default:                     return "unknown error";
	}
}

uint16_t diginet_sum16(const uint8_t *p, size_t n)
{
	uint32_t s = 0;
	for (size_t i = 0; i < n; i++)
		s += p[i];
	return (uint16_t)s;
}

int diginet_mac_is_digidesign(const uint8_t mac[DIGINET_MAC_LEN])
{
	return mac && mac[0] == DIGINET_OUI_0 && mac[1] == DIGINET_OUI_1 && mac[2] == DIGINET_OUI_2;
}

int diginet_frame_is_keepalive(const struct diginet_frame *f)
{
	return f && f->h.cmd == DIGINET_CMD_DATA && f->body_len == 1 && f->body[0] == 0x00;
}

int diginet_frame_parse(const uint8_t *buf, size_t len, struct diginet_frame *f)
{
	if (!buf || !f)
		return DIGINET_E_ARG;
	if (len < DIGINET_BODY_OFFSET)
		return DIGINET_E_SHORT;
	uint16_t et = rd16(buf + 12);
	if (et != DIGINET_ETHERTYPE)
		return DIGINET_E_ETHERTYPE;

	const uint8_t *h = buf + DIGINET_ETH_HDR_LEN;
	uint16_t numbytes = rd16(h);
	if (numbytes < DIGINET_HDR_LEN || (size_t)numbytes > len - DIGINET_ETH_HDR_LEN)
		return DIGINET_E_LENGTH;

	memcpy(f->dst, buf, DIGINET_MAC_LEN);
	memcpy(f->src, buf + 6, DIGINET_MAC_LEN);
	f->ethertype = et;
	f->h.numbytes = numbytes;
	f->h.sum = rd16(h + 2);
	f->h.send_counter = rd32(h + 4);
	f->h.ack_counter = rd32(h + 8);
	f->h.retry = rd16(h + 12);
	f->h.cmd = h[14];
	f->h.num_commands = h[15];
	f->body = buf + DIGINET_BODY_OFFSET;
	f->body_len = (size_t)numbytes - DIGINET_HDR_LEN;
	f->pad_len = len - DIGINET_BODY_OFFSET - f->body_len;
	f->body_sum = diginet_sum16(f->body, f->body_len);
	f->sum_matches = f->body_sum == f->h.sum;
	return DIGINET_OK;
}

int diginet_frame_build(uint8_t *buf, size_t cap,
			const uint8_t dst[DIGINET_MAC_LEN], const uint8_t src[DIGINET_MAC_LEN],
			const struct diginet_header *h, const uint8_t *body, size_t body_len,
			enum diginet_sum_mode mode)
{
	if (!buf || !dst || !src || !h || (body_len && !body))
		return DIGINET_E_ARG;
	if (mode != DIGINET_SUM_BODY && mode != DIGINET_SUM_ZERO)
		return DIGINET_E_ARG;
	if (body_len > DIGINET_MAX_BODY_LEN)
		return DIGINET_E_LENGTH;
	if (diginet_body_check(body, body_len) != DIGINET_OK)
		return DIGINET_E_REFUSED;   /* F0 13 xx 70 writes the desk's memory */
	size_t len = DIGINET_BODY_OFFSET + body_len;
	size_t out = len < DIGINET_MIN_FRAME_LEN ? DIGINET_MIN_FRAME_LEN : len;
	if (cap < out)
		return DIGINET_E_SPACE;

	memcpy(buf, dst, DIGINET_MAC_LEN);
	memcpy(buf + 6, src, DIGINET_MAC_LEN);
	wr16(buf + 12, DIGINET_ETHERTYPE);
	uint8_t *p = buf + DIGINET_ETH_HDR_LEN;
	wr16(p, (uint16_t)(DIGINET_HDR_LEN + body_len));
	wr16(p + 2, mode == DIGINET_SUM_BODY ? diginet_sum16(body, body_len) : 0);
	wr32(p + 4, h->send_counter);
	wr32(p + 8, h->ack_counter);
	wr16(p + 12, h->retry);
	p[14] = h->cmd;
	p[15] = h->num_commands;
	if (body_len)
		memcpy(buf + DIGINET_BODY_OFFSET, body, body_len);
	if (out > len)
		memset(buf + len, 0, out - len);
	return (int)out;
}

/* A fixed-size string field: copied up to its first NUL, always terminated. */
static void copy_strz(char *dst, size_t dst_size, const uint8_t *src, size_t n)
{
	size_t i = 0;
	for (; i < n && i + 1 < dst_size && src[i]; i++)
		dst[i] = (char)src[i];
	dst[i] = '\0';
}

int diginet_announce_parse(const struct diginet_frame *f, struct diginet_announce *a)
{
	if (!f || !a)
		return DIGINET_E_ARG;
	if (f->h.cmd != DIGINET_CMD_ANNOUNCE && f->h.cmd != DIGINET_CMD_ANNOUNCE_SESSION)
		return DIGINET_E_NOT_ANNOUNCE;
	if (f->body_len < 33)
		return DIGINET_E_LENGTH;
	a->unknown = f->body;
	a->unknown_len = 15;
	copy_strz(a->version, sizeof a->version, f->body + 15, 9);
	copy_strz(a->name, sizeof a->name, f->body + 24, 9);
	return DIGINET_OK;
}
