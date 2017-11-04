#pragma once

#include <stdint.h>

#define PKT_VERSION			2

#define PKT_TYPE_PUSH_DATA	0x0
#define PKT_TYPE_PUSH_ACK	0x1
#define PKT_TYPE_PULL_DATA	0x2
#define PKT_TYPE_PULL_RESP	0x3
#define PKT_TYPE_PULL_ACK	0x4
#define PKT_TYPE_TX_ACK		0x5

#define PKT_IDLEN			8

#define PKT_VALIDHEADER(hdr) (hdr->version &&\
(hdr->type >= PKT_TYPE_PUSH_DATA && hdr->type <= PKT_TYPE_TX_ACK))

#define PKT_HASID(hdr) (hdr->type == PKT_TYPE_PUSH_DATA ||\
		hdr->type == PKT_TYPE_PULL_DATA ||\
		hdr->type == PKT_TYPE_TX_ACK)

#define PKT_GATEWAYID(buf) (buf + sizeof(struct pkt_hdr))
#define PKT_JSON(buf) (PKT_GATEWAYID(buf) + PKT_IDLEN)
#define PKT_JSONSZ(pktsz) (pktsz - sizeof(struct pkt_hdr) - PKT_IDLEN)

struct pkt_hdr {
	uint8_t version;
	uint16_t token;
	uint8_t type;
}__attribute__((packed));

