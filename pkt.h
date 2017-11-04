#pragma once

#include <stdint.h>

#define PKT_VERSION			2

#define PKT_TYPE_PUSH_DATA	0x0
#define PKT_TYPE_PUSH_ACK	0x1
#define PKT_TYPE_PULL_DATA	0x2
#define PKT_TYPE_PULL_RESP	0x3
#define PKT_TYPE_PULL_ACK	0x4
#define PKT_TYPE_TX_ACK		0x5

#define PKT_VALIDHEADER(pkt) (pkt->hdr.version &&\
(pkt->hdr.type >= PKT_TYPE_PULL_DATA && pkt->hdr.type <= PKT_TYPE_TX_ACK))

struct pkt_hdr {
	uint8_t version;
	uint16_t token;
	uint8_t type;
}__attribute__((packed));

union pkt {
	struct pkt_hdr hdr;
};
