#include "arp.h"

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

void arp_header_prepend(struct rte_mbuf *mbuf,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode)
{
    struct rte_arp_hdr *arp_req = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_req, src_mac, dst_mac, src_ip, dst_ip, opcode);
}