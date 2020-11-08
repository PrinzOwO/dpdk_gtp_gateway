#ifndef __DPDK_GTP_GW_UDP_H__
#define __DPDK_GTP_GW_UDP_H__

#include <rte_byteorder.h>
#include <rte_udp.h>

static __rte_always_inline void udp_header_set_inplace(struct rte_udp_hdr *udp_hdr,
        rte_be16_t src_port, rte_be16_t dst_port, rte_be16_t len)
{
    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_len = len;
    udp_hdr->dgram_cksum = 0; // No UDP checksum check
}

static __rte_always_inline void udp_header_reply_set_inplace(struct rte_udp_hdr *udp_hdr,
        rte_be16_t src_port, rte_be16_t dst_port)
{
    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_cksum = 0; // No UDP checksum check
}

#endif /* __DPDK_GTP_GW_UDP_H__ */