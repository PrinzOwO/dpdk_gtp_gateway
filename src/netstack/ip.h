#ifndef __DPDK_GTP_GW_IP_H__
#define __DPDK_GTP_GW_IP_H__

#include <rte_byteorder.h>
#include <rte_ip.h>

static __rte_always_inline void ipv4_header_set_inplace(struct rte_ipv4_hdr *ipv4_hdr, rte_be32_t src_addr, rte_be32_t dst_addr, rte_be16_t len)
{
    ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(len);
    ipv4_hdr->packet_id = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->src_addr = src_addr;
    ipv4_hdr->dst_addr = dst_addr;
}

static __rte_always_inline void ipv4_header_reply_set_inplace(struct rte_ipv4_hdr *ipv4_hdr, rte_be32_t src_addr, rte_be32_t dst_addr)
{
    ipv4_hdr->src_addr = src_addr;
    ipv4_hdr->dst_addr = dst_addr;
    ipv4_hdr->hdr_checksum = 0;
}

#endif /* __DPDK_GTP_GW_IP_H__ */