#ifndef __DPDK_GTP_GW_UDP_H__
#define __DPDK_GTP_GW_UDP_H__

#include <rte_byteorder.h>
#include <rte_udp.h>

#define udp_header_set_inplace_macro(udp_hdr, sport, dport, len) \
    ((struct rte_udp_hdr *) (udp_hdr))->src_port = (sport); \
    ((struct rte_udp_hdr *) (udp_hdr))->dst_port = (dport); \
    ((struct rte_udp_hdr *) (udp_hdr))->dgram_len = rte_cpu_to_be_16(len); \
    ((struct rte_udp_hdr *) (udp_hdr))->dgram_cksum = 0

static __rte_always_inline void udp_header_set_inplace(struct rte_udp_hdr *udp_hdr,
        rte_be16_t src_port, rte_be16_t dst_port, uint16_t len)
{
    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_len = rte_cpu_to_be_16(len);
    udp_hdr->dgram_cksum = 0; // No UDP checksum check
}

static __rte_always_inline void udp_header_reply_set_inplace(struct rte_udp_hdr *udp_hdr,
        rte_be16_t src_port, rte_be16_t dst_port)
{
    udp_hdr->src_port = src_port;
    udp_hdr->dst_port = dst_port;
    udp_hdr->dgram_cksum = 0; // No UDP checksum check
}

/**
 * Output src and dst port in udp hdr with printf_dbg.
 */
static __rte_always_inline void print_dbg_udp_hdr_port(__attribute__((unused)) struct rte_udp_hdr *udp_hdr)
{
    printf_dbg(" UDP src_port: %u, dst_port %u", rte_be_to_cpu_16(udp_hdr->src_port), rte_be_to_cpu_16(udp_hdr->dst_port));
}


#endif /* __DPDK_GTP_GW_UDP_H__ */