#ifndef __DPDK_GTP_GW_IP_H__
#define __DPDK_GTP_GW_IP_H__

#include <rte_byteorder.h>
#include <rte_ip.h>

#include "logger.h"

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

/**
 * Check if target IPv4 is in the specific subnet
 */
static __rte_always_inline int in_ipv4_subnet(rte_be32_t target_ipv4, rte_be32_t ifa_ipv4, rte_be32_t ifa_mask)
{
    return !((target_ipv4 ^ ifa_ipv4) & ifa_mask);
}

/**
 * Convert IPv4 address from big endian to xx.xx.xx.xx and output with logger_s.
 */
static __rte_always_inline void logger_ipv4(rte_be32_t ipv4, TraceLevel trace_level)
{
    logger_s(LOG_IP, trace_level, "%u.%u.%u.%u",
         (ipv4 & 0xff), ((ipv4 >> 8) & 0xff),
         ((ipv4 >> 16) & 0xff), (ipv4 >> 24));
}

/**
 * Convert IPv4 address from big endian to xx.xx.xx.xx and output with printf_dbg.
 */
static __rte_always_inline void print_dbg_ipv4(__attribute__((unused)) rte_be32_t ipv4)
{
    printf_dbg("%u.%u.%u.%u",
         (ipv4 & 0xff), ((ipv4 >> 8) & 0xff),
         ((ipv4 >> 16) & 0xff), (ipv4 >> 24));
}

/**
 * Output src and dst ipv4 in ipv4 hdr with printf_dbg.
 */
static __rte_always_inline void print_dbg_ipv4_hdr_addr(__attribute__((unused)) struct rte_ipv4_hdr *ipv4_hdr)
{
    printf_dbg(" IPv4 s_addr: ");
    print_dbg_ipv4(ipv4_hdr->src_addr);
    printf_dbg(", d_addr: ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
}

#endif /* __DPDK_GTP_GW_IP_H__ */