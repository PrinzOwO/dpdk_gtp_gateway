/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __DPDK_GTP_GW_ETHER_H__
#define __DPDK_GTP_GW_ETHER_H__

#include <rte_ether.h>

/**
 * Convert string with Ethernet address to an ether_addr.
 * 
 * It is familiar to rte_ether_unformat_addr, but only support the format XX:XX:XX:XX:XX:XX.
 * Implement this function because rte_ether_unformat_addr is __rte_experimental.
 */
int ether_unformat_addr(const char *str, struct rte_ether_addr *eth_addr);

/**
 * An internal function to set ethernet header
 */
static __rte_always_inline void ethernet_header_set_inplace(struct rte_ether_hdr *eth,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        uint16_t ether_type)
{
    eth->ether_type = rte_cpu_to_be_16(ether_type);
    rte_ether_addr_copy(src_mac, &eth->s_addr);
    rte_ether_addr_copy(dst_mac, &eth->d_addr);
}

/**
 * An internal function to set ethernet header
 */
static __rte_always_inline void ethernet_header_reply_set_inplace(struct rte_ether_hdr *eth,
        struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac)
{
    rte_ether_addr_copy(src_mac, &eth->s_addr);
    rte_ether_addr_copy(dst_mac, &eth->d_addr);
}

#endif /* __DPDK_GTP_GW_ETHER_H__ */
