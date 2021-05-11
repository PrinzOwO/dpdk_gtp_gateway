/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __DPDK_GTP_GW_ETHER_H__
#define __DPDK_GTP_GW_ETHER_H__

#include <rte_ether.h>

#include "logger.h"

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

/**
 * Convert MAC address from 48bits Ethernet address to xx:xx:xx:xx:xx:xx and output with logger_s.
 */
static __rte_always_inline void logger_mac(struct rte_ether_addr *mac, TraceLevel trace_level)
{
    int i;
    for (i = 0; i < RTE_ETHER_ADDR_LEN - 1; i++) {
        logger_s(LOG_ETHER, trace_level, "%02x:", mac->addr_bytes[i]);
    }

    logger_s(LOG_ETHER, trace_level, "%02x", mac->addr_bytes[i]);
}

/**
 * Convert MAC address from 48bits Ethernet address to xx:xx:xx:xx:xx:xx and output with printf_dbg.
 */
static __rte_always_inline void print_dbg_mac(__attribute__((unused)) struct rte_ether_addr *mac)
{
    printf_dbg("%02x:%02x:%02x:%02x:%02x:%02x",
            mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
            mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

/**
 * Output src and dst mac in ethernet hdr with printf_dbg.
 */
static __rte_always_inline void print_dbg_ether_hdr_mac(__attribute__((unused)) struct rte_ether_hdr *eth_hdr)
{
    printf_dbg("Ether d_addr: ");
    print_dbg_mac(&eth_hdr->d_addr);
    printf_dbg(", s_addr: ");
    print_dbg_mac(&eth_hdr->s_addr);
}

#endif /* __DPDK_GTP_GW_ETHER_H__ */
