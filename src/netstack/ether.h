/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __EHTER_H_
#define __EHTER_H_

#include <string.h>

#include <rte_common.h>
#include <rte_ether.h>

#include "logger.h"

typedef struct interface_s {
    uint8_t id;
    rte_be32_t ipv4;
    struct rte_ether_addr mac;
    uint8_t gtp_type;
    uint8_t pkt_index;
} interface_t;

int ether_add_interface(uint8_t id, rte_be32_t ipv4, uint8_t gtp_type);

int ether_find_interface_by_id(const void *key, interface_t **data);

int ether_find_interface_by_ipv4(const void *key, interface_t **data);

int ether_find_interface_by_mac(const void *key, interface_t **data);

void ether_dump_interface(TraceLevel trace_level);

/**
 * Used in stats.c to show interface status
 */
void ether_dump_status(void);

int ether_interface_init(int with_locks);

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

#endif /* __EHTER_H_ */
