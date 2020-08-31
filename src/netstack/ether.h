/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __EHTER_H_
#define __EHTER_H_

#include <rte_common.h>
#include <rte_ether.h>

#define MAX_INTERFACES 10

typedef struct interface_s {
    uint8_t port;
    struct rte_ether_addr hw_addr;
    uint32_t ipv4_addr;
    struct interface_s *next;
} interface_t;

void add_interface(interface_t *iface);

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
