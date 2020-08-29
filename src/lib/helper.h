#ifndef __HELPER_H_
#define __HELPER_H_

#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ethdev.h>

static __rte_always_inline void
print_rte_ipv4(rte_be32_t addr4)
{
    struct in_addr addr = {.s_addr = addr4};
    printf("%s", inet_ntoa(addr));
}

static __rte_always_inline void
print_rte_ipv4_dbg(
#ifndef DEBUG
    __attribute__((unused))
#endif
    rte_be32_t addr4)
{
#ifdef DEBUG
    print_rte_ipv4(addr4);
#endif
}

/**
 * Convert IPv4 address from big endian to xx.xx.xx.xx.
 */
static __rte_always_inline void print_ipv4(rte_be32_t ipv4, TraceLevel trace_level)
{
    logger_s(LOG_ARP, trace_level, "%u.%u.%u.%u",
         (ipv4 & 0xff), ((ipv4 >> 8) & 0xff),
         ((ipv4 >> 16) & 0xff), (ipv4 >> 24));
}

/**
 * Convert MAC address from 48bits Ethernet address to xx:xx:xx:xx:xx:xx.
 */
static __rte_always_inline void print_mac(struct rte_ether_addr *mac, TraceLevel trace_level)
{
    int i;
    for (i = 0; i < RTE_ETHER_ADDR_LEN - 1; i++) {
        logger_s(LOG_ARP, trace_level, "%x:", mac->addr_bytes[i]);
    }

    logger_s(LOG_ARP, trace_level, "%x", mac->addr_bytes[i]);
}


#endif /* __HELPER_H_ */
