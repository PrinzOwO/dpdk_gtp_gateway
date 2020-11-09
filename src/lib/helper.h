#ifndef __HELPER_H_
#define __HELPER_H_

#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ethdev.h>

#include "logger.h"

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
 * Check and convert string to integer
 */
static __rte_always_inline int str_to_int(const char *string)
{
    uint16_t len = strlen(string);
    for (int i = 0; i < len; i++)
        if ((isdigit(string[i]) == 0))
            return -1;

    return atoi(string);
}

/**
 * Check and convert Hex char to integer
 */
static __rte_always_inline int xchar_to_int(const char xchar)
{
    if (xchar >= '0' && xchar <= '9')
        return xchar - '0';
    else if (xchar >= 'A' && xchar <= 'F')
        return xchar - 'A' + 10;
    else if (xchar >= 'a' && xchar <= 'f')
        return xchar - 'a' + 10;
    else
        return -1;
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
    int i;
    for (i = 0; i < RTE_ETHER_ADDR_LEN - 1; i++) {
        printf_dbg("%02x:", mac->addr_bytes[i]);
    }

    printf_dbg("%02x", mac->addr_bytes[i]);
}


#endif /* __HELPER_H_ */
