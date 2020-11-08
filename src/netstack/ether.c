/**
 * ether.c
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#include "ether.h"

#include <rte_ether.h>

#include "helper.h"

int ether_unformat_addr(const char *str, struct rte_ether_addr *eth_addr)
{
    if (strlen(str) < 17)
        return -1;

    int val;
    for (int i = 0; i < 6; i++) {
        if (i && str[i * 3 - 1] != ':')
            return -1;

        if ((val = xchar_to_int(str[i * 3])) < 0)
            return -1;
        eth_addr->addr_bytes[i] = (val << 4);

        if ((val = xchar_to_int(str[i * 3 + 1])) < 0)
            return -1;
        eth_addr->addr_bytes[i] += val;
    }

    return 0;
}