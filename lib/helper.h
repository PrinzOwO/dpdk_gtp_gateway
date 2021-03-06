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

#endif /* __HELPER_H_ */
