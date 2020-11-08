#ifndef __DPDK_GTP_GW_INTERFACE_H__
#define __DPDK_GTP_GW_INTERFACE_H__

#include <rte_common.h>
#include <rte_ether.h>

#include "logger.h"

#define INTERFACE_TYPE_N6           0
#define INTERFACE_TYPE_N3           1
#define INTERFACE_TYPE_N9           2
#define INTERFACE_TYPE_GTPU         3

typedef struct interface_s {
    uint8_t id;
    rte_be32_t ipv4;
    struct rte_ether_addr mac;
    uint8_t type;
    uint8_t pkt_index;
} interface_t;

interface_t *interface_get_this(int now_order);

interface_t *interface_get_next(int now_order);

int interface_add(uint8_t id, rte_be32_t ipv4, uint8_t type);

int interface_find_by_id(const void *key, interface_t **data);

int interface_find_by_ipv4(const void *key, interface_t **data);

int interface_find_by_mac(const void *key, interface_t **data);

void interface_dump(TraceLevel trace_level);

/**
 * Used in stats.c to show interface status
 */
void interface_dump_status(void);

int interface_init(int with_locks);

#endif /* __DPDK_GTP_GW_INTERFACE_H__ */