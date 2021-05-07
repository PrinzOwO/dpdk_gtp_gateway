#ifndef __DPDK_GTP_GW_ARP_TABLE_H__
#define __DPDK_GTP_GW_ARP_TABLE_H__

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include "logger.h"
#include "interface.h"

typedef enum {
    ARP_REQ = 1,
    ARP_REPLY,
    RARP_REQ,
    RARP_REPLY,
} arp_type_t;

// See also arp_state_str[] in arp.c
typedef enum {
    ARP_STATE_ANY = 0,
    ARP_STATE_INCOMPLETE,
    // states below are valid for arp_get_mac()
    ARP_STATE_REACHABLE,
    ARP_STATE_PERMANENT,
} arp_state_t;

typedef struct arp_entry_s {
    rte_be32_t ipv4_addr;
    struct rte_ether_addr mac_addr;
    arp_state_t state;
} arp_entry_t;

/**
 * Handle a APR frame
 * 
 * @return
 *   - 0 if handled successfully
 *   - A negative number if error occurred
 */
int arp_in(struct rte_mbuf *mbuf, interface_t *interface);

/**
 * Send ARP request with a new space
 * 
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int arp_send_request(rte_be32_t dst_ip, uint8_t port);

/**
 * Send ARP reply with a new space
 * 
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int arp_send_reply(rte_be32_t src_ip,
        interface_t *src_int, struct rte_ether_addr *dst_mac, rte_be32_t dst_ip);

/**
 * Get MAC by network type IPv4 address
 * 
 * @return
 *   - 0 if added successfully
 *   - A negative number if error occurred
 */
int arp_get_mac(rte_be32_t ipv4, struct rte_ether_addr *mac);

/**
 * Add an IPv4-MAC pair into arp table.
 * If there is an arp entry with same IP existed, the mac addr will be updated.
 *
 * @return
 *   - 0 if added successfully
 *   - A negative number if error occurred
 */
int arp_add_mac(rte_be32_t ipv4, struct rte_ether_addr *mac, int permanent);

/**
 * Dump ARP table
 */
void arp_dump_table(TraceLevel trace_level);

int arp_init(int with_locks);

int arp_terminate(void);

#endif /* __DPDK_GTP_GW_ARP_TABLE_H__ */