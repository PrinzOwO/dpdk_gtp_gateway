/**
 * arp.h - arp data structure
 *  TODO: thread safe
 */
#ifndef __ARP_H_
#define __ARP_H_

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_hash.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_arp.h>

#include "logger.h"
#include "ether.h"

#define MAX_ARP_ENTRIES 8192

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
 * An internal function to set ARP header
 */
static __rte_always_inline void arp_header_set_inplace(struct rte_arp_hdr *arp_req,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode)
{
    arp_req->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_req->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_req->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_req->arp_plen = sizeof(uint32_t);
    arp_req->arp_opcode = rte_cpu_to_be_16(opcode);

    struct rte_arp_ipv4 *arp_data = &arp_req->arp_data;
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    rte_ether_addr_copy(dst_mac, &arp_data->arp_tha);
    arp_data->arp_sip = src_ip;
    arp_data->arp_tip = dst_ip;
}

/**
 * Prepend and set ARP header
 */
void arp_header_prepend(struct rte_mbuf *mbuf,
        struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode);

/**
 * Handle a APR frame
 * 
 * @return
 *   - 0 if handled successfully
 *   - A negative number if error occurred
 */
int arp_in(struct rte_mbuf *mbuf);

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
        struct rte_ether_addr *dst_mac, rte_be32_t dst_ip);

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

#endif /* __ARP_H_ */
