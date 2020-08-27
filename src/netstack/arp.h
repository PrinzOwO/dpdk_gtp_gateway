/**
 * arp.h - arp data structure
 *  TODO: thread safe
 */
#ifndef __ARP_H_
#define __ARP_H_

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_arp.h>

#include "logger.h"

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
    uint32_t ipv4_addr;
    struct rte_ether_addr mac_addr;
    arp_state_t state;
} arp_entry_t;

int arp_init(int with_locks);
int arp_terminate(void);

int arp_in(struct rte_mbuf *mbuf);

/**
 * arp_table_create - Create ARP table using hash table with algorithm "rte_jhash"
 *
 * @name: hash table name
 * @entries: number of entries
 * @extra_flag: extra flag for rte_hash
 * @return
 *   - Non NULL pointer if successfully
 *   - NULL pointer if error occurred
 */
struct rte_hash *arp_table_create(const char *name, uint32_t entries, uint8_t extra_flag);

/**
 * arp_table_destroy - Detroy ARP table using hash table
 *
 * @arp_table: struct rte_hash pointer
 */
void arp_table_destroy(struct rte_hash *arp_table);

static __rte_always_inline void arp_header_prepend_inplace(struct rte_arp_hdr *arp_req,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        uint32_t src_ip, uint32_t dst_ip,
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

void arp_header_prepend(struct rte_mbuf *mbuf, struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint32_t opcode);

/**
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int arp_send_request(uint32_t dst_ip_addr, uint8_t port);

/**
 * @return
 *   - 0 if sent successfully
 *   - A negative number if error occurred
 */
int arp_send_reply(uint32_t src_ip_addr, struct rte_ether_addr *dst_hw_addr,
                   uint32_t dst_pr_add);

int arp_get_mac(uint32_t ipv4_addr, unsigned char *mac_addr);

/**
 * Add an IPv4-MAC pair into arp table.
 * If there is an arp entry with same IP existed, the mac addr will be updated.
 *
 * @return
 *   - 0 if added successfully
 *   - A negative number if error occurred
 */
int arp_add_mac(uint32_t ipv4_addr, struct rte_ether_addr *mac_addr, int permanent);

int arp_queue_egress_pkt(uint32_t ipv4_addr, struct rte_mbuf *m);

void arp_print_table(TraceLevel trace_level);
void print_ipv4(uint32_t ip_addr, TraceLevel trace_level);
void print_mac(struct rte_ether_addr *mac_addr, TraceLevel trace_level);

#endif /* __ARP_H_ */
