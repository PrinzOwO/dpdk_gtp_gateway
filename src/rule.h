#ifndef __DPDK_GTP_GW_RULE_H__
#define __DPDK_GTP_GW_RULE_H__

#include <rte_byteorder.h>

/**
 * GTP header action from FAR
 */
typedef struct rule_action_gtp_hdr_s {
    rte_be32_t teid;
} rule_action_gtp_hdr_t;

/**
 * IPv4 header add from FAR
 */
typedef struct rule_action_ipv4_hdr_s {
    rte_be32_t src_addr; // Default is rte_cpu_to_be_32(<interface IP>)
    rte_be32_t dst_addr;
} rule_action_ipv4_hdr_t;

/**
 * Transport header add from FAR
 */
typedef struct rule_action_l4port_hdr_s {
    rte_be32_t src_port; // Default is rte_cpu_to_be_16(2152)
    rte_be32_t dst_port;
} rule_action_l4port_hdr_t;

#define RULE_ACTION_APPLY_ACTION_UPSPEC 0x00
#define RULE_ACTION_APPLY_ACTION_DROP   0x01
#define RULE_ACTION_APPLY_ACTION_FORW   0x02
#define RULE_ACTION_APPLY_ACTION_BUFF   0x04
#define RULE_ACTION_APPLY_ACTION_MASK   0x07
#define RULE_ACTION_APPLY_ACTION_NOCP   0x08
#define RULE_ACTION_APPLY_ACTION_DUPL   0x10

/**
 * Action entries translated from FAR
 */
typedef struct rule_action_s {
    uint32_t                    id;
    uint8_t                     apply_action;

    // For outer header creation used now
    rule_action_ipv4_hdr_t      ipv4;
    rule_action_gtp_hdr_t       gtp;
    rule_action_l4port_hdr_t    l4;
} rule_action_t;

/**
 * GTP header matching from PDR
 */
typedef struct rule_match_gtp_hdr_s {
    rte_be32_t teid;
} rule_match_gtp_hdr_t;

/**
 * IPv4 header matching from PDR
 */
typedef struct rule_match_ipv4_hdr_s {
    uint8_t     next_proto_id;
    rte_be32_t  src_addr;
    rte_be32_t  dst_addr;
} rule_match_ipv4_hdr_t;

/**
 * Transport header matching from PDR
 */
typedef struct rule_match_l4port_hdr_s {
    rte_le32_t  port_low;
    rte_le32_t  port_high;
} rule_match_l4port_hdr_t;

/**
 * Matching entries translated from PDR
 */
typedef struct rule_match_s {
    uint16_t                id;
    rule_match_ipv4_hdr_t   outer_ipv4;
    rule_match_gtp_hdr_t    gtp;
    rule_match_ipv4_hdr_t   inner_ipv4;

    // TODO: Support ULCL
    /*
    rule_match_l4port_hdr_t src_port_range;
    rule_match_l4port_hdr_t dst_port_range;
    */

    uint32_t                action_id;
} rule_match_t;

int rule_init(uint8_t with_locks);

// TODO: Migrate from old version, it should be re-written to another version
int rule_match_set_temprary(uint16_t id, rte_be32_t teid_in, rte_be32_t ue_ipv4, uint32_t action_id);

// TODO: Migrate from old version, it should be re-written to another version
int rule_action_set_temprary(uint32_t id, rte_be32_t next_ipv4, rte_be32_t teid_out, rte_be16_t port);

#endif /* __DPDK_GTP_GW_RULE_H__ */