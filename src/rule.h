#ifndef __DPDK_GTP_GW_RULE_H__
#define __DPDK_GTP_GW_RULE_H__

// TODO: thread safe

#include <rte_byteorder.h>
#include <pktbuf.h>

#include "interface.h"

// Values for apply_action
#define RULE_ACTION_APPLY_ACTION_UPSPEC             0x00
#define RULE_ACTION_APPLY_ACTION_DROP               0x01
#define RULE_ACTION_APPLY_ACTION_FORW               0x02
#define RULE_ACTION_APPLY_ACTION_BUFF               0x04
#define RULE_ACTION_APPLY_ACTION_MASK               0x07
#define RULE_ACTION_APPLY_ACTION_NOCP               0x08
#define RULE_ACTION_APPLY_ACTION_DUPL               0x10

// Values for dst_interface
#define RULE_ACTION_DST_INT_ACCESS                  0x0     // Uplink
#define RULE_ACTION_DST_INT_CORE                    0x1     // Downlink
#define RULE_ACTION_DST_INT_N6_LAN                  0x2
#define RULE_ACTION_DST_INT_CP_FUNC                 0x3

// Values for outer_hdr_info.desp
#define RULE_ACTION_OUTER_HDR_DESP_UNSPEC           0x00
#define RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4        0x10
#define RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV6        0x20
#define RULE_ACTION_OUTER_HDR_DESP_UDP_IPV4         0x40
#define RULE_ACTION_OUTER_HDR_DESP_UDP_IPV6         0x80

/**
 * Action entries translated from FAR
 */
typedef struct rule_action_s {
    uint32_t                    id;
    uint8_t                     apply_action;
    uint8_t                     dst_int;

    // For outer header creation used now
    struct outer_hdr_info_t
    {
        rte_be16_t              desp;
        rte_be32_t              teid;
        rte_be32_t              peer_ipv4;
        rte_be16_t              peer_port;
    } outer_hdr_info;
} rule_action_t;

#define rule_action_zmalloc() rte_zmalloc("rule action in rule_match_zmalloc", sizeof(rule_action_t), 0)

#define rule_action_free(rule) rte_free(rule)

#define rule_action_set_id(rule, id_num) rule->id = (id_num)

#define rule_action_set_apply_action(rule, ap_ac) rule->apply_action = (ap_ac)

#define rule_action_set_dst_int(rule, d_i) rule->dst_int = (d_i)

#define rule_action_set_outer_hdr_desp(rule, d) rule->outer_hdr_info.desp = (d)

#define rule_action_set_outer_hdr_teid(rule, teid_out) rule->outer_hdr_info.teid = rte_cpu_to_be_32(teid_out)

#define rule_action_set_outer_hdr_ipv4(rule, ipv4) rule->outer_hdr_info.peer_ipv4 = (ipv4)
#define rule_action_set_outer_hdr_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &rule->outer_hdr_info.peer_ipv4)

#define rule_action_set_outer_hdr_port(rule, port) rule->outer_hdr_info.peer_port = rte_cpu_to_be_16(port)

// Values for origin remove_hdr, used for set value
#define RULE_MATCH_REMOVE_HDR_GTPU_IPV4             0x00
#define RULE_MATCH_REMOVE_HDR_GTPU_IPV6             0x01
#define RULE_MATCH_REMOVE_HDR_UDP_IPV4              0x02
#define RULE_MATCH_REMOVE_HDR_UDP_IPV6              0x03
#define RULE_MATCH_REMOVE_HDR_NO_REMOVE             0x06
// Values for remove_hdr (1 << Origin "Outer Header Removal" value + 4), used for packet handle
#define RULE_MATCH_REMOVE_HDR_COOKED_UNSPEC         0x00
#define RULE_MATCH_REMOVE_HDR_COOKED_GTPU_IPV4      0x10
#define RULE_MATCH_REMOVE_HDR_COOKED_GTPU_IPV6      0x20
#define RULE_MATCH_REMOVE_HDR_COOKED_UDP_IPV4       0x40
#define RULE_MATCH_REMOVE_HDR_COOKED_UDP_IPV6       0x80

/**
 * Matching entries translated from PDR
 */
typedef struct rule_match_s {
    uint16_t                id;
    uint32_t                precedence;

    uint8_t                 remove_hdr;

    // Based matching value, don't filter if the value is 0
    rte_be32_t              ue_ipv4;
    rte_be32_t              upf_ipv4;
    rte_be32_t              teid;

    uint32_t                action_id;
    rule_action_t           *action;

    // Accelerate to find which PDR the packet belong to
    struct rule_match_s     *next_id;
    struct rule_match_s     *next_ipv4;
    struct rule_match_s     *next_teid;
} rule_match_t;

#define rule_match_zmalloc() rte_zmalloc("rule match in rule_match_zmalloc", sizeof(rule_match_t), 0)

#define rule_match_free(rule) rte_free(rule)

#define rule_match_set_id(rule, id_num) rule->id = (id_num)

#define rule_match_set_precedence(rule, pcd) rule->precedence = (pcd)

#define rule_match_set_remove_hdr(rule, rm_hdr) rule->remove_hdr = (1 << ((rm_hdr) + 4))

#define rule_match_set_ue_ipv4(rule, ipv4) rule->ue_ipv4 = (ipv4)
#define rule_match_set_ue_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &rule->ue_ipv4)

#define rule_match_set_upf_ipv4(rule, ipv4) rule->upf_ipv4 = (ipv4)
#define rule_match_set_upf_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &rule->upf_ipv4)

#define rule_match_set_teid(rule, teid_in) rule->teid = rte_cpu_to_be_32(teid_in)

#define rule_match_set_action_id(rule, id_num) rule->action_id = (id_num)

int rule_init(uint8_t with_locks);

int rule_match_find_by_teid(uint32_t teid, rule_match_t **data);

int rule_match_find_by_ipv4(rte_be32_t ipv4, rule_match_t **data);

int rule_action_find_by_id(uint32_t id, rule_action_t **data);

int rule_match_register(rule_match_t *rule);

int rule_match_deregister(uint16_t id);

int rule_action_register(rule_action_t *rule);

int rule_action_deregister(uint32_t id);

void rule_match_dump_table(TraceLevel trace_level);

void rule_action_dump_table(TraceLevel trace_level);

// TODO: Migrate from old version, it should be re-written to another version
int rule_match_create_by_config(uint16_t id, uint8_t remove_hdr, uint32_t teid_in, rte_be32_t ue_ipv4, uint32_t action_id);

// TODO: Migrate from old version, it should be re-written to another version
int rule_action_create_by_config(uint32_t id, uint8_t dst_int, rte_be16_t desp, rte_be32_t teid, rte_be32_t peer_ipv4);

#endif /* __DPDK_GTP_GW_RULE_H__ */