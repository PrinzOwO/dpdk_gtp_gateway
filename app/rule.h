#ifndef __DPDK_GTP_GW_RULE_H__
#define __DPDK_GTP_GW_RULE_H__

// TODO: thread safe
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_gtp.h>

#include "pktbuf.h"
#include "interface.h"
#include "rule_5tuple.h"
#include "rule_pdr.h"
#include "rule_far.h"

/**
 * Matching entries translated from PDR
 */
typedef struct rule_match_s {
    rule_pdr_t              pdr;
    rule_far_t              *far;

    // Accelerate to find which PDR the packet belong to
    struct rule_match_s     *next_id;
    struct rule_match_s     *next_ipv4;
    struct rule_match_s     *next_teid;
} rule_match_t;

#define rule_match_zmalloc() rte_zmalloc("rule match in rule_match_zmalloc", sizeof(rule_match_t), 0)

#define rule_match_free(rule) rule_pdr_clean(&rule->pdr); rte_free(rule)

int rule_init(uint8_t with_locks);

#ifdef ULCL
int rule_match_find_by_teid(struct rte_ipv4_hdr *ipv4_hdr, struct rte_gtp_hdr *gtp_hdr, struct rte_ipv4_hdr *inner_ipv4_hdr, rule_match_t **rule);
#else
int rule_match_find_by_teid(struct rte_gtp_hdr *gtp_hdr, rule_match_t **rule);
#endif /* ULCL */

int rule_match_find_by_ipv4(struct rte_ipv4_hdr *ipv4_hdr, rule_match_t **rule);

int rule_far_find_by_id(uint32_t id, rule_far_t **data);

int rule_match_register(rule_match_t *rule);

int rule_match_deregister(uint16_t id);

int rule_far_register(rule_far_t *rule);

int rule_far_deregister(uint32_t id);

void rule_match_dump_table(TraceLevel trace_level);

void rule_far_dump_table(TraceLevel trace_level);

// TODO: Migrate from old version, it should be re-written to another version
int rule_match_create_by_config(uint16_t id, uint8_t remove_hdr, uint32_t teid_in, rte_be32_t ue_ipv4, uint32_t far_id);

// TODO: Migrate from old version, it should be re-written to another version
int rule_far_create_by_config(uint32_t id, uint8_t dst_int, rte_be16_t desp, rte_be32_t teid, rte_be32_t peer_ipv4);

#endif /* __DPDK_GTP_GW_RULE_H__ */