#ifndef __DPDK_GTP_GW_RULE_PDR_H__
#define __DPDK_GTP_GW_RULE_PDR_H__

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_ip.h>

#include "logger.h"
#include "rule_5tuple.h"

// Values for origin remove_hdr, used for set value
#define RULE_PDR_REMOVE_HDR_GTPU_IPV4             0x00
#define RULE_PDR_REMOVE_HDR_GTPU_IPV6             0x01
#define RULE_PDR_REMOVE_HDR_UDP_IPV4              0x02
#define RULE_PDR_REMOVE_HDR_UDP_IPV6              0x03
#define RULE_PDR_REMOVE_HDR_NO_REMOVE             0x06
// Values for remove_hdr (1 << Origin "Outer Header Removal" value + 4), used for packet handle
#define RULE_PDR_REMOVE_HDR_COOKED_UNSPEC         0x00
#define RULE_PDR_REMOVE_HDR_COOKED_GTPU_IPV4      0x10
#define RULE_PDR_REMOVE_HDR_COOKED_GTPU_IPV6      0x20
#define RULE_PDR_REMOVE_HDR_COOKED_UDP_IPV4       0x40
#define RULE_PDR_REMOVE_HDR_COOKED_UDP_IPV6       0x80

/**
 * Matching entries translated from PDR
 */
typedef struct rule_pdr_s {
    uint16_t                id;
    uint32_t                precedence;

    uint8_t                 remove_hdr;

    // Based matching value, don't filter if the value is 0
    rte_be32_t              ue_ipv4;
    rte_be32_t              upf_ipv4;
    rte_be32_t              teid;

    // Advanced matching
    char                    sdf_filter_str[0x40];   // Only record original data
    rule_5tuple_t           *sdf_filter;

    uint32_t                far_id;
} rule_pdr_t;

#define rule_pdr_zmalloc() rte_zmalloc("rule match in rule_pdr_zmalloc", sizeof(rule_pdr_t), 0)

#define rule_pdr_clean(rule) rule_5tuple_free((rule)->sdf_filter)

#define rule_pdr_free(rule)  rule_pdr_clean(rule); rte_free(rule)

// Set function and parameter as below
#define rule_pdr_set_id(rule, id_num) (rule)->id = (id_num)

#define rule_pdr_set_precedence(rule, pcd) (rule)->precedence = (pcd)

#define rule_pdr_set_remove_hdr(rule, rm_hdr) (rule)->remove_hdr = (1 << ((rm_hdr) + 4))

#define rule_pdr_set_ue_ipv4(rule, ipv4) (rule)->ue_ipv4 = (ipv4)
#define rule_pdr_set_ue_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &(rule)->ue_ipv4)

#define rule_pdr_set_upf_ipv4(rule, ipv4) (rule)->upf_ipv4 = (ipv4)
#define rule_pdr_set_upf_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &(rule)->upf_ipv4)

#define rule_pdr_set_teid(rule, teid_in) (rule)->teid = rte_cpu_to_be_32(teid_in)

#define rule_pdr_set_far_id(rule, id_num) (rule)->far_id = (id_num)

#define rule_pdr_set_sdf_filter(rule, desp) \
    strncpy((rule)->sdf_filter_str, desp, ((sizeof((rule)->sdf_filter_str) - 1) > strlen(desp) ? strlen(desp) : 0))

// Matching function and parameter as below
#define rule_pdr_is_ue_ipv4(rule, ipv4) ipv4_cmp2_first_is_zero_or_equal((rule)->ue_ipv4, ipv4)

#define rule_pdr_is_upf_ipv4(rule, ipv4) ipv4_cmp2_first_is_zero_or_equal((rule)->upf_ipv4, ipv4)

#define rule_pdr_is_teid(rule, teid_in) ((rule)->teid == teid_in)

// Show function as below
void logger_remove_hdr(uint8_t remove_hdr, TraceLevel trace_level);

#define rule_pdr_dump(rule, trace_level) \
    { \
        logger_s(LOG_GTP, trace_level, " - ID = "); \
                logger_s(LOG_GTP, trace_level, "%u", (rule)->id); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        logger_s(LOG_GTP, trace_level, "   Precedence = "); \
        logger_s(LOG_GTP, trace_level, "%u", (rule)->precedence); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        if ((rule)->remove_hdr) { \
            logger_s(LOG_GTP, trace_level, "   Outer Hdr Removal = "); \
            logger_remove_hdr((rule)->remove_hdr, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if ((rule)->ue_ipv4) { \
            logger_s(LOG_GTP, trace_level, "   UE IPv4 = "); \
            logger_ipv4((rule)->ue_ipv4, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if ((rule)->upf_ipv4) { \
            logger_s(LOG_GTP, trace_level, "   UPF IPv4 = "); \
            logger_ipv4((rule)->upf_ipv4, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if ((rule)->teid) { \
            logger_s(LOG_GTP, trace_level, "   TEID = "); \
            logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_32((rule)->teid)); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        logger_s(LOG_GTP, trace_level, "   Action ID = "); \
        logger_s(LOG_GTP, trace_level, "%u", (rule)->far_id); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        if ((rule)->sdf_filter) { \
            logger_s(LOG_GTP, trace_level, "   SDF Filter Description = "); \
            logger_s(LOG_GTP, trace_level, "%s", (rule)->sdf_filter_str); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
    }

#endif /* __DPDK_GTP_GW_RULE_PDR_H__ */