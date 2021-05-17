#ifndef __DPDK_GTP_GW_RULE_FAR_H__
#define __DPDK_GTP_GW_RULE_FAR_H__

#include <stdint.h>
#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_malloc.h>

#include "logger.h"

// Values for apply_action
#define RULE_FAR_APPLY_ACTION_UPSPEC             0x00
#define RULE_FAR_APPLY_ACTION_DROP               0x01
#define RULE_FAR_APPLY_ACTION_FORW               0x02
#define RULE_FAR_APPLY_ACTION_BUFF               0x04
#define RULE_FAR_APPLY_ACTION_MASK               0x07
#define RULE_FAR_APPLY_ACTION_NOCP               0x08
#define RULE_FAR_APPLY_ACTION_DUPL               0x10

// Values for dst_interface
#define RULE_FAR_DST_INT_ACCESS                  0x0     // Uplink
#define RULE_FAR_DST_INT_CORE                    0x1     // Downlink
#define RULE_FAR_DST_INT_N6_LAN                  0x2
#define RULE_FAR_DST_INT_CP_FUNC                 0x3

// Values for outer_hdr_info.desp
#define RULE_FAR_OUTER_HDR_DESP_UNSPEC           0x00
#define RULE_FAR_OUTER_HDR_DESP_GTPU_IPV4        0x10
#define RULE_FAR_OUTER_HDR_DESP_GTPU_IPV6        0x20
#define RULE_FAR_OUTER_HDR_DESP_UDP_IPV4         0x40
#define RULE_FAR_OUTER_HDR_DESP_UDP_IPV6         0x80

/**
 * Action entries translated from FAR
 */
typedef struct rule_far_s {
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
} rule_far_t;

#define rule_far_zmalloc() rte_zmalloc("rule action in rule_match_zmalloc", sizeof(rule_far_t), 0)

#define rule_far_free(rule) rte_free(rule)

// Set function and parameter as below
#define rule_far_set_id(rule, id_num) (rule)->id = (id_num)

#define rule_far_set_apply_action(rule, ap_ac) (rule)->apply_action = (ap_ac)

#define rule_far_set_dst_int(rule, d_i) (rule)->dst_int = (d_i)

#define rule_far_set_outer_hdr_desp(rule, d) (rule)->outer_hdr_info.desp = (d)

#define rule_far_set_outer_hdr_teid(rule, teid_out) (rule)->outer_hdr_info.teid = rte_cpu_to_be_32(teid_out)

#define rule_far_set_outer_hdr_ipv4(rule, ipv4) (rule)->outer_hdr_info.peer_ipv4 = (ipv4)
#define rule_far_set_outer_hdr_ipv4_str(rule, ipv4_str) inet_pton(AF_INET, (ipv4_str), &(rule)->outer_hdr_info.peer_ipv4)

#define rule_far_set_outer_hdr_port(rule, port) (rule)->outer_hdr_info.peer_port = rte_cpu_to_be_16(port)


//  Macro used to check & copy rule_far_t
#define rule_far_check_and_copy_val(d, s, target) if ((s)->target) (d)->target = (s)->target
#define rule_far_update(d, s) \
    rule_far_check_and_copy_val(d, s, id); \
    rule_far_check_and_copy_val(d, s, apply_action); \
    rule_far_check_and_copy_val(d, s, dst_int); \
    if ((s)->outer_hdr_info.desp) memcpy(&(d)->outer_hdr_info, &(s)->outer_hdr_info, sizeof((d)->outer_hdr_info))

// Show function as below

void logger_apply_action(uint8_t apply_action, TraceLevel trace_level);

void logger_dst_int(uint8_t dst_int, TraceLevel trace_level);

#define rule_far_dump(rule, trace_level) \
    { \
        logger_s(LOG_GTP, trace_level, " - ID = "); \
        logger_s(LOG_GTP, trace_level, "%u", (rule)->id); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        logger_s(LOG_GTP, trace_level, "   Apply Action =");  /* No space at the end of this sub-string for typesetting */ \
        logger_apply_action((rule)->apply_action, trace_level); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        logger_s(LOG_GTP, trace_level, "   Destination Interface = "); \
        logger_dst_int((rule)->dst_int, trace_level); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        if ((rule)->outer_hdr_info.desp) { \
            logger_s(LOG_GTP, trace_level, "   Outer Hdr Creation = \n"); \
            if ((rule)->outer_hdr_info.desp == RULE_FAR_OUTER_HDR_DESP_GTPU_IPV4 || \
                    (rule)->outer_hdr_info.desp == RULE_FAR_OUTER_HDR_DESP_UDP_IPV4) { \
                logger_s(LOG_GTP, trace_level, "      IPv4 DST = "); \
                logger_ipv4((rule)->outer_hdr_info.peer_ipv4, trace_level); \
                logger_s(LOG_GTP, trace_level, "\n"); \
            } \
            if ((rule)->outer_hdr_info.desp == RULE_FAR_OUTER_HDR_DESP_GTPU_IPV4 || \
                    (rule)->outer_hdr_info.desp == RULE_FAR_OUTER_HDR_DESP_GTPU_IPV6) { \
                logger_s(LOG_GTP, trace_level, "      TEID = "); \
                logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_32((rule)->outer_hdr_info.teid)); \
                logger_s(LOG_GTP, trace_level, "\n"); \
            } \
            logger_s(LOG_GTP, trace_level, "      UDP Port = "); \
            logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_16((rule)->outer_hdr_info.peer_port)); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
    }

#endif /* __DPDK_GTP_GW_RULE_FAR_H__ */