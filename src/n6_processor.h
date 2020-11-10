#ifndef __DPDK_GTP_GW_N6_PROCESSOR_H__
#define __DPDK_GTP_GW_N6_PROCESSOR_H__

#include <rte_mbuf.h>
#include <rte_gtp.h>

#include "logger.h"
#include "helper.h"
#include "stats.h"
#include "ip.h"
#include "udp.h"
#include "ip.h"
#include "pkt.h"
#include "rule.h"

// TODO: Temperay to use, need to delete it
/* EXTERN */
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_n6(struct rte_mbuf *m, interface_t *interface, struct rte_ipv4_hdr *ipv4_hdr)
{  
    int ret;
    int out_int = interface->id ^ 1;

    rule_match_t *rule_match = NULL;
    rule_action_t *rule_action = NULL;
    if (unlikely(rule_match_find_by_ipv4(ipv4_hdr->dst_addr, &rule_match) < 0)) {
        printf_dbg(" Do not match any PDR");
        return -ENOENT;
    }

    rule_action = rule_match->action;
    printf_dbg(" ---> Match PDR #%u with FAR #%u in IPv4 hash", rule_match->id, rule_match->action_id);
    switch(rule_action->apply_action) {
        case RULE_ACTION_APPLY_ACTION_FORW:
            printf_dbg(" , need to forward");
            if (unlikely((ret = process_outer_hdr_removal(m, rule_match, ipv4_hdr)) < 0)) {
                printf_dbg(", ERROR: cannot handle outer hdr removal");
                return ret;
            }

            if (unlikely((ret = process_outer_hdr_creation(m, rule_action, out_int)) < 0)) {
                printf_dbg(", ERROR: cannot handle outer hdr creation");
                return ret;
            }

            return process_egress_inplace(m, interface, out_int);
        case RULE_ACTION_APPLY_ACTION_DROP:
            printf_dbg(" , need to drop");
            rte_pktmbuf_free(m);
            port_pkt_stats[interface->id].dropped += 1;
            return 0;
        case RULE_ACTION_APPLY_ACTION_BUFF:
            printf_dbg(" , need to buffer but not support yet");
            // TODO: temporary handle
            rte_pktmbuf_free(m);
            port_pkt_stats[interface->id].dropped += 1;
            return 0;
        default:
            printf_dbg(" , need to %d but not support yet", rule_action->apply_action);
            return -EPROTONOSUPPORT;
    }
}

/**
 * This function would be the entry of packet proccessing.
 */
static __rte_always_inline void n6_processor(struct rte_mbuf *m, interface_t *interface)
{
    if (unlikely(rte_pktmbuf_data_len(m) < RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr)))
        goto FREE_PKT_MBUF;

    int ret;

    // Process frame
    struct rte_ether_hdr *eth_hdr =NULL;
    int offset = parse_frame_mbuf(m, interface, &eth_hdr);

    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        // Order of ether_type in switch case using happening frequency
        case RTE_ETHER_TYPE_IPV4:
            printf_dbg(";");
            if (unlikely((ret = parse_pkt_mbuf(m, interface, offset, &ipv4_hdr)) < 0)) {
                printf_dbg(" Warning: cannot handle IPv4 packet \n");
                goto FREE_PKT_MBUF;
            }

            offset += ret;
            break;
        case RTE_ETHER_TYPE_ARP:
            if (unlikely(arp_in(m, interface))) {
                printf_dbg(" Warning: cannot handle ARP frame \n");
                goto FREE_PKT_MBUF;
            }

            return;
        default:
            port_pkt_stats[interface->id].non_ipv4 += 1;
            printf_dbg(", next protocol: 0x%02x%02x, but not support yet \n", (eth_hdr->ether_type & 0xFF), (eth_hdr->ether_type >> 8));
            return;
    }

    if (unlikely(process_n6(m, interface, ipv4_hdr) < 0))
        goto FREE_PKT_MBUF;

    return;

FREE_PKT_MBUF:
    port_pkt_stats[interface->id].dropped += 1;
    rte_pktmbuf_free(m);
}

#endif /* __DPDK_GTP_GW_N6_PROCESSOR_H__ */