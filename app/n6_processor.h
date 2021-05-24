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
    int out_int = interface->id ^ 1;

    rule_match_t *rule_match = NULL;
    if (unlikely(rule_match_find_by_ipv4(ipv4_hdr, &rule_match) < 0)) {
        printf_dbg(" Do not match any PDR");
        return -ENOENT;
    }

    rule_far_t *far = rule_match->far;
    /*
    printf_dbg(" ---> Match PDR #%u with FAR #%u in IPv4 hash", rule_match->pdr.id, rule_match->pdr.far_id);
    switch(far->apply_action) {
        case RULE_FAR_APPLY_ACTION_FORW:
            printf_dbg(" , need to forward");

            process_outer_hdr_removal_switch_case_macro(rule_match->pdr.remove_hdr,
                    process_outer_hdr_removal_case_none_macro(m, break),
                    , // N6 ingress port don't support GTP-U decap
                    return -EPROTONOSUPPORT
            );

            struct rte_ether_hdr *eth_hdr;
            struct rte_udp_hdr *udp_hdr;
            struct rte_gtp_hdr *gtp_hdr;
            process_outer_hdr_creation_switch_case_macro(far->outer_hdr_info.desp,
                process_outer_hdr_creation_case_gtpu_ipv4_macro(m, eth_hdr, ipv4_hdr, udp_hdr, gtp_hdr, far, out_int, break),
                process_outer_hdr_creation_case_nono_macro(m, eth_hdr, break),
                return -EPROTONOSUPPORT
            );

            process_egress_marco(m, interface, eth_hdr, ipv4_hdr, out_int, return 0);
        case RULE_FAR_APPLY_ACTION_DROP:
            printf_dbg(" , need to drop");
            rte_pktmbuf_free(m);
            port_pkt_stats[interface->id].dropped += 1;
            return 0;
        case RULE_FAR_APPLY_ACTION_BUFF:
            printf_dbg(" , need to buffer but not support yet");
            // TODO: temporary handle
            rte_pktmbuf_free(m);
            port_pkt_stats[interface->id].dropped += 1;
            return 0;
        default:
            printf_dbg(" , need to %d but not support yet", far->apply_action);
            return -EPROTONOSUPPORT;
    }
    */

    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);
    const int outer_hdr_len = RTE_ETHER_GTP_HLEN + sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN;

    struct rte_ether_hdr *eth_hdr =
            (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, (uint16_t) outer_hdr_len);
    interface_t *out_iface = interface_get_this(out_int);

    ipv4_hdr = (struct rte_ipv4_hdr *) ((char *)(eth_hdr + 1));

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *) ((char *)(ipv4_hdr + 1));
    struct rte_gtp_hdr *gtp_hdr = (struct rte_gtp_hdr *) ((char *)(udp_hdr + 1));

    rte_be32_t ran_ipv4 = far->outer_hdr_info.peer_ipv4;

    eth_hdr->ether_type = 0x8;
    rte_ether_addr_copy(&out_iface->mac, &eth_hdr->s_addr);

    if (unlikely(arp_get_mac(ran_ipv4, &eth_hdr->d_addr) < 0)) {
        printf_dbg(" not found in arp table");
        /* Send ARP request and drop this packet */
        arp_send_request(ipv4_hdr->dst_addr, out_int);
        return -ENOENT;
    }

    ipv4_header_set_inplace_macro(ipv4_hdr,
            out_iface->ipv4, ran_ipv4,
            m->pkt_len - RTE_ETHER_HDR_LEN);

    udp_header_set_inplace_macro(udp_hdr, 0x6808, 0x6808,
            m->pkt_len - RTE_ETHER_HDR_LEN - sizeof(struct rte_ipv4_hdr));

    gtpu_header_set_inplace_macro(gtp_hdr, 0, 0xff, \
            m->pkt_len - RTE_ETHER_HDR_LEN - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr), \
            far->outer_hdr_info.teid);

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);
    m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;

    if (likely(rte_eth_tx_burst(out_int, 0, &m, 1)))
        return ;
    return -ENOSPC;
}

/**
 * This function would be the entry of packet proccessing.
 */
static __rte_always_inline void n6_processor(struct rte_mbuf *m, interface_t *interface)
{
    if (unlikely(rte_pktmbuf_data_len(m) < RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr)))
        goto FREE_PKT_MBUF;

    int offset;

    // Process frame
    struct rte_ether_hdr *eth_hdr = NULL;
    parse_frame_mbuf_marco(m, interface, eth_hdr);
    offset = RTE_ETHER_HDR_LEN;

    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        // Order of ether_type in switch case using happening frequency
        case RTE_ETHER_TYPE_IPV4:
            printf_dbg(";");

            parse_pkt_mbuf_macro(m, interface, eth_hdr, ipv4_hdr, goto FREE_PKT_MBUF);
            offset += sizeof(struct rte_ipv4_hdr);
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