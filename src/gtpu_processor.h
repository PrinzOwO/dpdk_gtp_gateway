#ifndef __DPDK_GTP_GW_GTPU_PROCESSOR_H__
#define __DPDK_GTP_GW_GTPU_PROCESSOR_H__

#include <rte_mbuf.h>
#include <rte_gtp.h>

#include "logger.h"
#include "helper.h"
#include "stats.h"
#include "ip.h"
#include "udp.h"
#include "ip.h"
#include "gtpu.h"
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
static __rte_always_inline int process_gtpu(struct rte_mbuf *m, interface_t *interface,
        struct rte_ipv4_hdr *ipv4_hdr, struct rte_gtp_hdr *gtp_hdr, struct rte_ipv4_hdr *inner_ipv4_hdr)
{
    int out_int = interface->id ^ 1;

    rule_match_t *rule_match = NULL;
    rule_action_t *rule_action = NULL;
    if (unlikely(rule_match_find_by_teid(gtp_hdr->teid, &rule_match) < 0)) {
        printf_dbg(" Do not match any PDR");
        return -ENOENT;
    }

    rule_action = rule_match->action;
    printf_dbg(" ---> Match PDR #%u with FAR #%u in TEID hash", rule_match->id, rule_match->action_id);
    switch(rule_action->apply_action) {
        case RULE_ACTION_APPLY_ACTION_FORW:
            printf_dbg(", need to forward");
            /* TODO: Will happen in N9
            if (rule_match->remove_hdr == rule_action->outer_hdr_info.desp) {
                switch(rule_action->outer_hdr_info.desp) {
                    case RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4: // no warning
                        network_info->gtp_hdr->teid = rule_action->outer_hdr_info.teid;
                        __attribute__((fallthrough)); // No break to do UDP and IPv4 hdr modification
                    case RULE_ACTION_OUTER_HDR_DESP_UDP_IPV4:
                        udp_header_reply_set_inplace(network_info->udp_hdr, network_info->udp_hdr->dst_port, rule_action->outer_hdr_info.peer_port);
                        ipv4_header_reply_set_inplace(network_info->ipv4_hdr, network_info->ipv4_hdr->src_addr, rule_action->outer_hdr_info.peer_ipv4);
                        break;
                    default:
                        printf_dbg(", not support IPv6 hdr yet");
                        return -EPROTONOSUPPORT;
                }
            }
            */

            process_outer_hdr_removal_macro(rule_match->remove_hdr,
                    process_outer_hdr_removal_gtpu_ipv4_macro(m, inner_ipv4_hdr, ipv4_hdr, break),
                    process_outer_hdr_removal_none_macro(m, break),
                    return -EPROTONOSUPPORT
            );

            struct rte_ether_hdr *eth_hdr;
            struct rte_udp_hdr *udp_hdr;
            uint16_t payload_len;
            process_outer_hdr_creation_macro(rule_action->outer_hdr_info.desp,
                process_outer_hdr_creation_nono_macro(m, eth_hdr, break),
                process_outer_hdr_creation_gtpu_ipv4_macro(m, eth_hdr, ipv4_hdr, udp_hdr, gtp_hdr, payload_len, rule_action, out_int, break),
                return -EPROTONOSUPPORT
            );

            process_egress_marco(m, interface, eth_hdr, ipv4_hdr, out_int, return 0);
        case RULE_ACTION_APPLY_ACTION_DROP:
            printf_dbg(", need to drop");
            rte_pktmbuf_free(m);
            port_pkt_stats[interface->id].dropped += 1;
            return 0;
        case RULE_ACTION_APPLY_ACTION_BUFF:
            printf_dbg(", need to buffer but not support yet");
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
 * @return
 *   - length of hdr
 *   - < 0 if do not handle this packet
 */
static __rte_always_inline int parse_gtpu_ext_mbuf(struct rte_mbuf *m, uint16_t offset)
{
    uint16_t gtp_total_offset = offset;
    uint8_t *next_ext_hdr_type = rte_pktmbuf_mtod_offset(m, uint8_t *, offset - 1);
    while (*next_ext_hdr_type) {
        gtp_total_offset += next_ext_hdr_type[1] * 4;

        if (unlikely(rte_pktmbuf_data_len(m) < gtp_total_offset))
            return -EBADMSG;

        next_ext_hdr_type = rte_pktmbuf_mtod_offset(m, uint8_t *, gtp_total_offset - 1);
    }

    printf_dbg(" with ext gtp hdr len %u", gtp_total_offset - offset);

    return gtp_total_offset - offset;
}

/**
 * @return
 *   - length of hdr
 *   - < 0 if do not handle this packet
 */
static __rte_always_inline int parse_udp_gtp_mbuf(struct rte_mbuf *m,
        interface_t *interface, uint16_t offset, struct rte_udp_hdr **udp_hdr, struct rte_gtp_hdr **gtp_hdr)
{   
    int ret;
    uint16_t udp_gtpu_offset;
    
    *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);
    print_dbg_udp_hdr_port(*udp_hdr);

    *gtp_hdr = (void *) &(*udp_hdr)[1];
    if (likely((*udp_hdr)->dst_port == 0x6808)) {
        if (unlikely(((*gtp_hdr)->gtp_hdr_info >> 5) != 0x1)) {
            port_pkt_stats[interface->id].non_gtpVer += 1;
            return -EPROTONOSUPPORT;
        }
        printf_dbg(";");

        // parse GTP-U
        print_dbg_gtp_hdr(*gtp_hdr);
        udp_gtpu_offset = RTE_ETHER_GTP_HLEN + (((*gtp_hdr)->gtp_hdr_info & 0x07) ? 4 : 0);

        // parse ext gtp-u hdr
        printf_dbg(" udp and gtpu hdr len %u", udp_gtpu_offset);
        if (unlikely(((*gtp_hdr)->gtp_hdr_info & 0x04))) {
            if (unlikely((ret = parse_gtpu_ext_mbuf(m, offset + udp_gtpu_offset)) < 0)) {
                printf_dbg(", but ext gtp-u hdr is bad msg");
                return ret;
            }

            return udp_gtpu_offset + ret;
        }

        return udp_gtpu_offset;
    }

    port_pkt_stats[interface->id].non_gtp += 1;
    return -EPROTONOSUPPORT;
}

/**
 * This function would be the entry of packet proccessing.
 */
static __rte_always_inline void gtpu_processor(struct rte_mbuf *m, interface_t *interface)
{
    if (unlikely(rte_pktmbuf_data_len(m) < RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) + sizeof(RTE_ETHER_GTP_HLEN)))
        goto FREE_PKT_MBUF;

    int ret, offset;

    // Process frame
    struct rte_ether_hdr *eth_hdr;
    parse_frame_mbuf_marco(m, interface, eth_hdr);
    offset = RTE_ETHER_HDR_LEN;

    // Process packet
    struct rte_ipv4_hdr *ipv4_hdr;
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

    struct rte_udp_hdr *udp_hdr = NULL;
    struct rte_gtp_hdr *gtp_hdr = NULL;
    struct rte_ipv4_hdr *inner_ipv4_hdr = NULL;
    switch (ipv4_hdr->next_proto_id)
    {
        case IPPROTO_UDP:
            printf_dbg(";");
            if (unlikely((ret = parse_udp_gtp_mbuf(m, interface, offset, &udp_hdr, &gtp_hdr)) < 0)) {
                printf_dbg(" Warning: cannot handle UDP and GTP-U packet \n");
                goto FREE_PKT_MBUF;
            }

            inner_ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset + ret);
            break;
        default:
            port_pkt_stats[interface->id].non_udp += 1;
            printf_dbg(", next protocol: 0x%02x", ipv4_hdr->next_proto_id);
            goto FREE_PKT_MBUF;
    }

    if (unlikely(process_gtpu(m, interface, ipv4_hdr, gtp_hdr, inner_ipv4_hdr) < 0))
        goto FREE_PKT_MBUF;

    return;

FREE_PKT_MBUF:
    port_pkt_stats[interface->id].dropped += 1;
    rte_pktmbuf_free(m);
}

#endif /* __DPDK_GTP_GW_GTPU_PROCESSOR_H__ */