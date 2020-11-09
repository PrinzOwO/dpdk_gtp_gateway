#ifndef __DPDK_GTP_GW_PKT_PROCESSOR_H__
#define __DPDK_GTP_GW_PKT_PROCESSOR_H__

#include <rte_mbuf.h>
#include <rte_gtp.h>

#include "logger.h"
#include "helper.h"
#include "stats.h"
#include "pktbuf.h"
#include "ip.h"
#include "udp.h"
#include "ip.h"
#include "gtpu.h"
#include "pkt.h"
#include "rule.h"

// TODO: Temperay to use, need to delete it
/* EXTERN */
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

// TODO: Ether transport operation here, please create another to handle
/*
static __rte_always_inline int process_ether(struct rte_mbuf *m, mbuf_network_info_t *network_info)
{

}
*/

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_frame_and_send(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint8_t out_int)
{
    printf_dbg(", find out dst IP ");
    print_dbg_ipv4(network_info->ipv4_hdr->dst_addr);
    printf_dbg(" in ARP table:");
    if (unlikely(arp_get_mac(network_info->ipv4_hdr->dst_addr, &network_info->eth_hdr->d_addr) < 0)) {
        printf_dbg(" not found in arp table");
        port_pkt_stats[network_info->interface->id].dropped += 1;

        arp_send_request(network_info->ipv4_hdr->dst_addr, out_int);
        return -ENOENT;
    }
    else {
        printf_dbg(" with dst mac ");
        print_dbg_mac(&network_info->eth_hdr->d_addr);
    }

    rte_ether_addr_copy(&network_info->eth_hdr->s_addr, &interface_get_this(out_int)->mac);
    // TODO: Set ether_type with payload
    network_info->eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    int nb_tx;
    printf_dbg("\n [TX]");
    if (likely((nb_tx = rte_eth_tx_burst(out_int, 0, &m, 1)) == 1)) {
        printf_dbg(" Sent frame to Port #%d with nb_tx=%d \n", out_int, nb_tx);
        return 0;
    }

    printf_dbg(" ERR(rte_eth_tx_burst=%d) \n", nb_tx);
    return -ENOSPC;
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_outer_hdr_removal(struct rte_mbuf *m,
        mbuf_network_info_t *network_info, rule_match_t *rule_match)
{
    switch(rule_match->remove_hdr) {
        case RULE_MATCH_REMOVE_HDR_COOKED_GTPU_IPV4:
            printf_dbg(", remove GTP-U, UDP, IPv4 and ethernet hdr");
            network_info->ipv4_hdr = (struct rte_ipv4_hdr *) rte_pktmbuf_adj(m,
                    (uint8_t *) network_info->origin.ipv4_hdr - (uint8_t *) network_info->eth_hdr);
            return 0;
        case RULE_MATCH_REMOVE_HDR_COOKED_UNSPEC: // No existed outer header removal
            printf_dbg(", remove ethernet hdr");
            rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);
            // network_info->eth_hdr = NULL;
            return 0;
        case RULE_MATCH_REMOVE_HDR_COOKED_UDP_IPV4:
            printf_dbg(", remove UDP, IPv4 and ethernet hdr");
            // TODO: maintain network_info pointer
            // rte_pktmbuf_adj(m, (uint8_t *) network_info->gtp_hdr - (uint8_t *) network_info->eth_hdr);
            return -EPROTONOSUPPORT;
        default:
            printf_dbg(", not support IPv6 hdr yet");
            return -EPROTONOSUPPORT;
    }
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_outer_hdr_creation(struct rte_mbuf *m,
        mbuf_network_info_t *network_info, rule_action_t *rule_action, uint8_t out_int)
{
    uint16_t payload_len, prepare_hdr_len;
    switch(rule_action->outer_hdr_info.desp) {
        case RULE_ACTION_OUTER_HDR_DESP_UNSPEC:
            printf_dbg(", don't create outer hdr");
            network_info->eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
            // ethernet hdr will be handled at send function
            return 0;
        case RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4: 
            printf_dbg(", don't create outer gtp-u, udp and ipv4 hdr");
            prepare_hdr_len = RTE_ETHER_GTP_HLEN + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);
            network_info->eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, prepare_hdr_len);
            // ethernet hdr will be handled at send function

            network_info->ipv4_hdr = (void *) &network_info->eth_hdr[1];
            ipv4_header_set_inplace(network_info->ipv4_hdr, 
                    interface_get_this(out_int)->ipv4, rule_action->outer_hdr_info.peer_ipv4,
                    (payload_len = rte_pktmbuf_data_len(m) - sizeof(struct rte_ether_hdr)));

            network_info->udp_hdr = (void *) &network_info->ipv4_hdr[1];
            udp_header_set_inplace(network_info->udp_hdr,
                    0x6808, rule_action->outer_hdr_info.peer_port,
                    (payload_len -= sizeof(struct rte_ipv4_hdr)));

            network_info->gtp_hdr = (void *) &network_info->udp_hdr[1];
            gtpu_header_set_inplace(network_info->gtp_hdr, 0, 0xff, (payload_len -= sizeof(struct rte_udp_hdr)),
                    rule_action->outer_hdr_info.teid);
            return 0;
        case RULE_ACTION_OUTER_HDR_DESP_UDP_IPV4:
            // TODO: 
            printf_dbg(" not support adding UDP and IPv4 hdr yet");
            return -EPROTONOSUPPORT;
        default:
            printf_dbg(" not support IPv6 hdr yet");
            return -EPROTONOSUPPORT;
    }
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_gtpu_forward(struct rte_mbuf *m,
        mbuf_network_info_t *network_info, rule_match_t *rule_match, rule_action_t *rule_action)
{
    int ret;
    
    // TODO: fix the two below, port should be dfrom routing
    uint8_t n6_interface = network_info->interface->id ^ 1;
    // uint8_t gtpu_interface = network_info->interface->id;

    // TODO: Do not test yet, function would not be finished
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
    else {
        if (unlikely((ret = process_outer_hdr_removal(m, network_info, rule_match)) < 0)) {
            printf_dbg(", ERROR: cannot handle outer hdr removal");
            return ret;
        }

        if (unlikely((ret = process_outer_hdr_creation(m, network_info, rule_action, n6_interface)) < 0)) {
            printf_dbg(", ERROR: cannot handle outer hdr creation");
            return ret;
        }
    }

    return process_frame_and_send(m, network_info, n6_interface);
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_gtpu(struct rte_mbuf *m, mbuf_network_info_t *network_info)
{
    rule_match_t *rule_match = NULL;
    rule_action_t *rule_action = NULL;
    if (unlikely(rule_match_find_by_teid(network_info, &rule_match) < 0)) {
        printf_dbg(" Do not match any PDR");
        return -1;
    }

    rule_action = rule_match->action;
    printf_dbg(" ---> Match PDR #%u with FAR #%u in TEID hash", rule_match->id, rule_match->action_id);
    switch(rule_action->apply_action) {
        case RULE_ACTION_APPLY_ACTION_FORW:
            printf_dbg(", need to forward");
            return process_gtpu_forward(m, network_info, rule_match, rule_action);
        case RULE_ACTION_APPLY_ACTION_DROP:
            printf_dbg(", need to drop");
            rte_pktmbuf_free(m);
            port_pkt_stats[network_info->interface->id].dropped += 1;
            return 0;
        case RULE_ACTION_APPLY_ACTION_BUFF:
            printf_dbg(", need to buffer but not support yet");
            // TODO: temporary handle
            rte_pktmbuf_free(m);
            port_pkt_stats[network_info->interface->id].dropped += 1;
            return 0;
        default:
            printf_dbg(" , need to %d but not support yet", rule_action->apply_action);
            return -EPROTONOSUPPORT;
    }
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_ipv4_forward(struct rte_mbuf *m,
        mbuf_network_info_t *network_info, rule_match_t *rule_match, rule_action_t *rule_action)
{
    int ret;

    // TODO: fix the two below, port should be dfrom routing
    uint8_t gtpu_interface = network_info->interface->id ^ 1;
    // uint8_t n6_interface = network_info->interface->id;

    if (unlikely((ret = process_outer_hdr_removal(m, network_info, rule_match)) < 0)) {
        printf_dbg(", ERROR: cannot handle outer hdr removal");
        return ret;
    }
    
    if (unlikely((ret = process_outer_hdr_creation(m, network_info, rule_action, gtpu_interface)) < 0)) {
        printf_dbg(", ERROR: cannot handle outer hdr creation");
        return ret;
    }

    return process_frame_and_send(m, network_info, gtpu_interface);
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_ipv4(struct rte_mbuf *m, mbuf_network_info_t *network_info)
{
    rule_match_t *rule_match = NULL;
    rule_action_t *rule_action = NULL;

    if (unlikely(rule_match_find_by_ipv4(network_info, &rule_match) < 0)) {
        printf_dbg(" Do not match any PDR");
        return -1;
    }

    rule_action = rule_match->action;
    printf_dbg(" ---> Match PDR #%u with FAR #%u in IPv4 hash", rule_match->id, rule_match->action_id);
    switch(rule_action->apply_action) {
        case RULE_ACTION_APPLY_ACTION_FORW:
            printf_dbg(" , need to forward");
            return process_ipv4_forward(m, network_info, rule_match, rule_action);
        case RULE_ACTION_APPLY_ACTION_DROP:
            printf_dbg(" , need to drop");
            rte_pktmbuf_free(m);
            port_pkt_stats[network_info->interface->id].dropped += 1;
            return 0;
        case RULE_ACTION_APPLY_ACTION_BUFF:
            printf_dbg(" , need to buffer but not support yet");
            // TODO: temporary handle
            rte_pktmbuf_free(m);
            port_pkt_stats[network_info->interface->id].dropped += 1;
            return 0;
        default:
            printf_dbg(" , need to %d but not support yet", rule_action->apply_action);
            return -EPROTONOSUPPORT;
    }

   return 0;
}

#endif /* __DPDK_GTP_GW_PKT_PROCESSOR_H__ */