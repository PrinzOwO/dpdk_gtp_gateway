#ifndef __DPDK_GTP_GW_PKT_H__
#define __DPDK_GTP_GW_PKT_H__

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>
#include <rte_gtp.h>

#include "stats.h"
#include "interface.h"
#include "ip.h"
#include "arp_table.h"
#include "rule.h"

// TODO: Temperay to use, need to delete it
/* EXTERN */
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

/**
 * Used to store network header pointer when parse mbuf
 * 
 * TODO: Remove it if the throughput is bad
typedef struct mbuf_network_info_s {
    interface_t             *interface;

    struct rte_ether_hdr    *eth_hdr;
    struct rte_ipv4_hdr     *ipv4_hdr;
    struct rte_udp_hdr      *udp_hdr;
    struct rte_gtp_hdr      *gtp_hdr;

    union origin_t {
        struct rte_ether_hdr    *eth_hdr;
        struct rte_ipv4_hdr     *ipv4_hdr;
    } origin;
    
} mbuf_network_info_t;
*/

/**
 * @return
 *   - length of hdr
 *   - < 0 if do not handle this packet
 */
static __rte_always_inline int parse_frame_mbuf(struct rte_mbuf *m,
        __attribute__((unused)) interface_t *interface, struct rte_ether_hdr **eth_hdr)
{   
    *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    printf_dbg("\n [RX] Port #%u (%s) ", interface->id, (interface->type == INTERFACE_TYPE_N6 ? "N6" : "GTP-U"));
    print_dbg_ether_hdr_mac(*eth_hdr);

    return RTE_ETHER_HDR_LEN;
}

/**
 * @return
 *   - length of hdr
 *   - < 0 if do not handle this packet
 */
static __rte_always_inline int parse_pkt_mbuf(struct rte_mbuf *m,
        interface_t *interface, uint16_t offset, struct rte_ipv4_hdr **ipv4_hdr)
{   
    *ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    print_dbg_ipv4_hdr_addr(*ipv4_hdr);
    
    // Check IP is fragmented
    if (unlikely(rte_ipv4_frag_pkt_is_fragmented(*ipv4_hdr))) {
        port_pkt_stats[interface->id].ipFrag += 1;
        *ipv4_hdr = NULL;
        printf_dbg(", detected ip fragment and not support yet");
        return -EPROTONOSUPPORT;
    }

    return (int) sizeof(struct rte_ipv4_hdr);
}

/**
 * @return
 *   - 0 if packet processes successfully
 *   - < 0 if packet processes failed, need to free this packet from caller
 */
static __rte_always_inline int process_egress_inplace(struct rte_mbuf *m, interface_t *interface, uint8_t out_int)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (void *) &eth_hdr[1];
    
    printf_dbg(", find out dst IP ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
    printf_dbg(" in ARP table:");
    if (unlikely(arp_get_mac(ipv4_hdr->dst_addr, &eth_hdr->d_addr) < 0)) {
        printf_dbg(" not found in arp table");
        port_pkt_stats[interface->id].dropped += 1;

        arp_send_request(ipv4_hdr->dst_addr, out_int);
        return -ENOENT;
    }
    else {
        printf_dbg(" with dst mac ");
        print_dbg_mac(&eth_hdr->d_addr);
    }

    rte_ether_addr_copy(&eth_hdr->s_addr, &interface_get_this(out_int)->mac);
    // TODO: Set ether_type with payload
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

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
        rule_match_t *rule_match, struct rte_ipv4_hdr *ipv4_hdr)
{
    switch(rule_match->remove_hdr) {
        case RULE_MATCH_REMOVE_HDR_COOKED_GTPU_IPV4: // More happen in ingress N3
            printf_dbg(", remove GTP-U, UDP, IPv4 and ethernet hdr");
            rte_pktmbuf_adj(m, (uint8_t *) ipv4_hdr - rte_pktmbuf_mtod(m, uint8_t *));
            return 0;
        case RULE_MATCH_REMOVE_HDR_COOKED_UNSPEC: // More happen in ingress N6
            printf_dbg(", remove ethernet hdr");
            rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);
            return 0;
        /* TODO: not support yet
        case RULE_MATCH_REMOVE_HDR_COOKED_UDP_IPV4:
            printf_dbg(", remove UDP, IPv4 and ethernet hdr");
            // rte_pktmbuf_adj(m, (uint8_t *) network_info->gtp_hdr - (uint8_t *) network_info->eth_hdr);
            return -EPROTONOSUPPORT;
        */
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
        rule_action_t *rule_action, uint8_t out_int)
{
    uint16_t payload_len;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct rte_gtp_hdr *gtp_hdr;

    switch(rule_action->outer_hdr_info.desp) {
        case RULE_ACTION_OUTER_HDR_DESP_UNSPEC: // More happen in egress N6
            printf_dbg(", don't create outer hdr");
            rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
            // ethernet hdr will be handled at send function
            return 0;
        case RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4: // More happen in egress N3
            printf_dbg(", create outer gtp-u, udp and ipv4 hdr");
            eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m,
                    RTE_ETHER_GTP_HLEN + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr));
            // ethernet hdr will be handled at send function

            ipv4_header_set_inplace((ipv4_hdr = (void *) &eth_hdr[1]), 
                    interface_get_this(out_int)->ipv4, rule_action->outer_hdr_info.peer_ipv4,
                    (payload_len = rte_pktmbuf_data_len(m) - sizeof(struct rte_ether_hdr)));

            udp_header_set_inplace((udp_hdr = (void *) &ipv4_hdr[1]),
                    0x6808, rule_action->outer_hdr_info.peer_port,
                    (payload_len -= sizeof(struct rte_ipv4_hdr)));

            gtpu_header_set_inplace((gtp_hdr = (void *) &udp_hdr[1]),
                    0, 0xff, (payload_len -= sizeof(struct rte_udp_hdr)), rule_action->outer_hdr_info.teid);
            return 0;
        /*
        case RULE_ACTION_OUTER_HDR_DESP_UDP_IPV4:
            // TODO: 
            printf_dbg(" not support adding UDP and IPv4 hdr yet");
            return -EPROTONOSUPPORT;
        */
        default:
            printf_dbg(" not support IPv6 hdr yet");
            return -EPROTONOSUPPORT;
    }
}

#endif /* __DPDK_GTP_GW_PKT_H__ */