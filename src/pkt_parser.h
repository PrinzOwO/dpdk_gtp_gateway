#ifndef __DPDK_GTP_GW_PKT_PARSER_H__
#define __DPDK_GTP_GW_PKT_PARSER_H__

#include <rte_ip_frag.h>

#include "stats.h"
#include "helper.h"
#include "interface.h"
#include "arp_table.h"
#include "rule.h"
#include "pkt.h"
#include "pkt_processor.h"

// TODO: Temperay to use, need to delete it
/* EXTERN */
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if segment comes from N6
 *   - COMMING_FROM_GTPU if segment is GTP-U
 */
static __rte_always_inline int parse_gtpu_ext_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    uint16_t gtp_total_offset = offset;
    uint8_t *next_ext_hdr_type = rte_pktmbuf_mtod_offset(m, uint8_t *, offset - 1);
    while (*next_ext_hdr_type) {
        gtp_total_offset += next_ext_hdr_type[1] * 4;

        if (unlikely(rte_pktmbuf_data_len(m) < gtp_total_offset))
            return CORRUPTED_PACKET;

        next_ext_hdr_type = rte_pktmbuf_mtod_offset(m, uint8_t *, gtp_total_offset - 1);
    }

    network_info->origin.ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, gtp_total_offset);
    printf_dbg(" with ext gtp hdr len %u", gtp_total_offset - offset);

    return COMMING_FROM_GTPU;
}

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if segment comes from N6
 *   - COMMING_FROM_GTPU if segment is GTP-U
 */
static __rte_always_inline int parse_gtp_mbuf_no_len_check(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    struct rte_gtp_hdr *gtp_hdr = network_info->gtp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_gtp_hdr *, offset);

    printf_dbg(" GTP version %u, msg_type 0x%02x, teid %u", (gtp_hdr->gtp_hdr_info >> 5), gtp_hdr->msg_type, rte_be_to_cpu_32(gtp_hdr->teid));
    if (likely((gtp_hdr->gtp_hdr_info >> 5) == 0x1)) {
        uint16_t gtpu_offset = offset + sizeof(struct rte_gtp_hdr) + ((gtp_hdr->gtp_hdr_info & 0x07) ? 4 : 0);
        printf_dbg(" gtpu hdr len %u", gtpu_offset - offset);
        if (unlikely((gtp_hdr->gtp_hdr_info & 0x04)))
            return parse_gtpu_ext_mbuf(m, network_info, gtpu_offset);
        else
            network_info->origin.ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, gtpu_offset);

        return COMMING_FROM_GTPU;
    }

    port_pkt_stats[network_info->interface->id].non_gtpVer += 1;
    return COMMING_FROM_N6;
}

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if segment comes from N6
 *   - COMMING_FROM_GTPU if segment is GTP-U
 */

static __rte_always_inline int parse_udp_gtp_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    if (unlikely(rte_pktmbuf_data_len(m) < offset + sizeof(RTE_ETHER_GTP_HLEN)))
        return COMMING_FROM_N6;
    
    struct rte_udp_hdr *udp_hdr = network_info->udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);

    printf_dbg(" UDP src_port: %u, dst_port %u", rte_be_to_cpu_16(udp_hdr->src_port), rte_be_to_cpu_16(udp_hdr->dst_port));
    if (likely(udp_hdr->dst_port == GTPU_NET_ENDIAN)) {
        printf_dbg(";");
        return parse_gtp_mbuf_no_len_check(m, network_info, offset + sizeof(struct rte_udp_hdr));
    }

    port_pkt_stats[network_info->interface->id].non_gtp += 1;
    return COMMING_FROM_N6;
}

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if packet comes from N6
 *   - COMMING_FROM_GTPU if packet is GTP-U
 */
static __rte_always_inline int parse_pkt_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    if (unlikely(rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ipv4_hdr)))
        return CORRUPTED_PACKET;
    
    struct rte_ipv4_hdr *ipv4_hdr = network_info->ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    printf_dbg(" IPv4 s_addr: ");
    print_dbg_ipv4(ipv4_hdr->src_addr);
    printf_dbg(", d_addr: ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
    
    // Check IP is fragmented
    if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr))) {
        port_pkt_stats[network_info->interface->id].ipFrag += 1;
        return -1;
    }

    // Order of ether_type in switch case using happening frequency
    switch (ipv4_hdr->next_proto_id)
    {
        case IPPROTO_UDP:
            printf_dbg(";");
            return parse_udp_gtp_mbuf(m, network_info, offset + sizeof(struct rte_ipv4_hdr));
        
        default:
            port_pkt_stats[network_info->interface->id].non_udp += 1;
            printf_dbg(", next protocol: 0x%02x", ipv4_hdr->next_proto_id);
            return COMMING_FROM_N6;
    }
}

/**
 * This function would be the entry of packet proccessing.
 */
static __rte_always_inline void parse_frame_mbuf(struct rte_mbuf *m, interface_t *interface)
{
    if (unlikely(rte_pktmbuf_data_len(m) < RTE_ETHER_HDR_LEN))
        goto FREE_PKT_MBUF;
    mbuf_network_info_t network_info = {0};
    network_info.interface = interface;

    struct rte_ether_hdr *eth_hdr = network_info.eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    printf_dbg("\n [RX] Port #%u ", interface->id);
    printf_dbg("Ether d_addr: ");
    print_dbg_mac(&eth_hdr->d_addr);
    printf_dbg(", s_addr: ");
    print_dbg_mac(&eth_hdr->s_addr);

    // TODO: Ether transport operation here, please create another to handle
    // ......

    int comming_from;
    // Order of ether_type in switch case using happening frequency
    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        case RTE_ETHER_TYPE_IPV4:
            printf_dbg(";");
            if (unlikely((comming_from = parse_pkt_mbuf(m, &network_info, RTE_ETHER_HDR_LEN)) < 0)) {
                logger(LOG_IP, L_DEBUG, " Warning: cannot handle IPv4 packet \n");
                goto FREE_PKT_MBUF;
            }

            break;
        case RTE_ETHER_TYPE_ARP:
            if (unlikely(arp_in(m, interface))) {
                logger(LOG_ARP, L_DEBUG, " Warning: cannot handle ARP frame \n");
                goto FREE_PKT_MBUF;
            }

            return;
        default:
            port_pkt_stats[interface->id].non_ipv4 += 1;
            printf_dbg(", next protocol: 0x%02x%02x, but not support yet \n", (eth_hdr->ether_type & 0xFF), (eth_hdr->ether_type >> 8));
            return;
    }

    printf_dbg("; ingress interface: ");
    // TODO: customized for N3, N6 and N9?
    switch(comming_from) {
        case COMMING_FROM_GTPU:
            printf_dbg("GTP-U; \n");
            if (process_gtpu(m, &network_info) < 0) {
                printf_dbg(" -> process_gtpu failed \n");
                goto FREE_PKT_MBUF;
            }
            return;
        case COMMING_FROM_N6:
            printf_dbg("N6; \n");
            if (process_ipv4(m, &network_info) < 0) {
                printf_dbg(" -> process_ipv4 failed \n");
                goto FREE_PKT_MBUF;
            }
            return;
        default:
            printf_dbg("Unknown \n");
            goto FREE_PKT_MBUF;
    }

FREE_PKT_MBUF:
    port_pkt_stats[interface->id].dropped += 1;
    rte_pktmbuf_free(m);
}

#endif /* __DPDK_GTP_GW_PKT_PARSER_H__ */