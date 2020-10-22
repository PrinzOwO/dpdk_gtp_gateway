#ifndef __DPDK_GTP_GW_PKT_PROCESS_H__
#define __DPDK_GTP_GW_PKT_PROCESS_H__

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>
#include <rte_gtp.h>

#include "helper.h"

#define COMMING_FROM_N6     0
#define COMMING_FROM_N3     1
#define COMMING_FROM_N9     2
#define CORRUPTED_PACKET    -1

#define COMMING_FROM_GTPU   3  // COMMING_FROM_N3 & COMMING_FROM_N9

#define GTPU_NET_ENDIAN     0x6808 // rte_cpu_to_be_16(2152)

/**
 * Used to store network header pointer when process mbuf
 */
typedef struct mbuf_network_info_s {
    interface_t             *interface;

    struct rte_ether_hdr    *eth_hdr;
    struct rte_ipv4_hdr     *ipv4_hdr;
    struct rte_udp_hdr      *udp_hdr;
    struct rte_gtp_hdr      *gtp_hdr;
} mbuf_network_info_t;

// TODO: Temperay to use, need to delete it
/* EXTERN */
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if segment comes from N6
 *   - COMMING_FROM_GTPU if segment is GTP-U
 */
static __rte_always_inline int process_gtp_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    if (unlikely(rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_gtp_hdr)))
        return CORRUPTED_PACKET;

    struct rte_gtp_hdr *gtp_hdr = network_info->gtp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_gtp_hdr *, offset);
    if (likely((gtp_hdr->gtp_hdr_info >> 5) == 0x1))
        return COMMING_FROM_GTPU;

    return COMMING_FROM_N6;
}

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if segment comes from N6
 *   - COMMING_FROM_GTPU if segment is GTP-U
 */
static __rte_always_inline int process_udp_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    if (unlikely(rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_udp_hdr)))
        return CORRUPTED_PACKET;
    
    struct rte_udp_hdr *udp_hdr = network_info->udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);
    if (likely(udp_hdr->dst_port == GTPU_NET_ENDIAN))
        return process_gtp_mbuf(m, network_info, offset + sizeof(struct rte_udp_hdr));

    return COMMING_FROM_N6;
}

/**
 * @return
 *   - < 0 if do not handle this packet
 *   - COMMING_FROM_N6 if packet comes from N6
 *   - COMMING_FROM_GTPU if packet is GTP-U
 */
static __rte_always_inline int process_pkt_mbuf(struct rte_mbuf *m, mbuf_network_info_t *network_info, uint16_t offset)
{
    if (unlikely(rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ipv4_hdr)))
        return CORRUPTED_PACKET;
    
    struct rte_ipv4_hdr *ipv4_hdr = network_info->ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
    printf_dbg(" IPv4 s_addr: ");
    print_dbg_ipv4(ipv4_hdr->src_addr);
    printf_dbg(" d_addr: ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
    
    // Check IP is fragmented
    if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr))) {
        port_pkt_stats[network_info->interface->id].ipFrag += 1;
        return -1;
    }

    // Order of ether_type in switch case using happening frequency
    printf_dbg(" next protocol: ");
    switch (ipv4_hdr->next_proto_id)
    {
        case IPPROTO_UDP:
            return process_udp_mbuf(m, network_info, offset + sizeof(struct rte_ipv4_hdr));
        
        default:
            return COMMING_FROM_N6;
    }
}

static __rte_always_inline void process_frame_mbuf(struct rte_mbuf *m, interface_t *interface)
{
    if (unlikely(rte_pktmbuf_data_len(m) < RTE_ETHER_HDR_LEN))
        goto FREE_PKT_MBUF;
    mbuf_network_info_t network_info = {0};

    struct rte_ether_hdr *eth_hdr = network_info.eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    printf_dbg("\n [RX] Port #%u ", interface->id);
    printf_dbg("Ether d_addr: ");
    printf_dbg_mac(&eth_hdr->d_addr);
    printf_dbg(" s_addr: ");
    printf_dbg_mac(&eth_hdr->s_addr);

    // TODO: Ether transport operation here, please create another to handle
    // ......


    // Order of ether_type in switch case using happening frequency
    printf_dbg(" next protocol: ");
    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
        case RTE_ETHER_TYPE_IPV4:
            if (unlikely(process_pkt_mbuf(m, &network_info, RTE_ETHER_HDR_LEN))) {
                logger(LOG_IP, L_DEBUG, "Warning: cannot handle IPv4 packet \n");
                goto FREE_PKT_MBUF;
            }

            break;

        case RTE_ETHER_TYPE_ARP:
            if (unlikely(arp_in(m, interface))) {
                logger(LOG_ARP, L_DEBUG, "Warning: cannot handle ARP frame \n");
                goto FREE_PKT_MBUF;
            }

            return;
        default:
            printf_dbg("0x%02x%02x, but not support yet \n", (eth_hdr->ether_type & 0xFF), (eth_hdr->ether_type >> 8));
            return;
    }

    


FREE_PKT_MBUF:
    rte_pktmbuf_free(m);

    /* TODO: Need to delete when I finish the config test
   
    // Test: forward all non-gtpu packets
    // int fwd_port = 1;
    // int ret = rte_eth_tx_burst(fwd_port, 0, &m, 1);
    // printf(" fwd to port#%d ret=%d\n", fwd_port, ret);
    // assert(likely(ret == 1));
    // return;

    // Ether type: IPv4 (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) = 0x8)
    if (likely(eth_hdr->ether_type == 0x8)) {
        ip_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1));
        printf_dbg(" IPv4(");
        print_rte_ipv4_dbg(ip_hdr->src_addr);
        printf_dbg(" -> ");
        print_rte_ipv4_dbg(ip_hdr->dst_addr);
        printf_dbg(") ");

        // Check for UDP
        // printf(" protocol: %x ", ip_hdr->next_proto_id);
        if (likely(ip_hdr->next_proto_id == 0x11)) {
            udp_hdr = (struct rte_udp_hdr *)((char *)(ip_hdr + 1));
            printf_dbg(" UDP(port src:%d dst:%d) ",
                rte_cpu_to_be_16(udp_hdr->src_port),
                rte_cpu_to_be_16(udp_hdr->dst_port));

            // GTPU LTE carries V1 only 2152 (htons(2152) = 0x6808)
            if (likely(udp_hdr->src_port == 0x6808 ||
                       udp_hdr->dst_port == 0x6808)) {
                gtp1_hdr = (gtpv1_t *)((char *)(udp_hdr + 1));
                printf_dbg(" GTP-U(type:0x%x, teid:%d) ", gtp1_hdr->type, ntohl(gtp1_hdr->teid));

                // Check if gtp version is 1
                if (unlikely(gtp1_hdr->flags >> 5 != 1)) {
                    printf(" NonGTPVer(gtp1_hdr->ver:%d)\n", gtp1_hdr->flags >> 5);
                    port_pkt_stats[port].non_gtpVer += 1;
                    goto out_flush;
                }

                // Check if msg type is PDU
                if (unlikely(gtp1_hdr->type != 0xff)) {
                    printf(" DROP(gtp1_hdr->type:%d)\n", gtp1_hdr->type);
                    port_pkt_stats[port].dropped += 1;
                    goto out_flush;
                }

                // GTP decap
                if (likely(process_gtpu(m, port, gtp1_hdr) > 0)) {
                    return;
                } else {
                    printf_dbg(" ERR(decap failed)\n");
                    port_pkt_stats[port].decap_err += 1;
                    goto out_flush;
                }
            } else {
                port_pkt_stats[port].non_gtp += 1;
            } // (unlikely(udp_hdr->src|dst_port != 2123))
        } else {
            port_pkt_stats[port].non_udp += 1;
        } // (unlikely(ip_hdr->next_proto_id != 0x11))

        // GTP encap
        if (likely(process_ipv4(m, port, ip_hdr) > 0)) {
            return;
        } else {
            printf_dbg(" ERR(encap failed)\n");
            port_pkt_stats[port].encap_err += 1;
            goto out_flush;
        }

    } else {
        port_pkt_stats[port].non_ipv4 += 1;

        // Ether type: ARP
        if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))) {
            arp_in(m);
            goto out_flush;
        }
    } // (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)))

out_flush:
    fflush(stdout);
    rte_pktmbuf_free(m);
    */
}

#endif /* __DPDK_GTP_GW_PKT_PROCESS_H__ */