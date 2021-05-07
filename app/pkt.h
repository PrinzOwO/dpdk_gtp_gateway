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
 * @m: struct rte_mbuf *
 * @interface: interface_t *
 * @eth_hdr: struct rte_ether_hdr *
 */
#define parse_frame_mbuf_marco(m, interface, eth_hdr) \
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *); \
    printf_dbg("\n [RX] Port #%u (%s) ", interface->id, (interface->type == INTERFACE_TYPE_N6 ? "N6" : "GTP-U")); \
    print_dbg_ether_hdr_mac(eth_hdr);

/**
 * @m: struct rte_mbuf *
 * @interface: interface_t *
 * @eth_hdr: struct rte_ether_hdr *
 * @ipv4_hdr: struct rte_ipv4_hdr *
 * @err_handle_expr: expr for free buffer
 */
#define parse_pkt_mbuf_macro(m, interface, eth_hdr, ipv4_hdr, err_handle_expr) \
    ipv4_hdr = (void *) &eth_hdr[1]; \
    print_dbg_ipv4_hdr_addr(ipv4_hdr); \
    /* Check IP is fragmented */ \
    if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr))) { \
        port_pkt_stats[interface->id].ipFrag += 1; \
        printf_dbg(", detected ip fragment and not support yet"); \
        err_handle_expr; \
    }

/**
 * @m: struct rte_mbuf *
 * @interface: interface_t *
 * @eth_hdr: struct rte_ether_hdr *
 * @ipv4_hdr: struct rte_ipv4_hdr *
 * @out_int: egress interface ID
 * @suss_handle_expr: expr for successful handling
 */
#define process_egress_marco(m, interface, eth_hdr, ipv4_hdr, out_int, suss_handle_expr) \
    printf_dbg(", find out dst IP "); \
    print_dbg_ipv4(ipv4_hdr->dst_addr); \
    printf_dbg(" in ARP table:"); \
    if (unlikely(arp_get_mac(ipv4_hdr->dst_addr, &eth_hdr->d_addr) < 0)) { \
        printf_dbg(" not found in arp table"); \
        port_pkt_stats[interface->id].dropped += 1; \
        /* Send ARP request and drop this packet */ \
        arp_send_request(ipv4_hdr->dst_addr, out_int); \
        return -ENOENT; \
    } \
    printf_dbg(" with dst mac "); \
    print_dbg_mac(&eth_hdr->d_addr); \
    rte_ether_addr_copy(&eth_hdr->s_addr, &interface_get_this(out_int)->mac); \
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4); \
    /* Put packet into TX queue */ \
    int nb_tx; \
    printf_dbg("\n [TX]"); \
    if (unlikely((nb_tx = rte_eth_tx_burst(out_int, 0, &m, 1)) < 1)) { \
        printf_dbg(" ERR(rte_eth_tx_burst=%d) \n", nb_tx); \
        return -ENOSPC; \
    } \
    printf_dbg(" Sent frame to Port #%d with nb_tx=%d \n", out_int, nb_tx); \
    suss_handle_expr;
    

/**
 * @m: struct rte_mbuf *
 * @inner_ipv4_hdr: struct rte_ipv4_hdr *
 * @ipv4_hdr: struct rte_ipv4_hdr *
 * @suss_handle_expr: expr for successful handling
 */
#define process_outer_hdr_removal_gtpu_ipv4_macro(m, inner_ipv4_hdr, ipv4_hdr, suss_handle_expr) \
    case RULE_PDR_REMOVE_HDR_COOKED_GTPU_IPV4: \
        printf_dbg(", remove GTP-U, UDP, IPv4 and ethernet hdr"); \
        ipv4_hdr = (struct rte_ipv4_hdr *) rte_pktmbuf_adj(m, (uint8_t *) inner_ipv4_hdr - rte_pktmbuf_mtod(m, uint8_t *)); \
        suss_handle_expr;

/**
 * @m: struct rte_mbuf *
 * @suss_handle_expr: expr for successful handling
 */
#define process_outer_hdr_removal_none_macro(m, suss_handle_expr) \
    case RULE_PDR_REMOVE_HDR_COOKED_UNSPEC: \
        printf_dbg(", remove ethernet hdr"); \
        rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN); \
        suss_handle_expr;

/**
 * @remove_hdr: uint8_t
 * @rm_hdr_expr_case1: first priority case expr
 * @rm_hdr_expr_case2: second priority case expr
 * @err_handle_expr: expr for free buffer
 */
#define process_outer_hdr_removal_macro(remove_hdr, rm_hdr_expr_case1, rm_hdr_expr_case2, err_handle_expr) \
    switch(remove_hdr) { \
        rm_hdr_expr_case1; \
        rm_hdr_expr_case2; \
        default: \
            printf_dbg(", not support IPv6 hdr yet"); \
            err_handle_expr; \
    }

/**
 * @m: struct rte_mbuf *
 * @eth_hdr: struct rte_ether_hdr *
 * @ipv4_hdr: struct rte_ipv4_hdr *
 * @udp_hdr: struct rte_udp_hdr *
 * @gtp_hdr: struct rte_udp_hdr *
 * @far: rule_far_t *
 * @out_int: interface id
 * @suss_handle_expr: expr for successful handling
 */
#define process_outer_hdr_creation_gtpu_ipv4_macro(m, eth_hdr, ipv4_hdr, udp_hdr, gtp_hdr, payload_len, far, out_int, suss_handle_expr) \
    case RULE_FAR_OUTER_HDR_DESP_GTPU_IPV4: \
        printf_dbg(", create outer gtp-u, udp and ipv4 hdr"); \
        eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, \
                RTE_ETHER_GTP_HLEN + sizeof(struct rte_ipv4_hdr) + RTE_ETHER_HDR_LEN); \
        /* ethernet hdr will be handled at send function */ \
        ipv4_header_set_inplace((ipv4_hdr = (void *) &eth_hdr[1]), \
                interface_get_this(out_int)->ipv4, far->outer_hdr_info.peer_ipv4, \
                (payload_len = rte_pktmbuf_data_len(m) - RTE_ETHER_HDR_LEN)); \
        udp_header_set_inplace((udp_hdr = (void *) &ipv4_hdr[1]), \
                0x6808, far->outer_hdr_info.peer_port, \
                (payload_len -= sizeof(struct rte_ipv4_hdr))); \
        gtpu_header_set_inplace((gtp_hdr = (void *) &udp_hdr[1]), \
                0, 0xff, (payload_len -= sizeof(struct rte_udp_hdr)), far->outer_hdr_info.teid); \
        suss_handle_expr;

/**
 * @m: struct rte_mbuf *
 * @eth_hdr: struct rte_ether_hdr *
 * @suss_handle_expr: expr for successful handling
 */
#define process_outer_hdr_creation_nono_macro(m, eth_hdr, suss_handle_expr) \
    case RULE_FAR_OUTER_HDR_DESP_UNSPEC: \
        printf_dbg(", don't create outer hdr"); \
        eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr)); \
        /* ethernet hdr will be handled at send function */ \
        suss_handle_expr;

/**
 * @create_hdr_desp: uint8_t
 * @create_hdr_expr_case1: first priority case expr
 * @create_hdr_expr_case2: second priority case expr
 * @err_handle_expr: expr for free buffer
 */
#define process_outer_hdr_creation_macro(create_hdr_desp, create_hdr_expr_case1, create_hdr_expr_case2, err_handle_expr) \
    switch (create_hdr_desp) { \
        create_hdr_expr_case1; \
        create_hdr_expr_case2; \
        default: \
            printf_dbg(", not support IPv6 hdr yet"); \
            err_handle_expr; \
    }

#endif /* __DPDK_GTP_GW_PKT_H__ */