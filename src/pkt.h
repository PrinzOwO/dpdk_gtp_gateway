#ifndef __DPDK_GTP_GW_PKT_H__
#define __DPDK_GTP_GW_PKT_H__

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_gtp.h>

#include "interface.h"

#define COMMING_FROM_N6     0
#define COMMING_FROM_N3     1
#define COMMING_FROM_N9     2
#define CORRUPTED_PACKET    -1

#define COMMING_FROM_GTPU   3  // COMMING_FROM_N3 & COMMING_FROM_N9

#define GTPU_NET_ENDIAN     0x6808 // rte_cpu_to_be_16(2152)

/**
 * Used to store network header pointer when parse mbuf
 */
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

#endif /* __DPDK_GTP_GW_PKT_H__ */