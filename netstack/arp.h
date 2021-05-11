/**
 * arp.h - arp data structure
 *  TODO: thread safe
 */
#ifndef __DPDK_GTP_GW_ARP_H__
#define __DPDK_GTP_GW_ARP_H__

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_arp.h>

/**
 * An internal function to set ARP header
 */
static __rte_always_inline void arp_header_set_inplace(struct rte_arp_hdr *arp_req,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode)
{
    arp_req->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_req->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_req->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_req->arp_plen = sizeof(uint32_t);
    arp_req->arp_opcode = rte_cpu_to_be_16(opcode);

    struct rte_arp_ipv4 *arp_data = &arp_req->arp_data;
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    rte_ether_addr_copy(dst_mac, &arp_data->arp_tha);
    arp_data->arp_sip = src_ip;
    arp_data->arp_tip = dst_ip;
}

/**
 * Prepend and set ARP header
 */
void arp_header_prepend(struct rte_mbuf *mbuf,
        struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode);

#endif /* __DPDK_GTP_GW_ARP_H__ */
