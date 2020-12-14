#ifndef __DPDK_GTP_GW_PARAM_H__
#define __DPDK_GTP_GW_PARAM_H__

// Physical ports on NIC
#define MAX_NUM_OF_INTERFACES 10

// ARP Table
#define MAX_NUM_OF_ARP_ENTRIES 8192

// Packet Operation from RX
#define MAX_NUM_OF_RX_BURST 0x08
#define RX_PREFETCH_OFFSET 0x04

// GTP Tunnel
#define GTP_CTX_MAX_TUNNELS 0xFF
#define GTP_CTX_MAX_ACL_PER_PDR 0x01
#define GTP_CTX_MAX_ONE_KIND_OF_ACL_RULE 0x08

#endif /* __DPDK_GTP_GW_PARAM_H__ */