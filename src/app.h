#ifndef __DPDK_GTP_GW_APP_H__
#define __DPDK_GTP_GW_APP_H__

#include <stdint.h>

#include <rte_byteorder.h>

typedef struct app_gtp_port_s {
    uint8_t port_num;
    // char ipv4[INET_ADDRSTRLEN];
    rte_be32_t ipv4;
    uint8_t gtp_type;
    uint8_t pkt_index;
} app_gtp_port_t;

typedef struct app_gtp_tunnel_s {
    uint8_t id;
    rte_be32_t teid_in;
    rte_be32_t teid_out;
    rte_be32_t ue_ipv4;
    rte_be32_t ran_ipv4;
} app_gtp_tunnel_t;

typedef struct app_ctx_s {
    uint8_t disp_stats;

    uint8_t gtp_port_count;
    app_gtp_port_t gtp_ports[GTP_CFG_MAX_PORTS];
    struct rte_hash *gtp_port_hash; // [port_num] = *gtp_port
} app_ctx_t;

#define GTP_CTX_MAX_PORTS   10
#define GTP_CTX_MAX_TUNNELS 100

// Functions for external
int app_init(int with_locks);

void app_set_disp_stats(uint8_t disp_stats);

int app_add_gtp_port(uint8_t id, rte_be32_t ipv4, uint8_t gtp_type);

#endif /* __DPDK_GTP_GW_APP_H__ */