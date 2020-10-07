#ifndef __DPDK_GTP_GW_APP_H__
#define __DPDK_GTP_GW_APP_H__

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

typedef struct app_gtp_tunnel_s {
    uint8_t     id;
    rte_be32_t  teid_in;
    rte_be32_t  teid_out;
    rte_be32_t  ue_ipv4;
    rte_be32_t  ran_ipv4;
} app_gtp_tunnel_t;

typedef struct app_ctx_s {
    uint8_t         disp_stats;
} app_ctx_t;

// Functions for external
int app_init(int with_locks);

void app_set_disp_stats(uint8_t disp_stats);

#endif /* __DPDK_GTP_GW_APP_H__ */