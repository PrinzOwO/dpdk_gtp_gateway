#ifndef __DPDK_GTP_GW_APP_H__
#define __DPDK_GTP_GW_APP_H__

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

typedef struct app_ctx_s {
    uint8_t         disp_stats;
} app_ctx_t;

// Functions for external
int app_init(int with_locks);

void app_set_disp_stats(uint8_t disp_stats);

uint8_t app_get_disp_stats(void);

#endif /* __DPDK_GTP_GW_APP_H__ */