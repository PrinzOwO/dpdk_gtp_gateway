#include "app.h"

#include <rte_hash.h>

#include "ether.h"
#include "interface.h"
#include "arp_table.h"
#include "rule.h"

static app_ctx_t app_ctx = {0};

void app_set_disp_stats(uint8_t disp_stats)
{
    app_ctx.disp_stats = disp_stats;
}

uint8_t app_get_disp_stats(void)
{
    return app_ctx.disp_stats;
}

int app_init(int with_locks)
{
    if (interface_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init ethernet interface\n");

    // Initialize hash for packet match & action
    if (rule_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init rule for process packet\n");

    // Init ARP table
    if (arp_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init ARP table\n");

    return 0;
}