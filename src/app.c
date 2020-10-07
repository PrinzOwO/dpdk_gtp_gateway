#include "app.h"

#include <rte_hash.h>

#include "ether.h"
#include "rule.h"
#include "arp.h"

static app_ctx_t app_ctx = {0};

void app_set_disp_stats(uint8_t disp_stats)
{
    app_ctx.disp_stats = disp_stats;
}

int app_init(int with_locks)
{
    if (ether_interface_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init ethernet interface\n");

    // Initialize hash for packet match & action
    if (rule_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init rule for process packet\n");

    // Init ARP table
    if (arp_init(with_locks))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init ARP table\n");

    return 0;
}