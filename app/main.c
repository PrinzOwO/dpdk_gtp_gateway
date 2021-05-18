#include <assert.h>
#include "arp.h"
#include "ether.h"

#include <rte_lcore.h>
#include <rte_ip_frag.h>
#include <rte_bus_pci.h>

#include "logger.h"
#include "pktbuf.h"
#include "unix_sock.h"
#include "memfd.h"

#include "param.h"
#include "config.h"
#include "node.h"
#include "stats.h"
#include "app.h"
#include "gtpu_processor.h"
#include "n6_processor.h"

/* GLOBALS */
volatile uint8_t keep_running = 1;

/* EXTERN */
extern numa_info_t numa_node_info[GTP_MAX_NUMANODE];
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

static void sigint_handler(__attribute__((unused)) int signo)
{
    keep_running = 0;
}

static __rte_always_inline int pkt_handler(void *arg)
{
    interface_t *interface = arg;

    struct rte_mbuf *pkt[MAX_NUM_OF_RX_BURST];

    unsigned int lcore_id = rte_lcore_id();
    unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
    uint8_t port_id = interface->id;

    void (*pkt_handler)(struct rte_mbuf *m, interface_t *interface) =
            (interface->type == INTERFACE_TYPE_GTPU ? gtpu_processor : n6_processor);

    // TODO: if mempool is per port ignore the below
    // mbuf_pool_tx = numa_node_info[socket_id].tx[0];
    // mbuf_pool_rx = numa_node_info[socket_id].rx[port_id];

    logger(LOG_APP, L_INFO,
            "\n Launched handler for port %u on thread ID %u on socket %u \n\n",
            port_id, lcore_id, socket_id);

    uint16_t nb_rx = 0, nb_pkt_proc = 0;
    while (keep_running) {
        // Fetch MAX Burst RX packets
        nb_rx = rte_eth_rx_burst(port_id, 0, pkt, MAX_NUM_OF_RX_BURST);

        if (unlikely(!nb_rx)) continue;

        // rte_pktmbuf_dump(stdout, pkt[0], 64);

        // Prefetch packets for pipeline
        for (int j = 0; j < RX_PREFETCH_OFFSET && j < nb_rx; j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkt[j], void *));
        }

        // Prefetch others packets and process packets
        for (nb_pkt_proc = 0; nb_pkt_proc < nb_rx - RX_PREFETCH_OFFSET; nb_pkt_proc++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkt[nb_pkt_proc + RX_PREFETCH_OFFSET], void *));
            pkt_handler(pkt[nb_pkt_proc], interface);
        }

        // Process remaining packets
        for (; nb_pkt_proc < nb_rx; nb_pkt_proc++) {
            pkt_handler(pkt[nb_pkt_proc], interface);
        }
    }

    logger(LOG_APP, L_INFO, "\n thread ID %u joined \n", lcore_id);

    return 0;
}

static __rte_always_inline void show_dpdk_gtp_gw_all_info(void)
{
    logger(LOG_APP, L_INFO, "Show current DPDK GTP GW information \n\n");
    interface_dump(L_INFO);
    logger_s(LOG_APP, L_INFO, "\n");
    arp_dump_table(L_INFO);
    logger_s(LOG_APP, L_INFO, "\n");
    rule_match_dump_table(L_INFO);
    logger_s(LOG_APP, L_INFO, "\n");
    rule_far_dump_table(L_INFO);
    logger_s(LOG_APP, L_INFO, "\n");
}

int main(int argc, char **argv)
{
    int32_t ret;

    logger_init();

    // Initialize DPDK EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init EAL \n");

    // Check Huge pages for memory buffers
    ret = rte_eal_has_hugepages();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: no Huge Page \n");

    // Register signals
    signal(SIGINT, sigint_handler);
    signal(SIGUSR1, sig_extra_stats);
    signal(SIGUSR2, sig_config);

    // APP init
    ret = app_init(0);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: failed to init app \n");

    // Load ini config file
    ret = load_config(DEFAULT_CFG_PATH);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: failed to load config \n");

    // Create packet buffer pool
    ret = mbuf_init();
    assert(ret == 0);

    ret = populate_node_info();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: in populating NUMA node Info \n");

    printf("\n");

    // Set interface options and queues
    if (node_interface_setup() < 0)
        rte_exit(EXIT_FAILURE, "\n ERROR: interface setup Failed \n");

    show_dpdk_gtp_gw_all_info();

    // Launch thread lcores
    interface_t *interface_it = NULL;
    unsigned int lcore = RTE_MAX_LCORE;
    for (int i = -1; (interface_it = interface_get_next(i)) && (lcore = rte_get_next_lcore(i, 0, 0)) != RTE_MAX_LCORE; i++) {
        // Skip the first lcore
        lcore = rte_get_next_lcore(lcore, 0, 0);
        logger(LOG_APP, L_INFO, "\n Starting packet handler %d at lcore %d \n", interface_it->id, lcore);
        rte_eal_remote_launch(pkt_handler, interface_it, lcore);
    }

    // rte_eal_mp_wait_lcore();

    // Communication with other program
    int unix_fd = unix_sock_create("gtpgw_unix_sock");
    int memfd, rcnt;
    char filename[0xff];
    char *buf = memfd_malloc(&memfd, filename, sizeof(filename));

    const char exit_str[] = "quit";
    while (keep_running) {
        if ((rcnt = unix_sock_read(unix_fd, buf, MAX_MEMFD_SIZE)) > 0) {
            memfd_ftruncate(memfd, rcnt);
            
            logger(LOG_APP, L_INFO, "Recv command with len %u from unix sock: \n", rcnt);
            logger_s(LOG_APP, L_INFO, "%s", buf);

            if (!strncmp(buf, exit_str, sizeof(exit_str))) {
                sigint_handler(SIGINT);
            }
            else if (load_config(filename) < 0) {
                logger(LOG_APP, L_WARN, "config load failed: \n");
                logger_s(LOG_APP, L_WARN, "%s", buf);
            }
        }
    }

    return 0;

/*

    // Show stats
    printf("\n DISP_STATS=%s\n", app_config.disp_stats ? "ON" : "OFF");
    if (app_config.disp_stats) {
        set_stats_timer();
        rte_delay_ms(1000);
        show_static_display();
    }

    while (keep_running) {
        rte_delay_ms(500);
        if (app_config.disp_stats) {
            show_static_display();
        }
        rte_timer_manage();
    }
    
    // Free resources
    printf("\n\nCleaning...\n");
    arp_terminate();
    printf("Done.\n");
    return 0;
*/
}
