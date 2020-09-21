#include "app.h"

#include <rte_hash.h>

static app_ctx_t app_ctx = {0};

void app_set_disp_stats(uint8_t disp_stats)
{
    app_ctx.disp_stats = disp_stats;
}

int app_add_gtp_port(uint8_t id, rte_be32_t ipv4, uint8_t gtp_type)
{
    app_ctx.gtp_ports[app_ctx.gtp_port_count].port_num = id;
    app_ctx.gtp_ports[app_ctx.gtp_port_count].ipv4 = ipv4;
    app_ctx.gtp_ports[app_ctx.gtp_port_count].gtp_type = gtp_type;
    app_ctx.gtp_ports[app_ctx.gtp_port_count].pkt_index = 0;

    if (rte_hash_add_key_data(app_ctx.gtp_port_hash,
            &app_ctx.gtp_ports[app_ctx.gtp_port_count].port_num,
            &app_ctx.gtp_ports[app_ctx.gtp_port_count]))
        return -1;
    
    app_ctx.gtp_port_count++;
    return 0;
}

static __rte_always_inline struct rte_hash *app_hash_table_create(const char *name,
        uint32_t entries, uint8_t extra_flag)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = sizeof(uint8_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = extra_flag,
    };

    if (rte_hash_find_existing(params.name))
        return NULL;

    return rte_hash_create(&params);
}

int app_init(int with_locks)
{
    uint8_t lock_flags = with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0;
    
    // Initialize gtp_port_hash
    app_ctx.gtp_port_hash = app_hash_table_create("gtp_port_hash",
        GTP_CTX_MAX_PORTS, lock_flags);
    if (!app_ctx.gtp_port_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for gtp port\n");

    // Initialize hash for packet match & action
    if (rule_init())
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init rule for process packet\n");

    return 0;
}