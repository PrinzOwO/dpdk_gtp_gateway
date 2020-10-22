/**
 * ether.c
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#include "ether.h"

#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_ethdev.h>

#include "logger.h"
#include "helper.h"

#define MAX_NUM_OF_INTERFACES 10

uint8_t         interface_count = 0;
interface_t     interface_ports[MAX_NUM_OF_INTERFACES] = {0};
struct rte_hash *interface_id_hash = NULL;
struct rte_hash *interface_mac_hash = NULL;
struct rte_hash *interface_ipv4_hash = NULL;

interface_t *ether_get_next_interface(int now_order)
{
    int next_order = now_order + 1;
    if (likely(next_order >= 0 && next_order < interface_count))
        return &interface_ports[next_order];
    
    return NULL;
}

static __rte_always_inline struct rte_hash *ether_hash_table_create(const char *name,
        uint32_t entries, uint8_t key_len, uint8_t extra_flag)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = key_len,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = extra_flag,
    };

    if (rte_hash_find_existing(params.name))
        rte_exit(EXIT_FAILURE,
                "\n ERROR: found the same name hash table #%s\n",
                name);

    return rte_hash_create(&params);
}

int ether_add_interface(uint8_t id, rte_be32_t ipv4, uint8_t gtp_type)
{
    uint8_t avail_dev_count = rte_eth_dev_count_avail();

    if (id > rte_eth_dev_count_avail()) {
        logger(LOG_ETHER, L_CRITICAL,
                "Interface index #%d in config >= avail dpdk eth devices (%d).\n",
                id, avail_dev_count);
        return -1;
    }
    
    if (interface_count + 1 > (uint8_t) (sizeof(interface_ports) / sizeof(interface_t))) {
        logger(LOG_APP, L_CRITICAL,
                "Number of interface in config (%d) > avail dpdk eth devices (%d).\n",
                interface_count + 1, avail_dev_count);
        return -1;
    }

    uint8_t int_idx = interface_count++;

    interface_ports[int_idx].id = id;
    interface_ports[int_idx].ipv4 = ipv4;
    interface_ports[int_idx].gtp_type = gtp_type;

    rte_eth_macaddr_get(interface_ports[int_idx].id,
        &interface_ports[int_idx].mac);

    if (rte_hash_add_key_data(interface_mac_hash,
            &interface_ports[int_idx].mac,
            &interface_ports[int_idx]))
        goto INTERFACE_CLEANUP;

    if (rte_hash_add_key_data(interface_id_hash,
            &interface_ports[int_idx].id,
            &interface_ports[int_idx]))
        goto HASH_TABLE_MAC_INT_REMOVE;

    if (rte_hash_add_key_data(interface_ipv4_hash,
            &interface_ports[int_idx].ipv4,
            &interface_ports[int_idx]))
        goto HASH_TABLE_ID_INT_REMOVE;

    return 0;

HASH_TABLE_ID_INT_REMOVE:
    rte_hash_del_key(interface_id_hash, &interface_ports[int_idx].id);

HASH_TABLE_MAC_INT_REMOVE:
    rte_hash_del_key(interface_mac_hash, &interface_ports[int_idx].mac);

INTERFACE_CLEANUP:
    interface_count--;
    return -1;
}

int ether_find_interface_by_id(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_id_hash, key, (void **) data);
}

int ether_find_interface_by_ipv4(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_ipv4_hash, key, (void **) data);
}

int ether_find_interface_by_mac(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_mac_hash, key, (void **) data);
}

void ether_dump_interface(TraceLevel trace_level)
{
    logger(LOG_ETHER, trace_level, "[Ethernet Interface Table]\n");
    logger(LOG_ETHER, trace_level, "There are %d entries in total:", interface_count);
    logger_s(LOG_ETHER, trace_level, "\n");

    for (int i = 0; i < interface_count; i++) {
        logger_s(LOG_ETHER, trace_level, " - ID = %d", interface_ports[i].id);
        logger_s(LOG_ETHER, trace_level, "\n");

        logger_s(LOG_ETHER, trace_level, "   IP = ");
        logger_ipv4(interface_ports[i].ipv4, trace_level);
        logger_s(LOG_ETHER, trace_level, "\n");

        logger_s(LOG_ETHER, trace_level, "   MAC = ");
        logger_mac(&interface_ports[i].mac, trace_level);
        logger_s(LOG_ETHER, trace_level, "\n");

        logger_s(LOG_ETHER, trace_level, "   Type = %s", (interface_ports[i].gtp_type == 1 ? "GTP-U" : "Internet"));
        logger_s(LOG_ETHER, trace_level, "\n");
    }
    fflush(stdout);
}

void ether_dump_status(void)
{
    for (int i = 0; i < interface_count; i++) {
        printf("\033[2;%dH", (15 + 10 * i));
        printf(" %8u ", i);
        printf("\033[11;%dH", (15 + 10 * i));
        printf(" %8u ", interface_ports[i].gtp_type);
        printf("\033[13;%dH", (15 + 10 * i));
        printf(" %8u ", interface_ports[i].pkt_index); // not used
    }
}

int ether_interface_init(int with_locks)
{
    uint8_t lock_flags = with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0;

    interface_id_hash = ether_hash_table_create("interface_id_hash",
        MAX_NUM_OF_INTERFACES, sizeof(uint8_t), lock_flags);
    if (!interface_id_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with id-int pair for interface port: %s\n"
                , rte_strerror(rte_errno));

    interface_ipv4_hash = ether_hash_table_create("interface_ipv4_hash",
        MAX_NUM_OF_INTERFACES, sizeof(rte_be32_t), lock_flags);
    if (!interface_ipv4_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with ipv4-int pair for interface port: %s\n"
                , rte_strerror(rte_errno));

    interface_mac_hash = ether_hash_table_create("interface_mac_hash",
        MAX_NUM_OF_INTERFACES, sizeof(struct rte_ether_addr), lock_flags);
    if (!interface_mac_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with mac-int pair for interface port: %s\n",
                rte_strerror(rte_errno));

    return 0;
}

int ether_unformat_addr(const char *str, struct rte_ether_addr *eth_addr)
{
    if (strlen(str) < 17)
        return -1;

    int val;
    for (int i = 0; i < 6; i++) {
        if (i && str[i * 3 - 1] != ':')
            return -1;

        if ((val = xchar_to_int(str[i * 3])) < 0)
            return -1;
        eth_addr->addr_bytes[i] = (val << 4);

        if ((val = xchar_to_int(str[i * 3 + 1])) < 0)
            return -1;
        eth_addr->addr_bytes[i] += val;
    }

    return 0;
}