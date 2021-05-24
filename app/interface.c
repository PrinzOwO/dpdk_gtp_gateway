#include "interface.h"

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_ethdev.h>

#include "logger.h"
#include "param.h"
#include "pktbuf.h"
#include "ether.h"
#include "ip.h"

uint8_t         interface_count = 0;
interface_t     interface_ports[MAX_NUM_OF_INTERFACES] = {0};
struct rte_hash *interface_id_hash = NULL;
struct rte_hash *interface_mac_hash = NULL;
struct rte_hash *interface_ipv4_hash = NULL;

interface_t *interface_get_this(int now_order)
{
    return &interface_ports[now_order];
}

interface_t *interface_get_next(int now_order)
{
    int next_order = now_order + 1;
    if (likely(next_order >= 0 && next_order < interface_count))
        return &interface_ports[next_order];
    
    return NULL;
}

static __rte_always_inline struct rte_hash *interface_hash_table_create(const char *name,
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

int interface_add(uint8_t id, rte_be32_t ipv4, uint8_t type)
{
    uint8_t avail_dev_count = rte_eth_dev_count_avail();

    if (id > rte_eth_dev_count_avail()) {
        logger(LOG_ETHER, L_CRITICAL,
                "Interface index #%d in config >= avail dpdk eth devices (%d).\n",
                id, avail_dev_count);
        return -1;
    }

    interface_t *exist_intf = NULL;
    if (interface_find_by_id(&id, &exist_intf) >= 0) {
        rte_hash_del_key(interface_ipv4_hash, &exist_intf->ipv4);

        exist_intf->ipv4 = ipv4;
        exist_intf->type = type;

        if (rte_hash_add_key_data(interface_ipv4_hash,
            &exist_intf->ipv4, exist_intf))
            goto HASH_TABLE_ID_INT_REMOVE;

        return 0;
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
    interface_ports[int_idx].type = type;

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

int interface_find_by_id(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_id_hash, key, (void **) data);
}

int interface_find_by_ipv4(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_ipv4_hash, key, (void **) data);
}

int interface_find_by_mac(const void *key, interface_t **data)
{
    return rte_hash_lookup_data(interface_mac_hash, key, (void **) data);
}

static const char *interface_type_str[] = {"N6", "N3", "N9", "GTP-U"};
void interface_dump(TraceLevel trace_level)
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

        logger_s(LOG_ETHER, trace_level, "   Type = %s", interface_type_str[interface_ports[i].type]);
        logger_s(LOG_ETHER, trace_level, "\n");
    }
    fflush(stdout);
}

void interface_dump_status(void)
{
    for (int i = 0; i < interface_count; i++) {
        printf("\033[2;%dH", (15 + 10 * i));
        printf(" %8u ", i);
        printf("\033[11;%dH", (15 + 10 * i));
        printf(" %8u ", interface_ports[i].type);
        printf("\033[13;%dH", (15 + 10 * i));
        printf(" %8u ", interface_ports[i].pkt_index); // not used
    }
}

int interface_init(int with_locks)
{
    uint8_t lock_flags = with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0;

    interface_id_hash = interface_hash_table_create("interface_id_hash",
        MAX_NUM_OF_INTERFACES, sizeof(uint8_t), lock_flags);
    if (!interface_id_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with id-int pair for interface port: %s\n"
                , rte_strerror(rte_errno));

    interface_ipv4_hash = interface_hash_table_create("interface_ipv4_hash",
        MAX_NUM_OF_INTERFACES, sizeof(rte_be32_t), lock_flags);
    if (!interface_ipv4_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with ipv4-int pair for interface port: %s\n"
                , rte_strerror(rte_errno));

    interface_mac_hash = interface_hash_table_create("interface_mac_hash",
        MAX_NUM_OF_INTERFACES, sizeof(struct rte_ether_addr), lock_flags);
    if (!interface_mac_hash)
        rte_exit(EXIT_FAILURE,
                "\n ERROR: cannot init hash with mac-int pair for interface port: %s\n",
                rte_strerror(rte_errno));

    return 0;
}