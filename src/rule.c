#include "rule.h"

#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include "param.h"

struct rte_hash *rule_id_hash = NULL;
struct rte_hash *teid_in_hash = NULL;
struct rte_hash *ue_ipv4_hash = NULL;

struct rte_hash *action_id_hash = NULL;

static __rte_always_inline struct rte_hash *rule_hash_table_create(const char *name,
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
        return NULL;

    return rte_hash_create(&params);
}

int rule_init(uint8_t with_locks)
{
    uint8_t lock_flags = with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0;

    // Initialize rule_id_hash
    rule_id_hash = rule_hash_table_create("rule_id_hash",
        GTP_CTX_MAX_TUNNELS, sizeof(uint16_t), lock_flags);
    if (!rule_id_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for rule ID matching\n");

    // Initialize teid_in_hash
    teid_in_hash = rule_hash_table_create("teid_in_hash",
        GTP_CTX_MAX_TUNNELS, sizeof(uint32_t), lock_flags);
    if (!teid_in_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for teid matching\n");

    // Initialize ue_ipv4_hash
    ue_ipv4_hash = rule_hash_table_create("ue_ipv4_hash",
        GTP_CTX_MAX_TUNNELS, sizeof(uint32_t), lock_flags);
    if (!ue_ipv4_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for IPv4 matching\n");

    action_id_hash = rule_hash_table_create("action_ipv4_hash",
        GTP_CTX_MAX_TUNNELS, sizeof(uint32_t), lock_flags);
    if (!action_id_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for action ID matching\n");

    return 0;
}

int rule_match_set_temprary(uint16_t id,
        rte_be32_t teid_in, rte_be32_t ue_ipv4, uint32_t action_id)
{
    rule_match_t *rule = NULL;
    
    // New rule ID
    if (rte_hash_lookup_data(rule_id_hash, &id, (void **) &rule) < 0) {
        if (!(rule = rte_zmalloc("Temprary rule match", sizeof(rule_match_t), 0)))
            rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");
        
        rule->id = id;
        if (rte_hash_add_key_data(rule_id_hash, &rule->id, rule))
            rte_exit(EXIT_FAILURE, "\n ERROR: cannot add new key-value into rule_id_hash\n");
    }
    else {
        // Delete hash entry from the two entries & don't care if it is existed
        rte_hash_del_key(teid_in_hash, &rule->gtp.teid);
        rte_hash_del_key(ue_ipv4_hash, &rule->inner_ipv4.src_addr);
    }
    
    rule->action_id = action_id;

    rule->gtp.teid = teid_in;
    rule->inner_ipv4.src_addr = ue_ipv4;

    // With teid & regist to teid_in_hash function
    if (rte_hash_add_key_data(teid_in_hash, &rule->gtp.teid, rule))
        return -1;

    return 0;
}

int rule_action_set_temprary(uint32_t id, rte_be32_t next_ipv4, rte_be32_t teid_out, rte_be16_t port)
{
    return 0;
}