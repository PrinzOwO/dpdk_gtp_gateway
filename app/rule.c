#include "rule.h"

#include <arpa/inet.h>

#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_gtp.h>

#include "param.h"
#include "logger.h"
#include "rule_pdr.h"
#include "rule_far.h"

struct rte_hash *rule_id_hash = NULL;
struct rte_hash *teid_in_hash = NULL;
struct rte_hash *ue_ipv4_hash = NULL;

struct rte_hash *far_id_hash = NULL;

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

    far_id_hash = rule_hash_table_create("action_ipv4_hash",
        GTP_CTX_MAX_TUNNELS, sizeof(uint32_t), lock_flags);
    if (!far_id_hash)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot init hash for action ID matching\n");

    return 0;
}

void rule_match_dump_table(TraceLevel trace_level)
{
    uint16_t *id = NULL;
    uint32_t iter = 0;
    rule_match_t *rule_match_entry;

    logger(LOG_GTP, trace_level, "[Rule Match Table]\n");
    logger(LOG_GTP, trace_level, "There are %d entries in total:", rte_hash_count(rule_id_hash));
    logger_s(LOG_GTP, trace_level, "\n");

    while (rte_hash_iterate(rule_id_hash, (void *)&id, (void **) &rule_match_entry, &iter) >= 0) {
        rule_pdr_dump(&rule_match_entry->pdr, trace_level);
    }
}

#ifndef ULCL
int rule_match_find_by_teid(struct rte_gtp_hdr *gtp_hdr, rule_match_t **rule)
{
    return rte_hash_lookup_data(teid_in_hash, &gtp_hdr->teid, (void **) rule);
}
#else
int rule_match_find_by_teid(struct rte_ipv4_hdr *ipv4_hdr,
        struct rte_gtp_hdr *gtp_hdr, struct rte_ipv4_hdr *inner_ipv4_hdr,
        rule_match_t **rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &gtp_hdr->teid, (void **) &existed_rule)) < 0) {
        printf_dbg(" Cannot find the rule matching entry with TEID #%u \n", gtp_hdr->teid);
        return ret;
    }

    // TODO: Test for throughput
    for (; existed_rule; existed_rule = existed_rule->next_teid) {
        if (rule_pdr_is_ue_ipv4(&existed_rule->pdr, inner_ipv4_hdr->src_addr) &&
                rule_pdr_is_upf_ipv4(&existed_rule->pdr, ipv4_hdr->dst_addr) &&
                rule_5tuple_matching(existed_rule->pdr.sdf_filter, inner_ipv4_hdr)) {

            *rule = existed_rule;
            return ret;
        }
    }

    printf_dbg(" Cannot find the rule matching with TEID #%u \n", gtp_hdr->teid);

    return -ENOENT;
}
#endif /* ULCL */

int rule_match_find_by_ipv4(struct rte_ipv4_hdr *ipv4_hdr, rule_match_t **rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &ipv4_hdr->dst_addr, (void **) &existed_rule)) < 0) {
        printf_dbg(" Cannot find the rule matching entry with UE IPv4 ");
        print_dbg_ipv4(ipv4_hdr->dst_addr);
        printf_dbg("\n");

        return ret;
    }

    for (; existed_rule; existed_rule = existed_rule->next_ipv4) {
        if (rule_5tuple_matching(existed_rule->pdr.sdf_filter, ipv4_hdr)) {
            *rule = existed_rule;
            return ret;
        }
    }

    printf_dbg(" Cannot find the rule matching with UE IPv4 ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
    printf_dbg("\n");

    return -ENOENT;
}

int rule_far_find_by_id(uint32_t id, rule_far_t **data)
{
    return rte_hash_lookup_data(far_id_hash, &id, (void **) data);
}

static int rule_register_ipv4_hash(rule_match_t *rule)
{
    int ret;
    rule_pdr_t *pdr = &rule->pdr;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &pdr->ue_ipv4, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            rule->next_ipv4 = NULL;
            return rte_hash_add_key_data(ue_ipv4_hash, &pdr->ue_ipv4, rule);
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", pdr->id);
            logger_ipv4(pdr->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            return ret;
        }
    }

    // Insert to the first
    if (pdr->precedence <= existed_rule->pdr.precedence) {
        rule->next_ipv4 = existed_rule;
        rte_hash_del_key(ue_ipv4_hash, &existed_rule->pdr.ue_ipv4);
        return rte_hash_add_key_data(ue_ipv4_hash, &pdr->ue_ipv4, rule);
    }
    
    for (; existed_rule->next_ipv4; existed_rule = existed_rule->next_ipv4) {
        if (pdr->precedence <= existed_rule->next_ipv4->pdr.precedence) {
            printf_dbg(" Add PDR #%u with precedence %u after PDR #%u with precedence %u",
                    pdr->id, pdr->precedence, existed_rule->pdr.id, existed_rule->pdr.precedence);
            break;
        }
    }

    rule->next_ipv4 = existed_rule->next_ipv4;
    existed_rule->next_ipv4 = rule;

    return ret;
}

static int rule_register_teid_hash(rule_match_t *rule)
{
    int ret;
    rule_pdr_t *pdr = &rule->pdr;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &pdr->teid, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            rule->next_teid = NULL;
            return rte_hash_add_key_data(teid_in_hash, &pdr->teid, rule);
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with teid #%u", pdr->id, pdr->teid);
            logger_s(LOG_GTP, L_WARN, " into teid hash table\n");
            return ret;
        }
    }

    // Insert to the first
    if (pdr->precedence <= existed_rule->pdr.precedence) {
        rule->next_teid = existed_rule;
        rte_hash_del_key(teid_in_hash, &existed_rule->pdr.teid);
        return rte_hash_add_key_data(teid_in_hash, &pdr->teid, rule);
    }
    
    for (; existed_rule->next_teid; existed_rule = existed_rule->next_teid) {
        if (pdr->precedence <= existed_rule->next_teid->pdr.precedence) {
            printf_dbg(" Add PDR #%u with precedence %u after PDR #%u with precedence %u",
                    pdr->id, pdr->precedence, existed_rule->pdr.id, existed_rule->pdr.precedence);
            break;
        }
    }

    rule->next_teid = existed_rule->next_teid;
    existed_rule->next_teid = rule;

    return ret;
}

static int rule_deregister_ipv4_hash(rule_match_t *rule)
{
    int ret;
    rule_pdr_t *pdr = &rule->pdr;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &pdr->ue_ipv4, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            goto NOTFOUND;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot delete PDR #%u with ", pdr->id);
            logger_ipv4(pdr->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            return ret;
        }
    }

    if (existed_rule->pdr.id == pdr->id) {
        rte_hash_del_key(ue_ipv4_hash, &pdr->ue_ipv4);
        rte_hash_add_key_data(ue_ipv4_hash, &existed_rule->next_ipv4->pdr.ue_ipv4, existed_rule->next_ipv4);
        rule->next_ipv4 = NULL;
        return 0;
    }

    for (; existed_rule->next_ipv4; existed_rule = existed_rule->next_ipv4) {
        if (pdr->id == existed_rule->next_ipv4->pdr.id) {
            printf_dbg(" Delete PDR #%u after PDR #%u", rule->pdr.id, existed_rule->pdr.id);
            existed_rule->next_ipv4 = rule->next_ipv4;
            rule->next_ipv4 = NULL;
            return 0;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with ", pdr->id);
    logger_ipv4(pdr->ue_ipv4, L_WARN);
    logger_s(LOG_GTP, L_WARN, " is not existed in IPv4 hash table\n");
    return -ENOENT;
}

static int rule_deregister_teid_hash(rule_match_t *rule)
{
    int ret;
    rule_pdr_t *pdr = &rule->pdr;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &pdr->teid, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            goto NOTFOUND;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with teid #%u", pdr->id, pdr->teid);
            logger_s(LOG_GTP, L_WARN, " into teid hash table\n");
            return ret;
        }
    }

    if (existed_rule->pdr.id == pdr->id) {
        rte_hash_del_key(teid_in_hash, &pdr->teid);
        rte_hash_add_key_data(teid_in_hash, &existed_rule->next_teid->pdr.teid, existed_rule->next_teid);
        rule->next_teid = NULL;
        return 0;
    }

    for (; existed_rule->next_teid; existed_rule = existed_rule->next_teid) {
        if (pdr->id == existed_rule->next_ipv4->pdr.id) {
            printf_dbg(" Delete PDR #%u after PDR #%u",rule->pdr.id, existed_rule->pdr.id);
            existed_rule->next_teid = rule->next_teid;
            rule->next_teid = NULL;
            return 0;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with teid #%u", pdr->id, pdr->teid);
    logger_s(LOG_GTP, L_WARN, " is not existed in teid hash table\n");
    return -ENOENT;
}

int rule_match_register(rule_match_t *rule)
{
    if (!rule || !rule->pdr.id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register PDR with NULL pointer or id with zero \n");
        return -ENOENT;
    }

    int ret;
    rule_pdr_t *pdr = &rule->pdr;
    // Check FAR in PDR is existed
    if ((ret = rule_far_find_by_id(pdr->far_id, &rule->far)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with non-existed FAR #%u \n", pdr->id, pdr->far_id);
        return -EEXIST;
    }

    rule_match_t *exised_rule;
    if ((ret = rte_hash_lookup_data(rule_id_hash, &pdr->id, (void **) &exised_rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed PDR #%u \n", pdr->id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with invalid parameter \n", pdr->id);
            return ret;
        }
    }

    if ((ret = rule_5tuple_complie(&pdr->sdf_filter, pdr->sdf_filter_str)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot compile sdf filter '%s' in existed PDR #%u \n",
                pdr->sdf_filter_str, pdr->id);
        return ret;
    }

    if ((ret = rte_hash_add_key_data(rule_id_hash, &pdr->id, rule))) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into rule_id_hash\n",
                    pdr->id, rule);
        goto err;
    }

    // With teid & regist to teid_in_hash function
    printf_dbg("\n Insert PDR #%d with ", pdr->id);
    if (pdr->teid) {
        printf_dbg("teid #%u into GTP-U hash table \n", pdr->teid);

        if ((ret = rule_register_teid_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add PDR #%u with teid #%u into GTP-U hash table\n",
                    pdr->id, pdr->teid);
            goto err;
        }
    }
    else {
        print_dbg_ipv4(pdr->ue_ipv4);
        printf_dbg(" into IPv4 hash table \n");

        if ((ret = rule_register_ipv4_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", pdr->id);
            logger_ipv4(pdr->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            goto err;
        }
    }

    return 0;

err:
    rule_5tuple_clean(pdr->sdf_filter);
    return ret;
}

int rule_match_deregister(uint16_t id)
{
    if (!id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot deregister PDR id with zero \n");
        return -ENOENT;
    }

    int ret;
    rule_match_t *existed_rule;
    if ((ret = rte_hash_lookup_data(rule_id_hash, &id, (void **) &existed_rule)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot deregister PDR #%u \n", id);
        return ret;
    }

    if (existed_rule->next_ipv4) {
        if (rule_deregister_ipv4_hash(existed_rule))
            logger(LOG_GTP, L_WARN, "ERROR: cannot deregister PDR #%u in ipv4_hash \n", id);
    }

    if (existed_rule->next_teid) {
        if (rule_deregister_teid_hash(existed_rule))
            logger(LOG_GTP, L_WARN, "ERROR: cannot deregister PDR #%u in teid_hash \n", id);
    }

    rte_hash_del_key(rule_id_hash, &existed_rule->pdr.id);
    existed_rule->next_id = NULL;

    return 0;
}

// TODO: ...

int rule_far_register(rule_far_t *rule)
{
    if (!rule || !rule->id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register FAR with NULL pointer or id with zero \n");
        return -ENOENT;
    }

    int ret;

    rule_far_t *exised_rule;
    if ((ret = rte_hash_lookup_data(far_id_hash, &rule->id, (void **) &exised_rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed FAR #%u \n", rule->id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create FAR #%u with invalid parameter \n", rule->id);
            return ret;
        }
    }

    if ((ret = rte_hash_add_key_data(far_id_hash, &rule->id, rule))) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into far_id_hash\n",
                    rule->id, rule);
        return ret;
    }

    return 0;
}

int rule_far_deregister(uint32_t id)
{
    if (!id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register FAR id with zero \n");
        return -ENOENT;
    }

    int ret;
    rule_far_t *existed_rule;
    if ((ret = rte_hash_lookup_data(far_id_hash, &id, (void **) &existed_rule)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot deregister FAR #%u \n", id);
        return ret;
    }

    rte_hash_del_key(far_id_hash, &existed_rule->id);

    return 0;
}

void rule_far_dump_table(TraceLevel trace_level)
{
    uint32_t *id = NULL;
    uint32_t iter = 0;
    rule_far_t *rule_far_entry;

    logger(LOG_GTP, trace_level, "[Rule Action Table]\n");
    logger(LOG_GTP, trace_level, "There are %d entries in total:", rte_hash_count(far_id_hash));
    logger_s(LOG_GTP, trace_level, "\n");

    while (rte_hash_iterate(far_id_hash, (void *)&id, (void **) &rule_far_entry, &iter) >= 0) {
        rule_far_dump(rule_far_entry, trace_level);
    }
}

int rule_match_create_by_config(uint16_t id, uint8_t remove_hdr, uint32_t teid_in, rte_be32_t ue_ipv4, uint32_t far_id)
{
    int ret;
    rule_match_t *rule = NULL;
    rule_pdr_t *pdr = NULL;
    rule_far_t *action = NULL;

    if ((ret = rule_far_find_by_id(far_id, &action)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with non-existed FAR #%u \n", id, far_id);
        return -EEXIST;
    }

    // New rule ID
    if ((ret = rte_hash_lookup_data(rule_id_hash, &id, (void **) &rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed PDR #%u \n", id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with invalid parameter \n", id);
            return ret;
        }
    }

    if (!(rule = rule_match_zmalloc()))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");

    pdr = &rule->pdr;

    rule_pdr_set_id(pdr, id);
    rule_pdr_set_precedence(pdr, 32);

    rule_pdr_set_remove_hdr(pdr, remove_hdr);

    rule_pdr_set_teid(pdr, teid_in);
    rule_pdr_set_ue_ipv4(pdr, ue_ipv4);

    rule_pdr_set_far_id(pdr, far_id);

    rule->far = action;

    if (rte_hash_add_key_data(rule_id_hash, &pdr->id, rule)) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into rule_id_hash\n",
                    id, rule);
        goto FREE_RULE;
    }

    // With teid & regist to teid_in_hash function
    printf_dbg("\n Insert PDR #%d with ", id);
    if (pdr->teid) {
        printf_dbg("teid #%u into GTP-U hash table \n", pdr->teid);

        if ((ret = rule_register_teid_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add PDR #%u with teid #%u into GTP-U hash table\n",
                    id, pdr->teid);
            goto FREE_RULE;
        }
    }
    else {
        print_dbg_ipv4(pdr->ue_ipv4);
        printf_dbg(" into GTP-U hash table \n");

        if ((ret = rule_register_ipv4_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", id);
            logger_ipv4(pdr->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into GTP-U hash table\n");
            goto FREE_RULE;
        }
    }

    return 0;

FREE_RULE:
    rule_match_free(rule);
    return ret;
}

int rule_far_create_by_config(uint32_t id, uint8_t dst_int, rte_be16_t desp, rte_be32_t teid, rte_be32_t peer_ipv4)
{
    int ret;
    rule_far_t *rule = NULL;

    // New rule ID
    if ((ret = rte_hash_lookup_data(far_id_hash, &id, (void **) &rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed FAR #%u \n", id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create FAR #%u with invalid parameter \n", id);
            return ret;
        }
    }

    if (!(rule = rule_far_zmalloc()))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");

    rule_far_set_id(rule, id);
    rule_far_set_apply_action(rule, RULE_FAR_APPLY_ACTION_FORW);
    rule_far_set_dst_int(rule, dst_int);

    rule_far_set_outer_hdr_desp(rule, desp);
    rule_far_set_outer_hdr_teid(rule, teid);
    rule_far_set_outer_hdr_ipv4(rule, peer_ipv4);
    rule_far_set_outer_hdr_port(rule, 2152);

    if (rte_hash_add_key_data(far_id_hash, &rule->id, rule)) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into far_id_hash\n",
                    id, rule);
        goto FREE_RULE;
    }

    return 0;

FREE_RULE:
    rule_far_free(rule);
    return ret;
}