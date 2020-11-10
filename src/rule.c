#include "rule.h"

#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_gtp.h>

#include "param.h"
#include "logger.h"
#include "ip.h"

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

int rule_match_find_by_teid(uint32_t teid, rule_match_t **rule)
{
    int ret;
    // rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &teid, (void **) rule)) < 0) {
        printf_dbg(" Cannot find the rule matching with TEID #%u \n", teid);
        return ret;
    }

    return ret;
/* TODO: Test for throughput
    for (; existed_rule; existed_rule = existed_rule->next_teid) {
        if (existed_rule->upf_ipv4)
            if (existed_rule->upf_ipv4 != info->ipv4_hdr->dst_addr)
                continue;

        if (existed_rule->ue_ipv4)
            if (existed_rule->ue_ipv4 != info->origin.ipv4_hdr->src_addr)
            continue;

        rule = existed_rule;
        return ret;
    }

    return -ENOENT;
*/
}

int rule_match_find_by_ipv4(rte_be32_t ipv4, rule_match_t **rule)
{
    int ret;
    // rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &ipv4, (void **) rule)) < 0) {
        printf_dbg(" Cannot find the rule matching with UE IPv4 ");
        print_dbg_ipv4(ipv4);
        printf_dbg("\n");

        return ret;
    }

    return ret;
/* TODO: Test for throughput
    for (; existed_rule; existed_rule = existed_rule->next_ipv4) {
        // TODO: another field to matching

        data = existed_rule;
        return ret;
    }

    return -ENOENT;
*/
}

int rule_action_find_by_id(uint32_t id, rule_action_t **data)
{
    return rte_hash_lookup_data(action_id_hash, &id, (void **) data);
}

int rule_register_ipv4_hash(rule_match_t *rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &rule->ue_ipv4, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            rule->next_ipv4 = NULL;
            return rte_hash_add_key_data(ue_ipv4_hash, &rule->ue_ipv4, rule);
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", rule->id);
            logger_ipv4(rule->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            return ret;
        }
    }

    // Insert to the first
    if (rule->precedence <= existed_rule->precedence) {
        rule->next_ipv4 = existed_rule;
        rte_hash_del_key(ue_ipv4_hash, &existed_rule->ue_ipv4);
        return rte_hash_add_key_data(ue_ipv4_hash, &rule->ue_ipv4, rule);
    }
    
    for (; existed_rule->next_ipv4; existed_rule = existed_rule->next_ipv4) {
        if (rule->precedence <= existed_rule->next_ipv4->precedence) {
            printf_dbg(" Add PDR #%u with precedence %u after PDR #%u with precedence %u",
                    rule->id, rule->precedence, existed_rule->id, existed_rule->precedence);
            break;
        }
    }

    rule->next_ipv4 = existed_rule->next_ipv4;
    existed_rule->next_ipv4 = rule;

    return ret;
}

int rule_register_teid_hash(rule_match_t *rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &rule->teid, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            rule->next_teid = NULL;
            return rte_hash_add_key_data(teid_in_hash, &rule->teid, rule);
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with teid #%u", rule->id, rule->teid);
            logger_s(LOG_GTP, L_WARN, " into teid hash table\n");
            return ret;
        }
    }

    // Insert to the first
    if (rule->precedence <= existed_rule->precedence) {
        rule->next_teid = existed_rule;
        rte_hash_del_key(teid_in_hash, &existed_rule->teid);
        return rte_hash_add_key_data(teid_in_hash, &rule->teid, rule);
    }
    
    for (; existed_rule->next_teid; existed_rule = existed_rule->next_teid) {
        if (rule->precedence <= existed_rule->next_teid->precedence) {
            printf_dbg(" Add PDR #%u with precedence %u after PDR #%u with precedence %u",
                    rule->id, rule->precedence, existed_rule->id, existed_rule->precedence);
            break;
        }
    }

    rule->next_teid = existed_rule->next_teid;
    existed_rule->next_teid = rule;

    return ret;
}

int rule_deregister_ipv4_hash(rule_match_t *rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(ue_ipv4_hash, &rule->ue_ipv4, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            goto NOTFOUND;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot delete PDR #%u with ", rule->id);
            logger_ipv4(rule->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            return ret;
        }
    }

    if (existed_rule->id == rule->id) {
        rte_hash_del_key(ue_ipv4_hash, &rule->ue_ipv4);
        rte_hash_add_key_data(ue_ipv4_hash, &existed_rule->next_ipv4->ue_ipv4, existed_rule->next_ipv4);
        rule->next_ipv4 = NULL;
        return ret;
    }

    for (; existed_rule->next_ipv4; existed_rule = existed_rule->next_ipv4) {
        if (rule->id == existed_rule->next_ipv4->id) {
            printf_dbg(" Delete PDR #%u after PDR #%u", rule->id, existed_rule->id);
            existed_rule->next_ipv4 = rule->next_ipv4;
            rule->next_ipv4 = NULL;
            return ret;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with ", rule->id);
    logger_ipv4(rule->ue_ipv4, L_WARN);
    logger_s(LOG_GTP, L_WARN, " is not existed in IPv4 hash table\n");
    return -ENOENT;
}

int rule_deregister_teid_hash(rule_match_t *rule)
{
    int ret;
    rule_match_t *existed_rule = NULL;
    if ((ret = rte_hash_lookup_data(teid_in_hash, &rule->teid, (void **) &existed_rule)) < 0) {
        // The first element
        if (ret == -ENOENT) {
            goto NOTFOUND;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with teid #%u", rule->id, rule->teid);
            logger_s(LOG_GTP, L_WARN, " into teid hash table\n");
            return ret;
        }
    }

    if (existed_rule->id == rule->id) {
        rte_hash_del_key(teid_in_hash, &rule->teid);
        rte_hash_add_key_data(teid_in_hash, &existed_rule->next_teid->teid, existed_rule->next_teid);
        rule->next_teid = NULL;
        return ret;
    }

    for (; existed_rule->next_teid; existed_rule = existed_rule->next_teid) {
        if (rule->id == existed_rule->next_ipv4->id) {
            printf_dbg(" Delete PDR #%u after PDR #%u", rule->id, existed_rule->id);
            existed_rule->next_teid = rule->next_teid;
            rule->next_teid = NULL;
            return ret;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with teid #%u", rule->id, rule->teid);
    logger_s(LOG_GTP, L_WARN, " is not existed in teid hash table\n");
    return -ENOENT;
}

static const char *remove_hdr_str[] = {"GTP-U/UDP/IPv4", "GTP-U/UDP/IPv6", "UDP/IPv4", "UDP/IPv6"};
static __rte_always_inline void logger_remove_hdr(uint8_t remove_hdr, TraceLevel trace_level)
{
    remove_hdr >>= 4;
    for (int i = 0; remove_hdr; remove_hdr >>= 1, i++) {
        if (remove_hdr & 1) {
            logger_s(LOG_GTP, trace_level, "%s", remove_hdr_str[i]);
            return;
        }
    }
    logger_s(LOG_GTP, trace_level, "Invalid");
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
        logger_s(LOG_GTP, trace_level, " - ID = ");
        logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->id);
        logger_s(LOG_GTP, trace_level, "\n");

        logger_s(LOG_GTP, trace_level, "   Precedence = ");
        logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->precedence);
        logger_s(LOG_GTP, trace_level, "\n");

        if (rule_match_entry->remove_hdr) {
            logger_s(LOG_GTP, trace_level, "   Outer Hdr Removal = ");
            logger_remove_hdr(rule_match_entry->remove_hdr, trace_level);
            logger_s(LOG_GTP, trace_level, "\n");
        }

        if (rule_match_entry->ue_ipv4) {
            logger_s(LOG_GTP, trace_level, "   UE IPv4 = ");
            logger_ipv4(rule_match_entry->ue_ipv4, trace_level);
            logger_s(LOG_GTP, trace_level, "\n");
        }

        if (rule_match_entry->upf_ipv4) {
            logger_s(LOG_GTP, trace_level, "   UPF IPv4 = ");
            logger_ipv4(rule_match_entry->upf_ipv4, trace_level);
            logger_s(LOG_GTP, trace_level, "\n");
        }
        
        if (rule_match_entry->teid) {
            logger_s(LOG_GTP, trace_level, "   TEID = ");
            logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_32(rule_match_entry->teid));
            logger_s(LOG_GTP, trace_level, "\n");
        }

        logger_s(LOG_GTP, trace_level, "   Action ID = ");
        logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->action_id);
        logger_s(LOG_GTP, trace_level, " %s", (rule_match_entry->action ? "linked" : "unlinked"));
        logger_s(LOG_GTP, trace_level, "\n");
    }
}

static const char *apply_action_str[] = {"INVALID", "DROP", "FORW", "BUFF", "NOCP", "DUPL"};
static __rte_always_inline void logger_apply_action(uint8_t apply_action, TraceLevel trace_level)
{
    if (unlikely(!apply_action)) {
        logger_s(LOG_GTP, trace_level, " %s", apply_action_str[0]);
        return;
    }

    for (int i = 1; apply_action && i <= 5; apply_action >>= 1, i++)
        if (apply_action & 1)
            logger_s(LOG_GTP, trace_level, " %s", apply_action_str[i]);
}

static const char *dst_int_str[] = {"Access (Downlink)", "Core (Uplink)", "SGi-LAN/N6-LAN", "CP- Function", "LI Function"};
static __rte_always_inline void logger_dst_int(uint8_t dst_int, TraceLevel trace_level)
{
    if (unlikely(dst_int > 4)) {
        logger_s(LOG_GTP, trace_level, "Invalid");
        return;
    }
    logger_s(LOG_GTP, trace_level, "%s", dst_int_str[dst_int]);
}   

void rule_action_dump_table(TraceLevel trace_level)
{
    uint32_t *id = NULL;
    uint32_t iter = 0;
    rule_action_t *rule_action_entry;

    logger(LOG_GTP, trace_level, "[Rule Action Table]\n");
    logger(LOG_GTP, trace_level, "There are %d entries in total:", rte_hash_count(action_id_hash));
    logger_s(LOG_GTP, trace_level, "\n");

    while (rte_hash_iterate(action_id_hash, (void *)&id, (void **) &rule_action_entry, &iter) >= 0) {
        logger_s(LOG_GTP, trace_level, " - ID = ");
        logger_s(LOG_GTP, trace_level, "%u", rule_action_entry->id);
        logger_s(LOG_GTP, trace_level, "\n");

        logger_s(LOG_GTP, trace_level, "   Apply Action =");  // No space at the end of this sub-string for typesetting
        logger_apply_action(rule_action_entry->apply_action, trace_level);
        logger_s(LOG_GTP, trace_level, "\n");

        logger_s(LOG_GTP, trace_level, "   Destination Interface = ");
        logger_dst_int(rule_action_entry->dst_int, trace_level);
        logger_s(LOG_GTP, trace_level, "\n");

        if (rule_action_entry->outer_hdr_info.desp) {
            logger_s(LOG_GTP, trace_level, "   Outer Hdr Creation = \n");
            if (rule_action_entry->outer_hdr_info.desp == RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4 ||
                    rule_action_entry->outer_hdr_info.desp == RULE_ACTION_OUTER_HDR_DESP_UDP_IPV4) {
                logger_s(LOG_GTP, trace_level, "      IPv4 DST = ");
                logger_ipv4(rule_action_entry->outer_hdr_info.peer_ipv4, trace_level);
                logger_s(LOG_GTP, trace_level, "\n");
            }
            if (rule_action_entry->outer_hdr_info.desp == RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4 ||
                    rule_action_entry->outer_hdr_info.desp == RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV6) {
                logger_s(LOG_GTP, trace_level, "      TEID = ");
                logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_32(rule_action_entry->outer_hdr_info.teid));
                logger_s(LOG_GTP, trace_level, "\n");
            }
            logger_s(LOG_GTP, trace_level, "      UDP Port = ");
            logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_16(rule_action_entry->outer_hdr_info.peer_port));
            logger_s(LOG_GTP, trace_level, "\n");
        }
    }
}

int rule_match_create_by_config(uint16_t id, uint8_t remove_hdr, rte_be32_t teid_in, rte_be32_t ue_ipv4, uint32_t action_id)
{
    int ret;
    rule_match_t *rule = NULL;
    rule_action_t *action = NULL;

    if ((ret = rule_action_find_by_id(action_id, &action)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with non-existed FAR #%u \n", id, action_id);
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

    if (!(rule = rte_zmalloc("Temprary rule match", sizeof(rule_match_t), 0)))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");
        
    rule->id = id;
    rule->precedence = 32;

    rule->remove_hdr = (1 << (remove_hdr + 4));

    rule->teid = teid_in;
    rule->ue_ipv4 = ue_ipv4;

    rule->action_id = action_id;
    rule->action = action;

    if (rte_hash_add_key_data(rule_id_hash, &rule->id, rule))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot add new key-value into rule_id_hash\n");

    // With teid & regist to teid_in_hash function
    printf_dbg("\n Insert PDR #%d with ", id);
    if (rule->teid) {
        printf_dbg("teid #%u into GTP-U hash table \n", rule->teid);

        if ((ret = rule_register_teid_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add PDR #%u with teid #%u into GTP-U hash table\n",
                    id, rule->teid);
            return ret;
        }
    }
    else {
        print_dbg_ipv4(rule->ue_ipv4);
        printf_dbg(" into GTP-U hash table \n");

        if ((ret = rule_register_ipv4_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", id);
            logger_ipv4(rule->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into GTP-U hash table\n");
            return ret;
        }
    }

    return 0;
}

int rule_action_create_by_config(uint32_t id, uint8_t dst_int, rte_be16_t desp, rte_be32_t teid, rte_be32_t peer_ipv4)
{
    int ret;
    rule_action_t *rule = NULL;

    // New rule ID
    if ((ret = rte_hash_lookup_data(action_id_hash, &id, (void **) &rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed FAR #%u \n", id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create FAR #%u with invalid parameter \n", id);
            return ret;
        }
    }

    if (!(rule = rte_zmalloc("Temprary rule match", sizeof(rule_action_t), 0)))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");

    rule->id = id;
    rule->apply_action = RULE_ACTION_APPLY_ACTION_FORW;
    rule->dst_int = dst_int;

    rule->outer_hdr_info.desp = desp;
    rule->outer_hdr_info.teid = teid;
    rule->outer_hdr_info.peer_ipv4 = peer_ipv4;
    rule->outer_hdr_info.peer_port = rte_cpu_to_be_16(2152);

    if (rte_hash_add_key_data(action_id_hash, &rule->id, rule))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot add new key-value into rule_id_hash\n");

    return 0;
}