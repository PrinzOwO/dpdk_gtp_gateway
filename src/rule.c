#include "rule.h"

#include <string.h>
#include <regex.h>
#include <arpa/inet.h>

#include <rte_jhash.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>
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

// TODO: "rule_match_5tuple_set_*" is used to an API to set 5-tuple liked struct now
#define rule_match_5tuple_is_proto(rule, proto_num) \
    (rule->sdf_filter.proto == 0xff || rule->sdf_filter.proto == proto_num)

#define rule_match_5tuple_is_src_ipv4_subnet(rule, be_type_ipv4_addr) \
    in_ipv4_subnet(be_type_ipv4_addr, rule->sdf_filter.src_addr, rule->sdf_filter.src_mask)

#define rule_match_5tuple_is_dst_ipv4_subnet(rule, be_type_ipv4_addr) \
    in_ipv4_subnet(be_type_ipv4_addr, rule->sdf_filter.dst_addr, rule->sdf_filter.dst_mask)

static int ports_match(uint32_t *port_list, uint16_t port) {
    if (!port_list) {
        // TODO: debug
        printf_dbg(" no limit");
        return 1;
    }

    for (int i = 0; port_list[i]; i++) {
        // TODO: debug
        printf_dbg(" %d. %u <= %u <= %u", i, ((uint16_t *) &port_list[i])[0], port, ((uint16_t *) &port_list[i])[1]);
        if (((uint16_t *) &port_list[i])[0] <= port && ((uint16_t *) &port_list[i])[1] >= port)
            return 1;
    }
    return 0;
}

#define rule_match_5tuple_is_src_ports(rule, be_type_port) \
    ports_match(rule->sdf_filter.src_port_range, rte_be_to_cpu_16(be_type_port))

#define rule_match_5tuple_is_dst_ports(rule, be_type_port) \
    ports_match(rule->sdf_filter.dst_port_range, rte_be_to_cpu_16(be_type_port))


#define _rule_match_5tuple_matching(rule, l3_pkt) \
    ( \
        rule_match_5tuple_is_proto(rule, *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id))) && \
        rule_match_5tuple_is_src_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr)))) && \
        rule_match_5tuple_is_dst_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr)))) && \
        rule_match_5tuple_is_src_ports(rule, *((uint16_t *) ((uint8_t *) l3_pkt + sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_udp_hdr, src_port)))) && \
        rule_match_5tuple_is_dst_ports(rule, *((uint16_t *) ((uint8_t *) l3_pkt + sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_udp_hdr, dst_port)))) \
    )

#ifndef DEBUG
#define rule_match_5tuple_matching(rule, l3_pkt) _rule_match_5tuple_matching(rule, l3_pkt)
#else
static int rule_match_5tuple_matching_debug(rule_match_t *rule, struct rte_ipv4_hdr *l3_pkt)
{
    printf_dbg(" 5-tuple matching proto: result[%d], rule[%u], pkt[%u]",
            rule_match_5tuple_is_proto(rule, *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id))),
            rule->sdf_filter.proto, *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id)));

    printf_dbg(" 5-tuple matching src IPv4: result[%d], rule IPv4[",
           rule_match_5tuple_is_src_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr)))));
    print_dbg_ipv4(rule->sdf_filter.src_addr);
    printf_dbg("], rule mask[%d],  pkt[", ipv4_subnet_mask_to_num(rule->sdf_filter.src_mask));
    print_dbg_ipv4(*((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr))));
    printf_dbg("]");

    printf_dbg(" 5-tuple matching dst IPv4: result[%d], rule IPv4[",
            rule_match_5tuple_is_dst_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr)))));
    print_dbg_ipv4(rule->sdf_filter.dst_addr);
    printf_dbg("], rule mask[%d],  pkt[", ipv4_subnet_mask_to_num(rule->sdf_filter.dst_mask));
    print_dbg_ipv4(*((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr))));
    printf_dbg("]");
    
    return _rule_match_5tuple_matching(rule, l3_pkt);
}

#define rule_match_5tuple_matching(rule, l3_pkt) rule_match_5tuple_matching_debug(rule, l3_pkt)

#endif

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

#define rule_match_dump_entry(rule_match_entry, trace_level) \
    { \
        logger_s(LOG_GTP, trace_level, " - ID = "); \
                logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->id); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        logger_s(LOG_GTP, trace_level, "   Precedence = "); \
        logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->precedence); \
        logger_s(LOG_GTP, trace_level, "\n"); \
        if (rule_match_entry->remove_hdr) { \
            logger_s(LOG_GTP, trace_level, "   Outer Hdr Removal = "); \
            logger_remove_hdr(rule_match_entry->remove_hdr, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if (rule_match_entry->ue_ipv4) { \
            logger_s(LOG_GTP, trace_level, "   UE IPv4 = "); \
            logger_ipv4(rule_match_entry->ue_ipv4, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if (rule_match_entry->upf_ipv4) { \
            logger_s(LOG_GTP, trace_level, "   UPF IPv4 = "); \
            logger_ipv4(rule_match_entry->upf_ipv4, trace_level); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        if (rule_match_entry->teid) { \
            logger_s(LOG_GTP, trace_level, "   TEID = "); \
            logger_s(LOG_GTP, trace_level, "%u", rte_be_to_cpu_32(rule_match_entry->teid)); \
            logger_s(LOG_GTP, trace_level, "\n"); \
        } \
        logger_s(LOG_GTP, trace_level, "   Action ID = "); \
        logger_s(LOG_GTP, trace_level, "%u", rule_match_entry->action_id); \
        logger_s(LOG_GTP, trace_level, " %s", (rule_match_entry->action ? "linked" : "unlinked")); \
        logger_s(LOG_GTP, trace_level, "\n"); \
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
        rule_match_dump_entry(rule_match_entry, trace_level);
    }
}


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
        rule_match_dump_entry(existed_rule, L_INFO);
        if (existed_rule->upf_ipv4)
            if (existed_rule->upf_ipv4 != ipv4_hdr->dst_addr)
                continue;

        if (existed_rule->ue_ipv4)
            if (existed_rule->ue_ipv4 != inner_ipv4_hdr->src_addr)
                continue;

        if (existed_rule->sdf_filter_str[0])
            if (!rule_match_5tuple_matching(existed_rule, inner_ipv4_hdr))
                continue;

        *rule = existed_rule;
        return ret;
    }

    printf_dbg(" Cannot find the rule matching with TEID #%u \n", gtp_hdr->teid);

    return -ENOENT;
}

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
        rule_match_dump_entry(existed_rule, L_INFO);
        if (existed_rule->sdf_filter_str[0])
            if (!rule_match_5tuple_matching(existed_rule, ipv4_hdr))
                continue;

        *rule = existed_rule;
        return ret;
    }

    printf_dbg(" Cannot find the rule matching with UE IPv4 ");
    print_dbg_ipv4(ipv4_hdr->dst_addr);
    printf_dbg("\n");

    return -ENOENT;
}

int rule_action_find_by_id(uint32_t id, rule_action_t **data)
{
    return rte_hash_lookup_data(action_id_hash, &id, (void **) data);
}

static int rule_register_ipv4_hash(rule_match_t *rule)
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

static int rule_register_teid_hash(rule_match_t *rule)
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

static int rule_deregister_ipv4_hash(rule_match_t *rule)
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
        return 0;
    }

    for (; existed_rule->next_ipv4; existed_rule = existed_rule->next_ipv4) {
        if (rule->id == existed_rule->next_ipv4->id) {
            printf_dbg(" Delete PDR #%u after PDR #%u", rule->id, existed_rule->id);
            existed_rule->next_ipv4 = rule->next_ipv4;
            rule->next_ipv4 = NULL;
            return 0;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with ", rule->id);
    logger_ipv4(rule->ue_ipv4, L_WARN);
    logger_s(LOG_GTP, L_WARN, " is not existed in IPv4 hash table\n");
    return -ENOENT;
}

static int rule_deregister_teid_hash(rule_match_t *rule)
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
        return 0;
    }

    for (; existed_rule->next_teid; existed_rule = existed_rule->next_teid) {
        if (rule->id == existed_rule->next_ipv4->id) {
            printf_dbg(" Delete PDR #%u after PDR #%u", rule->id, existed_rule->id);
            existed_rule->next_teid = rule->next_teid;
            rule->next_teid = NULL;
            return 0;
        }
    }

NOTFOUND:
    logger(LOG_GTP, L_WARN, "ERROR: PDR #%u with teid #%u", rule->id, rule->teid);
    logger_s(LOG_GTP, L_WARN, " is not existed in teid hash table\n");
    return -ENOENT;
}

#define rule_match_sdf_filter_free(rule) \
    memset(rule->sdf_filter_str, 0, sizeof(rule->sdf_filter_str)); \
    rte_free(rule->sdf_filter.src_port_range); \
    rte_free(rule->sdf_filter.dst_port_range)

// TODO: "rule_match_5tuple_set_*" is used to an API to set 5-tuple liked struct now
#define rule_match_5tuple_set_proto(rule, proto_num) \
    rule->sdf_filter.proto = proto_num

#define rule_match_5tuple_set_src_ipv4(rule, cpu_type_ipv4) \
    rule->sdf_filter.src_addr = rte_cpu_to_be_32(cpu_type_ipv4)
#define rule_match_5tuple_set_src_ipv4_str(rule, str_type_ipv4) \
    inet_pton(AF_INET, (str_type_ipv4), &rule->sdf_filter.src_addr)

#define rule_match_5tuple_set_src_ipv4_mask(rule, num_type_mask) \
    rule->sdf_filter.src_mask = ipv4_subnet_num_to_mask(num_type_mask)

#define rule_match_5tuple_set_dst_ipv4(rule, cpu_type_ipv4) \
    rule->sdf_filter.dst_addr = rte_cpu_to_be_32(cpu_type_ipv4)
#define rule_match_5tuple_set_dst_ipv4_str(rule, str_type_ipv4) \
    inet_pton(AF_INET, (str_type_ipv4), &rule->sdf_filter.dst_addr)

#define rule_match_5tuple_set_dst_ipv4_mask(rule, num_type_mask) \
    rule->sdf_filter.dst_mask = ipv4_subnet_num_to_mask(num_type_mask)


static void rule_match_5tuple_set_ports(uint32_t **dst, char *port_list)
{
    if (!port_list)
        return;

    *dst = rte_zmalloc("rule match in rule_match_zmalloc", sizeof(uint32_t) * 0x10, 0);
    uint32_t port1, port2, cnt = 0;

    char *tok_ptr = strtok(port_list, ","), *chr_ptr;
    while (tok_ptr != NULL)  {
        chr_ptr = strchr(tok_ptr, '-');
        if (chr_ptr) {
            *chr_ptr = '\0'; port1 = atoi(tok_ptr); port2 = atoi(chr_ptr + 1);
            if (port1 <= port2)
                (*dst)[cnt++] = port1 + (port2 << 16);
            else
                (*dst)[cnt++] = port2 + (port1 << 16);
        }
        else {
            port1 = atoi(tok_ptr);
            (*dst)[cnt++] = port1 + (port1 << 16);
        }
        tok_ptr = strtok(NULL, ",");
    }
}

#define rule_match_5tuple_set_src_ports(rule, str_type_src_ports) \
    rule_match_5tuple_set_ports(&rule->sdf_filter.src_port_range, str_type_src_ports)

#define rule_match_5tuple_set_dst_ports(rule, str_type_dst_ports) \
    rule_match_5tuple_set_ports(&rule->sdf_filter.dst_port_range, str_type_dst_ports)

static int rule_match_sdf_filter_complie(rule_match_t *rule)
{
    if (!strlen(rule->sdf_filter_str))
        return 0;

    logger_s(LOG_GTP, L_INFO, "\n \n");

    const char *rule_str = rule->sdf_filter_str;
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string: %s \n", rule_str);

    char reg_act[] = "(permit)";
    char reg_direction[] = "(in|out)";
    char reg_proto[] = "(ip|[0-9]{1,3}})";
    char reg_src_ip_mask[] = "(any|assigned|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(/[0-9]{1,5})?)";
    char reg_dest_ip_mask[] = "(any|assigned|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(/[0-9]{1,5})?)";
    char reg_port[] = "([ ][0-9]{1,5}([,-][0-9]{1,5})*)?";

    char reg[0x1ff];
    sprintf(reg, "^%s %s %s from %s%s to %s%s$", reg_act, reg_direction, reg_proto,
            reg_src_ip_mask, reg_port,
            reg_dest_ip_mask, reg_port);

    regex_t preg;
    regmatch_t pmatch[0x10];
    int nmatch = sizeof(pmatch) / sizeof(regmatch_t);
    int cflags = REG_EXTENDED | REG_ICASE;

    if (regcomp(&preg, reg, cflags) != 0) {
        logger(LOG_GTP, L_WARN, "Regex string for SDF filter description format error \n");
        goto err;
    }
    if (regexec(&preg, rule_str, nmatch, pmatch, 0) != 0) {
        logger(LOG_GTP, L_WARN, "SDF filter description format error \n");
        goto err;
    }

    int len;
    char buf[0xff];

    // Get Action
    len = pmatch[1].rm_eo - pmatch[1].rm_so;
    strncpy(buf, rule_str + pmatch[1].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Action: %s \n", buf);
    if (strcmp(buf, "permit") == 0) {
        // TODO:
    }
    else {
        logger(LOG_GTP, L_WARN, "SDF filter description action not support \n");
        goto err;
    }

    // Get Protocol
    len = pmatch[3].rm_eo - pmatch[3].rm_so;
    strncpy(buf, rule_str + pmatch[3].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Protocol: %s \n", buf);
    if (strcmp(buf, "ip") == 0)
        rule_match_5tuple_set_proto(rule, 0xff);
    else {
        int tmp = atoi(buf);
        if (tmp > 0xff) {
            logger(LOG_GTP, L_WARN, "SDF filter description protocol not support \n");
            goto err;
        }
        rule_match_5tuple_set_proto(rule, tmp);
    }

    // Get SRC Mask
    len = pmatch[5].rm_eo - pmatch[5].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[5].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse SRC Mask: %s \n", buf);
        int smask = atoi(buf);
        if (smask > 32) {
            logger(LOG_GTP, L_WARN, "SDF filter description SRC mask is invalid \n");
            goto err;
        }
        rule_match_5tuple_set_src_ipv4_mask(rule, smask);
    }
    else
        rule_match_5tuple_set_src_ipv4_mask(rule, 32);

    // Get SRC IP
    len = pmatch[4].rm_eo - pmatch[4].rm_so - len;
    strncpy(buf, rule_str + pmatch[4].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse SRC IP: %s \n", buf);
    if (strcmp(buf, "any") == 0) {
        rule_match_5tuple_set_src_ipv4_str(rule, "0.0.0.0");
        rule_match_5tuple_set_src_ipv4_mask(rule, 0);
    }
    else if (strcmp(buf, "assigned") == 0) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip do NOT support assigned yet \n");
        goto err;
    }
    else if((rule_match_5tuple_set_src_ipv4_str(rule, buf)) != 1) {
        logger(LOG_GTP, L_WARN, "SDF filter description src ip is invalid \n");
        goto err;
    }

    // Get SRC Port
    len = pmatch[6].rm_eo - pmatch[6].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[6].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse SRC Port: %s \n", buf);
        rule_match_5tuple_set_src_ports(rule, buf);
    }
    else
        rule_match_5tuple_set_src_ports(rule, NULL);


    // Get Dest Mask
    len = pmatch[9].rm_eo - pmatch[9].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[9].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Dst Mask: %s \n", buf);
        int dmask = atoi(buf);
        if (dmask > 32) {
            logger(LOG_GTP, L_WARN, "SDF filter description Dest mask is invalid \n");
            goto err;
        }
        rule_match_5tuple_set_dst_ipv4_mask(rule, dmask);
    }
    else
        rule_match_5tuple_set_dst_ipv4_mask(rule, 32);

    // Get Dest IP
    len = pmatch[8].rm_eo - pmatch[8].rm_so - len;
    strncpy(buf, rule_str + pmatch[8].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Dst IP: %s \n", buf);
    if (strcmp(buf, "any") == 0) {
        rule_match_5tuple_set_dst_ipv4_str(rule, "0.0.0.0");
        rule_match_5tuple_set_dst_ipv4_mask(rule, 0);
    }
    else if (strcmp(buf, "assigned") == 0) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip do NOT support assigned yet \n");
        goto err;
    }
    else if((rule_match_5tuple_set_dst_ipv4_str(rule, buf)) != 1) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip is invalid \n");
        goto err;
    }

    // Get Dest Port
    len = pmatch[10].rm_eo - pmatch[10].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[10].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Dst Port: %s \n", buf);
        rule_match_5tuple_set_dst_ports(rule, buf);
    }
    else
        rule_match_5tuple_set_dst_ports(rule, NULL);

   return 0;

err:
    rule_match_sdf_filter_free(rule);
    return -EINVAL;
}

int rule_match_register(rule_match_t *rule)
{
    if (!rule || !rule->id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register PDR with NULL pointer or id with zero \n");
        return -ENOENT;
    }

    int ret;

    // Check FAR in PDR is existed
    if ((ret = rule_action_find_by_id(rule->action_id, &rule->action)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with non-existed FAR #%u \n", rule->id, rule->action_id);
        return -EEXIST;
    }

    rule_match_t *exised_rule;
    if ((ret = rte_hash_lookup_data(rule_id_hash, &rule->id, (void **) &exised_rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed PDR #%u \n", rule->id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create PDR #%u with invalid parameter \n", rule->id);
            return ret;
        }
    }

    if ((ret = rule_match_sdf_filter_complie(rule)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot compile sdf filter '%s' in existed PDR #%u \n",
                rule->sdf_filter_str, rule->id);
        return ret;
    }

    if ((ret = rte_hash_add_key_data(rule_id_hash, &rule->id, rule))) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into rule_id_hash\n",
                    rule->id, rule);
        goto err;
    }

    // With teid & regist to teid_in_hash function
    printf_dbg("\n Insert PDR #%d with ", rule->id);
    if (rule->teid) {
        printf_dbg("teid #%u into GTP-U hash table \n", rule->teid);

        if ((ret = rule_register_teid_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add PDR #%u with teid #%u into GTP-U hash table\n",
                    rule->id, rule->teid);
            goto err;
        }
    }
    else {
        print_dbg_ipv4(rule->ue_ipv4);
        printf_dbg(" into IPv4 hash table \n");

        if ((ret = rule_register_ipv4_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", rule->id);
            logger_ipv4(rule->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into IPv4 hash table\n");
            goto err;
        }
    }

    return 0;

err:
    rule_match_sdf_filter_free(rule);
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

    rte_hash_del_key(rule_id_hash, &existed_rule->id);
    existed_rule->next_id = NULL;

    // Clean up SDF filter
    rule_match_sdf_filter_free(existed_rule);

    return 0;
}

int rule_action_register(rule_action_t *rule)
{
    if (!rule || !rule->id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register FAR with NULL pointer or id with zero \n");
        return -ENOENT;
    }

    int ret;

    rule_action_t *exised_rule;
    if ((ret = rte_hash_lookup_data(action_id_hash, &rule->id, (void **) &exised_rule)) != -ENOENT) {
        if (ret > 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create existed FAR #%u \n", rule->id);
            return -EEXIST;
        }
        else {
            logger(LOG_GTP, L_WARN, "ERROR: cannot create FAR #%u with invalid parameter \n", rule->id);
            return ret;
        }
    }

    if ((ret = rte_hash_add_key_data(action_id_hash, &rule->id, rule))) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into action_id_hash\n",
                    rule->id, rule);
        return ret;
    }

    return 0;
}

int rule_action_deregister(uint32_t id)
{
    if (!id) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot register FAR id with zero \n");
        return -ENOENT;
    }

    int ret;
    rule_action_t *existed_rule;
    if ((ret = rte_hash_lookup_data(action_id_hash, &id, (void **) &existed_rule)) < 0) {
        logger(LOG_GTP, L_WARN, "ERROR: cannot deregister FAR #%u \n", id);
        return ret;
    }

    rte_hash_del_key(action_id_hash, &existed_rule->id);

    return 0;
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

int rule_match_create_by_config(uint16_t id, uint8_t remove_hdr, uint32_t teid_in, rte_be32_t ue_ipv4, uint32_t action_id)
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

    if (!(rule = rule_match_zmalloc()))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");

    rule_match_set_id(rule, id);
    rule_match_set_precedence(rule, 32);

    rule_match_set_remove_hdr(rule, remove_hdr);

    rule_match_set_teid(rule, teid_in);
    rule_match_set_ue_ipv4(rule, ue_ipv4);

    rule_match_set_action_id(rule, action_id);

    rule->action = action;

    if (rte_hash_add_key_data(rule_id_hash, &rule->id, rule)) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into rule_id_hash\n",
                    id, rule);
        goto FREE_RULE;
    }

    // With teid & regist to teid_in_hash function
    printf_dbg("\n Insert PDR #%d with ", id);
    if (rule->teid) {
        printf_dbg("teid #%u into GTP-U hash table \n", rule->teid);

        if ((ret = rule_register_teid_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add PDR #%u with teid #%u into GTP-U hash table\n",
                    id, rule->teid);
            goto FREE_RULE;
        }
    }
    else {
        print_dbg_ipv4(rule->ue_ipv4);
        printf_dbg(" into GTP-U hash table \n");

        if ((ret = rule_register_ipv4_hash(rule)) < 0) {
            logger(LOG_GTP, L_WARN, "ERROR: cannot add PDR #%u with ", id);
            logger_ipv4(rule->ue_ipv4, L_WARN);
            logger_s(LOG_GTP, L_WARN, " into GTP-U hash table\n");
            goto FREE_RULE;
        }
    }

    return 0;

FREE_RULE:
    rule_match_free(rule);
    return ret;
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

    if (!(rule = rule_action_zmalloc()))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for rule matching\n");

    rule_action_set_id(rule, id);
    rule_action_set_apply_action(rule, RULE_ACTION_APPLY_ACTION_FORW);
    rule_action_set_dst_int(rule, dst_int);

    rule_action_set_outer_hdr_desp(rule, desp);
    rule_action_set_outer_hdr_teid(rule, teid);
    rule_action_set_outer_hdr_ipv4(rule, peer_ipv4);
    rule_action_set_outer_hdr_port(rule, 2152);

    if (rte_hash_add_key_data(action_id_hash, &rule->id, rule)) {
        logger(LOG_GTP, L_WARN,
                    "ERROR: cannot add new key-value <%u, %p> into action_id_hash\n",
                    id, rule);
        goto FREE_RULE;
    }

    return 0;

FREE_RULE:
    rule_action_free(rule);
    return ret;
}