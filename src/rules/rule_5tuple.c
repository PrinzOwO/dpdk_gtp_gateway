#include "rule_5tuple.h"

void rule_5tuple_set_ports(uint32_t **dst, char *port_list)
{
    if (!port_list)
        return;

    rte_free(*dst);
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

int rule_5tuple_complie(rule_5tuple_t **rule_ptr, const char *rule_str)
{
    if (!strlen(rule_str))
        return 0;

    if (!(*rule_ptr = rule_5tuple_zmalloc()))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot zmalloc far in 5-tuple compile \n");
    rule_5tuple_t *rule = *rule_ptr;

    logger_s(LOG_GTP, L_INFO, "\n \n");
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
        rule_5tuple_set_proto(rule, RULE_5TUPLE_PROTO_IP);
    else {
        int tmp = atoi(buf);
        if (tmp > RULE_5TUPLE_PROTO_IP) {
            logger(LOG_GTP, L_WARN, "SDF filter description protocol not support \n");
            goto err;
        }
        rule_5tuple_set_proto(rule, tmp);
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
        rule_5tuple_set_src_ipv4_mask(rule, smask);
    }
    else
        rule_5tuple_set_src_ipv4_mask(rule, 32);

    // Get SRC IP
    len = pmatch[4].rm_eo - pmatch[4].rm_so - len;
    strncpy(buf, rule_str + pmatch[4].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse SRC IP: %s \n", buf);
    if (strcmp(buf, "any") == 0) {
        rule_5tuple_set_src_ipv4_str(rule, "0.0.0.0");
        rule_5tuple_set_src_ipv4_mask(rule, 0);
    }
    else if (strcmp(buf, "assigned") == 0) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip do NOT support assigned yet \n");
        goto err;
    }
    else if((rule_5tuple_set_src_ipv4_str(rule, buf)) != 1) {
        logger(LOG_GTP, L_WARN, "SDF filter description src ip is invalid \n");
        goto err;
    }

    // Get SRC Port
    len = pmatch[6].rm_eo - pmatch[6].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[6].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse SRC Port: %s \n", buf);
        rule_5tuple_set_src_ports(rule, buf);
    }
    else
        rule_5tuple_set_src_ports(rule, NULL);


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
        rule_5tuple_set_dst_ipv4_mask(rule, dmask);
    }
    else
        rule_5tuple_set_dst_ipv4_mask(rule, 32);

    // Get Dest IP
    len = pmatch[8].rm_eo - pmatch[8].rm_so - len;
    strncpy(buf, rule_str + pmatch[8].rm_so, len); buf[len] = '\0';
    logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Dst IP: %s \n", buf);
    if (strcmp(buf, "any") == 0) {
        rule_5tuple_set_dst_ipv4_str(rule, "0.0.0.0");
        rule_5tuple_set_dst_ipv4_mask(rule, 0);
    }
    else if (strcmp(buf, "assigned") == 0) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip do NOT support assigned yet \n");
        goto err;
    }
    else if((rule_5tuple_set_dst_ipv4_str(rule, buf)) != 1) {
        logger(LOG_GTP, L_WARN, "SDF filter description dest ip is invalid \n");
        goto err;
    }

    // Get Dest Port
    len = pmatch[10].rm_eo - pmatch[10].rm_so;
    if (len) {
        strncpy(buf, rule_str + pmatch[10].rm_so + 1, len - 1); buf[len - 1] = '\0';
        logger(LOG_GTP, L_INFO, "SDF Filter 5-tpule string parse Dst Port: %s \n", buf);
        rule_5tuple_set_dst_ports(rule, buf);
    }
    else
        rule_5tuple_set_dst_ports(rule, NULL);

   return 0;

err:
    rule_5tuple_clean(rule);
    return -EINVAL;
}

#ifdef DEBUG
int rule_5tuple_matching_debug(rule_5tuple_t *rule, struct rte_ipv4_hdr *l3_pkt)
{
    if (!rule)
        return 1;

    printf_dbg(" 5-tuple matching proto: result[%d], rule[%u], pkt[%u]",
            rule_5tuple_is_proto(rule, *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id))),
            rule->proto, *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id)));

    printf_dbg(" 5-tuple matching src IPv4: result[%d], rule IPv4[",
           rule_5tuple_is_src_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr)))));
    print_dbg_ipv4(rule->src_addr);
    printf_dbg("], rule mask[%d],  pkt[", ipv4_subnet_mask_to_num(rule->src_mask));
    print_dbg_ipv4(*((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr))));
    printf_dbg("]");

    printf_dbg(" 5-tuple matching dst IPv4: result[%d], rule IPv4[",
            rule_5tuple_is_dst_ipv4_subnet(rule, *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr)))));
    print_dbg_ipv4(rule->dst_addr);
    printf_dbg("], rule mask[%d],  pkt[", ipv4_subnet_mask_to_num(rule->dst_mask));
    print_dbg_ipv4(*((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr))));
    printf_dbg("]");
    
    return _rule_5tuple_matching(rule, l3_pkt);
}
#endif

int ports_match(uint32_t *port_list, uint16_t port) {
    if (!port_list) {
        printf_dbg(" no limit");
        return 1;
    }

    for (int i = 0; port_list[i]; i++) {
        printf_dbg(" %d. %u <= %u <= %u", i, ((uint16_t *) &port_list[i])[0], port, ((uint16_t *) &port_list[i])[1]);
        if (((uint16_t *) &port_list[i])[0] <= port && ((uint16_t *) &port_list[i])[1] >= port)
            return 1;
    }
    return 0;
}