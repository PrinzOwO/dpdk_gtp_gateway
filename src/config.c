#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_jhash.h>

#include "helper.h"
#include "ether.h"
#include "interface.h"
#include "arp_table.h"
#include "app.h"
#include "rule.h"


static int load_global_entries(struct rte_cfgfile *file)
{
    const char *section_name = "Global";

    int32_t j = 0, ret = -1;
    struct rte_cfgfile_entry entries[32];

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);

    for (j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        switch (strlen(entries[j].name)) {
            case 10:
                if (STRCMP("disp_stats", entries[j].name) == 0) {
                    app_set_disp_stats(STRCMP("1", entries[j].value) == 0);
                }
                break;

            default:
                printf("\n ERROR: unexpected entry %s with value %s\n",
                        entries[j].name, entries[j].value);
                fflush(stdout);
                return -1;
        } /* update per entry */
    } /* iterate entries */

    return 0;
}

static int load_interface_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t port_num, ret = -1;
    struct rte_cfgfile_entry entries[32];

    rte_be32_t ipv4 = 0;
    uint8_t type = 0;

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    port_num = str_to_int(section_name + strlen(GTP_CFG_TAG_INTF));

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("ipv4", entries[j].name) == 0) {
            inet_pton(AF_INET, entries[j].value, &ipv4);
        }
        else if (STRCMP("type", entries[j].name) == 0) {
            if (STRCMP("GTPU", entries[j].value) == 0)
                type = INTERFACE_TYPE_GTPU;
            else if (STRCMP("N6", entries[j].value) == 0)
                type = INTERFACE_TYPE_N6;
            else if (STRCMP("N3", entries[j].value) == 0)
                type = INTERFACE_TYPE_N3;
            else if (STRCMP("N9", entries[j].value) == 0)
                type = INTERFACE_TYPE_N3;
            else {
                printf("\n ERROR: unexpected interface type with value %s\n", entries[j].value);
                fflush(stdout);
                return -1;
            }
        }
        else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                    entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    return interface_add(port_num, ipv4, type);
}

static int load_tunnel_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t ret = -1;
    struct rte_cfgfile_entry entries[32];
    
    uint16_t id;
    rte_be32_t teid_in = 0, teid_out = 0, ue_ipv4 = 0, peer_ipv4 = 0;

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    id = str_to_int(section_name + strlen(GTP_CFG_TAG_TUNNEL));

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("teid_in", entries[j].name) == 0) {
            teid_in = atoi(entries[j].value);
        } else if (STRCMP("teid_out", entries[j].name) == 0) {
            teid_out = atoi(entries[j].value);
        } else if (STRCMP("ue_ipv4", entries[j].name) == 0) {
            inet_pton(AF_INET, entries[j].value, &ue_ipv4);
        } else if (STRCMP("ran_ipv4", entries[j].name) == 0) {
            inet_pton(AF_INET, entries[j].value, &peer_ipv4);
        } else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    uint8_t uplink_id = id * 2 + 1;
    // Uplink FAR with no extra outer header creation, so set the third param as unspec and don't care the forth and fifth
    ret = rule_action_create_by_config(uplink_id, RULE_ACTION_DST_INT_ACCESS, RULE_ACTION_OUTER_HDR_DESP_UNSPEC, 0, 0);
    if (ret) {
        printf("\n ERROR: cannot add uplink rule action %u\n", id);
        fflush(stdout);
        return -1;
    }

    // Uplink PDR matches with TEID and UE IP
    ret = rule_match_create_by_config(uplink_id, RULE_MATCH_REMOVE_HDR_GTPU_IPV4, teid_in, 0, uplink_id);
    if (ret) {
        printf("\n ERROR: cannot add uplink rule match %u\n", id);
        fflush(stdout);
        return -1;
    }

    uint8_t downlink_id = id * 2 + 2;
    // Downlink FAR with outer header creation
    ret = rule_action_create_by_config(downlink_id, RULE_ACTION_DST_INT_CORE, RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4, teid_out, peer_ipv4);
    if (ret) {
        printf("\n ERROR: cannot add downlink rule action %u\n", id);
        fflush(stdout);
        return -1;
    }

    // Downlink PDR matched with UE IP
    ret = rule_match_create_by_config(downlink_id, RULE_MATCH_REMOVE_HDR_NO_REMOVE, 0, ue_ipv4, downlink_id);
    if (ret) {
        printf("\n ERROR: cannot add downlink rule match %u\n", id);
        fflush(stdout);
        return -1;
    }

    return 0;
}

static int load_pdr_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t ret = -1;
    struct rte_cfgfile_entry entries[32];

    rule_match_t *rule = rule_match_zmalloc();
    if (!rule)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot zmalloc rule_match_t in load_pdr_entries \n");
    
    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    rule_match_set_id(rule, str_to_int(section_name + strlen(GTP_CFG_TAG_PDR)));

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("precedence", entries[j].name) == 0) {
            rule_match_set_precedence(rule, atoi(entries[j].value));
        }
        else if (STRCMP("far_id", entries[j].name) == 0) {
            rule_match_set_action_id(rule, atoi(entries[j].value));
        }
        else if (STRCMP("outer_hdr_rm", entries[j].name) == 0) {
            rule_match_set_remove_hdr(rule, atoi(entries[j].value));
        }
        else if (STRCMP("ue_ipv4", entries[j].name) == 0) {
            rule_match_set_ue_ipv4_str(rule, entries[j].value);
        }
        else if (STRCMP("local_ipv4", entries[j].name) == 0) {
            rule_match_set_upf_ipv4_str(rule, entries[j].value);
        }
        else if (STRCMP("teid_in", entries[j].name) == 0) {
            rule_match_set_teid(rule, atoi(entries[j].value));
        }
        else if (STRCMP("sdf_filter", entries[j].name) == 0) {
            // TODO:
        }
        else {
            printf("\n ERROR: unexpected entry %s with value %s \n",
                entries[j].name, entries[j].value);
            fflush(stdout);
            ret = -EINVAL;
            goto FREE_RULE;
        }
    } /* iterate entries */

    if ((ret = rule_match_register(rule))) {
        printf("\n ERROR: cannot register PDR #%u \n",
                rule->id);
        fflush(stdout);
        goto FREE_RULE;
    }

    return 0;

FREE_RULE:
    rule_match_free(rule);
    return ret;
}

static int load_far_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t ret = -1;
    struct rte_cfgfile_entry entries[32];

    rule_action_t *rule = rule_action_zmalloc();
    if (!rule)
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot zmalloc rule_action in load_far_entries \n");
    
    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    rule_action_set_id(rule, str_to_int(section_name + strlen(GTP_CFG_TAG_FAR)));

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);
        if (STRCMP("action", entries[j].name) == 0) {
            rule_action_set_apply_action(rule, atoi(entries[j].value));
        }
        else if (STRCMP("dst_int", entries[j].name) == 0) {
            rule_action_set_dst_int(rule, atoi(entries[j].value));
        }
        else if (STRCMP("outer_hdr_ipv4", entries[j].name) == 0) {
            rule_action_set_outer_hdr_desp(rule, RULE_ACTION_OUTER_HDR_DESP_GTPU_IPV4);
            rule_action_set_outer_hdr_ipv4_str(rule, entries[j].value);
            rule_action_set_outer_hdr_port(rule, 2152);
        }
        else if (STRCMP("outer_hdr_teid", entries[j].name) == 0) {
            rule_action_set_outer_hdr_teid(rule, atoi(entries[j].value));
        }
        else {
            printf("\n ERROR: unexpected entry %s with value %s \n",
                entries[j].name, entries[j].value);
            fflush(stdout);
            ret = -EINVAL;
            goto FREE_RULE;
        }
    } /* iterate entries */

    if ((ret = rule_action_register(rule))) {
        printf("\n ERROR: cannot register FAR #%u \n",
                rule->id);
        fflush(stdout);
        goto FREE_RULE;
    }

    return 0;

FREE_RULE:
    rule_action_free(rule);
    return ret;
}

static int load_arp_entries(struct rte_cfgfile *file, const char *section_name)
{
    int32_t ret = -1;
    struct rte_cfgfile_entry entries[32];

    rte_be32_t ipv4 = 0;
    struct rte_ether_addr mac = {0};

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("ipv4", entries[j].name) == 0) {
            if (inet_pton(AF_INET, entries[j].value, &ipv4) != 1)
                rte_exit(EXIT_FAILURE, "\n ERROR: cannot translate ipv4 '%s' in config\n", entries[j].value);

            if (!ipv4)
                rte_exit(EXIT_FAILURE, "\n ERROR: cannot add static arp with zero ipv4\n");
        }
        else if (STRCMP("mac", entries[j].name) == 0) {
            if (ether_unformat_addr(entries[j].value, &mac) < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: cannot translate mac address '%s' in config\n", entries[j].value);
            
            if (rte_is_zero_ether_addr(&mac))
                rte_exit(EXIT_FAILURE, "\n ERROR: cannot add static arp with zero mac\n");
        }
        else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    return arp_add_mac(ipv4, &mac, ARP_STATE_PERMANENT);
}

int32_t load_config(void)
{
    struct rte_cfgfile *file = NULL;
    int32_t ret;
    char **section_names = NULL;

    file = rte_cfgfile_load(GTP_CFG_FILE, 0);
    if (file == NULL)
        rte_exit(EXIT_FAILURE, "\n Cannot load configuration profile %s\n", GTP_CFG_FILE);

    printf("\n Loading config entries:");

    int32_t intf_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_INTF, strlen(GTP_CFG_TAG_INTF));
    int32_t tunnel_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_TUNNEL, strlen(GTP_CFG_TAG_TUNNEL));
    int32_t pdr_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_PDR, strlen(GTP_CFG_TAG_PDR));
    int32_t far_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_FAR, strlen(GTP_CFG_TAG_FAR));
    int32_t arp_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_ARP, strlen(GTP_CFG_TAG_ARP));

    const int32_t section_count = 1 + intf_count + tunnel_count + pdr_count + far_count + arp_count; // "Global" + ...
    section_names = rte_malloc("Section entry name", section_count * sizeof(char *), 0);
    for (int i = 0; i < section_count; i++)
        section_names[i] = rte_malloc("Section name", GTP_CFG_MAX_KEYLEN + 1, 0);

    rte_cfgfile_sections(file, section_names, section_count);

    for (int i = 0; i < section_count; i++) {
        printf("\n\n              [%s]", section_names[i]);
        printf("\n --------------------------------");

        if (STRCMP("Global", section_names[i]) == 0) {
            ret = load_global_entries(file);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load global entries in load_config\n");
        }
        else if (STRNCMP(GTP_CFG_TAG_INTF, section_names[i], strlen(GTP_CFG_TAG_INTF)) == 0) {
            ret = load_interface_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load interface entries in load_config\n");
        }
        else if (STRNCMP(GTP_CFG_TAG_TUNNEL, section_names[i], strlen(GTP_CFG_TAG_TUNNEL)) == 0) {
            ret = load_tunnel_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load tunnel entries in load_config\n");
        }
        else if (STRNCMP(GTP_CFG_TAG_PDR, section_names[i], strlen(GTP_CFG_TAG_PDR)) == 0) {
            ret = load_pdr_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load PDR entries in load_config\n");
        }
        else if (STRNCMP(GTP_CFG_TAG_FAR, section_names[i], strlen(GTP_CFG_TAG_FAR)) == 0) {
            ret = load_far_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load FAR entries in load_config\n");
        }
        else if (STRNCMP(GTP_CFG_TAG_ARP, section_names[i], strlen(GTP_CFG_TAG_ARP)) == 0) {
            ret = load_arp_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load ARP entries in load_config\n");
        }
    } /* per section */

    ret = rte_cfgfile_close(file);
    if (ret != 0)
        rte_exit(EXIT_FAILURE, "\n Cannot close configuration profile %s\n", GTP_CFG_FILE);

    printf("\n\n");
    fflush(stdout);
    return 0;
}
