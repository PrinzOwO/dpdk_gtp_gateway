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
    uint8_t gtp_type = 0;

    ret = rte_cfgfile_section_entries(file, section_name, entries, 32);
    port_num = str_to_int(section_name + strlen(GTP_CFG_TAG_INTF));

    for (int j = 0; j < ret; j++) {
        printf("\n %15s : %-15s", entries[j].name, entries[j].value);

        if (STRCMP("ipv4", entries[j].name) == 0) {
            inet_pton(AF_INET, entries[j].value, &ipv4);
        } else if (STRCMP("type", entries[j].name) == 0) {
            gtp_type = (STRCMP("GTPU", entries[j].value) == 0) ? CFG_VAL_GTPU : 0xff;
        // } else if (STRCMP("index", entries[j].name) == 0) {
        //     app_config.gtp_ports[intf_idx].pkt_index = atoi(entries[j].value);
        } else {
            printf("\n ERROR: unexpected entry %s with value %s\n",
                    entries[j].name, entries[j].value);
            fflush(stdout);
            return -1;
        }
    } /* iterate entries */

    return ether_add_interface(port_num, ipv4, gtp_type);
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
            teid_in = rte_cpu_to_be_32(atoi(entries[j].value));
        } else if (STRCMP("teid_out", entries[j].name) == 0) {
            teid_out = rte_cpu_to_be_32(atoi(entries[j].value));
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

    ret = rule_action_set_temprary(id, peer_ipv4, teid_out, rte_cpu_to_be_32(2152));
    if (ret) {
        printf("\n ERROR: cannot add rule action %u\n", id);
        fflush(stdout);
        return -1;
    }

    ret = rule_match_set_temprary(id, teid_in, ue_ipv4, id);
    if (ret) {
        printf("\n ERROR: cannot add rule match %u\n", id);
        fflush(stdout);
        return -1;
    }

    return 0;
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
    int32_t arp_count = rte_cfgfile_num_sections(file, GTP_CFG_TAG_ARP, strlen(GTP_CFG_TAG_ARP));

    const int32_t section_count = 1 + intf_count + tunnel_count + arp_count; // "Global" + ...
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
        } else if (STRNCMP(GTP_CFG_TAG_INTF, section_names[i], strlen(GTP_CFG_TAG_INTF)) == 0) {
            ret = load_interface_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load interface entries in load_config\n");
        } else if (STRNCMP(GTP_CFG_TAG_TUNNEL, section_names[i], strlen(GTP_CFG_TAG_TUNNEL)) == 0) {
            ret = load_tunnel_entries(file, section_names[i]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "\n ERROR: load tunnel entries in load_config\n");
        } else if (STRNCMP(GTP_CFG_TAG_ARP, section_names[i], strlen(GTP_CFG_TAG_ARP)) == 0) {
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
