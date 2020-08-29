#include "arp.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_jhash.h>
#include <rte_arp.h>

#include "helper.h"
#include "pktbuf.h"
#include "ether.h"

/* EXTERN */
extern interface_t *iface_list;
extern interface_t *port_iface_map[MAX_INTERFACES];

/* GLOBALS */
static const char *arp_state_str[] = {"FREE", "PENDING", "RESOLVED", "PERMANENT"};
static struct rte_hash *arp_table = NULL; // [uint32_t ipv4_addr] = (arp_entry_t *arp_entry)

static __rte_always_inline struct rte_hash *arp_table_create(const char *name, uint32_t entries, uint8_t extra_flag);
static __rte_always_inline void arp_table_destroy(struct rte_hash *arp_table);

static __rte_always_inline int arp_send_reply_inplace(struct rte_mbuf *m, uint32_t src_ip_addr, struct rte_arp_hdr *arp_hdr);
static __rte_always_inline int arp_send(struct rte_mbuf *mbuf, uint8_t port);
static __rte_always_inline int arp_add(uint32_t ipv4_addr, struct rte_ether_addr *mac_addr, arp_state_t state);
static __rte_always_inline int arp_update(uint32_t ipv4_addr, struct rte_ether_addr *mac_addr, arp_state_t prev_state, arp_state_t new_state);

int arp_init(int with_locks)
{
    arp_table = arp_table_create("arp_table", MAX_ARP_ENTRIES, with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0);

    if ((intptr_t) arp_table <= 0)
        return -1;

    return 0;
}

int arp_terminate(void)
{
    arp_table_destroy(arp_table);
    logger(LOG_ARP, L_INFO, "ARP table freed.\n");
    return 0;
}

int arp_in(struct rte_mbuf *mbuf)
{
    int ret;

    // Length of ARP frame should be larger than (ethernet frame + arp header)
    if (unlikely(rte_pktmbuf_data_len(mbuf) < (sizeof(struct rte_arp_hdr) + sizeof(struct rte_ether_hdr)))) {
        logger(LOG_ARP, L_INFO, "[ARP Frame] Length of ARP is not enough, drop it\n");
        ret = -1;
        goto PKTMBUF_FREE;
    }

    struct rte_arp_hdr *arp_hdr = (rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, sizeof(struct rte_ether_hdr)));
    struct rte_arp_ipv4 *arp_data = &arp_hdr->arp_data;

    switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
        case ARP_REQ: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Request] Who has ");
            print_ipv4(arp_data->arp_tip, L_DEBUG);
            logger_s(LOG_ARP, L_INFO, "  Tell ");
            print_ipv4(arp_data->arp_sip, L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            arp_add_mac(arp_data->arp_sip, &arp_data->arp_sha, 0);
            arp_print_table(L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            ret = arp_send_reply_inplace(mbuf, arp_data->arp_tip, arp_hdr);

            if (unlikely(ret != 0))
                goto PKTMBUF_FREE;

            break;
        }
        case ARP_REPLY: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Reply] ");
            print_ipv4(arp_data->arp_sip, L_DEBUG);
            logger_s(LOG_ARP, L_INFO, "  is at ");
            print_mac(&arp_data->arp_sha, L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            // Check if dst mac is hosted
            interface_t *iface = iface_list;
            while (iface && !rte_is_same_ether_addr(&arp_data->arp_tha, &iface->hw_addr)) {
                iface = iface->next;
            }

            if (unlikely(iface == NULL)) {
                logger(LOG_ARP, L_INFO, "ARP reply ignored, mac not hosted\n");
                goto PKTMBUF_FREE;
            }

            ret = arp_update(arp_data->arp_sip, &arp_data->arp_sha,
                ARP_STATE_INCOMPLETE, ARP_STATE_REACHABLE);
            
            if (unlikely(ret != 0))
                goto PKTMBUF_FREE;

            arp_print_table(L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");
            rte_pktmbuf_free(mbuf);
            break;
        }
    }

    fflush(stdout);
    return 0;

PKTMBUF_FREE:
    rte_pktmbuf_free(mbuf);
    return -1;
}

static __rte_always_inline struct rte_hash *arp_table_create(const char *name, uint32_t entries, uint8_t extra_flag)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = extra_flag,
    };

    if (rte_hash_find_existing(params.name) != NULL)
        return NULL;

    return rte_hash_create(&params);
}

static __rte_always_inline void arp_table_destroy(struct rte_hash *arp_table) {
    uint32_t *ipv4, iter;
    arp_entry_t *arp_entry;

    while (rte_hash_iterate(arp_table, (void *) &ipv4, (void **)&arp_entry, &iter) >= 0) {
        free(arp_entry);
    }

    rte_hash_free(arp_table);
}

void arp_header_prepend(struct rte_mbuf *mbuf,
        struct rte_ether_addr *src_mac,
        struct rte_ether_addr *dst_mac,
        rte_be32_t src_ip, rte_be32_t dst_ip,
        uint32_t opcode)
{
    struct rte_arp_hdr *arp_req = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_req, src_mac, dst_mac, src_ip, dst_ip, opcode);
}

int arp_send_request(rte_be32_t dst_ip, uint8_t port)
{
    unsigned char dst_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    interface_t *iface = port_iface_map[port];

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_CRITICAL,
            "ARP request failed, port(%d) not in interface list\n",
            port);
        return 0;
    }

    logger_s(LOG_ARP, L_DEBUG, "\n");
    logger(LOG_ARP, L_DEBUG, "<ARP Request> Who has ");
    print_ipv4(dst_ip, L_DEBUG);
    logger_s(LOG_ARP, L_INFO, "  Tell ");
    print_ipv4(iface->ipv4_addr, L_DEBUG);

    struct rte_mbuf *mbuf = get_mbuf();
    if (unlikely(mbuf == NULL))
        return -1;

    struct rte_arp_hdr *arp_req = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_req, &iface->hw_addr, (struct rte_ether_addr *) dst_mac, iface->ipv4_addr, dst_ip, RTE_ARP_OP_REQUEST);

    if (likely(arp_send(mbuf, iface->port) == 0))
        return arp_add(dst_ip, NULL, ARP_STATE_INCOMPLETE);;

    rte_pktmbuf_free(mbuf);
    return -1;
}

static __rte_always_inline int arp_send_reply_inplace(struct rte_mbuf *m,
        uint32_t src_ip, struct rte_arp_hdr *arp_hdr)
{
    interface_t *iface = iface_list;
    while (iface && src_ip != iface->ipv4_addr)
        iface = iface->next;

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address not hosted\n");
        return -1;
    }

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    // Switch src and dst data and set bonding MAC
    rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    rte_ether_addr_copy((struct rte_ether_addr *) &iface->hw_addr, &eth_hdr->s_addr);

    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    struct rte_arp_ipv4 *arp_data = &arp_hdr->arp_data;
    rte_ether_addr_copy(&arp_data->arp_sha, &arp_data->arp_tha);
    rte_ether_addr_copy(&iface->hw_addr, &arp_data->arp_sha);
    arp_data->arp_tip = arp_data->arp_sip;
    arp_data->arp_sip = src_ip;

    logger(LOG_ARP, L_DEBUG, "<ARP Reply> ");
    print_ipv4(src_ip, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "  is at ");
    print_mac(&iface->hw_addr, L_DEBUG);

    // TODO: fix the below, port should be dfrom routing
    logger_s(LOG_ARP, L_DEBUG, " [TX#%d]", iface->port);
    const int queue_id = 0;
    const int ret = rte_eth_tx_burst(iface->port, queue_id, &m, 1);
    if (unlikely(ret != 1)) {
        logger_s(LOG_ARP, L_CRITICAL, " ERR(rte_eth_tx_burst=%d)\n", ret);
        return -1;
    }

    logger_s(LOG_ARP, L_DEBUG, "\n");
    return 0;
}

int arp_send_reply(rte_be32_t src_ip,
        struct rte_ether_addr *dst_mac, rte_be32_t dst_ip)
{
    interface_t *iface = iface_list;
    while (iface && src_ip != iface->ipv4_addr)
        iface = iface->next;

    if (unlikely(iface == NULL)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address not hosted\n");
        return -1;
    }

    struct rte_mbuf *mbuf = get_mbuf();
    if (unlikely(mbuf == NULL))
        return -1;

    struct rte_arp_hdr *arp_reply = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_reply, &iface->hw_addr, dst_mac, src_ip, dst_ip, RTE_ARP_OP_REPLY);

    logger(LOG_ARP, L_DEBUG, "<ARP Reply> ");
    print_ipv4(src_ip, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "  is at ");
    print_mac(&iface->hw_addr, L_DEBUG);

    int ret = arp_send(mbuf, iface->port);
    if (likely(ret == 0))
        return 0;

    rte_pktmbuf_free(mbuf);
    return -1;
}

static __rte_always_inline int arp_send(struct rte_mbuf *mbuf, uint8_t port)
{
    unsigned char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));

    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    if (arp_hdr->arp_opcode == rte_be_to_cpu_16(ARP_REQ)) {
        rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &eth->s_addr);
        rte_ether_addr_copy((struct rte_ether_addr *) dst_mac, &eth->d_addr);
    }
    else if (arp_hdr->arp_opcode == rte_be_to_cpu_16(ARP_REPLY)) {
        rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &eth->s_addr);
        rte_ether_addr_copy(&arp_hdr->arp_data.arp_tha, &eth->d_addr);
    }
    else {
        logger(LOG_ARP, L_CRITICAL, "Invalid opcode %d", arp_hdr->arp_opcode);
        return -1;
    }

    // TODO: fix the below, port should be dfrom routing
    logger_s(LOG_ARP, L_DEBUG, " [TX#%d]", port);
    const int queue_id = 0;
    const int ret = rte_eth_tx_burst(port, queue_id, &mbuf, 1);
    if (unlikely(ret != 1)) {
        logger_s(LOG_ARP, L_CRITICAL, " ERR(rte_eth_tx_burst=%d)\n", ret);
        return -1;
    }

    logger_s(LOG_ARP, L_DEBUG, "\n");
    return 0;
}

int arp_get_mac(rte_be32_t ipv4, struct rte_ether_addr *mac)
{
    arp_entry_t *arp_entry;
    int ret = rte_hash_lookup_data(arp_table, (const void *)&ipv4, (void **)&arp_entry);
    
    // REACHABLE or PERMANENT
    if (likely(ret >= 0 && arp_entry->state >= ARP_STATE_REACHABLE)) {
        rte_ether_addr_copy(&arp_entry->mac_addr, mac);
        return 0;
    }

    return -1;
}

int arp_add_mac(rte_be32_t ipv4, struct rte_ether_addr *mac, int permanent)
{
    logger(LOG_ARP, L_INFO, "Adding to arp table: IP ");
    print_ipv4(ipv4, L_INFO);
    logger_s(LOG_ARP, L_INFO, " MAC ");
    print_mac(mac, L_INFO);
    logger_s(LOG_ARP, L_INFO, "\n");

    return arp_add(ipv4, mac, permanent ? ARP_STATE_PERMANENT : ARP_STATE_REACHABLE);
}

static __rte_always_inline int arp_update(uint32_t ipv4, struct rte_ether_addr *mac,
           arp_state_t prev_state, arp_state_t new_state)
{
    arp_entry_t *arp_entry;

    if (rte_hash_lookup_data(arp_table, (const void *) &ipv4, (void **) &arp_entry) >= 0 &&
            (arp_entry->state == prev_state || prev_state == ARP_STATE_ANY)) {
        rte_ether_addr_copy(mac, &arp_entry->mac_addr);
        arp_entry->state = new_state;

        return 0;
    }

    return -1;
}

static __rte_always_inline int arp_add(uint32_t ipv4, struct rte_ether_addr *mac, arp_state_t state)
{
    arp_entry_t *arp_entry = malloc(sizeof(arp_entry_t));
    arp_entry->state = state;
    arp_entry->ipv4_addr = ipv4;
    if (mac)
        rte_ether_addr_copy(mac, &arp_entry->mac_addr);

    return rte_hash_add_key_data(arp_table, (const void *) &ipv4, (void *) arp_entry);
}

void arp_print_table(TraceLevel trace_level)
{
    uint32_t *ipv4, iter = 0;
    arp_entry_t *arp_entry;

    logger(LOG_ARP, trace_level, "{ARP Table}\n");
    logger(LOG_ARP, trace_level, "There are %d entries in total:", rte_hash_count(arp_table));
    logger_s(LOG_ARP, trace_level, "\n");

    while (rte_hash_iterate(arp_table, (void *)&ipv4, (void **)&arp_entry, &iter) >= 0) {
        logger(LOG_ARP, trace_level, " - IP = ");
        print_ipv4(*ipv4, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");

        logger(LOG_ARP, trace_level, "   MAC = ");
        print_mac(&arp_entry->mac_addr, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");

        logger(LOG_ARP, trace_level, "   STATE = ");
        logger(LOG_ARP, trace_level, "%s", arp_state_str[arp_entry->state]);
        logger_s(LOG_ARP, trace_level, "\n");
    }
}