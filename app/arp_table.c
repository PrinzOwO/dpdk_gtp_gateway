#include "arp_table.h"

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ethdev.h>

#include "pktbuf.h"
#include "param.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

static const char *arp_state_str[] = {"FREE", "PENDING", "RESOLVED", "PERMANENT"};
static struct rte_hash *arp_table = NULL; // [rte_be32_t ipv4_addr] = (arp_entry_t *arp_entry)

static __rte_always_inline struct rte_hash *arp_table_create(const char *name, uint32_t entries, uint8_t extra_flag);
static __rte_always_inline void arp_table_destroy(struct rte_hash *arp_table);

static __rte_always_inline int arp_send_reply_inplace(struct rte_mbuf *m, interface_t *interface, uint32_t src_ip_addr, struct rte_arp_hdr *arp_hdr);
static __rte_always_inline int arp_send(struct rte_mbuf *mbuf, uint8_t port);
static __rte_always_inline int arp_add(uint32_t ipv4_addr, struct rte_ether_addr *mac_addr, arp_state_t state);
static __rte_always_inline int arp_update(uint32_t ipv4_addr, struct rte_ether_addr *mac_addr, arp_state_t prev_state, arp_state_t new_state);

int arp_init(int with_locks)
{
    arp_table = arp_table_create("arp_table", MAX_NUM_OF_ARP_ENTRIES, with_locks ?
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY : 0);

    if (!arp_table)
        return -1;

    return 0;
}

int arp_terminate(void)
{
    arp_table_destroy(arp_table);
    logger(LOG_ARP, L_INFO, "ARP table freed.\n");
    return 0;
}

int arp_in(struct rte_mbuf *mbuf, interface_t *interface)
{
    int ret;

    // Length of ARP frame should be larger than (ethernet frame + arp header)
    if (unlikely(rte_pktmbuf_data_len(mbuf) < (sizeof(struct rte_arp_hdr) + RTE_ETHER_HDR_LEN))) {
        logger(LOG_ARP, L_INFO, "[ARP Frame] Length of ARP is not enough, drop it\n");
        ret = -1;
        goto PKTMBUF_FREE;
    }

    struct rte_arp_hdr *arp_hdr = (rte_pktmbuf_mtod_offset(mbuf, struct rte_arp_hdr *, RTE_ETHER_HDR_LEN));
    struct rte_arp_ipv4 *arp_data = &arp_hdr->arp_data;

    switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
        case ARP_REQ: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Request] Who has ");
            logger_ipv4(arp_data->arp_tip, L_DEBUG);
            logger_s(LOG_ARP, L_INFO, "  Tell ");
            logger_ipv4(arp_data->arp_sip, L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            arp_add_mac(arp_data->arp_sip, &arp_data->arp_sha, 0);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            ret = arp_send_reply_inplace(mbuf, interface, arp_data->arp_tip, arp_hdr);

            if (unlikely(ret != 0))
                goto PKTMBUF_FREE;

            break;
        }
        case ARP_REPLY: {
            logger_s(LOG_ARP, L_INFO, "\n");
            logger(LOG_ARP, L_INFO, "[ARP Reply] ");
            logger_ipv4(arp_data->arp_sip, L_DEBUG);
            logger_s(LOG_ARP, L_INFO, "  is at ");
            logger_mac(&arp_data->arp_sha, L_DEBUG);
            logger_s(LOG_ARP, L_DEBUG, "\n");

            // Check if dst mac is hosted
            interface_t *iface = NULL;

            if (unlikely(interface_find_by_mac(&arp_data->arp_tha, &iface) < 0)) {
                logger(LOG_ARP, L_INFO, "ARP reply ignored, mac not hosted\n");
                goto PKTMBUF_FREE;
            }

            ret = arp_update(arp_data->arp_sip, &arp_data->arp_sha,
                ARP_STATE_INCOMPLETE, ARP_STATE_REACHABLE);
            
            if (unlikely(ret != 0))
                goto PKTMBUF_FREE;

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
        .key_len = sizeof(rte_be32_t),
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

int arp_send_request(rte_be32_t dst_ip, uint8_t port)
{
    unsigned char dst_mac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    interface_t *iface = NULL;

    if (unlikely(interface_find_by_id(&port, &iface) < 0)) {
        logger(LOG_ARP, L_CRITICAL,
            "ARP request failed, port(%d) not in interface list\n",
            port);
        return 0;
    }

    logger_s(LOG_ARP, L_DEBUG, "\n");
    logger(LOG_ARP, L_DEBUG, "<ARP Request> Who has ");
    logger_ipv4(dst_ip, L_DEBUG);
    logger_s(LOG_ARP, L_INFO, "  Tell ");
    logger_ipv4(iface->ipv4, L_DEBUG);

    struct rte_mbuf *mbuf = get_mbuf();
    if (unlikely(mbuf == NULL))
        return -1;

    struct rte_arp_hdr *arp_req = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_req, &iface->mac, (struct rte_ether_addr *) dst_mac, iface->ipv4, dst_ip, RTE_ARP_OP_REQUEST);

    if (likely(arp_send(mbuf, iface->id) == 0))
        return arp_add(dst_ip, NULL, ARP_STATE_INCOMPLETE);;

    rte_pktmbuf_free(mbuf);
    return -1;
}

static __rte_always_inline int arp_send_reply_inplace(struct rte_mbuf *m,
        interface_t *src_int, rte_be32_t src_ip, struct rte_arp_hdr *arp_hdr)
{
    interface_t *iface = NULL;

    if (unlikely(interface_find_by_ipv4(&src_ip, &iface) < 0)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address ");
        logger_ipv4(src_ip, L_INFO);
        logger_s(LOG_ARP, L_INFO, " not hosted\n");
        return -1;
    }

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    // Switch src and dst data and set bonding MAC
    rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    rte_ether_addr_copy((struct rte_ether_addr *) &iface->mac, &eth_hdr->s_addr);

    arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    struct rte_arp_ipv4 *arp_data = &arp_hdr->arp_data;
    rte_ether_addr_copy(&arp_data->arp_sha, &arp_data->arp_tha);
    rte_ether_addr_copy(&iface->mac, &arp_data->arp_sha);
    arp_data->arp_tip = arp_data->arp_sip;
    arp_data->arp_sip = src_ip;

    logger(LOG_ARP, L_DEBUG, "<ARP Reply> ");
    logger_ipv4(src_ip, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "  is at ");
    logger_mac(&iface->mac, L_DEBUG);

    // TODO: fix the below, port should be dfrom routing
    logger_s(LOG_ARP, L_DEBUG, " [TX#%d]", iface->id);
    const int queue_id = 0;
    const int ret = rte_eth_tx_burst(src_int->id, queue_id, &m, 1);
    if (unlikely(ret != 1)) {
        logger_s(LOG_ARP, L_CRITICAL, " ERR(rte_eth_tx_burst=%d)\n", ret);
        return -1;
    }

    logger_s(LOG_ARP, L_DEBUG, "\n");
    return 0;
}

int arp_send_reply(rte_be32_t src_ip,
        interface_t *src_int, struct rte_ether_addr *dst_mac, rte_be32_t dst_ip)
{
    interface_t *iface = NULL;

    if (unlikely(interface_find_by_ipv4(&src_ip, &iface) < 0)) {
        logger(LOG_ARP, L_INFO, "ARP request failed, address not hosted\n");
        return -1;
    }

    struct rte_mbuf *mbuf = get_mbuf();
    if (unlikely(mbuf == NULL))
        return -1;

    struct rte_arp_hdr *arp_reply = (struct rte_arp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_arp_hdr));
    arp_header_set_inplace(arp_reply, &iface->mac, dst_mac, src_ip, dst_ip, RTE_ARP_OP_REPLY);

    logger(LOG_ARP, L_DEBUG, "<ARP Reply> ");
    logger_ipv4(src_ip, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "  is at ");
    logger_mac(&iface->mac, L_DEBUG);

    int ret = arp_send(mbuf, src_int->id);
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
        (struct rte_ether_hdr *) rte_pktmbuf_prepend(mbuf, RTE_ETHER_HDR_LEN);

    if (arp_hdr->arp_opcode == rte_be_to_cpu_16(ARP_REQ)) {
        ethernet_header_set_inplace(eth,
            &arp_hdr->arp_data.arp_sha, (struct rte_ether_addr *) dst_mac,
            RTE_ETHER_TYPE_ARP);
    }
    else if (arp_hdr->arp_opcode == rte_be_to_cpu_16(ARP_REPLY)) {
        ethernet_header_set_inplace(eth,
            &arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha,
            RTE_ETHER_TYPE_ARP);
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
    logger_s(LOG_ARP, L_DEBUG, "\n");

    logger(LOG_ARP, L_DEBUG, "Adding to arp table: IP ");
    logger_ipv4(ipv4, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, " MAC ");
    logger_mac(mac, L_DEBUG);
    logger_s(LOG_ARP, L_DEBUG, "\n");

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

static __rte_always_inline int arp_add(rte_be32_t ipv4, struct rte_ether_addr *mac, arp_state_t state)
{
    arp_entry_t *arp_entry = NULL;
    
    if (!(arp_entry = rte_malloc("arp entry", sizeof(arp_entry_t), 0)))
        rte_exit(EXIT_FAILURE, "\n ERROR: cannot alloc memory for arp entry\n");

    arp_entry->state = state;
    arp_entry->ipv4_addr = ipv4;
    if (mac)
        rte_ether_addr_copy(mac, &arp_entry->mac_addr);

    return rte_hash_add_key_data(arp_table, &arp_entry->ipv4_addr, arp_entry);
}

void arp_dump_table(TraceLevel trace_level)
{
    uint32_t *ipv4, iter = 0;
    arp_entry_t *arp_entry;

    logger(LOG_ARP, trace_level, "[ARP Table]\n");
    logger(LOG_ARP, trace_level, "There are %d entries in total:", rte_hash_count(arp_table));
    logger_s(LOG_ARP, trace_level, "\n");

    while (rte_hash_iterate(arp_table, (void *)&ipv4, (void **)&arp_entry, &iter) >= 0) {
        logger_s(LOG_ARP, trace_level, " - IP = ");
        logger_ipv4(*ipv4, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");

        logger_s(LOG_ARP, trace_level, "   MAC = ");
        logger_mac(&arp_entry->mac_addr, trace_level);
        logger_s(LOG_ARP, trace_level, "\n");

        logger_s(LOG_ARP, trace_level, "   STATE = ");
        logger_s(LOG_ARP, trace_level, "%s", arp_state_str[arp_entry->state]);
        logger_s(LOG_ARP, trace_level, "\n");
    }
}