#ifndef __DPDK_GTP_GW_RULE_5TUPLE_H__
#define __DPDK_GTP_GW_RULE_5TUPLE_H__

#include <stdint.h>
#include <string.h>
#include <regex.h>
#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "logger.h"
#include "ip.h"

typedef struct rule_5tuple_s {
    uint8_t             proto;
    rte_be32_t          src_addr;
    rte_be32_t          src_mask;
    rte_be32_t          dst_addr;
    rte_be32_t          dst_mask;
    uint32_t            *src_port_range;
    uint32_t            *dst_port_range;
} rule_5tuple_t;

#define rule_5tuple_zmalloc() rte_zmalloc("rule 5-tuple", sizeof(rule_5tuple_t), 0)

#define rule_5tuple_clean(rule) \
    rte_free((rule)->src_port_range); \
    rte_free((rule)->dst_port_range)

#define rule_5tuple_free(rule) \
    rule_5tuple_clean(rule); \
    rte_free(rule)

// Set function and parameter as below
#define rule_5tuple_set_proto(rule, proto_num) \
    (rule)->proto = proto_num

#define rule_5tuple_set_src_ipv4(rule, cpu_type_ipv4) \
    (rule)->src_addr = rte_cpu_to_be_32(cpu_type_ipv4)
#define rule_5tuple_set_src_ipv4_str(rule, str_type_ipv4) \
    inet_pton(AF_INET, (str_type_ipv4), &(rule)->src_addr)

#define rule_5tuple_set_src_ipv4_mask(rule, num_type_mask) \
    (rule)->src_mask = ipv4_subnet_num_to_mask(num_type_mask)

#define rule_5tuple_set_dst_ipv4(rule, cpu_type_ipv4) \
    (rule)->dst_addr = rte_cpu_to_be_32(cpu_type_ipv4)
#define rule_5tuple_set_dst_ipv4_str(rule, str_type_ipv4) \
    inet_pton(AF_INET, (str_type_ipv4), &(rule)->dst_addr)

#define rule_5tuple_set_dst_ipv4_mask(rule, num_type_mask) \
    (rule)->dst_mask = ipv4_subnet_num_to_mask(num_type_mask)

void rule_5tuple_set_ports(uint32_t **dst, char *port_list);

#define rule_5tuple_set_src_ports(rule, str_type_src_ports) \
    rule_5tuple_set_ports(&(rule)->src_port_range, str_type_src_ports)

#define rule_5tuple_set_dst_ports(rule, str_type_dst_ports) \
    rule_5tuple_set_ports(&(rule)->dst_port_range, str_type_dst_ports)

int rule_5tuple_complie(rule_5tuple_t **rule_ptr, const char *rule_str);

// Matching function and parameter as below
#define RULE_5TUPLE_PROTO_IP 0xff

#define rule_5tuple_is_proto(rule, proto_num) \
    ((rule)->proto == RULE_5TUPLE_PROTO_IP || (rule)->proto == proto_num)

#define rule_5tuple_is_src_ipv4_subnet(rule, be_type_ipv4_addr) \
    in_ipv4_subnet(be_type_ipv4_addr, (rule)->src_addr, (rule)->src_mask)

#define rule_5tuple_is_dst_ipv4_subnet(rule, be_type_ipv4_addr) \
    in_ipv4_subnet(be_type_ipv4_addr, (rule)->dst_addr, (rule)->dst_mask)

int ports_match(uint32_t *port_list, uint16_t port);

#define rule_5tuple_is_src_ports(rule, be_type_port) \
    ports_match((rule)->src_port_range, rte_be_to_cpu_16(be_type_port))

#define rule_5tuple_is_dst_ports(rule, be_type_port) \
    ports_match((rule)->dst_port_range, rte_be_to_cpu_16(be_type_port))

#define _rule_5tuple_matching(rule, l3_pkt) \
    ( \
        !rule || \
        ( \
            rule_5tuple_is_proto((rule), *((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, next_proto_id))) && \
            rule_5tuple_is_src_ipv4_subnet((rule), *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, src_addr)))) && \
            rule_5tuple_is_dst_ipv4_subnet((rule), *((uint32_t *) ((uint8_t *) l3_pkt + offsetof(struct rte_ipv4_hdr, dst_addr)))) && \
            rule_5tuple_is_src_ports((rule), *((uint16_t *) ((uint8_t *) l3_pkt + sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_udp_hdr, src_port)))) && \
            rule_5tuple_is_dst_ports((rule), *((uint16_t *) ((uint8_t *) l3_pkt + sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_udp_hdr, dst_port)))) \
        ) \
    )

#ifndef DEBUG
#define rule_5tuple_matching(rule, l3_pkt) _rule_5tuple_matching(rule, l3_pkt)
#else
int rule_5tuple_matching_debug(rule_5tuple_t *rule, struct rte_ipv4_hdr *l3_pkt);
#define rule_5tuple_matching(rule, l3_pkt) rule_5tuple_matching_debug(rule, l3_pkt)
#endif

#endif /* __DPDK_GTP_GW_RULE_5TUPLE_H__ */