/**
 * ether.h
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#ifndef __EHTER_H_
#define __EHTER_H_

#include <rte_common.h>
#include <rte_ether.h>

#define MAX_INTERFACES 10

typedef struct interface_s {
    uint8_t port;
    struct rte_ether_addr hw_addr;
    uint32_t ipv4_addr;
    struct interface_s *next;
} interface_t;

void add_interface(interface_t *iface);
void set_interface_hw(uint8_t port, uint8_t *mac_addr);

#endif /* __EHTER_H_ */
