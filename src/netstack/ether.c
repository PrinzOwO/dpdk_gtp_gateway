/**
 * ether.c
 *  ref: https://github.com/rajneshrat/dpdk-tcpipstack
 */
#include "ether.h"

#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_malloc.h>

#include "arp.h"

interface_t *iface_list = NULL;
interface_t *port_iface_map[MAX_INTERFACES] = {0};

void add_interface(interface_t *iface)
{
    interface_t *ptr = rte_malloc("interface", sizeof(interface_t), 0);

    memcpy(ptr, iface, sizeof(interface_t));
    ptr->next = NULL;

    if (iface_list == NULL) {
        iface_list = ptr;
    } else {
        iface_list->next = ptr;
    }

    if (ptr->port + 1 < MAX_INTERFACES) {
        port_iface_map[ptr->port] = ptr;
    } else {
        printf("ERROR :: interface number more than max\n");
    }

    arp_add_mac(ptr->ipv4_addr, &ptr->hw_addr, 1);
}
