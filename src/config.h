#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <rte_debug.h>
#include <rte_cfgfile.h>
#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash.h>

#include "netstack/arp.h"

/* DEFINES */
#define GTP_CFG_FILE        "gtp_config.ini"
#define GTP_CFG_MAX_KEYLEN  15

#define GTP_CFG_TAG_INTF    "INTF_"
#define GTP_CFG_MAX_PORTS   10

#define GTP_CFG_TAG_TUNNEL  "TUNNEL_"
#define GTP_CFG_MAX_TUNNELS 100

#define GTP_CFG_TAG_ARP     "ARP_"
#define GTP_CFG_MAX_ARPS    100

#define GTP_CFG_TAG_PDR     "PDR_"
#define GTP_CFG_MAX_PDRS    100

#define GTP_CFG_TAG_FAR     "FAR_"
#define GTP_CFG_MAX_FARS    100

#define GTP_MAX_NUMANODE    4
#define GTP_MAX_LCORECOUNT  32
#define GTP_MAX_INTFCOUNT   4

#define CFG_VAL_GTPU        0x01

#define STRCPY(x, y) strcpy((char *)x, (const char *)y)
#define STRCMP(x, y) strcmp((const char *)x, (const char *)y)
#define STRNCMP(x, y, n) strncmp((const char *)x, (const char *)y, n)

int32_t load_config(void);

#endif /*__CONFIG_H__*/
