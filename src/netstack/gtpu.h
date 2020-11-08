#include <stdint.h>
#include <rte_gtp.h>

/* GTP-U Flag */
#define GTP1_F_NONE     0x00
#define GTP1_F_NPDU     0x01
#define GTP1_F_SEQ      0x02
#define GTP1_F_EXTHDR   0x04
#define GTP1_F_MASK     0x07

/* GTP-U Message Type */
#define GTP1_MSG_ECHO_REQ         0x01
#define GTP1_MSG_ECHO_RSP         0x02
#define GTP1_MSG_ERR_INDICATION   0x1A
#define GTP1_MSG_END_MARKER       0xFE
#define GTP1_MSG_TPDU             0xFF

static __rte_always_inline void gtpu_header_set_inplace(struct rte_gtp_hdr *gtp_hdr,
        uint8_t ext_flag, uint8_t type, uint16_t len, uint32_t teid)
{
    /* Bits 8  7  6  5  4  3  2  1
     *    +--+--+--+--+--+--+--+--+
     *    |version |PT| 0| E| S|PN|
     *    +--+--+--+--+--+--+--+--+
     *     0  0  1  1  0  0  0  0
     */
    gtp_hdr->gtp_hdr_info = 0x30 | ext_flag;
    gtp_hdr->msg_type = type;
    gtp_hdr->plen = rte_cpu_to_be_16(len);
    gtp_hdr->teid = rte_cpu_to_be_32(teid);
}