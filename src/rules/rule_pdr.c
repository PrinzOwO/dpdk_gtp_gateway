#include "rule_pdr.h"

#include "logger.h"

static const char *remove_hdr_str[] = {"GTP-U/UDP/IPv4", "GTP-U/UDP/IPv6", "UDP/IPv4", "UDP/IPv6"};
void logger_remove_hdr(uint8_t remove_hdr, TraceLevel trace_level)
{
    remove_hdr >>= 4;
    for (int i = 0; remove_hdr; remove_hdr >>= 1, i++) {
        if (remove_hdr & 1) {
            logger_s(LOG_GTP, trace_level, "%s", remove_hdr_str[i]);
            return;
        }
    }
    logger_s(LOG_GTP, trace_level, "Invalid");
}
