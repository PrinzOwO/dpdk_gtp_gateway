#include "rule_far.h"

#include "logger.h"

static const char *apply_action_str[] = {"INVALID", "DROP", "FORW", "BUFF", "NOCP", "DUPL"};
void logger_apply_action(uint8_t apply_action, TraceLevel trace_level)
{
    if (unlikely(!apply_action)) {
        logger_s(LOG_GTP, trace_level, " %s", apply_action_str[0]);
        return;
    }

    for (int i = 1; apply_action && i <= 5; apply_action >>= 1, i++)
        if (apply_action & 1)
            logger_s(LOG_GTP, trace_level, " %s", apply_action_str[i]);
}

static const char *dst_int_str[] = {"Access (Downlink)", "Core (Uplink)", "SGi-LAN/N6-LAN", "CP- Function", "LI Function"};
void logger_dst_int(uint8_t dst_int, TraceLevel trace_level)
{
    if (unlikely(dst_int > 4)) {
        logger_s(LOG_GTP, trace_level, "Invalid");
        return;
    }
    logger_s(LOG_GTP, trace_level, "%s", dst_int_str[dst_int]);
}