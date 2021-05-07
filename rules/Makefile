RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/$(RTE_TARGET)/.config
include $(RTE_SDK)/mk/rte.vars.mk

LIB = librules.a
LIBABIVER := 0

CFLAGS += -std=gnu99 -g -O0 $(DEFINE_FLAGS) -I$(RTE_SRCDIR)

SRCS-y += rule_pdr.c
SRCS-y += rule_far.c
SRCS-y += rule_5tuple.c

SYMLINK-y-include += ../lib/logger.h
SYMLINK-y-include += ../netstack/ip.h

include $(RTE_SDK)/mk/rte.extlib.mk
