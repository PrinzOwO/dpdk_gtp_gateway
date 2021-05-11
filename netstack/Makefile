RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/$(RTE_TARGET)/.config
include $(RTE_SDK)/mk/rte.vars.mk

LIB = libnetstack.a
LIBABIVER := 0

CFLAGS += -std=gnu99 -g -O0 $(DEFINE_FLAGS) -I$(RTE_SRCDIR)

SRCS-y += ether.c
SRCS-y += arp.c

SYMLINK-y-include += ../lib/logger.h
SYMLINK-y-include += ../lib/helper.h

include $(RTE_SDK)/mk/rte.extlib.mk
