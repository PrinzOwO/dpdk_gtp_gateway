RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

APP = gtpgw
DEFAULT_CFG_PATH := \"$(PWD)/gtp_config.ini\"


CFLAGS += -D DEFAULT_CFG_PATH="$(DEFAULT_CFG_PATH)"

CFLAGS += -std=gnu99 -g -O0 $(DEFINE_FLAGS) -I$(RTE_SRCDIR)
CFLAGS += $(WERROR_FLAGS)

LIB_DIR := $(RTE_SRCDIR)/../lib
LIB_LIB := $(LIB_DIR)/$(RTE_TARGET)/lib

NETSTACK_DIR := $(RTE_SRCDIR)/../netstack
NETSTACK_LIB := $(NETSTACK_DIR)/$(RTE_TARGET)/lib

RULES_DIR := $(RTE_SRCDIR)/../rules
RULES_LIB := $(RULES_DIR)/$(RTE_TARGET)/lib

SRCS-y := \
	app.c arp_table.c config.c interface.c main.c node.c rule.c stats.c

LIB_NAME := librte_lib.a
MYLIBS     += -lrte_lib
MYLIB_PATH += -L$(LIB_LIB)
LIB_DEP := $(LIB_LIB)/$(LIB_NAME)

NETSTACK_NAME   := libnetstack.a
MYLIBS     += -lnetstack
MYLIB_PATH += -L$(NETSTACK_LIB)
NETSTACK_DEP += $(NETSTACK_LIB)/$(NETSTACK_NAME)

RULES_NAME   := librules.a
MYLIBS     += -lrules
MYLIB_PATH += -L$(RULES_LIB)
RULES_DEP += $(RULES_LIB)/$(RULES_NAME)

gtpgw: $(LIB_DEP) $(NETSTACK_DEP) $(RULES_DEP)

CFLAGS += -I$(LIB_DIR) -I$(NETSTACK_DIR) -I$(RULES_DIR)
LDFLAGS += $(MYLIB_PATH) $(MYLIBS)

include $(RTE_SDK)/mk/rte.extapp.mk
