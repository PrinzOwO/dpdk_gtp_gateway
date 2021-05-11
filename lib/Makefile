include $(RTE_SDK)/$(RTE_TARGET)/.config
include $(RTE_SDK)/mk/rte.vars.mk

LIB = librte_lib.a
LIBABIVER := 0

CFLAGS += -std=gnu99 -g -O0 $(DEFINE_FLAGS) -I$(RTE_SRCDIR)

SRCS-y := logger.c pktbuf.c

include $(RTE_SDK)/mk/rte.extlib.mk
