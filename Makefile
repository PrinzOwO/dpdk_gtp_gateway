# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

DIRS-y += lib app netstack rules

DEPDIRS-app += lib netstack rules

.PHONY: clean

include $(RTE_SDK)/mk/rte.extsubdir.mk

clean:
	@rm -rf lib/build lib/$(RTE_TARGET)
	@rm -rf netstack/build netstack/$(RTE_TARGET)
	@rm -rf rules/build rules/$(RTE_TARGET)
	@rm -rf app/build app/$(RTE_TARGET)