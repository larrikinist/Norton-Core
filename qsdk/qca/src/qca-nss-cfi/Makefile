#
# @brief NSS CFI Makefile
#

export BUILD_ID = \"Build Id: $(shell date +'%m/%d/%y, %H:%M:%S')\"

obj-m += ocf/
obj-m += ipsec/
ifeq ($(findstring 4.4, $(KERNELVERSION)),)
obj-m += cryptoapi/
endif


