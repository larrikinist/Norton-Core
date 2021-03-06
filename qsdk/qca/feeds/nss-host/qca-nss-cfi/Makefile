include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-nss-cfi
PKG_SOURCE_PROTO:=git
PKG_BRANCH:=master
PKG_RELEASE:=2

include $(INCLUDE_DIR)/local-development.mk
ifeq ($(DUMP)$(PKG_VERSION),)
  PKG_VERSION:=$(shell git ls-remote $(PKG_SOURCE_URL) $(PKG_BRANCH) | cut -b -7)
endif
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=ocf-crypto-headers

ifeq ($(findstring 4.4, $(LINUX_VERSION)),)
 CRYPTO_API_MODULE:=$(PKG_BUILD_DIR)/cryptoapi/qca-nss-cfi-cryptoapi.ko
endif

define KernelPackage/qca-nss-cfi
  SECTION:=kernel
  CATEGORY:=Kernel modules
  SUBMENU:=Network Devices
  DEPENDS:=@TARGET_ipq806x +kmod-qca-nss-crypto +kmod-crypto-ocf @!LINUX_3_18
  TITLE:=Kernel driver for NSS cfi
  FILES:=$(PKG_BUILD_DIR)/ocf/qca-nss-cfi-ocf.ko \
	 $(PKG_BUILD_DIR)/ipsec/qca-nss-ipsec.ko \
	 $(CRYPTO_API_MODULE)
  AUTOLOAD:=$(call AutoLoad,59,qca-nss-cfi-ocf qca-nss-cfi-cryptoapi qca-nss-ipsec)
endef

define KernelPackage/qca-nss-cfi/Description
This package contains a NSS cfi driver for QCA chipset
endef

EXTRA_CFLAGS+= \
	-DCONFIG_NSS_DEBUG_LEVEL=4 \
	-I$(STAGING_DIR)/usr/include/qca-nss-crypto \
	-I$(STAGING_DIR)/usr/include/crypto \
	-I$(STAGING_DIR)/usr/include/qca-nss-drv \

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		CC="$(TARGET_CC)" \
		modules
endef

$(eval $(call KernelPackage,qca-nss-cfi))
