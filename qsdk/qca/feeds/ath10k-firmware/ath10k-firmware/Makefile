include $(TOPDIR)/rules.mk

PKG_NAME:=ath10k-firmware
PKG_FW_VERSION:=10.2.4-1.0-00017
PKG_SW_FW_VERSION:=10.2.4-1.0-00017
PKG_BL_FW_VERSION:=10.4.3.00063-1
PKG_DK_FW_VERSION:=10.4-3.3-00092
PKG_BES_FW_VERSION:=10.4-3.3-00092
PKG_CAS_FW_VERSION:=10.4-3.3-00092
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_RELEASE:=1


include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/local-development.mk

define Package/$(PKG_NAME)
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=QCA ath10k firmware
endef

define Package/$(PKG_NAME)/description
  This package contains the ATH10k Firmware binaries
endef

Build/Compile=true

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA988X/hw2.0
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA9887/hw1.0
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA99X0/hw2.0
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA9888/hw2.0
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA9984/hw1.0
	$(INSTALL_DIR) $(1)/lib/firmware/ath10k/QCA4019/hw1.0
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA988X/hw2.0/board.bin \
	$(1)/lib/firmware/ath10k/QCA988X/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA988X/hw2.0/firmware-5.bin_$(PKG_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA988X/hw2.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA99X0/hw2.0/board-pci-0001-0001.bin  \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA99X0/hw2.0/board-pci-0002-0001.bin  \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA99X0/hw2.0/board-pci-0004-0001.bin  \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA99X0/hw2.0/board-pci-0006-0001.bin  \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA99X0/hw2.0/board-2.bin  \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/10.4/firmware-5.bin_$(PKG_BL_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA99X0/hw2.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA40XX/hw1.0/board-ahb-0014-0000.bin  \
	$(1)/lib/firmware/ath10k/QCA4019/hw1.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA40XX/hw1.0/board-ahb-0015-0000.bin  \
	$(1)/lib/firmware/ath10k/QCA4019/hw1.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/10.5/firmware-5.bin_$(PKG_DK_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA4019/hw1.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA40XX/hw1.0/board-2.bin  \
	$(1)/lib/firmware/ath10k/QCA4019/hw1.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9888/hw2.0/firmware-5.bin_$(PKG_BES_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA9888/hw2.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9888/hw2.0/board-2.bin  \
	$(1)/lib/firmware/ath10k/QCA9888/hw2.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9984/hw1.0/firmware-5.bin_$(PKG_CAS_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA9984/hw1.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9984/hw1.0/board-2.bin  \
	$(1)/lib/firmware/ath10k/QCA9984/hw1.0/
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9887/hw1.0/firmware-5.bin_$(PKG_SW_FW_VERSION) \
	$(1)/lib/firmware/ath10k/QCA9887/hw1.0/firmware-5.bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/ath10k/QCA9887/hw1.0/board.bin  \
	$(1)/lib/firmware/ath10k/QCA9887/hw1.0/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
