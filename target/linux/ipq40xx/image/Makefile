include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

DEVICE_VARS += NETGEAR_BOARD_ID NETGEAR_HW_ID
DEVICE_VARS += RAS_BOARD RAS_ROOTFS_SIZE RAS_VERSION
DEVICE_VARS += WRGG_DEVNAME WRGG_SIGNATURE

define Device/Default
	PROFILES := Default
	KERNEL_DEPENDS = $$(wildcard $(DTS_DIR)/$$(DEVICE_DTS).dts)
	KERNEL_INITRAMFS_PREFIX := $$(IMG_PREFIX)-$(1)-initramfs
	KERNEL_PREFIX := $$(IMAGE_PREFIX)
	KERNEL_LOADADDR := 0x80208000
	DEVICE_DTS = $$(SOC)-$(lastword $(subst _, ,$(1)))
	SUPPORTED_DEVICES := $(subst _,$(comma),$(1))
	IMAGE/sysupgrade.bin = sysupgrade-tar | append-metadata
	IMAGE/sysupgrade.bin/squashfs :=
endef

define Device/FitImage
	KERNEL_SUFFIX := -fit-uImage.itb
	KERNEL = kernel-bin | gzip | fit gzip $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/FitImageLzma
	KERNEL_SUFFIX := -fit-uImage.itb
	KERNEL = kernel-bin | lzma | fit lzma $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/FitzImage
	KERNEL_SUFFIX := -fit-zImage.itb
	KERNEL = kernel-bin | fit none $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := zImage
endef

define Device/UbiFit
	KERNEL_IN_UBI := 1
	IMAGES := nand-factory.ubi nand-sysupgrade.bin
	IMAGE/nand-factory.ubi := append-ubi
	IMAGE/nand-sysupgrade.bin := sysupgrade-tar | append-metadata
endef

define Device/DniImage
	KERNEL_SUFFIX := -fit-uImage.itb
	KERNEL = kernel-bin | gzip | fit gzip $$(DTS_DIR)/$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
	NETGEAR_BOARD_ID :=
	NETGEAR_HW_ID :=
	IMAGES := factory.img sysupgrade.bin
	IMAGE/factory.img := append-kernel | pad-offset 64k 64 | append-uImage-fakehdr filesystem | append-rootfs | pad-rootfs | netgear-dni
	IMAGE/sysupgrade.bin := append-kernel | pad-offset 64k 64 | append-uImage-fakehdr filesystem | append-rootfs | pad-rootfs | append-metadata
endef

define Build/mkmylofw_32m
	$(eval device_id=$(word 1,$(1)))
	$(eval revision=$(word 2,$(1)))

	let \
		size="$$(stat -c%s $@)" \
		pad="$(subst k,* 1024,$(BLOCKSIZE))" \
		pad="(pad - (size % pad)) % pad" \
		newsize='size + pad'; \
		$(STAGING_DIR_HOST)/bin/mkmylofw \
		-B WPE72 -i 0x11f6:$(device_id):0x11f6:$(device_id) -r $(revision) \
		-s 0x2000000 -p0x180000:$$newsize:al:0x80208000:"OpenWrt":$@ \
		$@.new
	@mv $@.new $@
endef

define Build/SenaoFW
	-$(STAGING_DIR_HOST)/bin/mksenaofw \
		-n $(BOARD_NAME) -r $(VENDOR_ID) -p $(1) \
		-c $(DATECODE) -w $(2) -x $(CW_VER) -t 0 \
		-e $@ \
		-o $@.new
	@cp $@.new $@
endef

define Build/wrgg-image
	mkwrggimg -i $@ \
	-o $@.new \
	-d "$(WRGG_DEVNAME)" \
	-s "$(WRGG_SIGNATURE)" \
	-v "" -m "" -B ""
	mv $@.new $@
endef

define Device/8dev_jalapeno-common
	$(call Device/FitImage)
	$(call Device/UbiFit)
	BLOCKSIZE := 128k
	PAGESIZE := 2048
	SOC := qcom-ipq4018
endef

define Device/8dev_jalapeno
	$(call Device/8dev_jalapeno-common)
	DEVICE_VENDOR := 8devices
	DEVICE_MODEL := Jalapeno
endef
TARGET_DEVICES += 8dev_jalapeno

define Device/alfa-network_ap120c-ac
	$(call Device/FitImage)
	$(call Device/UbiFit)
	DEVICE_VENDOR := ALFA Network
	DEVICE_MODEL := AP120C-AC
	SOC := qcom-ipq4018
	DEVICE_PACKAGES := kmod-usb-acm \
		kmod-tpm-i2c-atmel uboot-envtools
	BLOCKSIZE := 256k
	PAGESIZE := 4096
	IMAGE_SIZE := 65536k
	IMAGES := nand-factory.bin nand-sysupgrade.bin
	IMAGE/nand-factory.bin := append-ubi | qsdk-ipq-factory-nand
endef
TARGET_DEVICES += alfa-network_ap120c-ac

$(eval $(call BuildImage))
