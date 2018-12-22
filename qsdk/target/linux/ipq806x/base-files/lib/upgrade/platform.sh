#
# Copyright (C) 2011 OpenWrt.org
#

USE_REFRESH=1

. /lib/ipq806x.sh
. /lib/upgrade/common.sh

RAMFS_COPY_DATA=/lib/ipq806x.sh
RAMFS_COPY_BIN="/usr/bin/dumpimage /bin/mktemp /usr/sbin/mkfs.ubifs
	/usr/sbin/ubiattach /usr/sbin/ubidetach /usr/sbin/ubiformat /usr/sbin/ubimkvol
	/usr/sbin/ubiupdatevol /usr/bin/basename /bin/rm /usr/bin/find"

get_full_section_name() {
	local img=$1
	local sec=$2

	dumpimage -l ${img} | grep "^ Image.*(${sec})" | \
		sed 's,^ Image.*(\(.*\)),\1,'
}

image_contains() {
	local img=$1
	local sec=$2
	dumpimage -l ${img} | grep -q "^ Image.*(${sec}.*)" || return 1
}

print_sections() {
	local img=$1

	dumpimage -l ${img} | awk '/^ Image.*(.*)/ { print gensub(/Image .* \((.*)\)/,"\\1", $0) }'
}

image_has_mandatory_section() {
	local img=$1
	local mandatory_sections=$2

	for sec in ${mandatory_sections}; do
		image_contains $img ${sec} || {\
			return 1
		}
	done
}

# Make sure fullname is either "script" or has the following format
# (known name)-(20 hex numbers)
# 
# Examples:
# hlos-74bc58fcf4824fdc0de18c62abb64676f8fac267
verify_fullname() {
	local fullname=$1
	local names="gpt- bootconfig- bootconfig1- sbl1- sbl2- sbl3- u-boot- \
		     ddr-db149- ddr-db147- ddr-ap145- ddr-ap145_1xx- ddr-ap148- \
		     ddr-ap148_1xx- ddr-db149_2xx- ddr-ap161- \
		     tz- rpm- hlos- fs- gptbackup-"	
	local hex_len=40
	local min_fullname_len=43

	if [ "$fullname" = "script" ]; then
		return 0
	fi

	fullname_len=${#fullname}

	if [ $fullname_len -lt $min_fullname_len ]; then
		return 1
	fi

	# Break fullname into name and hex
	name_len=$((fullname_len - hex_len))                                
	name=${fullname:0:$name_len}                                   
	hex=${fullname:$name_len:$hex_len}  

	# Delete number and [abcdef], and expect to be ""
	res=$(echo $hex | tr -d "0123456789abcdef")
	if [ ! -z $res ]; then
		return 1
	fi

	for n in $names; do
		if [ "$name" = "$n" ]; then
			return 0
		fi
	done

	return 1
}
 
image_demux() {
	local img=$1

	for sec in $(print_sections ${img}); do
		local fullname=$(get_full_section_name ${img} ${sec})

		verify_fullname "$fullname"
		if [ $? -eq 1 ]; then 
			echo "Fail to verify $fullname"
			logger "Sysupgrade detected invalid partition $fullname!!!" 
			return 1
		fi

		dumpimage -i ${img} -o /tmp/${fullname}.bin ${fullname} > /dev/null || { \
			echo "Error while extracting \"${sec}\" from ${img}"
			return 1
		}
	done
	return 0
}

image_is_FIT() {
	if ! dumpimage -l $1 > /dev/null 2>&1; then
		echo "$1 is not a valid FIT image"
		return 1
	fi
	return 0
}

switch_layout() {
	local layout=$1
	local boot_layout=`find / -name boot_layout`

	# Layout switching is only required as the  boot images (up to u-boot)
	# use 512 user data bytes per code word, whereas Linux uses 516 bytes.
	# It's only applicable for NAND flash. So let's return if we don't have
	# one.

	[ -n "$boot_layout" ] || return

	case "${layout}" in
		boot|1) echo 1 > $boot_layout;;
		linux|0) echo 0 > $boot_layout;;
		*) echo "Unknown layout \"${layout}\"";;
	esac
}

do_flash_mtd() {
	local bin=$1
	local mtdname=$2
	local append=""

	local mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')
	local pgsz=$(cat /sys/class/mtd/${mtdpart}/writesize)
	[ -f "$CONF_TAR" -a "$SAVE_CONFIG" -eq 1 -a "$2" == "rootfs" ] && append="-j $CONF_TAR"

	dd if=/tmp/${bin}.bin bs=${pgsz} conv=sync | mtd $append write - -e "/dev/${mtdpart}" "/dev/${mtdpart}"
}

do_flash_emmc() {
	local bin=$1
	local emmcblock=$2
	local block=512
	local num_of_tries=3   
                    
	local bin_checksum=$(md5sum /tmp/${bin}.bin | awk '{print $1}')
	local size=$(stat -c %s /tmp/${bin}.bin)
	local num_of_blocks=$((size / block))                   
	local offset=$((num_of_blocks * block))    
	local remainder=$((size - offset))
	local emmc_bin=/tmp/${bin}_emmc_bin
                  
	i=0         
	while [ $i -lt $num_of_tries ]; do
		dd if=/dev/zero of=${emmcblock}
		dd if=/tmp/${bin}.bin of=${emmcblock}
		# Read back and verify, re-flash if different
		dd if=$emmcblock of=$emmc_bin bs=$block count=$num_of_blocks
		dd if=$emmcblock skip=$offset bs=1 count=$remainder >> $emmc_bin
		emmc_checksum=$(md5sum $emmc_bin | awk '{print $1}')
		[ $bin_checksum == $emmc_checksum ] && break                                       
		i=$((i + 1))
	done                       
	# Exit sysupgrade if verification failed after num_of_tries
	if [ $i -eq $num_of_tries ]; then
		logger "sysupgrade emmc flash failed: $emmcblock."
		exit 1
	fi
}

do_flash_partition() {
	local bin=$1
	local mtdname=$2
	local emmcblock="$(find_mmc_part "$mtdname")"

	if [ -e "$emmcblock" ]; then
		do_flash_emmc $bin $emmcblock
	else
		do_flash_mtd $bin $mtdname
	fi
}

do_flash_partition_if_different() {                                                                            
	local bin=$1                                                           
	local mtdname=$2                                                      
	local emmcblock="$(find_mmc_part $mtdname)"                      
                                                                                      
	new_bin=/tmp/${bin}.bin                                        
	size=$(wc -c $new_bin | awk '{print $1}')                                                          
	old_bin=/tmp/${mtdname}_old_bin                     
	dd if=$emmcblock of=$old_bin bs=$size count=1                 
                                                                                            
	new_checksum=$(md5sum $new_bin | awk '{print $1}')                    
	old_checksum=$(md5sum $old_bin | awk '{print $1}')
                               
	[ $new_checksum != $old_checksum ] && do_flash_partition $bin $mtdname
}     

do_flash_bootconfig() {
	local bin=$1
	local mtdname=$2

	# Fail safe upgrade
	if [ -f /proc/boot_info/getbinary_${bin} ]; then
		cat /proc/boot_info/getbinary_${bin} > /tmp/${bin}.bin
		do_flash_partition $bin $mtdname
	fi
}

do_flash_failsafe_partition() {
	local bin=$1
	local mtdname=$2
	local emmcblock
	local primaryboot

	# Fail safe upgrade
	[ -f /proc/boot_info/$mtdname/upgradepartition ] && {
		default_mtd=$mtdname
		mtdname=$(cat /proc/boot_info/$mtdname/upgradepartition)
		primaryboot=$(cat /proc/boot_info/$default_mtd/primaryboot)
		if [ $primaryboot -eq 0 ]; then
			echo 1 > /proc/boot_info/$default_mtd/primaryboot
		else
			echo 0 > /proc/boot_info/$default_mtd/primaryboot
		fi
	}

	emmcblock="$(find_mmc_part "$mtdname")"

	if [ -e "$emmcblock" ]; then
		do_flash_emmc $bin $emmcblock
	else
		do_flash_mtd $bin $mtdname
	fi

}

do_flash_ubi() {
	local bin=$1
	local mtdname=$2
	local mtdpart
	local primaryboot

	mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')
	ubidetach -f -p /dev/${mtdpart}

	# Fail safe upgrade
	[ -f /proc/boot_info/$mtdname/upgradepartition ] && {
		primaryboot=$(cat /proc/boot_info/$mtdname/primaryboot)
		if [ $primaryboot -eq 0 ]; then
			echo 1 > /proc/boot_info/$mtdname/primaryboot
		else
			echo 0 > /proc/boot_info/$mtdname/primaryboot
		fi

		mtdname=$(cat /proc/boot_info/$mtdname/upgradepartition)
	}

	mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')

	ubiformat /dev/${mtdpart} -y -f /tmp/${bin}.bin
}

do_flash_tz() {
	local sec=$1
	local mtdpart=$(grep "\"0:QSEE\"" /proc/mtd | awk -F: '{print $1}')
	local emmcblock="$(find_mmc_part "0:QSEE")"

	if [ -n "$mtdpart" -o -e "$emmcblock" ]; then
		do_flash_failsafe_partition ${sec} "0:QSEE"
	else
		do_flash_failsafe_partition ${sec} "0:TZ"
	fi
}

do_flash_ddr() {
	local sec=$1
	local mtdpart=$(grep "\"0:CDT\"" /proc/mtd | awk -F: '{print $1}')
	local emmcblock="$(find_mmc_part "0:CDT")"

	if [ -n "$mtdpart" -o -e "$emmcblock" ]; then
		do_flash_failsafe_partition ${sec} "0:CDT"
	else
		do_flash_failsafe_partition ${sec} "0:DDRPARAMS"
	fi
}

to_upper ()
{
	echo $1 | awk '{print toupper($0)}'
}

flash_section() {
	local sec=$1

	local board=$(ipq806x_board_name)
	case "${sec}" in
		hlos*) switch_layout linux; do_flash_failsafe_partition ${sec} "0:HLOS";;
		rootfs*) switch_layout linux; do_flash_failsafe_partition ${sec} "rootfs";;
		fs*) switch_layout linux; do_flash_failsafe_partition ${sec} "rootfs";;
		ubi*) switch_layout linux; do_flash_ubi ${sec} "rootfs";;
		sbl1*) switch_layout boot; do_flash_partition_if_different ${sec} "0:SBL1";;
		sbl2*) switch_layout boot; do_flash_failsafe_partition ${sec} "0:SBL2";;
		sbl3*) switch_layout boot; do_flash_failsafe_partition ${sec} "0:SBL3";;
		mibib*) switch_layout boot; do_flash_partition ${sec} "0:MIBIB";;
		dtb-$(to_upper $board)*) switch_layout boot; do_flash_partition ${sec} "0:DTB";;
		u-boot*) switch_layout boot; do_flash_failsafe_partition ${sec} "0:APPSBL";;
		ddr-$(to_upper $board)*) switch_layout boot; do_flash_ddr ${sec};;
		ddr-${board}-*) switch_layout boot; do_flash_failsafe_partition ${sec} "0:DDRCONFIG";;
		ssd*) switch_layout boot; do_flash_partition ${sec} "0:SSD";;
		tz*) switch_layout boot; do_flash_tz ${sec};;
		rpm*) switch_layout boot; do_flash_failsafe_partition ${sec} "0:RPM";;
		*) echo "Section ${sec} ignored"; return 1;;
	esac

	echo "Flashed ${sec}"
}

erase_emmc_config() {
        # dm-crypt mapper of rootfs_data
	local emmcblock="/dev/mapper/overlay"
	if [ -e "$emmcblock" -a "$SAVE_CONFIG" -ne 1 ]; then
		dd if=/dev/zero of=${emmcblock}
	fi
}

check_rollback_counter()
{
	IMAGE=$1
	MBN_HEADER_SIZE=40
	HLOS=hlos

	kernel_image_mbn=$(print_sections $IMAGE | grep $HLOS | sed -e 's/^[ \t]*//')
	dumpimage -i $IMAGE -o /tmp/$kernel_image_mbn $kernel_image_mbn
	cat /tmp/$kernel_image_mbn | dd of=/tmp/kernel_image bs=$MBN_HEADER_SIZE skip=1
	rm /tmp/$kernel_image_mbn

	# Retrieve the kernel version embedded in the header of config@1
	kernel_ver=$(mkimage -l /tmp/kernel_image | grep -A 1 "config@1" | grep Description | awk '{ print $2 }')
	echo "Kernel ver: $kernel_ver"
	
	if [ -z  $kernel_ver  ]; then
		echo "Failed to read RFS version string."                                              
		return 1
	fi

	# Retrieve the atmel version
	NUM_RETRY_MAX=4
	num_retry=0
	atmel_ver=-1

	while [ $num_retry -lt $NUM_RETRY_MAX ] && [ $atmel_ver -lt 0 ]                                       
	do
		echo "atmel read counter num tries: $num_retry"              
		num_retry=`expr $num_retry + 1`
		atmel_ver=`ecc508 rover-get-counter | tail -n 1`
	done
	echo "Atmel ver: $atmel_ver, retry num $num_retry"

	if [ -z  $atmel_ver -o $atmel_ver -lt 0 ]; then
		echo "Atmel monotonic counter returned an empty string or a negative number."
		return 1
	fi

	# Compare the counters
	if [ $atmel_ver -le $kernel_ver ]; then
		echo "atmel_ver $atmel_ver is less than or equal to kernel_ver $kernel_ver"       
		return 0
	else
		echo "Sysupgrade detected attempt to program obsolete firmware!!!"                                                        
		logger "Sysupgrade detected attempt to program obsolete firmware!!!"                                                        
		return 1
	fi
}

platform_check_image() {
	local board=$(ipq806x_board_name)

	local mandatory_nand="ubi"
	local mandatory_nor_emmc="hlos fs"
	local mandatory_nor="hlos"
	local mandatory_section_found=0
	local optional="sb11 sbl2 u-boot ddr-${board} ssd tz rpm"
	local ignored="mibib bootconfig"

	image_is_FIT $1 || return 1

# Disable rollback prevention for now
#	check_rollback_counter $1 || return 1

	image_has_mandatory_section $1 ${mandatory_nand} && {\
		mandatory_section_found=1
	}

	image_has_mandatory_section $1 ${mandatory_nor_emmc} && {\
		mandatory_section_found=1
	}

	image_has_mandatory_section $1 ${mandatory_nor} && {\
		mandatory_section_found=1
	}

	if [ $mandatory_section_found -eq 0 ]; then
		echo "Error: mandatory section(s) missing from \"$1\". Abort..."
		return 1
	fi

	for sec in ${optional}; do
		image_contains $1 ${sec} || {\
			echo "Warning: optional section \"${sec}\" missing from \"$1\". Continue..."
		}
	done

	for sec in ${ignored}; do
		image_contains $1 ${sec} && {\
			echo "Warning: section \"${sec}\" will be ignored from \"$1\". Continue..."
		}
	done

	image_demux $1 || {\
		echo "Error: \"$1\" couldn't be extracted. Abort..."
		return 1
	}

	[ -f /tmp/hlos_version ] && rm -f /tmp/*_version
	dumpimage -c $1
	return $?
}

platform_version_upgrade() {
	local version_files="appsbl_version sbl_version tz_version hlos_version rpm_version"
	local sys="/sys/devices/system/qfprom/qfprom0/"
	local tmp="/tmp/"

	for file in $version_files; do
		[ -f "${tmp}${file}" ] && {
			echo "Updating "${sys}${file}" with `cat "${tmp}${file}"`"
			echo `cat "${tmp}${file}"` > "${sys}${file}"
			rm -f "${tmp}${file}"
		}
	done
}

set_boot_config() {                     
	# Find the primaryboot partition                             
	part=$(ls -la /dev/root | cut -d '/' -f 5)                                                 
	if [ $part = "mmcblk0p10" ]; then                   
		primary=0                                               
	else                                                
		primary=1                      
	fi                                                               
                                               
	# Set the primary boot                                       
	BOOT_INFO=/proc/boot_info                 
	rootfs=$(cat $BOOT_INFO/rootfs/primaryboot)                                       
	if [ $primary -ne $rootfs ]; then                                   
		for d in $BOOT_INFO/*/; do
			primaryboot="$d"primaryboot                        
			echo $primary  > $primaryboot
		done          
	fi                                                                                  
}         

platform_do_upgrade() {
	local board=$(ipq806x_board_name)

	# verify some things exist before erasing
	if [ ! -e $1 ]; then
		echo "Error: Can't find $1 after switching to ramfs, aborting upgrade!"
		reboot
	fi

	# Make sure we flash the correct partition              
	set_boot_config 

	for sec in $(print_sections $1); do
		if [ ! -e /tmp/${sec}.bin ]; then
			echo "Error: Cant' find ${sec} after switching to ramfs, aborting upgrade!"
			reboot
		fi
	done

	case "$board" in
	db149 | ap148 | ap145 | ap148_1xx | db149_1xx | db149_2xx | ap145_1xx | ap160 | ap160_2xx | ap161 | ak01_1xx | ap-dk01.1-c1 | ap-dk01.1-c2 | ap-dk04.1-c1 | ap-dk04.1-c2 | ap-dk04.1-c3 | ap-dk04.1-c4 | ap-dk04.1-c5 | ap-dk05.1-c1 |  ap-dk06.1-c1 | ap-dk07.1-c1 | ap-dk07.1-c2)
		for sec in $(print_sections $1); do
			flash_section ${sec}
		done

		switch_layout linux
		# update bootconfig to register that fw upgrade has been done
		do_flash_bootconfig bootconfig "0:BOOTCONFIG"
		do_flash_bootconfig bootconfig1 "0:BOOTCONFIG1"
		platform_version_upgrade

		erase_emmc_config
		return 0;
		;;
	esac

	echo "Upgrade failed!"
	return 1;
}

platform_copy_config() {
	local nand_part="$(find_mtd_part "ubi_rootfs")"
	# dm-crypt mapper of rootfs_data
        local emmcblock="/dev/mapper/overlay"

	if [ -e "$nand_part" ]; then
		local mtdname=rootfs
		local mtdpart

		[ -f /proc/boot_info/$mtdname/upgradepartition ] && {
			mtdname=$(cat /proc/boot_info/$mtdname/upgradepartition)
		}

		mtdpart=$(grep "\"${mtdname}\"" /proc/mtd | awk -F: '{print $1}')
		ubiattach -p /dev/${mtdpart}
		mount -t ubifs ubi0:rootfs_data /tmp/overlay
		cp /tmp/sysupgrade.tgz /tmp/overlay/
		sync
		umount /tmp/overlay
	fi
}

