/*
 * (C) Copyright 2000-2009
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */


/*
 * Boot support
 */
#include <common.h>
#include <command.h>
#include <image.h>
#include <string.h>
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ca_crt.h"
#include <mmc.h>
#include <part.h>
#include <asm/arch-ipq806x/smem.h>

#define SHA256_HASH_SIZE 32 // bytes (256 bits)
#define CMD_SIZE 128
static int get_mem_addr(const void *fit, const char *image_name, const void **data, size_t *size)
{
	int noffset = fit_image_get_node(fit, image_name);

	if (noffset < 0) {
		printf("fit_image_get_node for %s failed \n", image_name);
		return -1;
	}
	if (fit_image_get_data(fit, noffset, data, size) != 0)
	{
		printf("fit_image_get_data for %s failed.\n", image_name);
		return -1;
	}
	return 0;;
}

static int calculate_sha256_hash(const void * data, const size_t size,  unsigned char * hash) 
{
	mbedtls_md_context_t ctx;
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
	int res = -1;

	if( md_info == NULL ) {
		printf("SHA256 is not supported.\n");
		return res;
	}

	mbedtls_md_init(&ctx);

	do {
		if (mbedtls_md_setup( &ctx, md_info, 0 ) != 0 )
		{
			printf("MD setup failed.\n");
			break;
		}

		// Calculate hash for image
		md_info->starts_func( ctx.md_ctx );

		md_info->update_func(ctx.md_ctx, (unsigned char *)data, size);
	
		md_info->finish_func(ctx.md_ctx, hash);

		res = 0;

	} while (0);

	mbedtls_md_free(&ctx);

	return res;
}

static int verify_sig(const void * fit)
{
	mbedtls_x509_crt crt;
	mbedtls_rsa_context *rsa;
	unsigned char hash[SHA256_HASH_SIZE];
	const void * data;
	size_t size;
	int res = -1;

	mbedtls_x509_crt_init(&crt);	

	do {
		// Get image offset and size
		if (get_mem_addr(fit, "image", &data, &size) != 0)
		{
			printf("Faled to get image.\n");
			break;
		}

		// Calculate image sha256 hash
		if (calculate_sha256_hash(data, size, hash) != 0) {
			printf("Failed to calculate hash.\n");
			break;
		}

		// Get intermediate_cert data
		if (get_mem_addr(fit, "signing_cert", &data, &size) != 0) {
			printf("Failed to get signing cert.\n");
			break;
		}
		// Retrieve pub key from crt 
		if (mbedtls_x509_crt_parse(&crt, (unsigned char *)data, size + 1) != 0) {
			printf("Failed to parse signing cert.\n");
			break;
		}

		// Retrieve public key
		mbedtls_pk_can_do(&(crt.pk), MBEDTLS_PK_RSA);

		rsa = mbedtls_pk_rsa( crt.pk );

		if (mbedtls_rsa_check_pubkey(rsa) != 0) {
			printf("Certificate does not contain a pub key.\n");
			break;
		}

		// Retrieve signature
		if (get_mem_addr(fit, "signature", &data, &size) != 0) {
			printf("Failed to get signature.\n");
			break;
		}
        
		// Verify signature
		if( mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0, hash, data) != 0 ) {
			printf( "Failed to verify signature.\n");
			break;
		}

		printf( "Signature verification OK.\n" );

		res = 0;

	} while (0);

	mbedtls_x509_crt_free( &crt );

	return res;
}

static int verify_crt_chain(const void * fit)
{
	uint32_t flags;
	mbedtls_x509_crt trusted;
	mbedtls_x509_crt chain;
	const void * data;
	size_t size;
	int res = -1;

	// Verify certificate chain
	mbedtls_x509_crt_init(&trusted);
	mbedtls_x509_crt_init(&chain);

	do {

		// Get intermediate_cert data
		if (get_mem_addr(fit, "intermediate_cert", &data, &size) != 0) {
			printf("Failed to get intermediate cert.\n");
			break;
		}
	
		if (mbedtls_x509_crt_parse(&chain, (unsigned char *)data, size + 1) != 0) {
			printf("Failed to parse intermediate cert\n");
			break;
		}

		// Get signing_cert data
		if (get_mem_addr(fit, "signing_cert", &data, &size) != 0) {
			printf("Failed to get signing cert.\n");
			break;
		}

		if (mbedtls_x509_crt_parse(&chain, (unsigned char *)data, size + 1) != 0) {
			printf("Failed to parse signing cert.\n");
			break;
		}

		// Parse the embedded ca cert
		if (mbedtls_x509_crt_parse(&trusted, trusted_ca, strlen((char*)trusted_ca) + 1) != 0) {
			printf("Failed to parse trusted_ca.\n");
			break;
		}

		if (mbedtls_x509_crt_verify(&chain, &trusted, NULL, NULL, &flags, NULL, NULL) != 0) {
			printf("Certificate chain verification failed.\n");
			break;
		}

		printf("Certificate chain verification OK.\n");

		res = 0;

	} while (0);

	mbedtls_x509_crt_free(&trusted);
	mbedtls_x509_crt_free(&chain);

	return res;
}

static int shift_image(const void * fit)
{
	const void * data;
	size_t size;
	char cmd[CMD_SIZE];

	// Get intermediate_cert data
	if (get_mem_addr(fit, "image", &data, &size) != 0) {
		printf("Failed to get image.\n");
		return -1;
	}

	// Shift image to a known offset (0x42000000)
	snprintf(cmd, CMD_SIZE, "cp 0x%08lx 0x42000000 0x%08lx", (ulong)data, (ulong)size);
	printf("%s\n", cmd);

	return run_command(cmd, 0);
}	

static int check(ulong addr)
{
	void *hdr = (void *)addr;

	printf("\n## Checking Image at %08lx ...\n", addr);

	switch (genimg_get_format(hdr)) {
	case IMAGE_FORMAT_FIT:
		printf("FIT image found\n");

		if (!fit_check_format(hdr)) {
			puts("Bad FIT image format!\n");
			return -1;
		}

		if (verify_crt_chain(hdr) != 0) {
			printf("Certificate chain verification failed!\n");
			return -1;
		}

		if (verify_sig(hdr) != 0) {
			printf("Signature verification failed!\n");
			return -1;
		}

		if (shift_image(hdr) != 0) {
			printf("Failed to shift the image.");
			return -1;
		}

		return 0;
	default:
		printf("Unknown image format!\n");
		break;
	}

	return -1;
}

int do_checkimg(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	if (argc < 2) {
		return check(load_addr);
	}
	else {
		ulong   addr;
		addr = simple_strtoul(argv[1], NULL, 16);
		return check(addr);
	}	
}

U_BOOT_CMD(
	checkimg,	CONFIG_SYS_MAXARGS,	1,	do_checkimg,
	"check image signature",
	"addr [addr ...]\n"
	"    - Check the image signature using a chain of certificates."
);

// Serach for a subnode identified by a key, e.g. "hlso"
static int search(const void * fit, const char * key, const int key_len, const void **data, size_t *size)
{
	int images_noffset;
	int noffset;
	int ndepth;

	//Find images parent node offset 
	images_noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images_noffset < 0) {
		printf("Can't find images parent node '%s' (%s)\n", FIT_IMAGES_PATH, fdt_strerror(images_noffset));
		return -1;
	}

	// Loop through subnodes for a subnode matching the key
	for (ndepth = 0, noffset = fdt_next_node(fit, images_noffset, &ndepth);
		(noffset >= 0) && (ndepth > 0);
		noffset = fdt_next_node(fit, noffset, &ndepth)) {

		// Direct child node of the images parent node, i.e. component image node.
		if (ndepth == 1) {
			if (strncmp(key, fit_get_name(fit, noffset, NULL), key_len) == 0) {
				printf("Found %s\n", fit_get_name(fit, noffset, NULL));
				if (fit_image_get_data(fit, noffset, data, size) != 0)
				{
					printf("fit_image_get_data for %s failed.\n", key);
					return -1;
				}
				return 0;
			}
		}
	}

	return -1;
}

typedef struct mbn_header {
    uint16_t image_id;
    uint32_t ver_num;
    uint32_t image_src;
    uint8_t *image_dest_ptr;
    uint32_t image_size;
    uint32_t code_size;
    uint8_t *sig_ptr;
    uint32_t sig_sz;
    uint8_t *cert_ptr;
    uint32_t cert_sz;
} Mbn_Hdr;

#define SIG_CERT_SIZE  6400
static int is_signed(const void * data, const size_t size)
{
	Mbn_Hdr *mbn_hdr;
	int sig_cert_size;

	mbn_hdr = (Mbn_Hdr *) data;

	sig_cert_size = mbn_hdr->image_size - mbn_hdr->code_size;

	printf("sig_cert_size = %d\n", sig_cert_size);

	if (sig_cert_size != SIG_CERT_SIZE) {
		return -1;
	}

	return 0;
}

static int verify(ulong addr)
{
	void *hdr = (void *)addr;
	const void * data;
	size_t size;

	printf("\n## Verifying image is signed at %08lx ...\n", addr);

	switch (genimg_get_format(hdr)) {
	case IMAGE_FORMAT_FIT:
		printf("FIT image found\n");

		if (!fit_check_format(hdr)) {
			puts("Bad FIT image format!\n");
			return -1;
		}

		if (search(hdr, "hlos", 4, &data, &size) < 0) {
			printf("Could not find hlos sub image\n");
			return -1;
		}

		if (is_signed(data, size) != 0){
			printf("Image is not signed.\n");
			return -1;
		}

		printf("Image is signed.\n");
		return 0;
	default:
		printf("Unknown image format!\n");
		break;
	}

	return -1;
}

// This command returns 0 if loaded image is signed, -1 otherwise.
int do_verifyimg(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	if (argc < 2) {
		return verify(load_addr);
	}
	else {
		ulong   addr;
		addr = simple_strtoul(argv[1], NULL, 16);
		return verify(addr);
	}
}

U_BOOT_CMD(
	verifyimg,   CONFIG_SYS_MAXARGS, 1,  do_verifyimg,
	"verify if the loaded image is signed.",
	"addr [addr ...]\n"
	"    - verify if FW image is signed."
);

// This command returns 0 if hw is security enabled, -1 otherwise
#include <asm/arch-ipq806x/scm.h>
int do_verifyhw(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	int ret;
	char buf;

	ret = scm_call(SCM_SVC_FUSE, QFPROM_IS_AUTHENTICATE_CMD, NULL, 0, &buf, sizeof(char));

	if (ret != 0) {
		printf("Failed to check the status of Secure Boot\n");
		return -1;
	}

	if (buf == 1) {
		printf("Secure boot is enabled.\n");
		return 0;
	}

	printf("Secure boot is not enabled yet.\n");
	return -1;
}

U_BOOT_CMD(
	verifyhw,   CONFIG_SYS_MAXARGS, 1,  do_verifyhw,
	"verify if HW is security enabled.",
	"addr [addr ...]\n"
	"    - verify if FW is security enabled."
);

#define CMD_SIZE 128
#define PART_NAME_SIZE 16
static int load_mmc_image(char * part)
{	
	int curr_device = -1;
	struct mmc *mmc;
	block_dev_desc_t *mmc_dev;
	disk_partition_t disk_info;
	unsigned int active_part = 0;
	char runcmd[CMD_SIZE];
	char part_1[PART_NAME_SIZE];
	int ret;

	if (curr_device < 0) {
		if (get_mmc_num() > 0)
			curr_device = 0;
		else {
			printf("No MMC device available\n");
			return -1;
		}
	}

	mmc = find_mmc_device(curr_device);
	if (!mmc) {
		printf("No mmc device at slot %x\n", curr_device);
		return -1;
	}

	mmc_init(mmc);

	mmc_dev = mmc_get_dev(curr_device);

	if (mmc_dev == NULL || mmc_dev->type == DEV_TYPE_UNKNOWN) {
		printf("Can not get mmc device.\n");
		return -1;
	} 

	active_part = get_rootfs_active_partition();

	if (active_part) {
		sprintf(part_1, "%s_1", part);
		ret = find_part_efi(mmc_dev, part_1, &disk_info);
	} else {
		ret = find_part_efi(mmc_dev, part, &disk_info);
	}

	if (ret <= 0) {
		printf(" Can not find partition %s\n", active_part ? part_1 : part);
		return -1;
	}

	snprintf(runcmd, sizeof(runcmd), "mmc read 0x%x 0x%X 0x%X",
			CONFIG_SYS_LOAD_ADDR, (uint)disk_info.start, (uint)disk_info.size);

	if (run_command(runcmd, 0) != CMD_RET_SUCCESS) {
		printf(" cmd %s failed.", runcmd);
		return -1;
	}

	printf("Loaded %s\n", active_part ? part_1 : part);
	return 0;
}

#define MBN_HDR_SIZE 40
#define CERT_SIZE 2048
// The hash here is for the current int ca cert, will be updated to that of the product ca cert when it is finalized
unsigned char expected_ca_hash[] = {0xe7, 0xc5, 0xbb, 0x52, 0xb2, 0x46, 0x34, 0xaa, 0x2d, 0xc6, 0x55, 0x4a, 0xaa, 0x41, 0x2f, 0x3c, 
    		                        0xba, 0x14, 0x0b, 0x17, 0x64, 0x98, 0xdb, 0x52, 0x38, 0xd1, 0x7d, 0xe2, 0xb8, 0xc9, 0x9a, 0x77};

static int verify_hash(const uint8_t * data)
{
	Mbn_Hdr *mbn_hdr;
	int cert_offset;
	int cert_size;
	unsigned char ca_hash[SHA256_HASH_SIZE];

	// mbn header contains pointer to signing certificate 
	mbn_hdr = (Mbn_Hdr *) data;

	cert_offset = mbn_hdr->cert_ptr - mbn_hdr->image_dest_ptr + MBN_HDR_SIZE;

	// signing cert size
	cert_size = ( (data[cert_offset + 2] << 8) | data[cert_offset + 3] ) + 4;
	if (cert_size >= CERT_SIZE) {
		printf("signing cert size %d is too big.\n", cert_size);
		return -1;
	}

	// intermediate cert offset
	cert_offset += cert_size;

	// intermediate cert size  
	cert_size = ( (data[cert_offset + 2] << 8) | data[cert_offset + 3] ) + 4;
	if (cert_size >= CERT_SIZE) {
		printf("intermediate cert size %d is too big.\n", cert_size);
		return -1;
	}

	// ca cert offset
	cert_offset += cert_size;

	// ca cert size  
	cert_size = ( (data[cert_offset + 2] << 8) | data[cert_offset + 3] ) + 4;
	if (cert_size >= CERT_SIZE) {
		printf("ca cert size %d is too big.\n", cert_size);
		return -1;
	}

	// calculate hash of ca cert
	if (calculate_sha256_hash(data + cert_offset, cert_size, ca_hash) != 0) {
		printf("can not calculate ca cert hash\n");
		return -1;
	}

	if (memcmp(ca_hash, expected_ca_hash, SHA256_HASH_SIZE) != 0) {
		printf("ca cert hash does not match.\n");
		return -1;
	}

	return 0;
}

// Load a partition image and verify if it is a product image based on the hash of ca cert
int do_verifyprod(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	
	// Load 0:SBL3 image to CONFIG_SYS_LOAD_ADDR
	if (load_mmc_image("0:SBL3") != 0) {
		printf("can not load kernel image.\n");
		return -1;
	}

	if (verify_hash((const uint8_t *) CONFIG_SYS_LOAD_ADDR) != 0) {
		printf("Imgae is not prod image.\n");
		return -1;
	}

	printf("Image is prod image.\n");
	return 0;
}

U_BOOT_CMD(
	verifyprod,   CONFIG_SYS_MAXARGS, 1,  do_verifyprod,
	"verify if the image is a product image.",
	"addr [addr ...]\n"
	"    - verify if FW is security enabled."
);

#define MAX_KERNEL_SIZE 0x1000000
extern int rover_get_vcounter(uint *virtual_counter);

static int compare_ver(const void * data, const size_t size)
{
	const char *fit_config_ver = "config@1";
	void *hdr = (void*) data + sizeof(Mbn_Hdr);
	int cfg_noffset;
	int ret = 0;
	char *desc = NULL;
	char *endptr = NULL;
	uint kernel_ver = 0;
	uint atmel_ver = -1;

	if (size >= MAX_KERNEL_SIZE) {
		printf("Kernel image size %u is too big.\n", size);
		return -1;
	}

	switch (genimg_get_format(hdr)) {
	case IMAGE_FORMAT_FIT:
		printf("FIT image found\n");

		if (!fit_check_format(hdr)) {
			printf("Bad FIT image format!\n");
			return -1;
		}

		cfg_noffset = fit_conf_get_node (hdr, fit_config_ver);
		if (cfg_noffset < 0) {
			// Wasn't able to find the version in kernel image.
			printf ("Failed to find kernel config node.\n");	
			return -1;
		}

		// Extract the description field.
		ret = fit_get_desc (hdr, cfg_noffset, &desc);

		if (ret != 0) {
			printf ("Failed to read kernel virtual counter.\n");
			return -1;
		}
		
		// Found version in text format and convert char* to int.
		kernel_ver = (unsigned int) simple_strtoul (desc, &endptr, 10);

		if (*endptr != 0) {
			printf ("kernel version %s is not an integer.\n", desc);
			return -1;
		}

		printf ("Kernel version: %d\n", kernel_ver);

		ret = rover_get_vcounter (&atmel_ver);

		if (ret < 0) {
			printf ("Failed to read atmel virtual counter.\n");
			return -1;
		}

		if (atmel_ver > kernel_ver) {
			printf ("Kernel rollback has been detected.\n");
			return -1;
		}
		break;
	default:
		printf("Unknown image format!\n");
		return -1;
	}

	return 0;
}


static int check_kernel_ver(ulong addr)
{
	void *hdr = (void *)addr;
	const void * data;
	size_t size;

	printf("\n## Checking image has right version at %08lx ...\n", addr);

	switch (genimg_get_format(hdr)) {
	case IMAGE_FORMAT_FIT:
		printf("FIT image found\n");

		if (!fit_check_format(hdr)) {
			puts("Bad FIT image format!\n");
			return -1;
		}

		if (search(hdr, "hlos", 4, &data, &size) < 0) {
			printf("Failed to find hlos sub image\n");
			return -1;
		}

		if (compare_ver(data, size) != 0){
			printf("Failed to verify image version.\n");
			return -1;
		}

		printf("Image version is OK.\n");
		return 0;
	default:
		printf("Unknown image format!\n");
		break;
	}

	return -1;
}

int do_checkver(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{
	if (argc < 2) {
		return check_kernel_ver(load_addr);
	}
	else {
		ulong   addr;
		addr = simple_strtoul(argv[1], NULL, 16);
		return check_kernel_ver(addr);
	}
}

U_BOOT_CMD(
        checkver,   CONFIG_SYS_MAXARGS, 1,  do_checkver,
        "check if the kernel image has the right rollback prevention version.",
        "addr [addr ...]\n"
        "    - check if FW version is OK."
);
