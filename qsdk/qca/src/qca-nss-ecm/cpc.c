/*
 *
 * Copyright (c) 2016-2018 Symantec Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/slab.h>		/* kzalloc() kfree() */
#include <linux/string.h>	/* strsep() */
#include <linux/delay.h>	/* msleep() */
#include <linux/inet.h>		/* in4_pton() */
#include <linux/rbtree.h>
#include <net/ipv6.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>

#include "ecm_types.h"
#include "ecm_db_types.h"
#include "ecm_tracker.h"
#include "ecm_state.h"
#include "ecm_classifier.h"
#include "ecm_db.h"
#include "ecm_state.h"
#include "ecm_classifier_default.h"
#include "ecm_classifier_pcc_public.h"

#include "cpc.h"

MODULE_AUTHOR("Symantec, Corp.");
MODULE_DESCRIPTION("Classifier for Parental Control");
MODULE_LICENSE("GPL");

static struct ecm_classifier_pcc_registrant ecm_classifier_registrant;

/* Our local acceleration cache */
struct cpc_accel_cache_t {
	struct rb_node node;
	__be32 src_ip;
	__be32 dst_ip;
	int src_port;
	int dst_port;
	int protocol;
};
static struct rb_root cpc_accel_cache;
static DEFINE_SPINLOCK(cpc_accel_cache_lock);

/* ECM DB listener */
static struct ecm_db_listener_instance *cpc_db_li;

/* debugfs dentry object */
static struct dentry *cpc_dentry;

/* debufs variable entries */
static u32 cpc_enabled;
static u32 cpc_always_ipv4;
static u32 cpc_always_ipv6;
static u8  cpc_dbg_level;

/* Carry this across the entire file */
static const char *cpc_dev_name  = CPC_DEV_NAME;
static const char *cpc_dev_entry = CPC_DEV_ENTRY;

/**
 * @brief Convert NIN4 address to string.
 * The result is copied into an existing buffer _str_, expected to be
 * DOTTED_IP_ADDR_MAX_LEN.
 *
 * @param[inout] str
 * 	Buffer of DOTTED_IP_ADDR_MAX_LEN size
 */
static void cpc_nin4_addr_to_str(const char* str, unsigned int str_len,
				 __be32 nin4_addr)
{
	BUG_ON(str_len != DOTTED_IP_ADDR_MAX_LEN);

	ip_addr_t ip_addr;
	ECM_NIN4_ADDR_TO_IP_ADDR(ip_addr, nin4_addr);
	ecm_ip_addr_to_string(str,ip_addr);
}

/**
 * @brief Initialize a cache entry.
 * This makes certain that the entrie's
 * src_ip is always less than the dst_ip. This is to avoid duplicate
 * entries given a bi-directional stream.
 *
 * @note Source/Dest ip/port should all be in network byte order.
 * @note The sequence of parameters matches the sequence of entries
 *       when the command is called
 */
static void cpc_accel_cache_entry_init(struct cpc_accel_cache_t * entry,
				       __be32 src_ip_n, int src_port_n,
				       int protocol,
				       __be32 dst_ip_n, int dst_port_n)
{
	/*
	 * We only want to keep/query one bi-directional stream
	 */
	if (src_ip_n < dst_ip_n) {
		entry->src_ip = src_ip_n;
		entry->src_port = src_port_n;
		entry->dst_ip = dst_ip_n;
		entry->dst_port = dst_port_n;
	} else {
		entry->src_ip = dst_ip_n;
		entry->src_port = dst_port_n;
		entry->dst_ip = src_ip_n;
		entry->dst_port = src_port_n;
	}
	entry->protocol = protocol;
}

static int cpc_accel_cache_cmp(struct cpc_accel_cache_t *left,
			       struct cpc_accel_cache_t *right)
{
	if (left->src_ip < right->src_ip)
		return 1;
	else if (left->src_ip > right->src_ip)
		return -1;
	else if (left->src_port < right->src_port)
		return 1;
	else if (left->src_port > right->src_port)
		return -1;
	else if (left->dst_ip < right->dst_ip)
		return 1;
	else if (left->dst_ip > right->dst_ip)
		return -1;
	else if (left->dst_port < right->dst_port)
		return 1;
	else if (left->dst_port > right->dst_port)
		return -1;
	else if (left->protocol < right->protocol)
		return 1;
	else if (left->protocol > right->protocol)
		return -1;
	else
		return 0;
}

static struct cpc_accel_cache_t *cpc_accel_cache_search(
			struct rb_root *root,
			struct cpc_accel_cache_t *conn)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct cpc_accel_cache_t *one_entry =
			container_of(node, struct cpc_accel_cache_t, node);
		int result;

		result = cpc_accel_cache_cmp(one_entry, conn);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return one_entry;

	}
	return NULL;
}

static int cpc_accel_cache_insert(struct rb_root *root,
				  struct cpc_accel_cache_t *conn)
{
	struct rb_node **new = &(root->rb_node);
	struct rb_node *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct cpc_accel_cache_t *one_entry =
			container_of(*new, struct cpc_accel_cache_t, node);

		int result = cpc_accel_cache_cmp(one_entry, conn);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&conn->node, parent, new);
	rb_insert_color(&conn->node, root);

	return true;
}

static int cpc_accel_cache_erase(struct rb_root *root,
				 struct cpc_accel_cache_t *conn)
{
	struct cpc_accel_cache_t *del;

	del = cpc_accel_cache_search(root, conn);
	if (del) {
		rb_erase(&del->node, root);
		kfree(del);
	}

	return true;
}

static void cpc_accel_cache_dump(struct rb_root *root)
{
	struct rb_node *node;
	char src_ip_str[DOTTED_IP_ADDR_MAX_LEN];
	char dst_ip_str[DOTTED_IP_ADDR_MAX_LEN];

	for (node = rb_first(root); node; node = rb_next(node)) {
		struct cpc_accel_cache_t *one_entry =
			rb_entry(node, struct cpc_accel_cache_t, node);

		cpc_nin4_addr_to_str(src_ip_str, DOTTED_IP_ADDR_MAX_LEN,
				     one_entry->src_ip);
		cpc_nin4_addr_to_str(dst_ip_str, DOTTED_IP_ADDR_MAX_LEN,
				     one_entry->dst_ip);

		PR_INFO("src=%s:%u dst=%s:%u\n",
			src_ip_str, ntohs(one_entry->src_port),
			dst_ip_str, ntohs(one_entry->dst_port));
	}
}

static void cpc_accel_cache_free(struct rb_root *root)
{
	struct rb_node *node;

	while ((node = rb_first(root)) != NULL) {
		struct cpc_accel_cache_t *one_entry =
			rb_entry(node, struct cpc_accel_cache_t, node);
		rb_erase(&one_entry->node, root);
		kfree(one_entry);
	}

	/* There should be absolutely nothing to display. */
	cpc_accel_cache_dump(root);
}

static void cpc_db_connection_removed(void *arg,
				      struct ecm_db_connection_instance *ci)
{
	struct cpc_accel_cache_t one_entry;

	ip_addr_t src_ip;  /* This is internal ECM DB format */
	__be32 src_ip_n;   /* This is NETWORK order */
	int src_port_n;	   /* This is NETWORK order */

	ip_addr_t dst_ip;  /* This is internal ECM DB format */
	__be32 dst_ip_n;   /* This is NETWORK order */
	int dst_port_n;    /* This is NETWORK order */

	ecm_db_connection_from_address_get(ci, src_ip);
	ECM_IP_ADDR_TO_NIN4_ADDR(src_ip_n, src_ip);
	ecm_db_connection_to_address_get(ci, dst_ip);
	ECM_IP_ADDR_TO_NIN4_ADDR(dst_ip_n, dst_ip);

	src_port_n = htons(ecm_db_connection_from_port_get(ci));
	dst_port_n = htons(ecm_db_connection_to_port_get(ci));

	cpc_accel_cache_entry_init(&one_entry,
		src_ip_n, src_port_n,
		ecm_db_connection_protocol_get(ci),
		dst_ip_n, dst_port_n
	);

	/* We are done with the connection, so remove from the cache */
	spin_lock_bh(&cpc_accel_cache_lock);
	cpc_accel_cache_erase(&cpc_accel_cache, &one_entry);
	spin_unlock_bh(&cpc_accel_cache_lock);
}

static ecm_classifier_pcc_result_t cpc_okay_to_accel_v4(
		struct ecm_classifier_pcc_registrant *r,
		uint8_t *src_mac, __be32 src_ip, int src_port,
		uint8_t *dst_mac, __be32 dst_ip, int dst_port,
		int protocol)
{
	struct cpc_accel_cache_t entry;
	struct cpc_accel_cache_t *accelerate_this;
	char src_ip_str[DOTTED_IP_ADDR_MAX_LEN];
	char dst_ip_str[DOTTED_IP_ADDR_MAX_LEN];

	if (cpc_always_ipv4) {
		if (cpc_dbg_level >= LOGLEVEL_DEBUG) {
			cpc_nin4_addr_to_str(src_ip_str,
				DOTTED_IP_ADDR_MAX_LEN, src_ip);
			cpc_nin4_addr_to_str(dst_ip_str,
				DOTTED_IP_ADDR_MAX_LEN, dst_ip);
			PR_DEBUG("ALWAYS src=%s:%u dst=%s:%u\n",
				src_ip_str, ntohs(src_port),
				dst_ip_str, ntohs(dst_port));
		}
		return ECM_CLASSIFIER_PCC_RESULT_PERMITTED;
	}

	cpc_accel_cache_entry_init(&entry,
		src_ip, src_port,
		protocol,
		dst_ip, dst_port
	);

	spin_lock_bh(&cpc_accel_cache_lock);
	accelerate_this = cpc_accel_cache_search(&cpc_accel_cache, &entry);
	spin_unlock_bh(&cpc_accel_cache_lock);

	if (accelerate_this != NULL) {
		if (cpc_dbg_level >= LOGLEVEL_DEBUG) {
			cpc_nin4_addr_to_str(src_ip_str,
				DOTTED_IP_ADDR_MAX_LEN, src_ip);
			cpc_nin4_addr_to_str(dst_ip_str,
				DOTTED_IP_ADDR_MAX_LEN, dst_ip);
			PR_DEBUG("ECM_CLASSIFIER_PCC_RESULT_PERMITTED "
				"src=%s:%u dst=%s:%u\n",
				src_ip_str, ntohs(src_port),
				dst_ip_str, ntohs(dst_port));
		}
		return ECM_CLASSIFIER_PCC_RESULT_PERMITTED;
	}

	if (cpc_dbg_level >= LOGLEVEL_DEBUG) {
		cpc_nin4_addr_to_str(src_ip_str,
			DOTTED_IP_ADDR_MAX_LEN, src_ip);
		cpc_nin4_addr_to_str(dst_ip_str,
			DOTTED_IP_ADDR_MAX_LEN, dst_ip);
		PR_DEBUG("ECM_CLASSIFIER_PCC_RESULT_NOT_YET "
			"src=%s:%u dst=%s:%u\n",
			src_ip_str, ntohs(src_port),
			dst_ip_str, ntohs(dst_port));
	}
	return ECM_CLASSIFIER_PCC_RESULT_NOT_YET;
}

static ecm_classifier_pcc_result_t cpc_okay_to_accel_v6(
		struct ecm_classifier_pcc_registrant *r,
		uint8_t *src_mac, struct in6_addr *src_ip, int src_port,
		uint8_t *dst_mac, struct in6_addr *dst_ip, int dst_port,
		int protocol)
{
	if (cpc_always_ipv6)
		return ECM_CLASSIFIER_PCC_RESULT_PERMITTED;

	return ECM_CLASSIFIER_PCC_RESULT_DENIED;
}

static void cpc_ref(struct ecm_classifier_pcc_registrant *r)
{
	atomic_inc(&r->ref_count);
}

static void cpc_deref(struct ecm_classifier_pcc_registrant *r)
{
	atomic_dec(&r->ref_count);
}

/*
 * @brief Since registering with ECM during init() will create a reference
 * between ECM and CPC, it will not be possible to unload the CPC driver
 * in the exit() (rmmod will refuse altogether). We'll have to explicitly
 * register thru a command
 */
static int cpc_register_with_ecm(void)
{
	if (cpc_enabled) {
		PR_WARNING("CPC already enabled.\n");
		return true;
	}

	/* Initialize pcc registrant struct to register with pcc. */
	ecm_classifier_registrant.version = 1;
	atomic_set(&ecm_classifier_registrant.ref_count, 1);
	ecm_classifier_registrant.this_module = THIS_MODULE;

	ecm_classifier_registrant.okay_to_accel_v4 = cpc_okay_to_accel_v4;
	ecm_classifier_registrant.okay_to_accel_v6 = cpc_okay_to_accel_v6;

	ecm_classifier_registrant.ref = cpc_ref;
	ecm_classifier_registrant.deref = cpc_deref;

	/* Register with PCC. */
	if (ecm_classifier_pcc_register(&ecm_classifier_registrant) != 0) {
		PR_ERR("Cannot register with ECM.\n");
		return false;
	}

	/* Make sure our listener is properly allocated */
	if (NULL == cpc_db_li) {
		cpc_db_li = ecm_db_listener_alloc();
		if (NULL == cpc_db_li) {
			DEBUG_ERROR("Failed to allocate listener");
			return false;
		}
	}

	/* Add the listener into the database */
	ecm_db_listener_add(cpc_db_li,
			    NULL /* cpc_db_iface_added */,
			    NULL /* cpc_db_iface_removed */,
			    NULL /* cpc_db_node_added */,
			    NULL /* cpc_db_node_removed */,
			    NULL /* cpc_db_host_added */,
			    NULL /* cpc_db_host_removed */,
			    NULL /* cpc_db_mapping_added */,
			    NULL /* cpc_db_mapping_removed */,
			    NULL /* cpc_db_connection_added */,
			    cpc_db_connection_removed,
			    NULL /* cpc_db_listener_final */,
			    cpc_db_li);

	PR_INFO("Attaching to ECM.\n");

	/*
	 * After above register() call, PCC will get another ref, so the count
	 * will be 2. So, it's safe to release our ref count at this point.
	 */
	ecm_classifier_registrant.deref(&ecm_classifier_registrant);

	cpc_enabled = true;

	return true;
}

/*
 * @brief This is the function for the unregistering from ECM. The command must
 * be called prior to the driver being unloaded (rmmod).
 */
static int cpc_unregister_with_ecm(void)
{
	int attempts = 2;

	if (!cpc_enabled) {
		PR_WARNING("Not associated with ECM. Safely return.\n");
		return true;
	}

	PR_INFO("Detaching from ECM.\n");

	/*
	 * Release our ref to the listener.
	 * This will cause it to be unattached to the db listener list.
	 */
	if (cpc_db_li) {
		ecm_db_listener_deref(cpc_db_li);
		cpc_db_li = NULL;
	}

	ecm_classifier_pcc_unregister_begin(&ecm_classifier_registrant);

	/* Wait until reference goes to zero before exiting the module. */
	while ((atomic_read(&ecm_classifier_registrant.ref_count) > 0) &&
	       (attempts != 0)) {
		attempts--;
		msleep(1000);
	}

	if (attempts == 0) {
		PR_WARNING("Could not detach from ECM.\n");
		return false;
	}

	cpc_enabled = false;

	return true;
}

/** @brief Overwrite of in4_pton so we can have error output
 *
 *  @param msg A char buffer containing the IPv4 address to be converted
 *  @param ip The binary representation of the IPv4 address
 *  @return 1 on success and zero on any error (similar to in4_pton())
 */
static int cpc_in4_pton(char *ip_txt, __be32 *ip)
{
	const char *end;

	if (in4_pton(ip_txt, -1, (u8 *)ip, '\0', &end) > 0) {
		if (*end != '\0') {
			PR_WARNING("Extra text at end of: %s.\n", ip_txt);
			return 0;
		}
	} else {
		PR_WARNING("Illegal IP address: %s.\n", ip_txt);
		return 0;
	}
	return 1;
}

/** @brief This function will decelerate all currently accelerated connections
 *         where either the source or destination IP address matches the input
 *         IP address.
 *
 * Returns 0 on error.
 *         1 on success.
 */
static int cpc_decelerate_per_ip(char *ip_to_del_pchar)
{
	__be32 ip_to_del_be32;
	struct rb_node *node;
	struct rb_root *root = &cpc_accel_cache;

	PR_DEBUG("Decelerating per ip addr: %s\n", ip_to_del_pchar);

	/* Converts char* to __be32 before comparison. */
	if (cpc_in4_pton(ip_to_del_pchar, &ip_to_del_be32) == 0)
		return 0;

	spin_lock_bh(&cpc_accel_cache_lock);

	/* Walk the tree and decelerate all matching connections. */
	for (node = rb_first(root); node; node = rb_next(node)) {
		struct cpc_accel_cache_t *one_entry =
			rb_entry(node, struct cpc_accel_cache_t, node);

		if (one_entry == NULL)
			continue;

		if (one_entry->src_ip == ip_to_del_be32 ||
		    one_entry->dst_ip == ip_to_del_be32) {
			/* Decelerate this connection. */
			ecm_classifier_pcc_deny_accel_v4(NULL,
				one_entry->src_ip,
				one_entry->src_port,
				NULL,
				one_entry->dst_ip,
				one_entry->dst_port,
				one_entry->protocol);

			/* NOTE: RB Tree node deletion will be handled
			 * automaticly when ecm callback fires due to a
			 * connection being removed. */
		}
	}

	spin_unlock_bh(&cpc_accel_cache_lock);

	return 1;
}

/** @brief Processed payload received thru write()
 *  @param msg A char buffer containing the message to be processed
 *         Possible forms:
 *         [0]
 *         <CMD>
 *         where CMD:
 *             l = Register the driver with ECM
 *             u = Un-register from ECM
 *             p = Dump all currently accelerated connections to log.
 *
 *         [0]   [1]
 *         <CMD>/<src_ip>
 *         where CMD:
 *             i = Decelerate all connections from src_ip
 *
 *         [0]   [1]      [2]        [3]     [4]       [5]
 *         <CMD>/<src_ip>/<src_port>/<proto>/<dst_ip>/<dst_port>
 *         where CMD:
 *             a = Accelerate connection
 *             d = Decelerate connection
 *             x = Remove connection from cache
 *
 * @note for convenience, the order of the parameters passed for 'adx' in
 *       commands is maintained in the call to cpc_accel_cache_entry_init()
 */
#define ECM_CLASSIFIER_SYMC_MAX_COMMAND_FIELDS 6

#define K_CPC_LOAD   'l'
#define K_CPC_UNLOAD 'u'
#define K_DUMP_ALL   'p'
#define K_CONN_ACCEL 'a'
#define K_CONN_DECEL 'd'
#define K_DEV_DECEL  'i'
#define K_DEL_CACHE  'x'

static int cpc_handle_message(char *msg)
{
	int retval = -EINVAL;

	char *tok;
	char *next;
	int field_count;
	char *fields[ECM_CLASSIFIER_SYMC_MAX_COMMAND_FIELDS];

	char cmd;
	int proto;
	uint16_t src_port;
	uint16_t dst_port;

	/*
	 * Since ecp_classifier_pcc_*_accel_v*() handles NETWORK order
	 * arguments, get them in the correct order.
	 */
	__be32 src_ip_n;
	__be32 dst_ip_n;
	uint16_t src_port_n;
	uint16_t dst_port_n;

	/* Split the buffer into its fields. */
	field_count = 0;
	tok  = msg;
	next = msg;
	strsep(&msg, "\n");  /* strip any trailing '\n' in the way. */

	/* Tokenize the command that we just received */
	while (tok != NULL &&
	       field_count <= ECM_CLASSIFIER_SYMC_MAX_COMMAND_FIELDS) {
		strsep(&next, "/");
		fields[field_count] = tok;
		field_count++;
		tok = next;
	}

	if (field_count == 0) {
		PR_WARNING("Empty input buffer.\n");
		return retval;
	}

	/* Start with the command. */
	if (strlen(fields[0]) != 1) {
		PR_WARNING("Illegal command %s.\n", fields[0]);
		return retval;
	}

	cmd = *fields[0];

	if (field_count == 1) {
		switch (cmd) {
		case K_CPC_LOAD:
			if (!cpc_register_with_ecm())
				retval = -EINVAL;
			else
				retval = 0;
			break;
		case K_CPC_UNLOAD:
			if (!cpc_unregister_with_ecm())
				retval = -EINVAL;
			else
				retval = 0;
			break;
		case K_DUMP_ALL:
			spin_lock_bh(&cpc_accel_cache_lock);
			cpc_accel_cache_dump(&cpc_accel_cache);
			spin_unlock_bh(&cpc_accel_cache_lock);
			retval = 0;
			break;
		default:
			PR_WARNING("Unknown command %c.\n", cmd);
			break;
		}
		return retval;
	}

	/* If we are not yet registered with ECM, all the rest makes no sense */
	if (!cpc_enabled)
		return retval;

	/* Handle commands with only 1 argument */
	if (field_count == 2 && cmd == K_DEV_DECEL) {
		if (cpc_decelerate_per_ip(fields[1]) == 0) {
			PR_ERR("Can't decelerate connection per IP address.\n");
			return -EINVAL;
		}
		return 0;
	}

	if (field_count != ECM_CLASSIFIER_SYMC_MAX_COMMAND_FIELDS) {
		PR_WARNING("Invalid field count %d(%s).\n", field_count, msg);
		return retval;
	}

	if (cpc_in4_pton(fields[1], &src_ip_n) == 0)
		return retval;

	retval = kstrtou16(fields[2], 10, &src_port);
	if (retval != 0) {
		PR_WARNING("Wrong src_port (err=%d) %s.\n", retval, fields[2]);
		return retval;
	}
	src_port_n = htons(src_port);

	retval = kstrtoint(fields[3], 10, &proto);
	if (retval != 0) {
		PR_WARNING("Wrong protocol (err=%d) %s.\n", retval, fields[3]);
		return retval;
	}

	if (cpc_in4_pton(fields[4], &dst_ip_n) == 0)
		return retval;

	retval = kstrtou16(fields[5], 10, &dst_port);
	if (retval != 0) {
		PR_WARNING("Wrong dst_port (err=%d) %s.\n", retval, fields[5]);
		return retval;
	}
	dst_port_n = htons(dst_port);

	/* NOTE:
	 * src_mac and dest_mac are not used in
	 * ecm_classifier_pcc_permit_*_v4(), so passing in NULL.
	 */
	switch (cmd) {
	case K_CONN_ACCEL: {
		struct cpc_accel_cache_t *new_entry;

		PR_DEBUG("Accel connection: %s:%u | %s:%u | %d.\n",
			  fields[1], src_port,
			  fields[4], dst_port,
			  proto);

		/*
		 * There is a discrepancy between documentation and header+src
		 * files. This does not return anything.
		 */
		ecm_classifier_pcc_permit_accel_v4(NULL, src_ip_n, src_port_n,
						   NULL, dst_ip_n, dst_port_n,
						   proto);

		/*
		 * Save the connection to local cache so we can
		 * accelerate if/when PCC is ready for it
		 */
		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (new_entry == NULL)
			return -ENOMEM;

		cpc_accel_cache_entry_init(new_entry,
			src_ip_n, src_port_n,
			proto,
			dst_ip_n, dst_port_n
		);

		spin_lock_bh(&cpc_accel_cache_lock);
		cpc_accel_cache_insert(&cpc_accel_cache, new_entry);
		spin_unlock_bh(&cpc_accel_cache_lock);
		break;
	}
	case K_CONN_DECEL: {
		PR_DEBUG("Decel connection: %s:%u | %s:%u | %d.\n",
			  fields[1], src_port,
			  fields[4], dst_port,
			  proto);
		/*
		 * There is a discrepancy between documentation and header+src
		 * files. This does not return anything.
		 */
		ecm_classifier_pcc_deny_accel_v4(NULL, src_ip_n, src_port_n,
						 NULL, dst_ip_n, dst_port_n,
						 proto);
		break;
	}
	case K_DEL_CACHE: {
		struct cpc_accel_cache_t one_entry;

		PR_DEBUG("Erase connection: %s:%u | %s:%u | %d.\n",
			  fields[1], src_port,
			  fields[4], dst_port,
			  proto);

		cpc_accel_cache_entry_init(&one_entry,
			src_ip_n, src_port_n,
			proto,
			dst_ip_n, dst_port_n
		);

		spin_lock_bh(&cpc_accel_cache_lock);
		cpc_accel_cache_erase(&cpc_accel_cache, &one_entry);
		spin_unlock_bh(&cpc_accel_cache_lock);
		break;
	}
	default:
	{
		PR_WARNING("Unknown command %c.\n", cmd);
		return -EINVAL;
	}
	}

	return 0;
}

/*
 * Factoring in enough space for the longest possible command:
 * 2xIPv6 + 2x5-digit ports          = (2*INET6_ADDRLEN) + 2*5 = 106
 * cmd + delimiters + protocol + EOL =  10
 * Rounding up to 128
 */
#define MAX_CMD_LEN 128
static ssize_t cpc_set_command(struct file *file, const char __user *user_buf,
			       size_t count, loff_t *ppos)
{
	ssize_t retval;
	char cmd_buf[MAX_CMD_LEN];
	size_t cmd_buf_size;

	cmd_buf_size = min(count, sizeof(cmd_buf) - 1);
	if (copy_from_user(cmd_buf, user_buf, cmd_buf_size))
		return -EFAULT;
	cmd_buf[cmd_buf_size] = '\0';

	retval = cpc_handle_message(cmd_buf);
	if (retval == 0)
		retval = cmd_buf_size;

	return retval;
}

static const struct file_operations cpc_cmd_fops = {
	.open = simple_open,
	.write = cpc_set_command,
};

int cpc_init_module(void)
{
	const char *dbg_level = "dbg_level";
	const char *enabled = "enabled";
	const char *always_ipv4 = "always_ipv4";
	const char *always_ipv6 = "always_ipv6";
	const char *cmd = "cmd";

	/* We need to initialize very early so the first message is printed. */
	cpc_dbg_level = LOGLEVEL_INFO;

	PR_INFO("Starting %s module.\n", cpc_dev_name);

	cpc_dentry = debugfs_create_dir(cpc_dev_entry, NULL);
	if (!cpc_dentry) {
		PR_ERR("Cannot create '%s' directory in debugfs.\n",
			   cpc_dev_entry);
		return -1;
	}

	/* Allow to force hardware acceleration for all traffic */
	if (!debugfs_create_u8(dbg_level, S_IRUGO | S_IWUSR,
			       cpc_dentry, &cpc_dbg_level)) {
		PR_ERR("Failed to create '%s' file in debugfs.\n",
			   dbg_level);
		debugfs_remove_recursive(cpc_dentry);
		return -1;
	}

	/* Is the module fully loaded and enabled? */
	cpc_enabled = false;
	if (!debugfs_create_bool(enabled, S_IRUGO,
				 cpc_dentry, &cpc_enabled)) {
		PR_ERR("Failed to create '%s' file in debugfs.\n",
			   enabled);
		debugfs_remove_recursive(cpc_dentry);
		return -1;
	}

	/* Allow to force hardware acceleration for all traffic IPv4 */
	cpc_always_ipv4 = false;
	if (!debugfs_create_bool(always_ipv4, S_IRUGO | S_IWUSR,
				 cpc_dentry, &cpc_always_ipv4)) {
		PR_ERR("Failed to create '%s' file in debugfs.\n",
			   always_ipv4);
		debugfs_remove_recursive(cpc_dentry);
		return -1;
	}

	/* Allow to force hardware acceleration for all traffic IPv6 */
	cpc_always_ipv6 = false;
	if (!debugfs_create_bool(always_ipv6, S_IRUGO | S_IWUSR,
				 cpc_dentry, &cpc_always_ipv6)) {
		PR_ERR("Failed to create '%s' file in debugfs.\n",
			   always_ipv6);
		debugfs_remove_recursive(cpc_dentry);
		return -1;
	}

	/* Main variable addressed to toggle acceleration for a stream */
	if (!debugfs_create_file(cmd, S_IWUSR,
				 cpc_dentry, NULL, &cpc_cmd_fops)) {
		PR_ERR("Failed to create '%s' file in in debugfs.\n", cmd);
		debugfs_remove_recursive(cpc_dentry);
		return -1;
	}

	/* Will be properly allocated when attemtping to register with ECM */
	cpc_db_li = NULL;

	/* A non 0 return means init_module failed; module can't be loaded. */
	return 0;
}

void cpc_exit_module(void)
{
	PR_INFO("Cleaning up and exiting %s module.\n", cpc_dev_name);

	/* Scrub the cache */
	cpc_accel_cache_free(&cpc_accel_cache);

	debugfs_remove_recursive(cpc_dentry);
}

module_init(cpc_init_module);
module_exit(cpc_exit_module);
