/*
 *
 * Copyright (c) 2016-2018 Symantec Corporation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 */

#ifndef _CPC_H_
#define _CPC_H_

#include <linux/printk.h>

#define DOTTED_IP_ADDR_MAX_LEN 40

#define LOGLEVEL_EMERG          0       /* system is unusable */
#define LOGLEVEL_ALERT          1       /* action must be taken immediately */
#define LOGLEVEL_CRIT           2       /* critical conditions */
#define LOGLEVEL_ERR            3       /* error conditions */
#define LOGLEVEL_WARNING        4       /* warning conditions */
#define LOGLEVEL_NOTICE         5       /* normal but significant condition */
#define LOGLEVEL_INFO           6       /* informational */
#define LOGLEVEL_DEBUG          7       /* debug-level messages */

#define PR_GENERIC(LEVEL, ...)					\
	do {								\
		if (cpc_dbg_level >= LOGLEVEL_ ##LEVEL)			\
			printk(KERN_ ##LEVEL   CPC_DEV_NAME ": " __VA_ARGS__); \
	} while (0)
#define PR_EMERG(...)   PR_GENERIC(EMERG,   __VA_ARGS__)
#define PR_ALERT(...)   PR_GENERIC(ALERT,   __VA_ARGS__)
#define PR_CRIT(...)    PR_GENERIC(CRIT,    __VA_ARGS__)
#define PR_ERR(...)     PR_GENERIC(ERR,     __VA_ARGS__)
#define PR_WARNING(...) PR_GENERIC(WARNING, __VA_ARGS__)
#define PR_NOTICE(...)  PR_GENERIC(NOTICE,  __VA_ARGS__)
#define PR_INFO(...)    PR_GENERIC(INFO,    __VA_ARGS__)
#define PR_DEBUG(...)   PR_GENERIC(DEBUG,   __VA_ARGS__)

#define CPC_DEV_NAME  "cpc"
#define CPC_DEV_ENTRY "ecm_classifier_sym"

#endif /* _CPC_H_ */

