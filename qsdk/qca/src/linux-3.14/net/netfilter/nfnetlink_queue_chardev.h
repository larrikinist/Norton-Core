/*
 * Additional char driver header for nfnetlink_queue_core.c:
 *
 * (C) 2017-2018 Chris Beaumont <christophe_beaumont@symantec.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef NFNETLINK_QUEUE_CHARDEV_H_
#define NFNETLINK_QUEUE_CHARDEV_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define NFQCD_CMD_VERDICT_ACCEPT 'a'
#define NFQCD_CMD_VERDICT_REPEAT 'r'
#define NFQCD_CMD_VERDICT_DROP   'd'

#define NFQCD_CHARDEV "/dev/nfq"

#define NFQCD_MAX_QUEUE_NUM 16

struct nfqcd_msg_hdr {
    uint16_t  cmd;
    uint8_t   in_mac[6];
    uint32_t  id;
    uint32_t  len;
    uint16_t  mark;
} __attribute__((packed));

struct nfqcd_resp {
    uint16_t  cmd;
    uint16_t  mark;
    uint32_t  id;
} __attribute__((packed));

#endif
