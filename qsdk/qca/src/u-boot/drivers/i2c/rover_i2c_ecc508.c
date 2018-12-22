/*
 *
 * Copyright (C) 2016 Symantec Corporation
 *
 * Contact: Boris Presman <boris_presman@symantec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <common.h>
#include "rover_i2c.h"

static uchar counter0_cmd[] = { 0x7, 0x24, 0x00, 0x00, 0x00, 0x0c, 0xfd };
static uchar counter1_cmd[] = { 0x7, 0x24, 0x00, 0x01, 0x00, 0x05, 0x7d };

#define I2C_ECC508_ADDR 0x60
#define MAX_WAKEUP_RETRIES	5
#define MAX_COUNTER_READ_RETRIES	3

static int send_wake(void)
{
    uchar buf = 0;
    int num_tries = 0;
    uchar rspBuf[7];
    int len;
    
    rover_i2c_write (0, 0, 1, &buf, 1);
    udelay(500);

    // Reading wakeup response.
    // NOTE: A read should return "04 11 33 43" at this point if ecc508 is awake.
    while ((len = rover_i2c_read (I2C_ECC508_ADDR, 0x0, 0x1, rspBuf, 4)) != 4 ) {
        num_tries++;
        if (num_tries == MAX_WAKEUP_RETRIES) {
            printf("Can't read wakeup response\n");
            return -1;
        }
        udelay(1000);
    }

    if (rspBuf[0] != 0x04  || rspBuf[1] != 0x11 ||
        rspBuf[2] != 0x33 || rspBuf[3] != 0x43) {
        printf ("ERROR: Failed to wakeup ECC508.\n");
        return -1;
    }

    return 0;
}

static void send_sleep(void)
{
   // Put the chip back to sleep.
    uchar buf = 0x2;
    rover_i2c_write (I2C_ECC508_ADDR, 0x2, 1, &buf, 1);
}

// Read the atmel counter
// Function returns 0 on success.
//          returns negative number on error.
// The counter value is saved in "val".
static int get_counter (uchar *counter_cmd, uint cmd_len, uint *val)
{
    uchar rspBuf[7];
    uint counter = 0;
    int num_tries = 0;
    int len = 0;
 
    if (counter_cmd == NULL || val == NULL)
	return -1;
   
    // Read counter.
    do {
        // Send read command.
        rover_i2c_write (I2C_ECC508_ADDR, 0x3, 1, counter_cmd,  cmd_len);
        udelay (20000);

        memset (rspBuf, 0, sizeof(rspBuf));
        len = rover_i2c_read (I2C_ECC508_ADDR, 0x0, 0x1, rspBuf, sizeof(rspBuf));
        num_tries++;
    } while (len < 0 && num_tries < MAX_COUNTER_READ_RETRIES);

    if (num_tries >= 3) {
        printf ("ERROR: Failed to read counter.\n");
        return -1;
    }

    counter = (rspBuf[4] << 24) | (rspBuf[3] << 16) |
              (rspBuf[2] << 8) | rspBuf[1];

    *val = counter;
    return 0;
}

// Get the virtual counter.
// Function returns 0 on success.
//          returns negative number on error.
// The counter value is saved in "virtual_counter".
int rover_get_vcounter (uint *virtual_counter)
{
    uint counter0 = 0;
    uint counter1 = 0;
    int ret_val = 0;
    int ret = 0;

    if (virtual_counter == NULL) {
        return -1;
    }

    if (send_wake() != 0) {
        ret = -1;
        goto out;
    }
    ret_val = get_counter (counter0_cmd, sizeof(counter0_cmd), &counter0);
    if (ret_val < 0) {
        printf ("ERROR: Failed to read counter 0.\n");
        ret = -1;
        goto out;
    }
    
    ret_val = get_counter (counter1_cmd, sizeof(counter1_cmd), &counter1);
    if (ret_val < 0) {
        printf ("ERROR: Failed to read counter 1.\n");
        ret = -1;
        goto out;
    }

    if (counter0 < counter1) {
        *virtual_counter = counter0;
    } else {
        *virtual_counter = counter1;
    }

    printf ("Counter0: %d\n", counter0);
    printf ("Counter1: %d\n", counter1);
    printf ("Virtual counter: %d\n", *virtual_counter);
out:
    send_sleep(); 
    return ret;
}

// u-boot command ecc508 will invoke this function.
int rover_i2c_ecc508 ()
{
    uint virtual_counter = 0;
    int ret_val = 0;

    ret_val = rover_get_vcounter (&virtual_counter);
    return ret_val;
}
