/*
 * NCP5623 LED chip driver.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <common.h>
#include <rover_i2c.h>

#define LED_SLAVE_ADDR	0x38
/* NCP5623 internal register code list - 3 most significant bits */
#define NCP5623_SHUTDOWN		0	/* Shut down */
#define NCP5623_CURRENT_STEP	1	/* LED Current Step */
#define NCP5623_RED_PWM			2	/* Red PWM */
#define NCP5623_GREEN_PWM		3	/* Green PWM */
#define NCP5623_BLUE_PWM		4	/* Blue PWM */
#define NCP5623_DIM_UP			5	/* Set Gradual Dimming
											Upward lend Target */
#define NCP5623_DIM_DOWN		6	/* Set Gradual Dimming
											Downward lend Target */
#define NCP5623_DIM_TIME		7	/* Gradual Dimming
											Time & run */

#define	NCP5623_SET_CMD(cmd, val)	(((cmd) << 5) | ((val) & 0x1f))

/* All NCP5623 register values are between 0 to 31 */
#define LED_VALUE_MASK	0x1F
#define NCP5623_MAX_LEDS	3
#define LED_MAX_BRIGHTNESS	LED_VALUE_MASK
#define LED_MAX_CURRENT		LED_VALUE_MASK
#define LED_MAX_LED_ID		7

static int g_leds_initialized = 0;

static int ncp5623_write_reg(uchar cmd)
{
	return rover_i2c_write(LED_SLAVE_ADDR, cmd, 1, 0, 0);
}

int rover_i2c_leds_init(void)
{
	int err = 0;
	int i;
	/* Turn off LEDs */
	err = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_SHUTDOWN, 0));
	if (err == 0) {
		err = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_CURRENT_STEP, 31));
		if (err == 0) {
			/* Switch off LEDs */
			for (i = 0; i < NCP5623_MAX_LEDS; i++) {
				err = ncp5623_write_reg(NCP5623_SET_CMD(i + NCP5623_RED_PWM, 0));
				if (err != 0) {
					printf("Turn off LED %d failed\n", i);
					break;
				}
			}
		}
	}

	if (err == 0)
		g_leds_initialized = 1;

	return err;
}

int rover_i2c_led_set(int led_id, int brightness)
{
	uchar cmd;
	int res;
	int i = 0;
/* led_id - bitmap of connected LED pins */
	if (led_id > LED_MAX_LED_ID || brightness > LED_MAX_BRIGHTNESS) {
		printf("Wrong parameters\n");
		return -1;
	}
	if (!g_leds_initialized) {
		if (rover_i2c_leds_init() != 0 ) {
			return -1;
		}
	}
	while (led_id) {
		if (led_id & 1) {		
			cmd = NCP5623_SET_CMD(i + NCP5623_RED_PWM, brightness);
			res = ncp5623_write_reg(cmd);
			if (res != 0) break;
		}
		i++;
		led_id >>=1;
	}
	return res;
}
/*
 * Gradual upward dimming
 * Destination (final) current step is always max (31)
 * initial_current - initial current step (should be less than 31)
 * time_per_step - [1..31] in 8 ms units
 * total transition time = (31 - initial_current)*time_per_step*8 ms
 */
int rover_i2c_led_dim_up(int led_id, int dest_brightness,
		int initial_current, int time_per_step)
{
	int res;
	int i = 0;
/* led_id - bitmap of connected LED pins */
	if (led_id > LED_MAX_LED_ID || dest_brightness > LED_MAX_BRIGHTNESS
			|| initial_current > LED_MAX_CURRENT - 1
			|| time_per_step > LED_VALUE_MASK) {
		printf("Wrong parameters\n");
		return -1;
	}
	if (!g_leds_initialized) {
		if (rover_i2c_leds_init() != 0 ) {
			return -1;
		}
	}

	/* Upward dimming */
	res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_CURRENT_STEP, initial_current));
	if (res == 0) {
		while (led_id) {
			if (led_id & 1) {
				res = ncp5623_write_reg(NCP5623_SET_CMD(i +
					NCP5623_RED_PWM, dest_brightness));
				if (res != 0) break;
			}
			i++;
			led_id >>= 1;			
		}
		if (res == 0) {
			res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_DIM_UP, 31));
			if (res == 0) {
				res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_DIM_TIME, time_per_step));
			} else {
				printf("NCP5623_DIM_UP cmd fails [%d]\n", res);
			}
		} else {
			printf("PWM command fails [%d]\n", res);
		}
	} else {
		printf("NCP5623_CURRENT_STEP fails [%d]\n", res);
	}
	return res;
}
/*
 * Gradual downward dimming
 * Initial current step is always maximal (31)
 * dest_current - final current step (should be less than 31)
 * time_per_step - [1..31] in 8 ms units
 * total transition time = (31 - dest_current)*time_per_step*8 ms
 */
int rover_i2c_led_dim_down(int led_id, int initial_brightness,
		int dest_current, int time_per_step)
{
	int res;
	int i = 0;
/* led_id - bitmap of connected LED pins */
	if (led_id > LED_MAX_LED_ID || initial_brightness > LED_MAX_BRIGHTNESS
			|| time_per_step > LED_VALUE_MASK || time_per_step < 1
			|| dest_current >  LED_MAX_CURRENT - 1) {
		printf("Wrong parameters\n");
		return -1;
	}
	if (!g_leds_initialized) {
		if (rover_i2c_leds_init() != 0 ) {
			return -1;
		}
	}

	/* Upward dimming */
	res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_CURRENT_STEP, 31));
	if (res == 0) {
		while (led_id) {
			if (led_id & 1) {
				res = ncp5623_write_reg(NCP5623_SET_CMD(i +
					NCP5623_RED_PWM, initial_brightness));
				if (res != 0) break;
			}
			i++;
			led_id >>= 1;			
		}

		if (res == 0) {
			res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_DIM_DOWN, dest_current));
			if (res == 0) {
				res = ncp5623_write_reg(NCP5623_SET_CMD(NCP5623_DIM_TIME, time_per_step));
			} else {
				printf("NCP5623_DIM_DOWN cmd fails [%d]\n", res);
			}
		} else {
			printf("PWM command fails [%d]\n", res);
		}
	} else {
		printf("NCP5623_CURRENT_STEP fails [%d]\n", res);
	}
	return res;
}
