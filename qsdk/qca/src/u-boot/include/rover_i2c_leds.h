/*
 * ROVER LED chip driver.
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
#ifndef _ROVER_I2C_LEDS_H_
#define _ROVER_I2C_LEDS_H_
/* LED Bitmap: 
white led - connected to pin 0 and 2
amber led - connected to pin 1 */

#define		ROVER_LED_AMBER	2
#define		ROVER_LED_WHITE	5

#define 	ROVER_LED_HALF_BRIGHTNESS	11
#define 	ROVER_LED_FULL_BRIGHTNESS	31

int rover_i2c_leds_init(void);
int rover_i2c_led_set(int led_id, int brightness);
int rover_i2c_led_dim_up(int led_id, int dest_brightness,
		int initial_current, int time_per_step);
int rover_i2c_led_dim_down(int led_id, int initial_brightness,
		int dest_current, int time_per_step);
#endif
