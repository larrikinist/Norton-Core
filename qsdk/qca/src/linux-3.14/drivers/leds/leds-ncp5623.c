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

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/leds.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/workqueue.h>
#include <linux/sysfs.h>
#include <linux/slab.h>

enum ncp5623_led_id {
	NCP5623_RED,
	NCP5623_GREEN,
	NCP5623_BLUE,
	NCP5623_MAX_COLOR,
};


static const struct i2c_device_id ncp5623_id[] = {
	{ "ncp5623" },
	{ }
};

static const char *ncp5623_name[] = {
		"RED", "GREEN", "BLUE"
};

MODULE_DEVICE_TABLE(i2c, ncp5623_id);


struct ncp5623 {
	struct mutex lock;
	struct ncp5623_led *leds;
	struct i2c_client	*client;
	/* Used for sysfs data */
	/* Gradual dimming parameters */
	u8 dimming_enable; /* ON - 1, OFF - 0 */
	u8 low_i_step; /* value [0..30] */
	u8 high_i_step;     /* usually max value  (31) */
	u8 transition_time_on;  /* percentage of delay_on */
	u8 transition_time_off; /* percentage of delay_off */
};


struct ncp5623_led {
	struct 	ncp5623	*ncp5623;
	struct 	work_struct	work;
	enum 	led_brightness	brightness;
	struct 	led_classdev	led_cdev;
	u8	led_group;	/* 3 bits mask */
	u8	initial_state;
	u8 	prev_brightness;
	char	name[32];
};

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

/* Only three drive pins are available for ncp5623 controller */
#define NCP5623_LED_GROUP_MASK			0x07

/* Encoding of flags field  */
#define NCP5623_FLAG_LED_GROUP_MASK		0x00000007	/* bits 0,1,2:
							defines led_group */
#define NCP5623_FLAG_INIT_STATE_MASK	0x00000078  /* bits 3,4,5,6:
							defines	driver "init_state" */
#define NCP5623_GET_FLAG_LED_GROUP(a)	((a) & NCP5623_FLAG_LED_GROUP_MASK)
#define NCP5623_SET_FLAG_LED_GROUP(f,i)	{ \
	(f) |= ((i) & NCP5623_FLAG_LED_GROUP_MASK); \
}
#define NCP5623_GET_FLAG_INIT_STATE(a)	(((a) & NCP5623_FLAG_INIT_STATE_MASK) >> 3)
#define NCP5623_SET_FLAG_INIT_STATE(f,s)	{ \
	(f) |= (((s) << 3) & NCP5623_FLAG_INIT_STATE_MASK); \
}

/* Initial state - up to 15  */
enum ncp5623_init_state {
	NCP5623_INIT_NOP = 0,
	NCP5623_INIT_FULL_ON = 1, /* Switch FULL on upon init */
	NCP5623_INIT_HALF_ON = 2, /* Switch HALF on upon init */
};

#define NCP5623_FULL_BRIGHTNESS		31
#define NCP5623_HALF_BRIGHTNESS		11

#define NCP5623_INITIAL_DELAY_ON	500
#define NCP5623_INITIAL_DELAY_OFF	500

#define NCP5623_DEFAULT_LOW_I_STEP	6
#define NCP5623_DEFAULT_HIGH_I_STEP	31
#define NCP5623_DEFAULT_TRANSITION_ON	50 /* 50% */
#define NCP5623_DEFAULT_TRANSITION_OFF	50 /* 50% */

static inline s32 ncp5623_write_reg(struct i2c_client *client, u8 cmd)
{
	int res;
	res = i2c_smbus_write_byte(client, cmd);
	if (res)
		dev_err(&client->dev, "write failed cmd=%02x err=%d\n", cmd, res);
	msleep(1); /* Workaround. Fix i2c driver stuck */
	return res;
}

static inline s32 ncp5623_write_group_pwm(struct i2c_client *client, u8 group, u8 brightness)
{
	int i = 0;
	u8 cmd;
	s32 res = 0;

	group &= NCP5623_LED_GROUP_MASK;
	while(group) {
		if (group & 1) {
			cmd = NCP5623_SET_CMD(i + NCP5623_RED_PWM, brightness);
			res = ncp5623_write_reg(client, cmd);
		}
		group >>= 1;
		i++;
	}
	return res;
}

static void ncp5623_led_work(struct work_struct *work)
{
	struct ncp5623_led *ncp5623_led;
	struct ncp5623 *ncp5623;
	u8 brightness, cmd;
	s32 res;
	u32 transition_time;
	u32 transition_ticks;
	int i;

	ncp5623_led = container_of(work, struct ncp5623_led, work);
	ncp5623 = ncp5623_led->ncp5623;

	if (mutex_lock_interruptible(&ncp5623->lock) < 0)
		return;

	switch (ncp5623_led->brightness) {
	case LED_FULL:
		brightness = NCP5623_FULL_BRIGHTNESS;
		break;
	case LED_OFF:
		brightness = 0;
		break;
	case LED_HALF:
		brightness = NCP5623_HALF_BRIGHTNESS;
		break;
	default:
		break;
	}
	if (ncp5623->dimming_enable) {
		if (ncp5623_led->brightness) {
		/* We don't know current state of other LEDs */
		/* Switch off others if a current group is switching on */
			res = ncp5623_write_group_pwm(ncp5623->client,
					~ncp5623_led->led_group & NCP5623_LED_GROUP_MASK, 0);
		}
		if (ncp5623_led->led_cdev.blink_delay_on &&
				ncp5623_led->led_cdev.blink_delay_off) {
			/* Blinking is running */
			if (ncp5623_led->brightness) {
				/* Switch on */
				/* Setup initial current step */
				cmd = NCP5623_SET_CMD(NCP5623_CURRENT_STEP, ncp5623->low_i_step);
				res = ncp5623_write_reg(ncp5623->client, cmd);
				ncp5623_write_group_pwm(ncp5623->client, ncp5623_led->led_group, brightness);
				ncp5623_led->prev_brightness = brightness;
				cmd = NCP5623_SET_CMD(NCP5623_DIM_UP, ncp5623->high_i_step);
				res = ncp5623_write_reg(ncp5623->client, cmd);
				transition_time = ncp5623_led->led_cdev.blink_delay_on * ncp5623->transition_time_on/100;

			} else {
				cmd = NCP5623_SET_CMD(NCP5623_CURRENT_STEP, ncp5623->high_i_step);
				res = ncp5623_write_reg(ncp5623->client, cmd);
				res = ncp5623_write_group_pwm(ncp5623->client, ncp5623_led->led_group, ncp5623_led->prev_brightness);
				cmd = NCP5623_SET_CMD(NCP5623_DIM_DOWN, ncp5623->low_i_step);
				res = ncp5623_write_reg(ncp5623->client, cmd);
				transition_time = ncp5623_led->led_cdev.blink_delay_off * ncp5623->transition_time_off/100;
			}
			if (res)
				goto exit;
			/* Calculate gradual timing */
			transition_ticks = transition_time/((ncp5623->high_i_step - ncp5623->low_i_step) * 8);
			if (transition_ticks > 31)
				transition_ticks = 31;
			cmd = NCP5623_SET_CMD(NCP5623_DIM_TIME, transition_ticks);
			res = ncp5623_write_reg(ncp5623->client, cmd);
		} else {
			/* Blinking stopped. Disable dimming */
			cmd = NCP5623_SET_CMD(NCP5623_CURRENT_STEP, 31);
			res = ncp5623_write_reg(ncp5623->client, cmd);
			cmd = NCP5623_SET_CMD(NCP5623_DIM_TIME, 0);
			res = ncp5623_write_reg(ncp5623->client, cmd);
			res = ncp5623_write_group_pwm(ncp5623->client, ncp5623_led->led_group, brightness);
		}
	} else {
		cmd = NCP5623_SET_CMD(NCP5623_CURRENT_STEP, 31);
		res = ncp5623_write_reg(ncp5623->client, cmd);
		cmd = NCP5623_SET_CMD(NCP5623_DIM_TIME, 0);
		res = ncp5623_write_reg(ncp5623->client, cmd);
		res = ncp5623_write_group_pwm(ncp5623->client, ncp5623_led->led_group, brightness);
	}
exit:
	mutex_unlock(&ncp5623->lock);
}

static void ncp5623_led_set(struct led_classdev *led_cdev, enum led_brightness value)
{
	struct ncp5623_led *ncp5623;
	ncp5623 = container_of(led_cdev, struct ncp5623_led, led_cdev);

	ncp5623->brightness = value;
	/*
	 * Must use workqueue for the actual I/O since I2C operations
	 * can sleep.
	 */
	schedule_work(&ncp5623->work);
}

static ssize_t show_dimming(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	int ret;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	return scnprintf(buf, PAGE_SIZE, "%d\n", data->dimming_enable);
}

static ssize_t store_dimming(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	u8 value;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	ret = kstrtou8(buf, 10, &value);
	if (ret < 0 || value > 1) {
		dev_err(dev, "dimming: value is invalid!\n");
		return ret;
	}
	mutex_lock(&data->lock);
	data->dimming_enable = value;
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(dimming, S_IRUGO | S_IWUSR, show_dimming, store_dimming);

static ssize_t show_low_i_step(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	int ret;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	return scnprintf(buf, PAGE_SIZE, "%d\n", data->low_i_step);
}

static ssize_t store_low_i_step(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	u8 value;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	ret = kstrtou8(buf, 10, &value);
	if (ret < 0 || value > 31) {
		dev_err(dev, "low_i_step: value is invalid!\n");
		return ret;
	}
	mutex_lock(&data->lock);
	data->low_i_step = value;
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(low_i_step, S_IRUGO | S_IWUSR, show_low_i_step, store_low_i_step);

static ssize_t show_high_i_step(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	int ret;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	return scnprintf(buf, PAGE_SIZE, "%d\n", data->high_i_step);
}

static ssize_t store_high_i_step(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	u8 value;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	ret = kstrtou8(buf, 10, &value);
	if (ret < 0 || value > 31) {
		dev_err(dev, "high_i_step: value is invalid!\n");
		return ret;
	}
	mutex_lock(&data->lock);
	data->high_i_step = value;
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(high_i_step, S_IRUGO | S_IWUSR, show_high_i_step, store_high_i_step);

static ssize_t show_transition_time_on(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	int ret;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	return scnprintf(buf, PAGE_SIZE, "%d\n", data->transition_time_on);
}

static ssize_t store_transition_time_on(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	u8 value;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	ret = kstrtou8(buf, 10, &value);
	if (ret < 0 || value > 100) {
		dev_err(dev, "transition_time_on: value is invalid!\n");
		return ret;
	}
	mutex_lock(&data->lock);
	data->transition_time_on = value;
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(time_on, S_IRUGO | S_IWUSR, show_transition_time_on, store_transition_time_on);

static ssize_t show_transition_time_off(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	int ret;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	return scnprintf(buf, PAGE_SIZE, "%d\n", data->transition_time_off);
}

static ssize_t store_transition_time_off(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int ret;
	u8 value;
	struct ncp5623 *data;
	struct i2c_client *client;

	client = to_i2c_client(dev);
	data = i2c_get_clientdata(client);

	ret = kstrtou8(buf, 10, &value);
	if (ret < 0 || value > 100) {
		dev_err(dev, "transition_time_off: value is invalid!\n");
		return ret;
	}
	mutex_lock(&data->lock);
	data->transition_time_off = value;
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR(time_off, S_IRUGO | S_IWUSR, show_transition_time_off, store_transition_time_off);

static struct attribute *ncp5623_attrs[] = {
	&dev_attr_dimming.attr,
	&dev_attr_low_i_step.attr,
	&dev_attr_high_i_step.attr,
	&dev_attr_time_on.attr,
	&dev_attr_time_off.attr,
	NULL,
};

static struct attribute_group ncp5623_group = {
	.name = "ncp5623",
	.attrs = ncp5623_attrs,
};


#if IS_ENABLED(CONFIG_OF)

static struct led_platform_data *
ncp5623_dt_init(struct i2c_client *client)
{
	struct device_node *np = client->dev.of_node, *child;
	struct led_platform_data *pdata;
	struct led_info *ncp5623_leds;
	int count;
	int i = 0;
	char *state;

	count = of_get_child_count(np);
	if (!count) {
		return ERR_PTR(-ENODEV);
	}
	ncp5623_leds = devm_kzalloc(&client->dev,
			sizeof(struct led_info) * NCP5623_MAX_COLOR, GFP_KERNEL);
	if (!ncp5623_leds)
		return ERR_PTR(-ENOMEM);

	for_each_child_of_node(np, child) {
		struct led_info led;
		u32 led_group;
		int res;

		res = of_property_read_u32(child, "led_group", &led_group);
		if ((res != 0) || (led_group > NCP5623_LED_GROUP_MASK))
			continue;

		led.name =
			of_get_property(child, "label", NULL) ? : child->name;
		led.default_trigger =
			of_get_property(child, "linux,default-trigger", NULL);
		state = of_get_property(child, "init_state", NULL) ? : NULL;

		NCP5623_SET_FLAG_LED_GROUP(led.flags, led_group);
		if (state) {
			if (strcmp(state, "full_on") == 0) {
				NCP5623_SET_FLAG_INIT_STATE(led.flags, NCP5623_INIT_FULL_ON);
			} else if (strcmp(state, "half_on") == 0) {
				NCP5623_SET_FLAG_INIT_STATE(led.flags, NCP5623_INIT_HALF_ON);
			}
		}
		ncp5623_leds[i] = led;
		i++;
	}
	pdata = devm_kzalloc(&client->dev,
			     sizeof(struct led_platform_data), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->leds = ncp5623_leds;
	pdata->num_leds = i;

	return pdata;
}

static const struct of_device_id of_ncp5623_match[] = {
	{ .compatible = "ncp5623", },
	{},
};
#else
static struct led_platform_data *
ncp5623_dt_init(struct i2c_client *client)
{
	return ERR_PTR(-ENODEV);
}
#endif

static int ncp5623_probe(struct i2c_client *client,
					const struct i2c_device_id *id)
{
	struct ncp5623 *ncp5623;
	struct ncp5623_led *ncp5623_led;
	struct i2c_adapter *adapter;
	struct led_platform_data *pdata;
	int err;
	enum ncp5623_led_id i;
	int num_of_leds;
	unsigned long delay_on = NCP5623_INITIAL_DELAY_ON,
			delay_off = NCP5623_INITIAL_DELAY_OFF;

	adapter = to_i2c_adapter(client->dev.parent);
	pdata = dev_get_platdata(&client->dev);
	if (!pdata) {
		pdata = ncp5623_dt_init(client);
		if (IS_ERR(pdata)) {
			dev_warn(&client->dev, "could not parse configuration\n");
			pdata = NULL;
		}
	}
	dev_info(&client->dev, "leds-ncp5623: Using %s LED driver at "
			"slave address 0x%02x\n",
			id->name, client->addr);

	if (!i2c_check_functionality(adapter, I2C_FUNC_I2C))
		return -EIO;

	if (pdata) {
		int n;
		dev_info(&client->dev, "Board claims %d LEDs:\n",
				pdata->num_leds);
		for (n = 0; n < pdata->num_leds; n++) {
			dev_info(&client->dev, "==>%s\n", pdata->leds[n]);
		}
		num_of_leds = pdata->num_leds;
	} else {
		num_of_leds = NCP5623_MAX_COLOR;
	}

	ncp5623 = devm_kzalloc(&client->dev, sizeof(*ncp5623), GFP_KERNEL);
	if (!ncp5623)
		return -ENOMEM;

	ncp5623->leds = devm_kzalloc(&client->dev,
			sizeof(*ncp5623_led) * NCP5623_MAX_COLOR, GFP_KERNEL);
	if (!ncp5623->leds)
		return -ENOMEM;

	/* Write default values */
	ncp5623->dimming_enable = 1;
	ncp5623->high_i_step = NCP5623_DEFAULT_HIGH_I_STEP;
	ncp5623->low_i_step = NCP5623_DEFAULT_LOW_I_STEP;
	ncp5623->transition_time_on = NCP5623_DEFAULT_TRANSITION_ON;
	ncp5623->transition_time_off = NCP5623_DEFAULT_TRANSITION_OFF;

	i2c_set_clientdata(client, ncp5623);

	mutex_init(&ncp5623->lock);
	ncp5623->client = client;

	/* Register sysfs hooks */
	err = sysfs_create_group(&client->dev.kobj, &ncp5623_group);
	if (err < 0) {
		dev_err(&client->dev, "couldn't register sysfs group\n");
		goto exit;
	}


	for (i = 0; i < num_of_leds; i++) {
		ncp5623_led = &ncp5623->leds[i];
		ncp5623_led->ncp5623 = ncp5623;

		/* Platform data can specify LED names and default triggers */
		if (pdata) {
			if (pdata->leds[i].name)
				snprintf(ncp5623_led->name,
					sizeof(ncp5623_led->name), "ncp5623:%s",
					pdata->leds[i].name);
			if (pdata->leds[i].default_trigger)
				ncp5623_led->led_cdev.default_trigger =
					pdata->leds[i].default_trigger;
			ncp5623_led->led_group = NCP5623_GET_FLAG_LED_GROUP(pdata->leds[i].flags);
			ncp5623_led->initial_state = NCP5623_GET_FLAG_INIT_STATE(pdata->leds[i].flags);
			/* Reset flags for LED driver use */
			pdata->leds[i].flags = 0;
			switch (ncp5623_led->initial_state) {
			case NCP5623_INIT_FULL_ON:
				ncp5623_led->led_cdev.brightness = LED_FULL;
				ncp5623_led->led_cdev.blink_brightness = LED_FULL;
				break;
			case NCP5623_INIT_HALF_ON:
				ncp5623_led->led_cdev.brightness = LED_HALF;
				ncp5623_led->led_cdev.blink_brightness = LED_HALF;
				break;
			default:
				ncp5623_led->led_cdev.brightness = LED_FULL;
				ncp5623_led->led_cdev.blink_brightness = LED_FULL;
				break;
			}
		} else {
			snprintf(ncp5623_led->name, sizeof(ncp5623_led->name),
				 "ncp5623:%s", ncp5623_name[i]);
			ncp5623_led->led_group = (1 << i);
		}

		ncp5623_led->led_cdev.name = ncp5623_led->name;
		ncp5623_led->led_cdev.brightness_set = ncp5623_led_set;
		INIT_WORK(&ncp5623_led->work, ncp5623_led_work);

		err = led_classdev_register(&client->dev,
					&ncp5623_led->led_cdev);
		if (err < 0)
			goto exit;
	}
	/* Turn off LEDs */
	err = ncp5623_write_reg(client, NCP5623_SET_CMD(NCP5623_SHUTDOWN, 0));
	if (err < 0)
		goto exit;
	err = ncp5623_write_reg(client, NCP5623_SET_CMD(NCP5623_CURRENT_STEP, 31));
	if (err < 0)
		goto exit;
	for (i = 0; i < num_of_leds; i++) {
		ncp5623_led = &ncp5623->leds[i];
		if (strcmp(ncp5623_led->led_cdev.default_trigger, "timer") == 0) {
			led_blink_set(&ncp5623_led->led_cdev,
								   &delay_on,
								   &delay_off);
		}
	}
	return 0;

exit:
	while (i--) {
		led_classdev_unregister(&ncp5623->leds[i].led_cdev);
		cancel_work_sync(&ncp5623->leds[i].work);
	}
	sysfs_remove_group(&client->dev.kobj, &ncp5623_group);

	return err;
}

static int ncp5623_remove(struct i2c_client *client)
{
	struct ncp5623 *ncp5623 = i2c_get_clientdata(client);
	int i;

	for (i = 0; i < NCP5623_MAX_COLOR; i++) {
		led_classdev_unregister(&ncp5623->leds[i].led_cdev);
		cancel_work_sync(&ncp5623->leds[i].work);
	}
	sysfs_remove_group(&client->dev.kobj, &ncp5623_group);
	return 0;
}

static struct i2c_driver ncp5623_driver = {
	.driver = {
		.name	= "leds-ncp5623",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(of_ncp5623_match),
	},
	.probe	= ncp5623_probe,
	.remove	= ncp5623_remove,
	.id_table = ncp5623_id,
};

module_i2c_driver(ncp5623_driver);

MODULE_AUTHOR("Boris Presman <boris_presman@symantec.com>");
MODULE_DESCRIPTION("ncp5623 LED driver");
MODULE_LICENSE("GPL v2");
