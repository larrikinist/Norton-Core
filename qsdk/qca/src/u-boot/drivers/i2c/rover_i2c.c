/*
 * ROVER board i2c driver
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
#include <i2c.h>
#include "ipq_i2c.h"
#include <asm/io.h>
#include <asm/errno.h>
#include <asm/arch-ipq806x/gsbi.h>
#include <asm/arch-ipq806x/gpio.h>
#include <asm/arch-ipq806x/iomap.h>
#include <asm/arch-ipq806x/clock.h>

/* Rover GSBI6 */
#define GSBI_PORT					6
#define GSBI6_CTRL					0x16500000
#define UART6_DM_BASE				0x16540000
#define QUP6_BASE					0x16580000
#define GPIO_57_FUNC				3	/* p.19 of 80-Y6477-3 Rev. D */
#define GPIO_58_FUNC				3   /* p.19 of 80-Y6477-3 Rev. D */
#define CLK_SRC_PXO_FREQ			25000000
#define CLK_FREQ				100000
#define I2C_MASTER_CLK_HS_DIVIDER	3

static int i2c_hw_initialized;
static int i2c_board_initialized;
static unsigned int i2c_clk;

static void i2c_reset(void)
{
	writel(0x1, GSBI_QUP_BASE(GSBI_PORT) + QUP_SW_RESET_OFFSET);
	udelay(5);
}

static int check_bit_state(uint32_t reg_addr, int bit_num, int val,
				int us_delay)
{
	unsigned int count = TIMEOUT_CNT;
	unsigned int bit_val = ((readl(reg_addr) >> bit_num) & 0x01);

	while (bit_val != val) {
		count--;
		if (count == 0) {
			return -ETIMEDOUT;
		}
		udelay(us_delay);
		bit_val = ((readl(reg_addr) >> bit_num) & 0x01);
	}

	return SUCCESS;
}

/*
 * Check whether GSBIn_QUP State is valid
 */
static int check_qup_state_valid(void)
{
	return check_bit_state(GSBI_QUP_BASE(GSBI_PORT) + QUP_STATE_OFFSET,
				QUP_STATE_VALID_BIT,
				QUP_STATE_VALID, 1);
}

/*
 * Configure GSBIn Core state
 */
static int config_i2c_state(unsigned int state)
{
	uint32_t val;
	int ret = SUCCESS;

	ret = check_qup_state_valid();
	if (ret != SUCCESS)
		return ret;

	/* Set the state  */
	val = readl(GSBI_QUP_BASE(GSBI_PORT) + QUP_STATE_OFFSET);
	val = ((val & ~QUP_STATE_MASK) | state);
	writel(val, GSBI_QUP_BASE(GSBI_PORT) + QUP_STATE_OFFSET);
	ret = check_qup_state_valid();

	return ret;
}

static void i2c_board_init(void)
{
	int cfg;
	/* Change GSBI-A to GSBI-B */
	writel(0x1, 0x00800000 + 0x2088);
	/* Configure GPIOs */
	gpio_tlmm_config(57, GPIO_57_FUNC, 0,
			GPIO_NO_PULL, GPIO_12MA, GPIO_OE_ENABLE);
	gpio_tlmm_config(58, GPIO_58_FUNC, 0,
				GPIO_NO_PULL, GPIO_12MA, GPIO_OE_ENABLE);
	/* Configure clock */
	/* Assert MND reset. */
	setbits_le32(GSBIn_QUP_APPS_NS_REG(GSBI_PORT), BIT(7));
	/* Program M and D values. */
	/* borisp - configuration is adopted from kernel
	 * M = D = 0 */
	writel(0, GSBIn_QUP_APPS_MD_REG(GSBI_PORT));
	/* Deassert MND reset. */
	clrbits_le32(GSBIn_QUP_APPS_NS_REG(GSBI_PORT), BIT(7));
	/* Enable gsbin_qup_apps_clk source and branch */
	cfg = BIT(9) | BIT(11);
	writel(cfg, GSBIn_QUP_APPS_NS_REG(GSBI_PORT));
	setbits_le32(GSBIn_HCLK_CTL_REG(GSBI_PORT), BIT(4));
	i2c_hw_initialized = 0;
	i2c_board_initialized = 1;
}

static int i2c_hw_init(void)
{
	int ret, cfg;

	/* GSBI module configuration */
	i2c_reset();
	/* Set the GSBIn QUP state */
	ret = config_i2c_state(QUP_STATE_RESET);
	if (ret) {
		printf("config_i2c_state(QUP_STATE_RESET) fails\n");
		return ret;
	}
	/* Configure GSBI_CTRL register to set protocol_mode to I2C_UART:110 */
	writel(GSBI_PROTOCOL_CODE_I2C_UART <<
			GSBI_CTRL_REG_PROTOCOL_CODE_S,
			GSBI_CTRL_REG(GSBI6_CTRL));

	/* Configure Mini core to I2C core */
	cfg = readl(GSBI_QUP_BASE(GSBI_PORT) + QUP_CONFIG_OFFSET);
	cfg |= (QUP_CONFIG_MINI_CORE_I2C |
		I2C_BIT_WORD);
	writel(cfg, GSBI_QUP_BASE(GSBI_PORT) + QUP_CONFIG_OFFSET);

	/* Configure I2C mode */
	cfg = readl(GSBI_QUP_BASE(GSBI_PORT) + QUP_IO_MODES_OFFSET);
	cfg |= (INPUT_FIFO_MODE |
		OUTPUT_FIFO_MODE |
		OUTPUT_BIT_SHIFT_EN);
	writel(cfg, GSBI_QUP_BASE(GSBI_PORT) + QUP_IO_MODES_OFFSET);


	/* Enable QUP Error Flags */
	writel(ERROR_FLAGS_EN,
		GSBI_QUP_BASE(GSBI_PORT) + QUP_ERROR_FLAGS_EN_OFFSET);

	/* Clear the MASTER_CTL_STATUS */
	writel(I2C_MASTER_STATUS_CLEAR,
		GSBI_QUP_BASE(GSBI_PORT) + QUP_I2C_MASTER_STATUS_OFFSET);

	/* Set to RUN STATE */
	ret = config_i2c_state(QUP_STATE_RUN);
	if (ret) {
		printf("config_i2c_state(QUP_STATE_RUN) fails\n");
		return ret;
	}

	/* Configure the I2C Master clock */
	cfg = (((CLK_SRC_PXO_FREQ / CLK_FREQ) / 2) - 3);
	cfg |= (I2C_MASTER_CLK_HS_DIVIDER << 8);
	i2c_clk = cfg;
	writel(cfg, GSBI_QUP_BASE(GSBI_PORT) + QUP_I2C_MASTER_CLK_CTL_OFFSET);
	i2c_hw_initialized = 1;

	return SUCCESS;
}

/*
 * Function to check wheather Input or Output FIFO
 * has data to be serviced. For invalid slaves, this
 * flag will not be set.
 */
static int check_fifo_status(uint dir)
{
	unsigned int count = TIMEOUT_CNT;
	unsigned int status_flag;
	unsigned int val;

	if (dir == READ) {
		do {
			val = readl(GSBI_QUP_BASE(GSBI_PORT)
				+ QUP_OPERATIONAL_OFFSET);
			count--;
			if (count == 0)
				return -ETIMEDOUT;
			status_flag = val & INPUT_SERVICE_FLAG;
			udelay(10);
		} while (!status_flag);

	} else if (dir == WRITE) {
		do {
			val = readl(GSBI_QUP_BASE(GSBI_PORT)
				+ QUP_OPERATIONAL_OFFSET);
			count--;
			if (count == 0)
				return -ETIMEDOUT;
			status_flag = val & OUTPUT_FIFO_FULL;
			udelay(10);
		} while (status_flag);

		/*
		 * Clear the flag and Acknowledge that the
		 * software has or will write the data.
		 */
		if (readl(GSBI_QUP_BASE(GSBI_PORT) + QUP_OPERATIONAL_OFFSET)
						& OUTPUT_SERVICE_FLAG) {
			writel(OUTPUT_SERVICE_FLAG, GSBI_QUP_BASE(GSBI_PORT)
				+ QUP_OPERATIONAL_OFFSET);
		}
	}
	return SUCCESS;
}

/*
 * Check whether the values in the OUTPUT FIFO are shifted out.
 */
static int check_write_done(void)
{
	unsigned int count = TIMEOUT_CNT;
	unsigned int status_flag;
	unsigned int val;

	do {
		val = readl(GSBI_QUP_BASE(GSBI_PORT)
				+ QUP_OPERATIONAL_OFFSET);
		count--;
		if (count == 0)
			return -ETIMEDOUT;

		status_flag = val & OUTPUT_FIFO_NOT_EMPTY;
		udelay(10);
	} while (status_flag);

	return SUCCESS;
}

/*
 * rover_i2c_read - Read data from i2c device
 * params:
 * chip - 7 bits device address
 * addr - register address
 * alen - address width. Not applicable
 * buffer - pointer to the buffrer to read to
 * len - length of data to read
 */

int rover_i2c_read(uchar chip, uint addr, int alen, uchar *buffer, int len)
{
	int ret = 0;
	unsigned int data = 0;
	int read_cnt = 0;

	if (!i2c_board_initialized) {
		i2c_board_init();
	}

	if(!i2c_hw_initialized) {
		if(i2c_hw_init() != 0) {
			printf("%s: i2c_hw_init fails\n", __FUNCTION__);
			return -1;
		}
	}
	writel(0xFF, GSBI_QUP_BASE(GSBI_PORT)
			+ QUP_ERROR_FLAGS_OFFSET);

	writel(0, GSBI_QUP_BASE(GSBI_PORT)
			+ QUP_I2C_MASTER_STATUS_OFFSET);

	/* Set to RUN state */
	ret = config_i2c_state(QUP_STATE_RUN);
	if (ret != SUCCESS)
		goto out;
	writel(i2c_clk, GSBI_QUP_BASE(GSBI_PORT) + QUP_I2C_MASTER_CLK_CTL_OFFSET);
	/* Send a write request to the chip */
	writel((QUP_I2C_START_SEQ | QUP_I2C_ADDR(chip)),
		GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);

	writel((QUP_I2C_DATA_SEQ | QUP_I2C_DATA(addr)),
		 GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);

	ret = check_write_done();
	if (ret != SUCCESS)
		goto out;

	ret = check_fifo_status(WRITE);
	if (ret != SUCCESS)
		goto out;

	/* Send read request */
	writel((QUP_I2C_START_SEQ |
		(QUP_I2C_ADDR(chip)|
		QUP_I2C_SLAVE_READ)),
		GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);

	writel((QUP_I2C_RECV_SEQ | len),
		GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);

	while (len--) {

		ret = check_fifo_status(READ);
		if (ret != SUCCESS)
			goto out;

		/* Read the data from the FIFO */
		data = readl(GSBI_QUP_BASE(GSBI_PORT) + QUP_INPUT_FIFO_OFFSET);
		*buffer = QUP_I2C_DATA(data);

		/*
		 * Clear the flag and Acknowledge that the
		 * software has or will read the data.
		 */
		writel(INPUT_SERVICE_FLAG,
			GSBI_QUP_BASE(GSBI_PORT) + QUP_OPERATIONAL_OFFSET);

		buffer++;
		read_cnt++;
	}

	/* Set to PAUSE state */
	ret = config_i2c_state(QUP_STATE_PAUSE);
	if (ret != SUCCESS)
		goto out;

out:
	/*
	 * Put the I2C Core back in the Reset State to end the transfer.
	 */
	(void)config_i2c_state(QUP_STATE_RESET);
	if (ret == SUCCESS)
		ret = read_cnt;
	return ret;
}

/*
 * rover_i2c_write - write data to i2c device
 * params:
 * chip - 7 bits device address
 * addr - register address
 * alen - address width. Not applicable
 * buffer - pointer to data to write
 * len - length of data to write
 */

int rover_i2c_write(uchar chip, uint addr, int alen, uchar *buffer, int len)
{
	int ret = 0;
	int idx = 0;

	if (!i2c_board_initialized) {
		i2c_board_init();
	}

	if(!i2c_hw_initialized) {
		if(i2c_hw_init() != 0) {
			printf("%s: i2c_hw_init fails\n", __FUNCTION__);
			return -1;
		}
	}

	/* Set to RUN state */
	ret = config_i2c_state(QUP_STATE_RUN);
	if (ret != SUCCESS) {
		printf("%s: Can't config_i2c_state(QUP_STATE_RUN)\n", __FUNCTION__);
		goto out;
	}
	writel(i2c_clk, GSBI_QUP_BASE(GSBI_PORT) + QUP_I2C_MASTER_CLK_CTL_OFFSET);

	/* Send the write request */
	writel((QUP_I2C_START_SEQ | QUP_I2C_ADDR(chip)),
		GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);
	if (len) {
		writel((QUP_I2C_DATA_SEQ | QUP_I2C_DATA(addr)),
				GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);
	} else {
		writel((QUP_I2C_STOP_SEQ | QUP_I2C_DATA(addr)),
					GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);
		ret = check_fifo_status(WRITE);
		if (ret != SUCCESS) {
			printf("%s: check_fifo_status(WRITE) fails\n", __FUNCTION__);
			goto out;
		}
	}

	while (len) {
		if (len == 1) {
			writel((QUP_I2C_STOP_SEQ | QUP_I2C_DATA(buffer[idx])),
			GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);
		} else {
			writel((QUP_I2C_DATA_SEQ | QUP_I2C_DATA(buffer[idx])),
			GSBI_QUP_BASE(GSBI_PORT) + QUP_OUTPUT_FIFO_OFFSET);
		}
		len--;
		idx++;

		ret = check_fifo_status(WRITE);
		if (ret != SUCCESS) {
			printf("%s: check_fifo_status(WRITE) [%d] (0x%x) fails\n", __FUNCTION__, ret, addr);
			goto out;
		}
	}

	ret = check_write_done();
	if (ret != SUCCESS) {
		printf("%s: check_write_done() fails [%d] (0x%x)\n", __FUNCTION__, ret, addr);
		goto out;
	}

	/* Set to PAUSE state */
	ret = config_i2c_state(QUP_STATE_PAUSE);
	if (ret != SUCCESS) {
		printf("%s: Can't config_i2c_state(QUP_STATE_PAUSE)\n", __FUNCTION__);
		goto out;
	}
	return ret;
out:
	/*
	 * Put the I2C Core back in the Reset State to end the transfer.
	 */
	(void)config_i2c_state(QUP_STATE_RESET);
	return ret;
}

int rover_i2c_probe(uchar chip)
{
	uchar buf;

	return i2c_read(chip, 0x0, 0x1, &buf, 0x1);
}

