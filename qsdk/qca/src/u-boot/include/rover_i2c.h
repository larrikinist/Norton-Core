#ifndef _ROVER_I2C_H_
#define _ROVER_I2C_H_
int rover_i2c_read(uchar chip, uint addr, int alen, uchar *buffer, int len);
int rover_i2c_write(uchar chip, uint addr, int alen, uchar *buffer, int len);
int rover_i2c_probe(uchar chip);
#endif
