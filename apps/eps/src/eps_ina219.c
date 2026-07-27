#include "eps_ina219.h"

static int INA219_WriteReg(int fd, uint8_t reg, uint16_t value)
{
	uint8_t buf[3] = {
		reg,
		(uint8_t)(value >> 8),
		(uint8_t)(value & 0xFF)
	};

	return write(fd, buf, sizeof(buf)) == sizeof(buf) ? 0 : -1;
}

static int INA219_ReadReg(int fd, uint8_t reg, uint16_t *value)
{
	uint8_t buf[2];

	if (write(fd, &reg, 1) != 1)
		return -1;

	if (read(fd, buf, 2) != 2)
		return -1;

	*value = ((uint16_t)buf[0] << 8) | buf[1];
	return 0;
}

int INA219_Open(INA219_Device_t *dev, const char *bus_path, uint8_t addr)
{
	dev->fd = open(bus_path, O_RDWR);
	dev->addr = addr;
	dev->present = 0;

	if (dev->fd < 0)
		return -1;

	if (ioctl(dev->fd, I2C_SLAVE, addr) < 0)
	{
		close(dev->fd);
		dev->fd = -1;
		return -1;
	}

	if (INA219_WriteReg(dev->fd, INA219_REG_CONFIG, INA219_CONFIG_32V_2A) < 0)
		return -1;

	dev->present = 1;
	return 0;
}

int INA219_Read(INA219_Device_t *dev, float *bus_voltage_v, float *current_ma)
{
	uint16_t raw_bus_u16;
	uint16_t raw_current_u16;
	int16_t raw_current_s16;

	if (dev == NULL || bus_voltage_v == NULL || current_ma == NULL)
		return -1;

	if (!dev->present)
		return -1;

	if (INA219_WriteReg(dev->fd, INA219_REG_CALIBRATION, INA219_CAL_32V_2A) < 0)
		return -1;

	if (INA219_ReadReg(dev->fd, INA219_REG_BUS_V, &raw_bus_u16) < 0)
		return -1;

	if (INA219_ReadReg(dev->fd, INA219_REG_CURRENT, &raw_current_u16) < 0)
		return -1;

	*bus_voltage_v = ((raw_bus_u16 >> 3) * 4.0f) / 1000.0f;

	raw_current_s16 = (int16_t)raw_current_u16;
	*current_ma = raw_current_s16 * INA219_CURRENT_LSB_MA;

	return 0;
}

void INA219_Close(INA219_Device_t *dev)
{
	if (dev->fd >= 0)
		close(dev->fd);

	dev->fd = -1;
	dev->present = 0;
}