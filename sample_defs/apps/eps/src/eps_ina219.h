#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

#define INA219_REG_CONFIG		0x00
#define INA219_REG_SHUNT_V		0x01
#define INA219_REG_BUS_V		0x02
#define INA219_REG_POWER		0x03
#define INA219_REG_CURRENT		0x04
#define INA219_REG_CALIBRATION	0x05

#define INA219_CONFIG_32V_2A	0x399F
#define INA219_CAL_32V_2A		4096
#define INA219_CURRENT_LSB_MA	0.1f

typedef struct 
{
	const char *bus;
	uint8_t addr;
	const char *name;
} EPS_ChannelConfig_t;

typedef struct 
{
	int fd;
	uint8_t addr;
	uint8_t present;
} INA219_Device_t;

int INA219_Open(INA219_Device_t *dev, const char *bus_path, uint8_t addr);
int INA219_Read(INA219_Device_t *dev, float *bus_voltage_v, float *current_ma);
void INA219_Close(INA219_Device_t *dev);