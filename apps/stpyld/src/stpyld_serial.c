#include "stpyld_serial.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static speed_t STEM_SERIAL_GetBaud(int baudrate)
{
	switch (baudrate)
	{
		case 9600: return B9600;
		case 19200: return B19200;
		case 38400: return B38400;
		case 57600: return B57600;
		case 115200: return B115200;
		default: return B9600;
	}
}

int STEM_SERIAL_Open(const char *device, int baudrate)
{
	int fd;
	struct termios tty;

	fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
	{
		return -1;
	}

	memset(&tty, 0, sizeof(tty));

	if (tcgetattr(fd, &tty) != 0)
	{
		close(fd);
		return -1;
	}

	cfsetispeed(&tty, STEM_SERIAL_GetBaud(baudrate));
	cfsetospeed(&tty, STEM_SERIAL_GetBaud(baudrate));

	tty.c_cflag |= (CLOCAL | CREAD);
	tty.c_cflag &= ~CSIZE;
	tty.c_cflag |= CS8;
	tty.c_cflag &= ~PARENB;
	tty.c_cflag &= ~CSTOPB;
	#ifdef CRTSCTS
	tty.c_cflag &= ~CRTSCTS;
	#endif

	tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);
	tty.c_oflag &= ~OPOST;

	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 10;

	tcflush(fd, TCIFLUSH);

	if (tcsetattr(fd, TCSANOW, &tty) != 0)
	{
		close(fd);
		return -1;
	}

	return fd;
}

int STEM_SERIAL_ReadLine(int fd, char *buffer, uint32_t buffer_size)
{
	uint32_t idx = 0;
	char c;
	int n;

	if (fd <= 0 || buffer == 0 || buffer_size < 2)
	{
		return -1;
	}

	while (idx < buffer_size - 1)
	{
		n = read(fd, &c, 1);

		if (n == 1)
		{
			if (c == '\n')
			{
				break;
			}

			if (c != '\r')
			{
				buffer[idx++] = c;
			}
		}
		else
		{
			break;
		}
	}

	buffer[idx] = '\0';

	return (int)idx;
}

void STEM_SERIAL_Close(int fd)
{
	if (fd >= 0)
	{
		close(fd);
	}
}