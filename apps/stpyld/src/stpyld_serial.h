#ifndef SP_SERIAL_H
#define SP_SERIAL_H

#include <stdint.h>

int STEM_SERIAL_Open(const char *device, int baudrate);
int STEM_SERIAL_ReadLine(int fd, char *buffer, uint32_t buffer_size);
void STEM_SERIAL_Close(int fd);

#endif