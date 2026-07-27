#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define SYSMON_SUCCESS 0
#define SYSMON_ERROR -1

int32_t SYSMON_ReadCpuTempC(float *cpu_temp_c);
int32_t SYSMON_ReadUptimeSeconds(uint32_t *uptime_seconds);
int32_t SYSMON_ReadMemoryKb(uint32_t *mem_total_kb, uint32_t *mem_available_kb);
int32_t SYSMON_ReadDiskMB(const char *path, uint32_t *disk_total_mb, uint32_t *disk_free_mb);
int32_t SYSMON_ReadCpuLoadPercent(float *cpu_load_percent);