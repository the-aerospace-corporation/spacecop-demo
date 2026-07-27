#include "sysmon_linux.h"

int32_t SYSMON_ReadCpuTempC(float *cpu_temp_c)
{
	FILE *fp;
	int temp_milli_c;

	if (cpu_temp_c == NULL)
	{
		return SYSMON_ERROR;
	}

	fp = fopen("/sys/class/thermal/thermal_zone0/temp", "r");
	if (fp == NULL)
	{
		return SYSMON_ERROR;
	}

	if (fscanf(fp, "%d", &temp_milli_c) != 1)
	{
		fclose(fp);
		return SYSMON_ERROR;
	}

	fclose(fp);

	*cpu_temp_c = temp_milli_c / 1000.0f;
	return SYSMON_SUCCESS;
}

int32_t SYSMON_ReadUptimeSeconds(uint32_t *uptime_seconds)
{
	FILE *fp;
	double uptime;

	if(uptime_seconds == NULL)
	{
		return SYSMON_ERROR;
	}

	fp = fopen("/proc/uptime", "r");
	if (fp == NULL)
	{
		return SYSMON_ERROR;
	}

	if (fscanf(fp, "%1lf", &uptime) != 1)
	{
		fclose(fp);
		return SYSMON_ERROR;
	}

	fclose(fp);

	if (uptime < 0)
	{
		return SYSMON_ERROR;
	}

	*uptime_seconds = (uint32_t)uptime;
	return SYSMON_SUCCESS;
}

int32_t SYSMON_ReadMemoryKb(uint32_t *mem_total_kb, uint32_t *mem_available_kb)
{
	FILE *fp;
	char key[64];
	uint32_t value;
	char unit[32];

	uint8_t found_total = 0;
	uint8_t found_available = 0;

	if (mem_total_kb == NULL || mem_available_kb == NULL)
	{
		return SYSMON_ERROR;
	}

	fp = fopen("/proc/meminfo", "r");
	if (fp == NULL)
	{
		return SYSMON_ERROR;
	}

	while (fscanf(fp, "%63s %u %31s", key, &value, unit) == 3)
	{
		if (strcmp(key, "MemTotal:") == 0)
		{
			*mem_total_kb = value;
			found_total = 1;
		}
		else if (strcmp(key, "MemAvailable:") == 0)
		{
			*mem_available_kb = value;
			found_available = 1;
		}

		if (found_total && found_available)
		{
			break;
		}
	}

	fclose(fp);

	if (!found_total || !found_available)
	{
		return SYSMON_ERROR;
	}

	return SYSMON_SUCCESS;
}

int32_t SYSMON_ReadDiskMB(const char *path, uint32_t *disk_total_mb, uint32_t *disk_free_mb)
{
	struct statvfs fs;
	unsigned long long total_bytes;
	unsigned long long free_bytes;

	if (path == NULL || disk_free_mb == NULL || disk_total_mb == NULL)
	{
		return SYSMON_ERROR;
	}

	if (statvfs(path, &fs) != 0)
	{
		return SYSMON_ERROR;
	}

	total_bytes = (unsigned long long)fs.f_blocks * (unsigned long long)fs.f_frsize;
	free_bytes = (unsigned long long)fs.f_bavail * (unsigned long long)fs.f_frsize;

	*disk_total_mb = (uint32_t)(total_bytes / (1024ULL * 1024ULL));
	*disk_free_mb = (uint32_t)(free_bytes / (1024ULL * 1024ULL));

	return SYSMON_SUCCESS;	
}

int32_t SYSMON_ReadCpuLoadPercent(float *cpu_load_percent)
{
	static uint64_t prev_idle = 0;
	static uint64_t prev_total = 0;
	static uint8_t initialized = 0;

	FILE *fp;
	char cpu_label[16];

	uint64_t user;
	uint64_t nice;
	uint64_t system;
	uint64_t idle;
	uint64_t iowait;
	uint64_t irq;
	uint64_t softirq;
	uint64_t steal;

	uint64_t idle_all;
	uint64_t non_idle;
	uint64_t total;

	uint64_t total_delta;
	uint64_t idle_delta;

	if (cpu_load_percent == NULL)
	{
		return SYSMON_ERROR;
	}

	fp = fopen("/proc/stat", "r");
	if (fp == NULL)
	{
		return SYSMON_ERROR;
	}

	if (fscanf(fp, "%15s %llu %llu %llu %llu %llu %llu %llu %llu", cpu_label, (unsigned long long *)&user, (unsigned long long *)&nice, (unsigned long long *)&system, (unsigned long long *)&idle, (unsigned long long *)&iowait, (unsigned long long *)&irq, (unsigned long long *)&softirq, (unsigned long long *)&steal) != 9)
	{
		fclose(fp);
		return SYSMON_ERROR;
	}

	fclose(fp);

	idle_all = idle + iowait;
	non_idle = user + nice + system + irq + softirq + steal;
	total = idle_all + non_idle;

	if (!initialized)
	{
		prev_idle = idle_all;
		prev_total = total;
		initialized = 1;
		*cpu_load_percent = 0.0f;
		return SYSMON_SUCCESS;
	}

	total_delta = total - prev_total;
	idle_delta = idle_all - prev_idle;

	prev_idle = idle_all;
	prev_total = total;

	if (total_delta == 0)
	{
		*cpu_load_percent = 0.0f;
		return SYSMON_SUCCESS;
	}

	*cpu_load_percent = 100.0f * (float)(total_delta - idle_delta) / (float)total_delta;

	return SYSMON_SUCCESS;
}