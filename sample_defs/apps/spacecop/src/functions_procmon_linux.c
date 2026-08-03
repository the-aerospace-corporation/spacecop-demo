// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file functions_procmon_linux.c
 * @brief Implementation of Linux process monitoring for SpaceCop IDS
 *
 * This file implements comprehensive process monitoring capabilities for
 * detecting unauthorized processes and excessive CPU usage on Linux systems.
 *
 * **Key Features:**
 * - Whitelist-based process authorization
 * - Real-time CPU usage calculation
 * - Integration with IDS alerting infrastructure
 * - STIX logging for correlation
 * - cFE event service integration
 *
 * **CPU Usage Calculation:**
 * The CPU usage calculation is based on the Linux /proc filesystem:
 * 1. Read process user time (utime) and system time (stime) from /proc/[pid]/stat
 * 2. Read process start time (starttime) from /proc/[pid]/stat
 * 3. Read system uptime from /proc/uptime
 * 4. Calculate total CPU time used by process
 * 5. Calculate time process has been running
 * 6. CPU % = (total_cpu_time / elapsed_time) * 100
 *
 * **Whitelist System:**
 * The whitelist is loaded from "cf/proc_whitelist.txt" and contains known-good
 * process names. Both exact matching and substring matching are supported to
 * handle process name variations.
 *
 * **Detection Capabilities:**
 * - Unauthorized process execution
 * - Cryptominers and resource exhaustion attacks
 * - Malware and backdoor processes
 * - Compromised applications with abnormal CPU usage
 */

#include "functions_procmon_linux.h"
#include "spacecop_platform_cfg.h"  /* SPACECOP_CF_DIR */

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/**
 * @brief Whitelist load status
 *
 * Tracks whether the process whitelist has been successfully loaded:
 * - <0: Not loaded / load failed (initial state is -1)
 * - >=0: Successfully loaded (number of entries)
 */
static int loaded = -1;

/*=======================================================================================
** Internal Helper Functions
**=======================================================================================*/

/**
 * @brief Calculate CPU usage percentage for a process
 *
 * Computes the CPU usage of a process by analyzing data from /proc/[pid]/stat
 * and /proc/uptime. The calculation accounts for:
 * - User mode CPU time (utime)
 * - Kernel mode CPU time (stime)
 * - Process start time relative to system boot
 * - Current system uptime
 *
 * Formula: CPU% = (total_cpu_time / elapsed_time) * 100
 * where:
 * - total_cpu_time = (utime + stime) / hertz
 * - elapsed_time = uptime - (starttime / hertz)
 *
 * @param[in] pid Process ID as a string (e.g., "1234")
 *
 * @return float CPU usage percentage (0.0-100.0+), or -1.0 on error
 *
 * @note Can exceed 100% on multi-core systems (e.g., 200% = 2 full cores)
 * @note Returns -1.0 if /proc files cannot be read
 * @note Uses system clock tick rate (sysconf(_SC_CLK_TCK)) for time conversion
 *
 * Implementation details:
 * - Reads /proc/uptime for system uptime in seconds
 * - Parses /proc/[pid]/stat for process timing information
 * - Extracts utime (field 14), stime (field 15), starttime (field 22)
 * - Converts clock ticks to seconds using hertz (typically 100 Hz)
 */
static float calculate_cpu_usage(char *pid)
{
    char stat_path[256];
    FILE *stat_file;
    unsigned long utime, stime, starttime;
    long total_time;
    long hertz = sysconf(_SC_CLK_TCK);  /* System clock ticks per second */
    long uptime;

    /* Read system uptime from /proc/uptime */
    FILE *uptime_file = fopen("/proc/uptime", "r");
    if (!uptime_file) {
        perror("Failed to read /proc/uptime");
        return -1.0;
    }
    fscanf(uptime_file, "%ld", &uptime);
    fclose(uptime_file);

    /* Build path to process stat file */
    snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", pid);

    /* Open process stat file */
    stat_file = fopen(stat_path, "r");
    if (!stat_file) {
        perror("Failed to open stat file");
        return -1.0;
    }

    /* Read stat file contents */
    char buffer[256];
    fgets(buffer, sizeof(buffer), stat_file);
    fclose(stat_file);

    /* Extract timing values from stat file
     * Format: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt 
     *         utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
     * We extract: utime (field 14), stime (field 15), starttime (field 22)
     */
    sscanf(buffer, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %lu",
           &utime, &stime, &starttime);

    /* Calculate total CPU time used by process (in clock ticks) */
    total_time = utime + stime;

    /* Calculate elapsed time since process started (in seconds) */
    float seconds = (float)(uptime - (starttime / hertz));
    
    /* Calculate CPU usage percentage
     * If elapsed time is 0 or negative, return 0 to avoid division by zero
     */
    return (seconds > 0) ? (100.0 * (total_time / (float)hertz) / seconds) : 0.0;
}

/*=======================================================================================
** Public API Functions
**=======================================================================================*/

/**
 * @brief Get the name of a process from its PID
 *
 * Retrieves the process name from /proc/[pid]/comm, which contains the
 * short command name without path or arguments. This is more reliable than
 * parsing the command line, which can be modified by the process.
 *
 * @param[in] pid Process ID as a string
 * @param[out] name Buffer to store the process name
 * @param[in] name_size Size of the name buffer
 *
 * @return void
 *
 * @note Sets name to "unknown" if the process cannot be read
 * @note Removes trailing newline character
 * @note Ensures null-termination of the output string
 */
void get_process_name(const char *pid, char *name, size_t name_size) 
{
    char comm_path[256];
    FILE *comm_file;

    /* Build path to process comm file */
    snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", pid);
    
    /* Open comm file */
    comm_file = fopen(comm_path, "r");
    if (!comm_file) {
        /* Process may have exited or we lack permissions */
        strncpy(name, "unknown", name_size - 1);
        name[name_size - 1] = '\0';
        return;
    }
    
    /* Read process name */
    fgets(name, name_size, comm_file);
    
    /* Remove trailing newline */
    name[strcspn(name, "\n")] = '\0';
    
    fclose(comm_file);
}

/**
 * @brief Initialize the process monitoring subsystem
 *
 * Loads the process whitelist from the configuration file. The whitelist
 * contains known-good process names that are authorized to run on the system.
 * This function must be called before any monitoring operations.
 *
 * @return void
 *
 * @note Whitelist file: "cf/proc_whitelist.txt"
 * @note Only loads once (subsequent calls are no-ops)
 * @note Prints status messages to stdout for debugging
 * @note If load fails, monitoring functions will return immediately
 */
void PROCMon_Init(void)
{
    /* Check if already loaded */
    if (loaded < 0)
    {
        printf("Initializing Proc WhiteList\n");
        
        /* Load whitelist from file */
        loaded = WL_LoadFromFile_Proc(SPACECOP_CF_DIR "/proc_whitelist.txt");
        
        if (loaded < 0)
        {
            printf("Couldn't load Proc Whitelist\n");
        }
    }
}

/**
 * @brief Check all processes for excessive CPU usage
 *
 * Scans the /proc filesystem to enumerate all running processes, calculates
 * their CPU usage, and generates alerts for non-whitelisted processes that
 * exceed the specified threshold.
 *
 * Alert generation:
 * - Only non-whitelisted processes trigger alerts
 * - Alerts include process name and actual CPU usage
 * - Multi-channel alerting: IDS telemetry, STIX, cFE events
 *
 * @param[in] threshold_percent CPU usage threshold (0-100+)
 * @param[in] name SPARTA/STIX identifier for alerts
 *
 * @return void
 *
 * @note Requires PROCMon_Init() to be called first
 * @note Returns immediately if whitelist not loaded
 * @note Processes using >= threshold trigger alerts
 * @note CPU usage can exceed 100% on multi-core systems
 */
void PROCMon_CPU_Check(float threshold_percent, const char* name)
{
    /* Return if whitelist not loaded */
    if (loaded < 0) return;
    
    /* Open /proc directory */
    DIR *d = opendir("/proc");
    if (!d) return;

    char message[IDS_REPORT_MESSAGE_LEN];
    struct dirent *entry;
    
    /* Iterate through all /proc entries */
    while ((entry = readdir(d)) != NULL)
    {
        /* Skip non-numeric entries (only process PIDs are numeric) */
        if (!isdigit(entry->d_name[0]))  continue;

        char *pid = entry->d_name;
        char process_name[256];
        
        /* Get process name */
        get_process_name(pid, process_name, sizeof(process_name));

        /* Calculate CPU usage for this process */
        float cpu_usage = calculate_cpu_usage(pid);
        
        /* Check if CPU usage exceeds threshold */
        if (cpu_usage >= threshold_percent) 
        {
            /* Check if process is whitelisted (exact match) */
            if (!WL_ContainsName_Proc(process_name))
            {
                /* Generate multi-channel alert */
                memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                        "[SPACECOP] IOB Detected: SPARTA ID=%s (process_name == %s, cpu_usage == %f)", 
                        name, process_name, cpu_usage);
                
                /* Send via IDS telemetry */
                SPACECOP_ReportIDSMsg(message);
                
                /* Write to STIX log */
                write_to_stix(process_name, NULL, name);
                
                /* Send cFE error event */
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                 "[SPACECOP] IOB Detected: SPARTA ID=%s (process_name == %s, cpu_usage == %f)", 
                                 name, process_name, cpu_usage);
            }
        }
    }
    
    closedir(d);
}

/**
 * @brief Check for unauthorized processes
 *
 * Scans all running processes and generates alerts for any process whose
 * name is not found in the whitelist. Uses substring matching to allow
 * flexibility in process name variations (e.g., "python3.8" matches "python").
 *
 * Alert generation:
 * - Triggered for any process not in whitelist
 * - Uses substring matching for flexibility
 * - Multi-channel alerting: IDS telemetry, STIX, cFE events
 *
 * @param[in] name SPARTA/STIX identifier for alerts
 *
 * @return void
 *
 * @note Requires PROCMon_Init() to be called first
 * @note Returns immediately if whitelist not loaded
 * @note Uses substring matching (partial name matches allowed)
 * @note Alerts include the unauthorized process name
 */
void PROCMon_Process_Check(const char* name)
{
    /* Return if whitelist not loaded */
    if (loaded < 0) return;
    
    char message[IDS_REPORT_MESSAGE_LEN];
    
    /* Open /proc directory */
    DIR *d = opendir("/proc");
    if (!d) return;

    struct dirent *entry;
    
    /* Iterate through all /proc entries */
    while ((entry = readdir(d)) != NULL)
    {
        /* Skip non-numeric entries (only process PIDs are numeric) */
        if (!isdigit(entry->d_name[0]))  continue;

        char *pid = entry->d_name;
        char process_name[256];
        
        /* Get process name */
        get_process_name(pid, process_name, sizeof(process_name));

        /* Check if process is whitelisted (substring match) */
        if (!WL_ContainsSubName_Proc(process_name))
        {
            /* Generate multi-channel alert for unauthorized process */
            memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] IOB Detected: SPARTA ID=%s (new_process_name == %s)", 
                    name, process_name);
            
            /* Send via IDS telemetry */
            SPACECOP_ReportIDSMsg(message);
            
            /* Write to STIX log */
            write_to_stix(process_name, NULL, name);
            
            /* Send cFE error event */
            CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (new_process_name == %s)", 
                             name, process_name);
        }
    }
    
    closedir(d);
}