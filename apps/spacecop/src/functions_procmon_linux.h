// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop - CE
// All rights reserved.
//
//This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
//limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
//for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
//any warranty that the software will be error free.
//
//In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
//arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
//contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
//documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

/**
 * @file functions_procmon_linux.h
 * @brief Linux process monitoring functions for SpaceCop IDS
 *
 * This header provides function prototypes for monitoring running processes
 * on Linux systems. It supports whitelist-based detection of unauthorized
 * processes and monitoring of CPU usage to detect:
 * - Unauthorized process execution
 * - Malware or backdoor processes
 * - Cryptominers or resource exhaustion attacks
 * - Compromised applications consuming excessive CPU
 *
 * The monitoring system uses a whitelist approach where known-good processes
 * are loaded from a configuration file. Any process not on the whitelist or
 * exceeding CPU thresholds triggers an IDS alert.
 */

#ifndef FUNC_PROCMON_LINUX_H
#define FUNC_PROCMON_LINUX_H

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include <stdint.h>
#include "spacecop_table_defs.h"
#include "spacecop_table_runtime.h"
#include "helpers_whitelist_funcs.h"
#include "cfe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <time.h>

#include "spacecop_ids_helper.h"

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Get the name of a process from its PID
 *
 * Retrieves the process name (command) from /proc/[pid]/comm. This is the
 * short name of the executable without path or arguments.
 *
 * @param[in] pid Process ID as a string (e.g., "1234")
 * @param[out] name Buffer to store the process name
 * @param[in] name_size Size of the name buffer
 *
 * @return void
 *
 * @note If the process cannot be read, name is set to "unknown"
 * @note Removes trailing newline from the process name
 * @note Name is null-terminated and truncated if necessary
 *
 * Example usage:
 * @code
 * char name[256];
 * get_process_name("1234", name, sizeof(name));
 * printf("Process name: %s\n", name);
 * @endcode
 */
void get_process_name(const char *pid, char *name, size_t name_size);

/**
 * @brief Initialize the process monitoring subsystem
 *
 * Loads the process whitelist from the configuration file. The whitelist
 * contains known-good process names that are expected to run on the system.
 * Must be called before any process monitoring functions.
 *
 * @return void
 *
 * @note Whitelist file location: "cf/proc_whitelist.txt"
 * @note Prints diagnostic messages to stdout
 * @note Safe to call multiple times (only loads once)
 * @note If whitelist fails to load, monitoring functions will not operate
 *
 * @see PROCMon_CPU_Check()
 * @see PROCMon_Process_Check()
 */
void PROCMon_Init(void);

/**
 * @brief Check all processes for excessive CPU usage
 *
 * Scans all running processes and calculates their CPU usage. Generates
 * IDS alerts for non-whitelisted processes that exceed the specified
 * threshold. Useful for detecting:
 * - Cryptominers
 * - Denial of service attacks
 * - Runaway processes
 * - CPU-intensive malware
 *
 * CPU usage is calculated based on:
 * - User time (utime) from /proc/[pid]/stat
 * - System time (stime) from /proc/[pid]/stat
 * - Process start time and system uptime
 *
 * @param[in] threshold_percent CPU usage threshold as a percentage (0-100+)
 *                              Processes using >= this percentage trigger alerts
 * @param[in] name SPARTA/STIX identifier for alert correlation
 *
 * @return void
 *
 * @note Requires PROCMon_Init() to be called first
 * @note Returns immediately if whitelist not loaded
 * @note Only non-whitelisted processes trigger alerts
 * @note CPU usage can exceed 100% on multi-core systems
 * @note Alerts include process name and actual CPU usage
 *
 * Example usage:
 * @code
 * // Alert if any non-whitelisted process uses >= 80% CPU
 * PROCMon_CPU_Check(80.0, "SMSR-7");
 * @endcode
 */
void PROCMon_CPU_Check(float threshold_percent, const char* name);

/**
 * @brief Check for unauthorized processes
 *
 * Scans all running processes and generates alerts for any process not
 * found in the whitelist. Uses substring matching to allow flexibility
 * in process name variations. Detects:
 * - Unauthorized executables
 * - Malware processes
 * - Backdoors and remote access tools
 * - Unexpected system services
 *
 * @param[in] name SPARTA/STIX identifier for alert correlation
 *
 * @return void
 *
 * @note Requires PROCMon_Init() to be called first
 * @note Returns immediately if whitelist not loaded
 * @note Uses substring matching (partial name matches are allowed)
 * @note Alerts include the unauthorized process name
 * @note Scans /proc filesystem for all running processes
 *
 * Example usage:
 * @code
 * // Alert for any process not in whitelist
 * PROCMon_Process_Check("SMSR-8");
 * @endcode
 */
void PROCMon_Process_Check(const char* name);

#endif /* FUNC_PROCMON_LINUX_H */