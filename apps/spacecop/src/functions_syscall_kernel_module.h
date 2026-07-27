// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop - CE
// All rights reserved.
//
//This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
//limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
//for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
//any warranty that the documentation will conform to the program, or any warranty that the software will be error free.
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
 * @file functions_syscall_kernel_module.h
 * @brief System call monitoring via Linux kernel module for SpaceCop IDS
 *
 * This header provides function prototypes and data structures for monitoring
 * system calls through a custom Linux kernel module. The system uses Netlink
 * sockets for kernel-to-userspace communication to detect:
 * - Excessive system call usage (potential exploits)
 * - Anomalous system call patterns
 * - Privilege escalation attempts
 * - System call-based attacks
 *
 * **Architecture:**
 * - Kernel module intercepts and counts system calls
 * - Netlink socket provides communication channel
 * - Userspace component receives counts and checks thresholds
 * - Configurable tolerance levels per system call type
 * - Enable/disable monitoring per IOB (Indicator of Behavior)
 *
 * **Key Features:**
 * - Real-time system call monitoring
 * - Tolerance-based threshold detection
 * - Dynamic enable/disable of monitors
 * - Integration with IDS alerting infrastructure
 */

#ifndef _FUNCTIONS_SYSCALL_KERNEL_MODULE_H_
#define _FUNCTIONS_SYSCALL_KERNEL_MODULE_H_

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

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
** Constants and Macros
**=======================================================================================*/

/** @brief Netlink protocol number for userspace communication */
#define NETLINK_USER 31

/** @brief Maximum payload size for Netlink messages in bytes */
#define MAX_PAYLOAD 1024

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief System call monitoring configuration structure
 *
 * Tracks the monitoring state, thresholds, and current counts for a specific
 * system call or group of system calls identified by an IOB (Indicator of Behavior).
 */
typedef struct 
{
    int8_t enabled;         /**< Monitor enabled flag (0=disabled, 1=enabled) */
    char name[64];          /**< Human-readable name of the system call or monitor */
    char iob[10];           /**< IOB identifier (e.g., "SMSR-4") */
    int16_t curr_count;     /**< Current count of system calls since last check */
    int32_t tolerance;      /**< Threshold before generating alert */
} SyscallInfo;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Initialize the system call monitoring subsystem
 *
 * Sets up the Netlink socket connection to the kernel module and initializes
 * the system call monitoring configuration. Must be called before any monitoring
 * operations can be performed.
 *
 * Initialization tasks:
 * - Create Netlink socket
 * - Bind to kernel module
 * - Initialize monitoring structures
 * - Load default tolerance values
 *
 * @return void
 *
 * @note Must be called before SYSCALL_Monitor(), Toggle_Monitor(), or Set_Tolerance()
 * @note Prints error messages to stdout if initialization fails
 * @note Requires appropriate permissions to create Netlink sockets
 *
 * @warning Requires the companion kernel module to be loaded
 *
 * @see SYSCALL_Monitor()
 */
void Init_Syscall(void);

/**
 * @brief Toggle monitoring on/off for a specific IOB
 *
 * Enables or disables system call monitoring for the specified IOB identifier.
 * When disabled, the monitor will not generate alerts even if thresholds are
 * exceeded.
 *
 * @param[in] iob IOB identifier string (e.g., "SMSR-4")
 *
 * @return void
 *
 * @note Requires Init_Syscall() to be called first
 * @note Toggles between enabled and disabled states
 * @note Does not affect tolerance settings
 * @note Prints status message to stdout
 *
 * Example usage:
 * @code
 * // Disable monitoring for SMSR-4
 * Toggle_Monitor("SMSR-4");
 * 
 * // Re-enable monitoring for SMSR-4
 * Toggle_Monitor("SMSR-4");
 * @endcode
 *
 * @see Init_Syscall()
 * @see Set_Tolerance()
 */
void Toggle_Monitor(const char *iob);

/**
 * @brief Set the tolerance threshold for a specific IOB
 *
 * Configures the maximum number of system calls allowed before generating
 * an alert. The tolerance value determines how many system calls can occur
 * within a monitoring period before being considered anomalous.
 *
 * @param[in] iob IOB identifier string (e.g., "SMSR-4")
 * @param[in] tolerance Maximum allowed system call count before alert
 *
 * @return void
 *
 * @note Requires Init_Syscall() to be called first
 * @note Tolerance value must be positive
 * @note Setting tolerance to 0 will alert on any system call
 * @note Changes take effect immediately
 *
 * Example usage:
 * @code
 * // Alert if more than 100 system calls occur
 * Set_Tolerance("SMSR-4", 100);
 * 
 * // Very strict: alert on any occurrence
 * Set_Tolerance("SMSR-5", 0);
 * @endcode
 *
 * @see Init_Syscall()
 * @see Toggle_Monitor()
 */
void Set_Tolerance(const char *iob, int16_t tolerance);

/**
 * @brief Perform system call monitoring check
 *
 * Queries the kernel module via Netlink socket for current system call counts,
 * compares them against configured tolerance thresholds, and generates IDS
 * alerts for any violations. Should be called periodically to maintain
 * real-time monitoring.
 *
 * Monitoring process:
 * 1. Receive system call counts from kernel module via Netlink
 * 2. Parse received data and update current counts
 * 3. Compare counts against tolerance thresholds
 * 4. Generate alerts for enabled monitors exceeding tolerance
 * 5. Reset counts for next monitoring period
 *
 * Alerts are sent via:
 * - IDS telemetry messages (SPACECOP_ReportIDSMsg)
 * - STIX reports (write_to_stix)
 * - cFE error events (CFE_EVS_SendEvent)
 *
 * @return void
 *
 * @note Requires Init_Syscall() to be called first
 * @note Should be called periodically (recommended: every 1-5 seconds)
 * @note Only generates alerts for enabled monitors
 * @note Resets counts after each check
 * @note Blocks briefly waiting for kernel module response
 *
 * @warning Requires the kernel module to be loaded and responsive
 *
 * Example usage:
 * @code
 * // Initialize once at startup
 * Init_Syscall();
 * Set_Tolerance("SMSR-4", 100);
 * 
 * // Call periodically in monitoring loop
 * while (monitoring_active) {
 *     SYSCALL_Monitor();
 *     sleep(5);  // Check every 5 seconds
 * }
 * @endcode
 *
 * @see Init_Syscall()
 * @see Toggle_Monitor()
 * @see Set_Tolerance()
 */
void SYSCALL_Monitor(void);

#endif /* _FUNCTIONS_SYSCALL_KERNEL_MODULE_H_ */