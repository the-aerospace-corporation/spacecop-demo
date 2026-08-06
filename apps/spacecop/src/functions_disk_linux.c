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
 * @file functions_disk_linux.c
 * @brief Implementation of Linux disk space monitoring for SpaceCop IDS
 *
 * This file implements disk space monitoring functionality for Linux systems
 * using the statvfs() system call. It provides threshold-based alerting for
 * low disk space conditions that may indicate:
 * - Log flooding attacks
 * - Denial of service attempts
 * - System compromise with file creation
 * - Operational anomalies
 *
 * Alerts are integrated with the SpaceCop IDS reporting infrastructure,
 * STIX logging, and cFE event services for comprehensive monitoring.
 */

#include "functions_disk_linux.h"
#include "spacecop_ids_helper.h"

/*=======================================================================================
** Function Definitions
**=======================================================================================*/

/**
 * @brief Check disk space availability and report if below threshold
 *
 * Queries the root filesystem ("/") for disk space statistics and calculates
 * the percentage of available space. If the available space falls at or below
 * the specified threshold, generates a multi-channel alert including:
 * - IDS telemetry message via SPACECOP_ReportIDSMsg()
 * - STIX report via write_to_stix()
 * - cFE error event via CFE_EVS_SendEvent()
 *
 * The function uses statvfs() to obtain filesystem statistics, which provides
 * block-level information about total and available space.
 *
 * @param[in] storage_threshold Minimum acceptable available disk space as a percentage (0-100).
 *                              Alert triggers when available space <= threshold.
 * @param[in] name SPARTA/STIX identifier string for this IOB (e.g., "SMSR-5").
 *                 Used in all alert messages for correlation.
 *
 * @return void
 *
 * @note Monitors the root filesystem ("/") by default
 * @note Uses perror() to report statvfs() failures to stderr
 * @note Alert condition: available_percentage <= storage_threshold
 * @note All alert messages include the actual available percentage for analysis
 *
 * @warning Requires read permissions on the root filesystem
 * @warning Does not distinguish between different filesystem mount points
 *
 * Example usage:
 * @code
 * // Check if available disk space is 15% or less
 * CheckDiskSpace(15.0, "SMSR-5");
 * 
 * // Stricter threshold for critical systems
 * CheckDiskSpace(5.0, "SMSR-5-CRITICAL");
 * @endcode
 */
void CheckDiskSpace(float storage_threshold, const char* name)
{
    const char *disk_path = "/";
    char message[IDS_REPORT_MESSAGE_LEN];
    struct statvfs stat;

    /* Get file system statistics using statvfs() */
    if (statvfs(disk_path, &stat) != 0) 
    {
        perror("Failed to get file system statistics");
        return;
    }

    /* Calculate disk availability percentage */
    unsigned long total_blocks = stat.f_blocks;      /* Total filesystem blocks */
    unsigned long free_blocks = stat.f_bfree;        /* Free blocks available to root */

    /* Calculate percentage of available space */
    double available_percentage = (double) free_blocks / total_blocks * 100;

    /* Check if available space is at or below threshold */
    if (available_percentage <= storage_threshold) 
    {
        /* Prepare alert message */
        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
        snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                 "[SPACECOP] IOB Detected: SPARTA ID=%s (available disk space == %f)", 
                 name, available_percentage);
        
        /* Send alert via IDS telemetry system */
        SPACECOP_ReportIDSMsg(message);
        
        /* Write to STIX log for correlation and analysis */
        write_to_stix(NULL, NULL, name);
        
        /* Send cFE error event for system-wide notification */
        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                          "[SPACECOP] IOB Detected: SPARTA ID=%s (available disk space == %f)", 
                          name, available_percentage);
    }
}