// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file functions_disk_linux.h
 * @brief Linux-specific disk monitoring functions for SpaceCop IDS
 *
 * This header provides function prototypes for monitoring disk space usage
 * on Linux systems. It supports threshold-based alerting for low disk space
 * conditions that may indicate system compromise or operational issues.
 */

#ifndef FUNCTIONS_DISK_LINUX_H
#define FUNCTIONS_DISK_LINUX_H

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

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Check disk space availability and report if below threshold
 *
 * Monitors the root filesystem ("/") for available disk space and generates
 * an IDS alert if the available space falls below the specified threshold.
 * Reports are sent via the SpaceCop IDS messaging system, STIX logging,
 * and cFE event services.
 *
 * @param[in] storage_threshold Minimum acceptable available disk space as a percentage (0-100)
 * @param[in] name SPARTA/STIX identifier string for this IOB (e.g., "SMSR-X")
 *
 * @return void
 *
 * @note Monitors the root filesystem ("/") by default
 * @note Prints error to stderr if filesystem statistics cannot be retrieved
 * @note Alert is triggered when available space <= threshold
 *
 * @warning Requires appropriate permissions to query filesystem statistics
 *
 * Example usage:
 * @code
 * // Alert if available disk space drops to 10% or below
 * CheckDiskSpace(10.0, "SMSR-5");
 * @endcode
 */
void CheckDiskSpace(float storage_threshold, const char* name);

#endif /* FUNCTIONS_DISK_LINUX_H */