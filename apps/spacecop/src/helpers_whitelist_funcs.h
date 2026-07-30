// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file helpers_whitelist_funcs.h
 * @brief Process whitelist management functions for SpaceCop IDS
 *
 * This header provides function prototypes and data structures for managing
 * a whitelist of authorized process names. The whitelist is used to filter
 * out known-good processes from IDS alerts, reducing false positive rates.
 *
 * **Key Features:**
 * - File-based whitelist loading
 * - Thread-safe operations with mutex protection
 * - Case-insensitive matching
 * - Exact and substring matching modes
 * - Sorted storage for efficient lookups
 * - Comment and whitespace handling
 *
 * **Whitelist File Format:**
 * - One process name per line
 * - Comments start with '#' character
 * - Leading/trailing whitespace is ignored
 * - Empty lines are ignored
 * - Names are converted to lowercase
 *
 * Example whitelist file:
 * @code
 * # System processes
 * systemd
 * init
 * 
 * # cFS applications
 * sch
 * to
 * ci
 * @endcode
 */

#ifndef HELPER_WHITELIST_FUNCS_H
#define HELPER_WHITELIST_FUNCS_H

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "spacecop_table_defs.h"

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/** @brief Maximum number of entries in the whitelist */
#define WL_MAX_ENTRIES 4096

/** @brief Maximum length of a process name including null terminator */
#define WL_NAME_MAX 64

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Whitelist data structure
 *
 * Stores a collection of authorized process names in a fixed-size array.
 * Names are stored in sorted order for efficient searching.
 */
typedef struct {
    uint16_t count;                         /**< Number of entries currently in the whitelist */
    char items[WL_MAX_ENTRIES][WL_NAME_MAX]; /**< Array of process names */
} WhiteList_t;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Load process whitelist from a file
 *
 * Reads a whitelist file and populates the global process whitelist. The file
 * should contain one process name per line. Comments (lines starting with '#')
 * and empty lines are ignored. All names are converted to lowercase and stored
 * in sorted order for efficient lookups.
 *
 * File format:
 * - One process name per line
 * - '#' starts a comment (rest of line ignored)
 * - Leading/trailing whitespace is trimmed
 * - Empty lines are skipped
 * - Maximum WL_MAX_ENTRIES entries
 *
 * @param[in] path Path to the whitelist file
 *
 * @return int Returns 0 on success, negative on error:
 *         - 0: Success
 *         - -1: Failed to open file
 *         - -2: Memory allocation failed or too many entries
 *
 * @note Thread-safe (uses mutex locking)
 * @note Previous whitelist contents are replaced
 * @note Names are automatically converted to lowercase
 * @note Whitelist is sorted after loading for efficient searching
 *
 * Example usage:
 * @code
 * int result = WL_LoadFromFile_Proc("cf/proc_whitelist.txt");
 * if (result == 0) {
 *     printf("Whitelist loaded successfully\n");
 * } else {
 *     printf("Failed to load whitelist: %d\n", result);
 * }
 * @endcode
 */
int WL_LoadFromFile_Proc(const char *path);

/**
 * @brief Check if a process name is in the whitelist (exact match)
 *
 * Performs a case-insensitive exact match to determine if the specified
 * process name is in the whitelist. The name is trimmed and converted to
 * lowercase before comparison.
 *
 * @param[in] name Process name to check
 *
 * @return int Returns 1 if name is in whitelist, 0 otherwise
 *
 * @note Thread-safe (uses mutex locking)
 * @note Case-insensitive comparison
 * @note Leading/trailing whitespace is ignored
 * @note Returns 0 if name is NULL or whitelist is empty
 *
 * Example usage:
 * @code
 * if (WL_ContainsName_Proc("systemd")) {
 *     printf("systemd is whitelisted\n");
 * } else {
 *     printf("systemd is NOT whitelisted\n");
 * }
 * @endcode
 */
int WL_ContainsName_Proc(const char *name);

/**
 * @brief Check if a process name contains a whitelisted substring
 *
 * Performs a case-insensitive substring match to determine if any whitelisted
 * name appears within the specified process name. This is useful for matching
 * process name variations (e.g., "python3.8" contains "python").
 *
 * The name is trimmed and converted to lowercase before searching for
 * whitelist entries as substrings.
 *
 * @param[in] name Process name to check
 *
 * @return int Returns 1 if any whitelist entry is a substring of name, 0 otherwise
 *
 * @note Thread-safe (uses mutex locking)
 * @note Case-insensitive comparison
 * @note Leading/trailing whitespace is ignored
 * @note Returns 0 if name is NULL or whitelist is empty
 * @note More permissive than WL_ContainsName_Proc()
 *
 * Example usage:
 * @code
 * // If whitelist contains "python"
 * if (WL_ContainsSubName_Proc("python3.8")) {
 *     printf("Process contains whitelisted substring\n");  // This will print
 * }
 * 
 * if (WL_ContainsSubName_Proc("/usr/bin/python")) {
 *     printf("Process contains whitelisted substring\n");  // This will print
 * }
 * @endcode
 */
int WL_ContainsSubName_Proc(const char *name);

#endif /* HELPER_WHITELIST_FUNCS_H */