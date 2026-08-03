// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file functions_file_integrity_linux.h
 * @brief File integrity monitoring using SHA-256 hashing for SpaceCop IDS
 *
 * This header provides data structures and function prototypes for monitoring
 * file integrity on Linux systems. It implements baseline comparison using
 * SHA-256 cryptographic hashing to detect:
 * - Unauthorized file modifications
 * - File additions or deletions
 * - Potential malware or rootkit installation
 * - Configuration tampering
 *
 * The system maintains baseline snapshots of monitored directories and
 * performs periodic comparisons to detect changes.
 */

#ifndef FUNC_FILE_INTEGRITY_LINUX_H
#define FUNC_FILE_INTEGRITY_LINUX_H

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "spacecop_ids_helper.h"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief File entry structure containing path and hash information
 *
 * Represents a single file in the integrity monitoring system with its
 * relative path and SHA-256 hash digest.
 */
typedef struct 
{
    char *rel_path;                              /**< Relative path from scan root (heap-allocated) */
    unsigned char sha256[SHA256_DIGEST_LENGTH];  /**< SHA-256 hash digest (32 bytes) */
} FileEntry;

/**
 * @brief Dynamic array of file entries
 *
 * Manages a resizable list of FileEntry structures for efficient storage
 * and comparison of file integrity baselines.
 */
typedef struct
{
    FileEntry *items;  /**< Pointer to array of file entries (heap-allocated) */
    size_t len;        /**< Current number of entries in the list */
    size_t cap;        /**< Current capacity of the items array */
} FileList;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Scan a directory tree and build a file list with hashes
 *
 * Recursively scans the specified root directory and computes SHA-256 hashes
 * for all regular files found. Skips symbolic links and ignores "logs" and
 * "cti" directories. Results are stored in a sorted FileList structure.
 *
 * @param[in] root Absolute or relative path to the directory to scan
 * @param[out] out Pointer to FileList structure to populate (will be reset first)
 *
 * @return void
 *
 * @note The output list is automatically sorted by relative path
 * @note Existing contents of 'out' are freed before scanning
 * @note Prints warnings for directories that cannot be accessed
 * @note Ignores "logs" and "cti" subdirectories
 *
 * @warning Caller must eventually free the FileList using filelist_free()
 */
void scan_root(const char *root, FileList *out);

/**
 * @brief Check if a file hash exists in the file list
 *
 * Searches the FileList for a matching SHA-256 hash. Optionally matches
 * against a specific filename if provided.
 *
 * @param[in] l Pointer to FileList to search
 * @param[in] name Filename to match (can contain partial path), max 128 chars
 * @param[in] sha256 SHA-256 hash digest to search for (32 bytes)
 *
 * @return int Returns 1 if hash exists (with optional name match), 0 otherwise
 *
 * @note If name contains a substring match with rel_path, both name and hash must match
 * @note If no name match, only hash is compared
 */
int does_hash_exist(const FileList *l, char name[128], unsigned char sha256[SHA256_DIGEST_LENGTH]);

/**
 * @brief Initialize file integrity monitoring system
 *
 * Performs initial baseline scan of monitored directories ("cf" and "data").
 * This function must be called once before any integrity checks can be performed.
 * Subsequent calls are ignored to prevent re-initialization.
 *
 * @return void
 *
 * @note Scans "cf" and "data" directories relative to current working directory
 * @note Safe to call multiple times (only initializes once)
 * @note Prints diagnostic information about scan results
 *
 * @see RunFileIntegrity()
 */
void Init_FileIntegrity(void);

/**
 * @brief Run file integrity check and report changes
 *
 * Performs a new scan of monitored directories and compares against the
 * baseline established by Init_FileIntegrity(). Detects and reports:
 * - Modified files (hash mismatch)
 * - Added files (present in new scan, absent in baseline)
 * - Deleted files (present in baseline, absent in new scan)
 *
 * Alerts are sent via multiple channels:
 * - IDS telemetry messages
 * - STIX reports
 * - cFE error events
 *
 * After reporting, the baseline is updated to the current state for
 * subsequent comparisons.
 *
 * @param[in] iob_id SPARTA/STIX identifier string for alert correlation (e.g., "SMSR-6")
 *
 * @return void
 *
 * @note Must call Init_FileIntegrity() first
 * @note Updates baseline after each check
 * @note Returns immediately if not properly initialized
 *
 * @see Init_FileIntegrity()
 */
void RunFileIntegrity(const char* iob_id);

#endif /* FUNC_FILE_INTEGRITY_LINUX_H */