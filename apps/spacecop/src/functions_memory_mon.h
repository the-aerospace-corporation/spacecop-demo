// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file functions_memory_mon.h
 * @brief Comprehensive memory monitoring for cFS based on MITRE ATT&CK MIRE patterns
 *
 * This header provides function prototypes and data structures for multi-layered
 * memory integrity monitoring in cFS environments. The implementation supports
 * three MITRE ATT&CK for ICS (MIRE) patterns:
 *
 * - MIRE-15: Payload Memory Block Monitoring
 *   Detects unauthorized modifications to application code and data segments
 *
 * - MIRE-16: Boot Memory Region Monitoring
 *   Protects boot loaders, kernel code, and cFE core from tampering
 *
 * - MIRE-18: Critical Memory with Error Detection
 *   Monitors mission-critical data structures with multiple error detection methods
 *
 * Key features:
 * - Automatic discovery of memory regions (apps, boot code)
 * - Multiple integrity checking algorithms (hash, checksum, parity, Hamming, redundancy)
 * - On-demand checking architecture (no background threads)
 * - Process memory usage monitoring
 * - Thread-safe operation with per-region locking
 * - Comprehensive violation reporting via IDS, STIX, and cFE events
 */

#ifndef _FUNCTIONS_MEMORY_MON_H_
#define _FUNCTIONS_MEMORY_MON_H_

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
#include <stdint.h>
#include <sys/mman.h> 
#include <fcntl.h>

#include "spacecop_ids_helper.h"

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @defgroup DetectionMethods Error Detection Methods for MIRE-18
 * @{
 */
#define DETECT_METHOD_HASH        0  /**< FNV-1a cryptographic hash */
#define DETECT_METHOD_PARITY      1  /**< Even parity bit checking */
#define DETECT_METHOD_HAMMING     2  /**< Hamming error correction code */
#define DETECT_METHOD_CHECKSUM    3  /**< Simple additive checksum */
#define DETECT_METHOD_REDUNDANCY  4  /**< Redundant copy comparison */
/** @} */

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Memory region configuration structure
 *
 * Defines a memory region to be monitored, including address, size, type,
 * and error detection method. Used for manual registration of regions.
 */
typedef struct {
    void *address;         /**< Starting address of memory region */
    uint32_t size;         /**< Size of region in bytes */
    const char *name;      /**< Human-readable region name */
    uint8_t type;          /**< Region type (REGION_TYPE_PAYLOAD, _BOOT, _CRITICAL) */
    uint8_t method;        /**< Error detection method (DETECT_METHOD_*) */
} MemoryRegionConfig_t;

/*=======================================================================================
** Process Memory Monitoring Functions
**=======================================================================================*/

/**
 * @brief Monitor process memory usage across all running processes
 *
 * Scans /proc filesystem to identify processes exceeding a memory threshold.
 * Generates IDS alerts for non-whitelisted processes that exceed the limit.
 * Useful for detecting memory exhaustion attacks or runaway processes.
 *
 * @param[in] memory_threshold Maximum allowed memory usage in kilobytes
 * @param[in] name SPARTA/STIX identifier for alert correlation
 *
 * @return void
 *
 * @note Requires access to /proc filesystem
 * @note Checks against process whitelist before alerting
 * @note Memory usage is calculated from /proc/[pid]/statm
 */
void Memory_Monitor_Start(uint32_t memory_threshold, const char* name);

/*=======================================================================================
** MIRE-15: Payload Memory Monitoring Functions
**=======================================================================================*/

/**
 * @brief Start or check payload memory monitoring (MIRE-15)
 *
 * Monitors application code and data segments for unauthorized modifications.
 * On first call, automatically discovers and registers all critical cFS
 * application memory regions. On subsequent calls, performs integrity checks
 * on all registered payload regions.
 *
 * Auto-discovery targets critical apps:
 * - SCH (Scheduler)
 * - TO (Telemetry Output)
 * - CI (Command Ingest)
 * - FM (File Manager)
 * - CS (Checksum)
 * - HK (Housekeeping)
 * - LC (Limit Checker)
 * - SC (Stored Commands)
 *
 * @param[in] iob_id SPARTA/STIX identifier for alert correlation (e.g., "MIRE-15")
 *
 * @return void
 *
 * @note Should be called periodically (recommended: every 10 seconds)
 * @note Auto-discovery runs only once on first call
 * @note Uses SHA-256 hashing for integrity verification
 * @note Parses /proc/self/maps to discover application memory regions
 *
 * @see Memory_Monitor_RegisterPayload() for manual registration
 */
void Memory_Monitor_Payload_Start(const char* iob_id);

/**
 * @brief Stop payload memory monitoring and reset discovery state
 *
 * Resets the payload discovery flag, allowing re-discovery on next start.
 * Does not unregister existing regions.
 *
 * @return void
 */
void Memory_Monitor_Payload_Stop(void);

/**
 * @brief Manually register a payload memory region for monitoring
 *
 * Registers a specific memory region for payload integrity monitoring.
 * Useful when auto-discovery doesn't capture all required regions or
 * for application-specific critical data.
 *
 * @param[in] address Starting address of memory region
 * @param[in] size Size of region in bytes
 * @param[in] name Descriptive name for the region
 *
 * @return int Region ID (>= 0) on success, -1 on failure
 *
 * @note Uses FNV-1a hash for integrity checking
 * @note Region is automatically assigned MIRE-15 identifier
 */
int Memory_Monitor_RegisterPayload(void* address, uint32_t size, const char* name);

/*=======================================================================================
** MIRE-16: Boot Memory Monitoring Functions
**=======================================================================================*/

/**
 * @brief Start or check boot memory monitoring (MIRE-16)
 *
 * Monitors boot loader, kernel code, and cFE core memory for tampering.
 * On first call, automatically discovers boot-related memory regions from
 * /proc/iomem. On subsequent calls, performs integrity checks using both
 * hash and checksum verification.
 *
 * Targets boot regions:
 * - Kernel code segments
 * - Kernel data segments
 * - Kernel BSS
 * - Kernel rodata
 *
 * @param[in] iob_id SPARTA/STIX identifier for alert correlation (e.g., "MIRE-16")
 *
 * @return void
 *
 * @note Should be called periodically (recommended: every 5 seconds)
 * @note Auto-discovery runs only once on first call
 * @note Requires root privileges to access /dev/mem
 * @note Uses mmap() to access physical memory regions
 * @note Dual verification: hash + checksum for higher confidence
 *
 * @warning Requires CAP_SYS_RAWIO capability or root to access /dev/mem
 *
 * @see Memory_Monitor_RegisterBoot() for manual registration
 */
void Memory_Monitor_Boot_Start(const char* iob_id);

/**
 * @brief Stop boot memory monitoring and reset discovery state
 *
 * Resets the boot discovery flag, allowing re-discovery on next start.
 * Does not unregister existing regions or unmap memory.
 *
 * @return void
 */
void Memory_Monitor_Boot_Stop(void);

/**
 * @brief Manually register a boot memory region for monitoring
 *
 * Registers a specific boot-related memory region for integrity monitoring.
 * Useful for monitoring specific firmware or bootloader regions not
 * automatically discovered.
 *
 * @param[in] address Starting address of memory region
 * @param[in] size Size of region in bytes
 * @param[in] name Descriptive name for the region
 *
 * @return int Region ID (>= 0) on success, -1 on failure
 *
 * @note Boot regions are verified using both hash and checksum
 * @note Region is automatically assigned MIRE-16 identifier
 */
int Memory_Monitor_RegisterBoot(void* address, uint32_t size, const char* name);

/*=======================================================================================
** MIRE-18: Critical Memory with Error Detection Functions
**=======================================================================================*/

/**
 * @brief Start or check critical memory monitoring (MIRE-18)
 *
 * Monitors mission-critical data structures using configurable error detection
 * methods. Unlike MIRE-15 and MIRE-16, this pattern requires manual registration
 * of regions using Memory_Monitor_RegisterCritical().
 *
 * Supported detection methods:
 * - Hash: Cryptographic integrity (FNV-1a)
 * - Parity: Even parity bit checking
 * - Hamming: Error correction code
 * - Checksum: Simple additive checksum
 * - Redundancy: Comparison with backup copy
 *
 * @param[in] iob_id SPARTA/STIX identifier for alert correlation (e.g., "MIRE-18")
 *
 * @return void
 *
 * @note Should be called frequently (recommended: every 1 second)
 * @note Regions must be manually registered before monitoring
 * @note Each region can use a different detection method
 * @note Error status is tracked per STIX compliance requirements
 *
 * @see Memory_Monitor_RegisterCritical() for region registration
 */
void Memory_Monitor_Critical_Start(const char* iob_id);

/**
 * @brief Stop critical memory monitoring and reset discovery state
 *
 * Resets the critical discovery flag. Does not unregister existing regions
 * or free redundant copies.
 *
 * @return void
 */
void Memory_Monitor_Critical_Stop(void);

/**
 * @brief Manually register a critical memory region with error detection
 *
 * Registers a mission-critical memory region with a specific error detection
 * method. The region will be checked on each call to Memory_Monitor_Critical_Start().
 *
 * @param[in] address Starting address of memory region
 * @param[in] size Size of region in bytes
 * @param[in] name Descriptive name for the region
 * @param[in] detection_method Error detection method (DETECT_METHOD_*)
 *
 * @return int Region ID (>= 0) on success, -1 on failure
 *
 * @note For DETECT_METHOD_REDUNDANCY, a backup copy is automatically allocated
 * @note Region is automatically assigned MIRE-18 identifier
 * @note Error status is tracked for STIX compliance
 *
 * Example usage:
 * @code
 * // Monitor flight control state with redundancy
 * Memory_Monitor_RegisterCritical(&flight_state, sizeof(flight_state),
 *                                 "flight_control_state",
 *                                 DETECT_METHOD_REDUNDANCY);
 *
 * // Monitor command queue with Hamming codes
 * Memory_Monitor_RegisterCritical(cmd_queue, CMD_QUEUE_SIZE,
 *                                 "command_queue",
 *                                 DETECT_METHOD_HAMMING);
 * @endcode
 */
int Memory_Monitor_RegisterCritical(void* address, uint32_t size, 
                                    const char* name, uint8_t detection_method);

/*=======================================================================================
** Core Memory Integrity API (Internal)
**=======================================================================================*/

/**
 * @brief Initialize the memory integrity monitoring subsystem
 *
 * Initializes global state, mutexes, and data structures. Called automatically
 * by monitoring functions but can be called explicitly for early initialization.
 *
 * @return int Returns 0 on success
 *
 * @note Thread-safe (uses pthread_once internally)
 * @note Safe to call multiple times
 */
int CFS_MemoryIntegrity_Init(void);

/**
 * @brief Register a memory region for monitoring (internal)
 *
 * Low-level registration function used by auto-discovery and manual registration
 * functions. Applications should use the higher-level registration functions instead.
 *
 * @param[in] address Starting address of memory region
 * @param[in] size Size of region in bytes
 * @param[in] type Region type (0=PAYLOAD, 1=BOOT, 2=CRITICAL, 3=GENERAL)
 * @param[in] method Error detection method (DETECT_METHOD_*)
 * @param[in] name Descriptive name for the region
 * @param[in] iob_id SPARTA/STIX identifier string
 *
 * @return int Region ID (>= 0) on success, -1 on failure
 *
 * @note Internal function - use type-specific registration functions instead
 */
int CFS_RegisterMemoryRegion(void *address, size_t size, uint8_t type, 
                             uint8_t method, const char *name, const char *iob_id);

/**
 * @brief Start continuous monitoring (deprecated - use on-demand checking)
 *
 * @deprecated This function is deprecated. Use on-demand checking instead.
 * @return int Returns 0
 */
int CFS_StartMonitoring(void);

/**
 * @brief Stop continuous monitoring (deprecated - use on-demand checking)
 *
 * @deprecated This function is deprecated. Use on-demand checking instead.
 * @return void
 */
void CFS_StopMonitoring(void);

/**
 * @brief Clean up memory integrity monitoring resources
 *
 * Frees all allocated memory, destroys mutexes, and resets global state.
 * Should be called during application shutdown.
 *
 * @return void
 *
 * @note Frees redundant copies for DETECT_METHOD_REDUNDANCY regions
 * @note Destroys all region-specific mutexes
 */
void CFS_MemoryIntegrity_Cleanup(void);

/**
 * @brief Get statistics for a specific memory region
 *
 * Retrieves check count and violation count for a registered region.
 * Useful for debugging and performance monitoring.
 *
 * @param[in] region_id Region ID returned from registration function
 * @param[out] checks Pointer to store number of integrity checks performed (can be NULL)
 * @param[out] violations Pointer to store number of violations detected (can be NULL)
 *
 * @return void
 *
 * @note Does nothing if region_id is invalid
 * @note Thread-safe (acquires region lock)
 */
void CFS_GetRegionStats(int region_id, uint64_t *checks, uint64_t *violations);

/*=======================================================================================
** Application Auto-Registration API (Optional)
**=======================================================================================*/

/**
 * @brief Register multiple memory regions for an application
 *
 * Convenience function for applications that need to register multiple memory
 * regions at once. Most applications don't need this - auto-discovery handles
 * typical use cases automatically.
 *
 * @param[in] app_name Name of the application registering regions
 * @param[in] regions Array of MemoryRegionConfig_t structures
 * @param[in] num_regions Number of regions in the array
 *
 * @return int32_t CFE_SUCCESS on success, -1 if any region fails to register
 *
 * @note Appropriate MIRE IDs are assigned automatically based on region type
 * @note Continues registering remaining regions even if one fails
 *
 * Example usage:
 * @code
 * MemoryRegionConfig_t my_regions[] = {
 *     { .address = &critical_data, .size = sizeof(critical_data),
 *       .name = "critical_data", .type = REGION_TYPE_CRITICAL,
 *       .method = DETECT_METHOD_REDUNDANCY },
 *     { .address = code_segment, .size = CODE_SIZE,
 *       .name = "my_code", .type = REGION_TYPE_PAYLOAD,
 *       .method = DETECT_METHOD_HASH }
 * };
 *
 * SPACECOP_RegisterAppMemory("MY_APP", my_regions, 2);
 * @endcode
 */
int32_t SPACECOP_RegisterAppMemory(const char *app_name, 
                                    MemoryRegionConfig_t *regions,
                                    uint32_t num_regions);

#endif /* _FUNCTIONS_MEMORY_MON_H_ */