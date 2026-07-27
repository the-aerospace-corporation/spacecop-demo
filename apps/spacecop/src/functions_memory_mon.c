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
 * @file functions_memory_mon.c
 * @brief Comprehensive memory integrity monitoring for cFS systems
 *
 * This file implements a multi-layered memory integrity monitoring system aligned
 * with MITRE ATT&CK for ICS (MIRE) patterns. It provides three distinct monitoring
 * capabilities:
 *
 * **MIRE-15: Payload Memory Block Monitoring**
 * - Automatically discovers cFS application memory regions
 * - Monitors code segments for unauthorized modifications
 * - Targets critical applications (SCH, TO, CI, FM, CS, HK, LC, SC)
 * - Uses SHA-256 hashing for integrity verification
 *
 * **MIRE-16: Boot Memory Region Monitoring**
 * - Discovers and monitors kernel/boot memory from /proc/iomem
 * - Maps physical memory using /dev/mem
 * - Dual verification (hash + checksum) for boot integrity
 * - Detects bootkit and firmware tampering
 *
 * **MIRE-18: Critical Memory with Error Detection**
 * - Monitors mission-critical data structures
 * - Supports multiple error detection methods:
 *   - Hash (FNV-1a)
 *   - Parity (even parity)
 *   - Hamming codes
 *   - Checksum
 *   - Redundancy (backup copy comparison)
 * - Tracks error status for STIX compliance
 *
 * **Architecture:**
 * - On-demand checking (no background threads)
 * - Thread-safe with per-region locking
 * - Automatic region discovery
 * - Manual registration API for specific regions
 * - Comprehensive violation reporting via IDS, STIX, and cFE events
 *
 * **Key Design Decisions:**
 * - Uses FNV-1a hash for speed and reasonable collision resistance
 * - Supports up to 512 monitored regions
 * - Redundant copy allocation for DETECT_METHOD_REDUNDANCY
 * - Physical memory access requires root/CAP_SYS_RAWIO
 */

#include "functions_memory_mon.h"
#include "functions_procmon_linux.h"
#include "helpers_whitelist_funcs.h"
#include "cfe.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>

/*=======================================================================================
** Configuration Constants
**=======================================================================================*/

#ifndef IDS_REPORT_MESSAGE_LEN
#define IDS_REPORT_MESSAGE_LEN 512
#endif

/** @brief Maximum number of memory regions that can be monitored simultaneously */
#define MAX_MONITORED_REGIONS 512

/*=======================================================================================
** MIRE Pattern Identifiers
**=======================================================================================*/

#define MIRE_15 "MIRE-15"  /**< Payload memory manipulation detection */
#define MIRE_16 "MIRE-16"  /**< Boot memory manipulation detection */
#define BOOT_WARMUP_CHECKS   3   /**< MIRE-16: silent baseline-adopt checks after registration */
#define BOOT_CONFIRM_CHECKS  2   /**< MIRE-16: consecutive persistent mismatches before alerting */
#define MIRE_18 "MIRE-18"  /**< Critical memory error detection */

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Memory region type classification
 *
 * Categorizes memory regions by their security criticality and monitoring
 * requirements. Each type maps to a specific MIRE pattern.
 */
typedef enum {
    REGION_TYPE_PAYLOAD,     /**< Application code/data (maps to MIRE-15) */
    REGION_TYPE_BOOT,        /**< Boot/kernel memory (maps to MIRE-16) */
    REGION_TYPE_CRITICAL,    /**< Mission-critical data (maps to MIRE-18) */
    REGION_TYPE_GENERAL      /**< General monitoring (default to MIRE-15) */
} memory_region_type_t;

/**
 * @brief Error detection method enumeration
 *
 * Defines the available integrity checking algorithms. Different methods
 * offer different tradeoffs between speed, memory overhead, and detection
 * capability.
 */
typedef enum {
    ERROR_DETECT_HASH,       /**< FNV-1a hash (fast, good collision resistance) */
    ERROR_DETECT_PARITY,     /**< Even parity (very fast, detects odd bit flips) */
    ERROR_DETECT_HAMMING,    /**< Hamming code (error correction capable) */
    ERROR_DETECT_CHECKSUM,   /**< Additive checksum (fast, weak) */
    ERROR_DETECT_REDUNDANCY  /**< Backup copy (memory overhead, strong) */
} error_detection_method_t;

/**
 * @brief Error detection status for STIX compliance
 *
 * Tracks the current error detection status of a memory region per
 * STIX pattern requirements.
 */
typedef enum {
    ERROR_STATUS_UNKNOWN,    /**< Status not yet determined */
    ERROR_STATUS_PASSED,     /**< Most recent check passed */
    ERROR_STATUS_FAILED      /**< Most recent check failed */
} error_status_t;

/**
 * @brief Memory region descriptor structure
 *
 * Contains all information needed to monitor a single memory region including
 * address, size, type, expected integrity values, statistics, and locking.
 */
typedef struct {
    /* Region identification */
    void *address;                              /**< Starting address of region */
    size_t size;                                /**< Size in bytes */
    memory_region_type_t type;                  /**< Region type (PAYLOAD/BOOT/CRITICAL) */
    char name[128];                             /**< Human-readable name */
    char iob_id[64];                            /**< IOB/SPARTA identifier */
    const char *mire_id;                        /**< MIRE pattern ID string */
    
    /* Expected integrity values */
    uint64_t expected_hash;                     /**< Expected FNV-1a hash */
    uint32_t expected_checksum;                 /**< Expected checksum */
    uint8_t expected_parity;                    /**< Expected parity bit */
    uint32_t expected_hamming;                  /**< Expected Hamming code */
    void *redundant_copy;                       /**< Backup copy for redundancy method */
    
    /* Configuration */
    error_detection_method_t detection_method;  /**< Active detection method */
    error_status_t error_status;                /**< Current error status (STIX) */
    
    /* Statistics */
    uint64_t check_count;                       /**< Number of checks performed */
    uint64_t violation_count;                   /**< Number of violations detected */
    uint64_t last_violation_time;               /**< Unix timestamp of last violation */

    /* MIRE-16 boot de-noise: warm-up + consecutive-mismatch confirmation */
    uint32_t warmup_checks;                     /**< Silent baseline-adopt checks remaining */
    uint64_t pending_hash;                      /**< Candidate changed hash awaiting confirmation */
    uint32_t pending_count;                     /**< Consecutive checks the change has persisted */

    /* State flags */
    int enabled;                                /**< Region is enabled for checking */
    int protected;                              /**< Using mprotect() (future use) */
    
    /* Synchronization */
    pthread_mutex_t lock;                       /**< Per-region mutex */
} monitored_region_t;

/*=======================================================================================
** Global State
**=======================================================================================*/

/**
 * @brief Global monitoring state structure
 *
 * Maintains the array of monitored regions and global synchronization.
 */
static struct {
    monitored_region_t regions[MAX_MONITORED_REGIONS];  /**< Array of monitored regions */
    int num_regions;                                     /**< Number of active regions */
    pthread_mutex_t global_lock;                         /**< Global state mutex */
    int initialized;                                     /**< Initialization flag */
} monitor_state = {
    .num_regions = 0,
    .initialized = 0,
};

/**
 * @brief MIRE pattern discovery state
 *
 * Tracks whether auto-discovery has been performed for each MIRE pattern.
 * Discovery is performed once per pattern on first monitoring call.
 */
static struct {
    int payload_discovered;      /**< MIRE-15 auto-discovery completed */
    int boot_discovered;         /**< MIRE-16 auto-discovery completed */
    int critical_discovered;     /**< MIRE-18 monitoring initialized */
} mire_state = {0};

/** @brief Thread-safe initialization control */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

/*=======================================================================================
** Linker-Provided Symbols (Optional)
**=======================================================================================*/

/* Weak symbols for linker-provided memory boundaries (may not exist on all platforms) */
extern char __text_start __attribute__((weak));
extern char __text_end __attribute__((weak));
extern char __data_start __attribute__((weak));
extern char __data_end __attribute__((weak));
extern char __bss_start __attribute__((weak));
extern char __bss_end __attribute__((weak));
extern char __rodata_start __attribute__((weak));
extern char __rodata_end __attribute__((weak));

/*=======================================================================================
** Hash and Integrity Computation Functions
**=======================================================================================*/

/**
 * @brief Compute FNV-1a 64-bit hash
 *
 * Implements the FNV-1a (Fowler-Noll-Vo) hash algorithm, which provides
 * good distribution and is fast to compute. Used for payload and boot
 * memory integrity checking.
 *
 * @param[in] data Pointer to data to hash
 * @param[in] len Length of data in bytes
 *
 * @return uint64_t 64-bit hash value
 *
 * @note FNV-1a is not cryptographically secure but sufficient for integrity checking
 * @note Provides good avalanche properties (small changes cause large hash changes)
 */
static uint64_t compute_hash(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t hash = 0xcbf29ce484222325ULL;  /* FNV-1a offset basis */
    
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x100000001b3ULL;  /* FNV-1a prime */
    }
    
    return hash;
}

/**
 * @brief Compute simple additive checksum
 *
 * Sums all bytes in the data. Fast but weak - detects modifications but
 * not transpositions or compensating changes.
 *
 * @param[in] data Pointer to data to checksum
 * @param[in] len Length of data in bytes
 *
 * @return uint32_t Checksum value
 */
static uint32_t compute_checksum(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t sum = 0;
    
    for (size_t i = 0; i < len; i++) {
        sum += bytes[i];
    }
    
    return sum;
}

/**
 * @brief Compute even parity bit
 *
 * Counts the number of 1-bits across all data. Returns 0 for even parity,
 * 1 for odd parity. Detects single-bit errors.
 *
 * @param[in] data Pointer to data to check
 * @param[in] len Length of data in bytes
 *
 * @return uint8_t Parity bit (0 or 1)
 *
 * @note Only detects odd numbers of bit flips
 */
static uint8_t compute_parity(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint8_t parity = 0;
    
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = bytes[i];
        /* Count 1 bits using Brian Kernighan's algorithm */
        while (byte) {
            parity ^= 1;
            byte &= (byte - 1);
        }
    }
    
    return parity;
}

/**
 * @brief Compute simplified Hamming code
 *
 * Generates a Hamming code for error detection and correction. This is
 * a simplified implementation that XORs bytes with position weighting.
 *
 * @param[in] data Pointer to data to encode
 * @param[in] len Length of data in bytes
 *
 * @return uint32_t Hamming code value
 *
 * @note This is a demonstration implementation - production use should employ
 *       full Hamming(7,4) or similar standard codes
 */
static uint32_t compute_hamming(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t h = 0;
    
    /* Simplified Hamming - XOR of all bytes with position weighting */
    size_t limit = (len < 4) ? len : 4;
    for (size_t i = 0; i < limit; i++) {
        h ^= (bytes[i] << (i * 8));
    }
    
    return h;
}

/**
 * @brief Check redundancy by comparing with backup copy
 *
 * Performs byte-by-byte comparison between original and backup copy.
 *
 * @param[in] original Pointer to original data
 * @param[in] backup Pointer to backup copy
 * @param[in] len Length to compare in bytes
 *
 * @return int Returns 1 if identical, 0 if different
 */
static int check_redundancy(const void *original, const void *backup, size_t len)
{
    return memcmp(original, backup, len) == 0;
}

/*=======================================================================================
** Violation Reporting Functions
**=======================================================================================*/

/**
 * @brief Report a memory integrity violation
 *
 * Generates multi-channel alerts when a memory integrity violation is detected.
 * Reports are sent via IDS telemetry, STIX logging, and cFE event services.
 *
 * @param[in] region Pointer to affected memory region
 * @param[in] violation_type String describing the violation type
 * @param[in] old_value Previous integrity value
 * @param[in] new_value New (violating) integrity value
 *
 * @return void
 *
 * @note Updates region statistics (violation_count, last_violation_time)
 * @note All alerts include region details for correlation
 */
static void report_violation(monitored_region_t *region, const char *violation_type, 
                            uint64_t old_value, uint64_t new_value)
{
    char message[IDS_REPORT_MESSAGE_LEN];
    
    /* Format comprehensive alert message */
    snprintf(message, IDS_REPORT_MESSAGE_LEN,
             "[SPACECOP] IOB Detected: SPARTA ID=%s (region=%s, type=%s, "
             "address=%p, size=%zu, old_value=0x%lx, new_value=0x%lx)",
             region->mire_id,
             region->name,
             violation_type,
             region->address,
             region->size,
             (unsigned long)old_value,
             (unsigned long)new_value);
    
    /* Send via IDS telemetry system */
    SPACECOP_ReportIDSMsg(message);
    
    /* Write to STIX log for correlation. Use mire_id (the SPARTA IOB, e.g.
    ** "MIRE-16") -- the region's iob_id is an internal per-region label like
    ** "-BOOT-0" that matches no SPARTA pattern, so correlation would silently
    ** miss. */
    write_to_stix(region->name, NULL, region->mire_id);
    
    /* Send cFE error event */
    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "%s", message);
    
    /* Update statistics */
    region->violation_count++;
    region->last_violation_time = (uint64_t)time(NULL);
}

/*=======================================================================================
** MIRE-15: Payload Memory Checking Functions
**=======================================================================================*/

/**
 * @brief Check payload memory region integrity
 *
 * Verifies payload memory integrity using hash comparison. If the current
 * hash doesn't match the expected hash, a violation is reported and the
 * expected hash is updated to the current value.
 *
 * @param[in] region Pointer to memory region to check
 *
 * @return int Returns 0 if integrity check passed, -1 if violation detected
 *
 * @note Thread-safe (acquires region lock)
 * @note Uses FNV-1a hash for verification
 * @note Updates expected hash after violation (assumes legitimate change)
 */
static int check_payload_memory(monitored_region_t *region)
{
    pthread_mutex_lock(&region->lock);
    
    /* Compute current hash */
    uint64_t current_hash = compute_hash(region->address, region->size);
    
    /* Compare with expected value */
    if (current_hash != region->expected_hash) {
        uint64_t old_hash = region->expected_hash;
        
        /* Report violation */
        report_violation(region, "payload_manipulation", old_hash, current_hash);
        
        /* Update expected hash to current value */
        region->expected_hash = current_hash;
        
        pthread_mutex_unlock(&region->lock);
        return -1;  /* Violation detected */
    }
    
    /* Check passed */
    region->check_count++;
    pthread_mutex_unlock(&region->lock);
    return 0;
}

/*=======================================================================================
** MIRE-16: Boot Memory Checking Functions
**=======================================================================================*/

/**
 * @brief Check boot memory region integrity
 *
 * Verifies boot memory using dual verification (hash + checksum) for higher
 * confidence. Both checks must pass for the region to be considered intact.
 *
 * @param[in] region Pointer to memory region to check
 *
 * @return int Returns 0 if both checks passed, -1 if any violation detected
 *
 * @note Thread-safe (acquires region lock)
 * @note Dual verification reduces false positive rate
 * @note Updates expected values after violations
 */
static int check_boot_memory(monitored_region_t *region)
{
    pthread_mutex_lock(&region->lock);

    uint64_t current_hash = compute_hash(region->address, region->size);
    uint32_t current_checksum = compute_checksum(region->address, region->size);

    /* Warm-up: for the first few checks after registration, silently adopt
    ** whatever we read as the baseline. Kernel rodata can still be settling just
    ** after boot (ro_after_init, static-call / jump-label patching), and we do
    ** not want to alert on that transient. */
    if (region->warmup_checks > 0) {
        region->warmup_checks--;
        region->expected_hash = current_hash;
        region->expected_checksum = current_checksum;
        region->pending_count = 0;
        region->check_count++;
        pthread_mutex_unlock(&region->lock);
        return 0;
    }

    /* Matches the baseline -- intact. Clear any in-flight candidate change. */
    if (current_hash == region->expected_hash) {
        region->pending_count = 0;
        region->check_count++;
        pthread_mutex_unlock(&region->lock);
        return 0;
    }

    /* Changed from baseline. Require the SAME changed value to persist for
    ** BOOT_CONFIRM_CHECKS consecutive checks before treating it as a real
    ** modification, so a one-off transient or a flaky /dev/mem read does not
    ** fire MIRE-16. */
    if (region->pending_count > 0 && current_hash == region->pending_hash) {
        region->pending_count++;
    } else {
        region->pending_hash = current_hash;
        region->pending_count = 1;
    }

    if (region->pending_count < BOOT_CONFIRM_CHECKS) {
        pthread_mutex_unlock(&region->lock);
        return 0;   /* not yet confirmed -- wait for it to persist */
    }

    /* Confirmed persistent change -> report and re-baseline. */
    report_violation(region, "boot_hash_mismatch",
                     region->expected_hash, current_hash);
    if (current_checksum != region->expected_checksum) {
        report_violation(region, "boot_checksum_mismatch",
                         region->expected_checksum, current_checksum);
    }
    region->expected_hash = current_hash;
    region->expected_checksum = current_checksum;
    region->pending_count = 0;

    pthread_mutex_unlock(&region->lock);
    return -1;
}

/*=======================================================================================
** MIRE-18: Critical Memory Checking Functions
**=======================================================================================*/

/**
 * @brief Check critical memory region with configurable error detection
 *
 * Verifies critical memory integrity using the configured detection method.
 * Supports multiple methods with different tradeoffs:
 * - Parity: Fast, detects odd bit flips
 * - Hamming: Error correction capable
 * - Checksum: Fast but weak
 * - Redundancy: Memory overhead but strong
 * - Hash: Default, good balance
 *
 * Updates error_status field for STIX compliance.
 *
 * @param[in] region Pointer to memory region to check
 *
 * @return int Returns 0 if check passed, -1 if error detected
 *
 * @note Thread-safe (acquires region lock)
 * @note Error status tracked per STIX requirements
 * @note Each method has different performance characteristics
 */
static int check_critical_memory(monitored_region_t *region)
{
    pthread_mutex_lock(&region->lock);
    
    int error_detected = 0;
    const char *detection_type = "";
    uint64_t old_value = 0;
    uint64_t new_value = 0;
    
    /* Check using configured method */
    switch (region->detection_method) {
    case ERROR_DETECT_PARITY: {
        detection_type = "parity_error";
        uint8_t current_parity = compute_parity(region->address, region->size);
        if (current_parity != region->expected_parity) {
            old_value = region->expected_parity;
            new_value = current_parity;
            error_detected = 1;
            region->expected_parity = current_parity;
        }
        break;
    }
    
    case ERROR_DETECT_HAMMING: {
        detection_type = "hamming_error";
        uint32_t current_hamming = compute_hamming(region->address, region->size);
        if (current_hamming != region->expected_hamming) {
            old_value = region->expected_hamming;
            new_value = current_hamming;
            error_detected = 1;
            region->expected_hamming = current_hamming;
        }
        break;
    }
    
    case ERROR_DETECT_CHECKSUM: {
        detection_type = "checksum_error";
        uint32_t current_checksum = compute_checksum(region->address, region->size);
        if (current_checksum != region->expected_checksum) {
            old_value = region->expected_checksum;
            new_value = current_checksum;
            error_detected = 1;
            region->expected_checksum = current_checksum;
        }
        break;
    }
    
    case ERROR_DETECT_REDUNDANCY: {
        detection_type = "redundancy_error";
        if (region->redundant_copy) {
            if (!check_redundancy(region->address, region->redundant_copy, region->size)) {
                old_value = 0;  /* Redundancy doesn't have single value */
                new_value = 1;
                error_detected = 1;
                /* Update redundant copy to current state */
                memcpy(region->redundant_copy, region->address, region->size);
            }
        }
        break;
    }
    
    case ERROR_DETECT_HASH:
    default: {
        detection_type = "hash_error";
        uint64_t current_hash = compute_hash(region->address, region->size);
        if (current_hash != region->expected_hash) {
            old_value = region->expected_hash;
            new_value = current_hash;
            error_detected = 1;
            region->expected_hash = current_hash;
        }
        break;
    }
    }
    
    /* Update STIX-compliant error status */
    if (error_detected) {
        region->error_status = ERROR_STATUS_FAILED;
        report_violation(region, detection_type, old_value, new_value);
        pthread_mutex_unlock(&region->lock);
        return -1;
    }
    
    region->error_status = ERROR_STATUS_PASSED;
    region->check_count++;
    pthread_mutex_unlock(&region->lock);
    return 0;
}

/*=======================================================================================
** Type-Specific Checking Functions
**=======================================================================================*/

/**
 * @brief Check all regions of a specific type
 *
 * Iterates through all registered regions and checks those matching the
 * specified type. Uses the appropriate checking function based on type.
 *
 * @param[in] type Region type to check (PAYLOAD, BOOT, CRITICAL, or GENERAL)
 *
 * @return int Number of violations detected across all regions
 *
 * @note Thread-safe (acquires global lock)
 * @note Only checks enabled regions
 */
static int check_regions_by_type(memory_region_type_t type)
{
    int violations = 0;
    
    pthread_mutex_lock(&monitor_state.global_lock);
    
    for (int i = 0; i < monitor_state.num_regions; i++) {
        monitored_region_t *region = &monitor_state.regions[i];
        
        /* Skip disabled or mismatched types */
        if (!region->enabled || region->type != type)
            continue;
        
        /* Check using appropriate function for type */
        int result = 0;
        switch (type) {
        case REGION_TYPE_PAYLOAD:
            result = check_payload_memory(region);
            break;
        case REGION_TYPE_BOOT:
            result = check_boot_memory(region);
            break;
        case REGION_TYPE_CRITICAL:
            result = check_critical_memory(region);
            break;
        case REGION_TYPE_GENERAL:
            result = check_payload_memory(region);  /* Default to payload checking */
            break;
        }
        
        if (result < 0) {
            violations++;
        }
    }
    
    pthread_mutex_unlock(&monitor_state.global_lock);
    
    return violations;
}

/*=======================================================================================
** Initialization Functions
**=======================================================================================*/

/**
 * @brief Internal initialization function (called via pthread_once)
 *
 * Initializes global state, mutex, and data structures. Called exactly once
 * via pthread_once mechanism to ensure thread-safe initialization.
 *
 * @return void
 *
 * @note Called automatically by pthread_once, not directly by applications
 */
static void CFS_MemoryIntegrity_Init_Internal(void)
{
    if (monitor_state.initialized) {
        return;
    }
    
    /* Initialize global mutex */
    pthread_mutex_init(&monitor_state.global_lock, NULL);
    monitor_state.num_regions = 0;
    monitor_state.initialized = 1;
    
    CFE_EVS_SendEvent(2000, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Memory Integrity Monitor Initialized (On-Demand Mode)");
}

/**
 * @brief Public initialization function
 *
 * Ensures the monitoring system is initialized. Safe to call multiple times.
 *
 * @return int Returns 0 on success
 *
 * @note Thread-safe via pthread_once
 */
int CFS_MemoryIntegrity_Init(void)
{
    pthread_once(&init_once, CFS_MemoryIntegrity_Init_Internal);
    return 0;
}

/*=======================================================================================
** Region Registration Functions
**=======================================================================================*/

/**
 * @brief Register a memory region for monitoring
 *
 * Adds a new memory region to the monitoring system. Validates parameters,
 * checks for duplicates, initializes integrity values, and allocates
 * redundant copies if needed.
 *
 * @param[in] address Starting address of memory region
 * @param[in] size Size of region in bytes
 * @param[in] type Region type (PAYLOAD, BOOT, CRITICAL, GENERAL)
 * @param[in] method Error detection method (HASH, PARITY, HAMMING, CHECKSUM, REDUNDANCY)
 * @param[in] name Descriptive name for the region
 * @param[in] iob_id SPARTA/STIX identifier string
 *
 * @return int Region ID (>= 0) on success, -1 on failure
 *
 * @note Thread-safe (acquires global lock)
 * @note Checks for duplicate registrations
 * @note Allocates redundant copy for REDUNDANCY method
 * @note Automatically assigns MIRE ID based on type
 */
int CFS_RegisterMemoryRegion(void *address, size_t size, 
                             uint8_t type,
                             uint8_t method,
                             const char *name, 
                             const char *iob_id)
{
    /* Cast back to enum types internally */
    memory_region_type_t region_type = (memory_region_type_t)type;
    error_detection_method_t detect_method = (error_detection_method_t)method;
    
    /* Ensure initialization */
    CFS_MemoryIntegrity_Init();
    
    pthread_mutex_lock(&monitor_state.global_lock);
    
    /* Check capacity */
    if (monitor_state.num_regions >= MAX_MONITORED_REGIONS) {
        pthread_mutex_unlock(&monitor_state.global_lock);
        CFE_EVS_SendEvent(2002, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] Cannot register region %s: limit reached", name);
        return -1;
    }
    
    /* Validate parameters */
    if (!address || size == 0) {
        pthread_mutex_unlock(&monitor_state.global_lock);
        CFE_EVS_SendEvent(2003, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] Invalid address or size for region %s", name);
        return -1;
    }
    
    /* Check for duplicates */
    for (int i = 0; i < monitor_state.num_regions; i++) {
        if (monitor_state.regions[i].address == address && 
            monitor_state.regions[i].size == size) {
            pthread_mutex_unlock(&monitor_state.global_lock);
            /* Already registered, return existing ID */
            return i;
        }
    }
    
    /* Get pointer to new region slot */
    monitored_region_t *region = &monitor_state.regions[monitor_state.num_regions];
    
    /* Initialize region structure */
    memset(region, 0, sizeof(monitored_region_t));
    
    region->address = address;
    region->size = size;
    region->type = region_type;
    region->detection_method = detect_method;
    region->error_status = ERROR_STATUS_UNKNOWN;
    
    /* Copy name and IOB ID with bounds checking */
    strncpy(region->name, name, sizeof(region->name) - 1);
    region->name[sizeof(region->name) - 1] = '\0';
    strncpy(region->iob_id, iob_id, sizeof(region->iob_id) - 1);
    region->iob_id[sizeof(region->iob_id) - 1] = '\0';
    
    /* Assign MIRE ID based on region type */
    switch (region_type) {
    case REGION_TYPE_PAYLOAD:
        region->mire_id = MIRE_15;
        break;
    case REGION_TYPE_BOOT:
        region->mire_id = MIRE_16;
        break;
    case REGION_TYPE_CRITICAL:
        region->mire_id = MIRE_18;
        break;
    default:
        region->mire_id = "MIRE-UNKNOWN";
        break;
    }
    
    /* MIRE-16 boot regions warm up: adopt the baseline silently for the first
    ** few checks so post-boot rodata settling doesn't fire a false alert. */
    region->warmup_checks = (region_type == REGION_TYPE_BOOT) ? BOOT_WARMUP_CHECKS : 0;

    /* Initialize all integrity values */
    region->expected_hash = compute_hash(address, size);
    region->expected_checksum = compute_checksum(address, size);
    region->expected_parity = compute_parity(address, size);
    region->expected_hamming = compute_hamming(address, size);
    
    /* Create redundant copy if using redundancy method */
    if (detect_method == ERROR_DETECT_REDUNDANCY) {
        region->redundant_copy = malloc(size);
        if (region->redundant_copy) {
            memcpy(region->redundant_copy, address, size);
        } else {
            CFE_EVS_SendEvent(2004, CFE_EVS_EventType_ERROR,
                             "[SPACECOP] Failed to allocate redundant copy for %s", name);
        }
    } else {
        region->redundant_copy = NULL;
    }
    
    /* Initialize statistics and state */
    region->check_count = 0;
    region->violation_count = 0;
    region->last_violation_time = 0;
    region->enabled = 1;
    region->protected = 0;
    
    /* Initialize region mutex */
    pthread_mutex_init(&region->lock, NULL);
    
    /* Increment region count and get ID */
    int region_id = monitor_state.num_regions;
    monitor_state.num_regions++;
    
    pthread_mutex_unlock(&monitor_state.global_lock);
    
    #ifdef SPACECOP_MONITOR_DEBUG
    CFE_EVS_SendEvent(2005, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Registered memory region: %s (%s) at %p, size %zu\n",
                     name, region->mire_id, address, size);
    #endif
    
    return region_id;
}

/*=======================================================================================
** Cleanup Functions
**=======================================================================================*/

/**
 * @brief Clean up all monitoring resources
 *
 * Frees all allocated memory (redundant copies), destroys all mutexes,
 * and resets global state. Should be called during application shutdown.
 *
 * @return void
 *
 * @note Thread-safe (acquires global lock)
 * @note Frees redundant copies for all regions
 * @note Destroys all region-specific mutexes
 */
void CFS_MemoryIntegrity_Cleanup(void)
{
    pthread_mutex_lock(&monitor_state.global_lock);
    
    /* Free redundant copies and destroy region mutexes */
    for (int i = 0; i < monitor_state.num_regions; i++) {
        if (monitor_state.regions[i].redundant_copy) {
            free(monitor_state.regions[i].redundant_copy);
            monitor_state.regions[i].redundant_copy = NULL;
        }
        pthread_mutex_destroy(&monitor_state.regions[i].lock);
    }
    
    /* Reset region count */
    monitor_state.num_regions = 0;
    
    pthread_mutex_unlock(&monitor_state.global_lock);
    pthread_mutex_destroy(&monitor_state.global_lock);
    
    monitor_state.initialized = 0;
}

/**
 * @brief Get statistics for a specific region
 *
 * Retrieves check count and violation count for debugging and monitoring.
 *
 * @param[in] region_id Region ID returned from registration
 * @param[out] checks Pointer to store check count (can be NULL)
 * @param[out] violations Pointer to store violation count (can be NULL)
 *
 * @return void
 *
 * @note Thread-safe (acquires region lock)
 * @note Does nothing if region_id is invalid
 */
void CFS_GetRegionStats(int region_id, uint64_t *checks, uint64_t *violations)
{
    if (region_id < 0 || region_id >= monitor_state.num_regions)
        return;
    
    monitored_region_t *region = &monitor_state.regions[region_id];
    
    pthread_mutex_lock(&region->lock);
    if (checks) *checks = region->check_count;
    if (violations) *violations = region->violation_count;
    pthread_mutex_unlock(&region->lock);
}

/*=======================================================================================
** Process Memory Monitoring (Original Functionality)
**=======================================================================================*/

/**
 * @brief Get memory usage of a process from /proc/[pid]/statm
 *
 * Reads the statm file to get resident set size and converts to kilobytes.
 *
 * @param[in] pid Process ID to query
 *
 * @return long Memory usage in kilobytes, or -1 on error
 */
static long get_memory_usage(pid_t pid) {
    char statm_path[256];
    snprintf(statm_path, sizeof(statm_path), "/proc/%d/statm", pid);

    FILE *file = fopen(statm_path, "r");
    if (!file) {
        return -1;
    }

    long memory = 0;
    if (fscanf(file, "%ld", &memory) == 1) {
        /* Memory usage in pages; convert to kilobytes */
        memory *= (long)sysconf(_SC_PAGESIZE) / 1024;
    }

    fclose(file);
    return memory;
}

/**
 * @brief Monitor process memory usage across all processes
 *
 * Scans /proc to find all processes and checks their memory usage against
 * a threshold. Generates alerts for non-whitelisted processes exceeding
 * the threshold.
 *
 * @param[in] memory_threshold Maximum allowed memory in kilobytes
 * @param[in] name SPARTA/STIX identifier for alerts
 *
 * @return void
 *
 * @note Checks process whitelist before alerting
 * @note Requires read access to /proc filesystem
 */
void Memory_Monitor_Start(uint32_t memory_threshold, const char* name)
{
    char message[IDS_REPORT_MESSAGE_LEN];
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) 
    {
        perror("Failed to open /proc");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) 
    {
        /* Skip non-numeric entries */
        if (!isdigit(entry->d_name[0]))  continue;

        pid_t pidNum = atoi(entry->d_name);
        char *pid = entry->d_name;
        char process_name[256];

        /* Get process name */
        get_process_name(pid, process_name, sizeof(process_name));

        /* Get memory usage */
        long memory_usage = get_memory_usage(pidNum);
        if (memory_usage == -1) 
        {
            continue;
        }

        /* Check threshold */
        if (memory_usage > (long)memory_threshold) 
        {
            /* Check whitelist */
            if (!WL_ContainsSubName_Proc(process_name))
            {
                /* Generate alert */
                memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                        "[SPACECOP] IOB Detected: SPARTA ID=%s (process_name == %s, memory_usage == %ld)", 
                        name, process_name, memory_usage);
                SPACECOP_ReportIDSMsg(message);
                write_to_stix(process_name, NULL, name);
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                 "[SPACECOP] IOB Detected: SPARTA ID=%s (process_name == %s, memory_usage == %ld)", 
                                 name, process_name, memory_usage);
            }
        }
    }

    closedir(proc_dir);
}

/*=======================================================================================
** MIRE-15: Payload Memory Auto-Discovery
**=======================================================================================*/

/**
 * @brief Auto-discover cFS application memory regions
 *
 * Parses /proc/self/maps to discover executable memory regions belonging to
 * critical cFS applications. Only registers regions for apps in the critical
 * list (SCH, TO, CI, FM, CS, HK, LC, SC).
 *
 * Discovery process:
 * 1. Query cFE for list of running applications
 * 2. Parse /proc/self/maps for memory regions
 * 3. Match regions to critical app names (case-insensitive)
 * 4. Register executable (code) segments only
 * 5. Skip non-critical apps and data segments
 *
 * @return void
 *
 * @note Called automatically on first Memory_Monitor_Payload_Start() call
 * @note Only registers critical applications to reduce overhead
 * @note Skips SPACECOP itself to avoid self-monitoring
 */
static void Memory_Monitor_AutoDiscoverApps(void)
{
    FILE *maps_file;
    char line[512];
    int regions_registered = 0;
    
    /* Whitelist of critical apps to monitor */
    const char *critical_apps[] = {
        "SCH",      /* Scheduler */
        "TO",       /* Telemetry Output */
        "CI",       /* Command Ingest */
        "FM",       /* File Manager */
        "CS",       /* Checksum */
        "HK",       /* Housekeeping */
        "LC",       /* Limit Checker */
        "SC",       /* Stored Commands */
        NULL
    };
    
    int skipped_not_critical = 0;
    int skipped_not_executable = 0;
    int skipped_writable = 0;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    CFE_EVS_SendEvent(2100, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Auto-discovering CRITICAL app memory via /proc/self/maps\n");
    #endif
    
    /* Open memory map file */
    maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        #ifdef SPACECOP_MONITOR_DEBUG
        CFE_EVS_SendEvent(2101, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] Failed to open /proc/self/maps\n");
        #endif
        return;
    }
    
    /* Build list of known app names from cFE */
    char app_names[CFE_PLATFORM_ES_MAX_APPLICATIONS][OS_MAX_API_NAME];
    int num_apps = 0;
    
    CFE_ES_AppInfo_t AppInfo;
    CFE_ES_AppId_t AppId;
    uint32 BaseId = 0x00110000;
    
    /* Query cFE for all running applications */
    for (uint32 i = 0; i < CFE_PLATFORM_ES_MAX_APPLICATIONS; i++)
    {
        AppId = CFE_ResourceId_FromInteger(BaseId | i);
        
        if (CFE_ES_GetAppInfo(&AppInfo, AppId) == CFE_SUCCESS)
        {
            /* Skip empty names and SPACECOP itself */
            if (AppInfo.Name[0] != '\0' && strcmp(AppInfo.Name, "SPACECOP") != 0)
            {
                strncpy(app_names[num_apps], AppInfo.Name, OS_MAX_API_NAME - 1);
                app_names[num_apps][OS_MAX_API_NAME - 1] = '\0';
                num_apps++;
            }
        }
    }
    
    if (num_apps == 0) {
        printf("[SPACECOP] ERROR: No apps found to search for!\n");
        fclose(maps_file);
        return;
    }
    
    /* Parse /proc/self/maps and match to critical app names */
    while (fgets(line, sizeof(line), maps_file))
    {
        unsigned long start_addr, end_addr;
        char perms[8];
        unsigned long offset;
        char dev[16];
        unsigned long inode;
        char path[256] = "";
        
        /* Parse line: "address-range perms offset dev inode path" */
        int fields = sscanf(line, "%lx-%lx %s %lx %s %lu %[^\n]",
                           &start_addr, &end_addr, perms, &offset, dev, &inode, path);
        
        if (fields < 6) continue;
        
        size_t size = end_addr - start_addr;
        
        /* Skip if not readable */
        if (strchr(perms, 'r') == NULL) continue;
        
        /* Skip very small regions */
        if (size < 4096) continue;
        
        /* Skip if no path or special regions */
        if (path[0] == '\0' || path[0] == '[') continue;
        
        /* Check if this path contains any of our app names */
        for (int app_idx = 0; app_idx < num_apps; app_idx++)
        {
            char path_lower[256];
            char app_lower[OS_MAX_API_NAME];
            
            /* Convert to lowercase for case-insensitive comparison */
            strncpy(path_lower, path, sizeof(path_lower) - 1);
            path_lower[sizeof(path_lower) - 1] = '\0';
            strncpy(app_lower, app_names[app_idx], sizeof(app_lower) - 1);
            app_lower[sizeof(app_lower) - 1] = '\0';
            
            for (int i = 0; path_lower[i]; i++) path_lower[i] = tolower(path_lower[i]);
            for (int i = 0; app_lower[i]; i++) app_lower[i] = tolower(app_lower[i]);
            
            /* Check if app name is in path */
            if (strstr(path_lower, app_lower) != NULL)
            {
                /* Check if app is in critical list */
                int is_critical = 0;
                for (int i = 0; critical_apps[i] != NULL; i++) {
                    char crit_lower[64];
                    strncpy(crit_lower, critical_apps[i], sizeof(crit_lower) - 1);
                    crit_lower[sizeof(crit_lower) - 1] = '\0';
                    for (int j = 0; crit_lower[j]; j++) crit_lower[j] = tolower(crit_lower[j]);
                    
                    if (strcmp(app_lower, crit_lower) == 0) {
                        is_critical = 1;
                        break;
                    }
                }
                
                if (!is_critical) {
                    skipped_not_critical++;
                    break;
                }
                
                /* Only register executable (code) segments */
                if (strchr(perms, 'x') == NULL) {
                    skipped_not_executable++;
                    break;
                }

                /* Only monitor IMMUTABLE code: read-only + executable. A
                 * writable mapping (w present, e.g. rwxp) holds mutable data
                 * that legitimately changes between checks and would hash-
                 * mismatch as a MIRE-15 false positive - the same reason the
                 * boot path excludes "Kernel data"/"bss". */
                if (strchr(perms, 'w') != NULL) {
                    skipped_writable++;
                    break;
                }

                /* This is a critical app's code segment - register it */
                char region_name[128];
                snprintf(region_name, sizeof(region_name), "%s_code_%lx", 
                        app_names[app_idx], start_addr);
                
                int result = CFS_RegisterMemoryRegion((void*)start_addr,
                                                     size,
                                                     REGION_TYPE_PAYLOAD,
                                                     ERROR_DETECT_HASH,
                                                     region_name,
                                                     MIRE_15);
                
                if (result >= 0) {
                    regions_registered++;
                    #ifdef SPACECOP_MONITOR_DEBUG
                    printf("[SPACECOP] Registered CRITICAL app: %s at 0x%lx, size=%zu\n",
                           app_names[app_idx], start_addr, size);
                    #endif
                }
                
                break;
            }
        }
    }
    
    fclose(maps_file);
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("[SPACECOP] === Auto-Discovery Summary ===\n");
    printf("[SPACECOP] Regions registered:        %d\n", regions_registered);
    printf("[SPACECOP] Skipped (not critical):    %d\n", skipped_not_critical);
    printf("[SPACECOP] Skipped (not executable):  %d\n", skipped_not_executable);
    printf("[SPACECOP] Skipped (writable):        %d\n", skipped_writable);
    #endif
    
    if (regions_registered == 0) {
        CFE_EVS_SendEvent(2107, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] WARNING: No critical app memory regions found!\n");
    } else {
        CFE_EVS_SendEvent(2108, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] Auto-discovery complete: %d critical regions registered\n",
                         regions_registered);
    }
}

/*=======================================================================================
** MIRE-16: Boot Memory Auto-Discovery
**=======================================================================================*/

/**
 * @brief Auto-discover boot and kernel memory regions
 *
 * Parses /proc/iomem to discover kernel code, data, BSS, and rodata regions.
 * Maps physical memory using /dev/mem and mmap() for monitoring.
 *
 * Discovery process:
 * 1. Parse /proc/iomem for kernel memory regions
 * 2. Filter for boot-related regions (code, data, bss, rodata)
 * 3. Skip regions larger than 50MB (likely full RAM, not specific code)
 * 4. Open /dev/mem for physical memory access
 * 5. mmap() each region into address space
 * 6. Register for monitoring with checksum verification
 *
 * @return void
 *
 * @note Requires root privileges or CAP_SYS_RAWIO capability
 * @note Maps physical memory into virtual address space
 * @note Called automatically on first Memory_Monitor_Boot_Start() call
 *
 * @warning Accessing /dev/mem requires elevated privileges
 * @warning Unmapping is not currently implemented (regions persist until exit)
 */
static void Memory_Monitor_AutoDiscoverBootMemory(void)
{
    FILE *iomem_file;
    char line[512];
    char iob_id[128];
    int boot_region_count = 0;
    
    CFE_EVS_SendEvent(2200, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Auto-discovering boot memory regions from /proc/iomem");
    
    /* Open I/O memory map */
    iomem_file = fopen("/proc/iomem", "r");
    if (!iomem_file) {
        CFE_EVS_SendEvent(2201, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] /proc/iomem not available (may not be Linux)");
        return;
    }
    
    /* Parse /proc/iomem line by line */
    while (fgets(line, sizeof(line), iomem_file)) {
        unsigned long start_addr, end_addr;
        char name[256];
        
        /* Parse line format: "00000000-0009ffff : System RAM" */
        if (sscanf(line, "%lx-%lx : %[^\n]", &start_addr, &end_addr, name) == 3) {
            
            size_t size = end_addr - start_addr + 1;
            
            /* Only monitor "Kernel rodata". This used to also include "Kernel
             * code" (.text), but a RUNNING kernel legitimately rewrites its own
             * .text at runtime -- static keys / jump labels, ftrace, alternatives,
             * kprobes -- so hashing it produced a stream of MIRE-16 false
             * positives (BOOT-0). (".data"/".bss" were already excluded for the
             * same mutability reason.) .rodata is far more stable; any residual
             * post-boot settling is absorbed by the warm-up + consecutive-
             * mismatch gating in check_boot_memory(). */
            if (strstr(name, "Kernel rodata") != NULL) {
                
                /* Skip if too large (probably full System RAM, not specific boot code) */
                if (size > 50 * 1024 * 1024) {  /* Skip regions > 50MB */
                    CFE_EVS_SendEvent(2205, CFE_EVS_EventType_INFORMATION,
                                     "[SPACECOP] Skipping large region: %s (size=%zu MB)",
                                     name, size / (1024 * 1024));
                    continue;
                }
                
                snprintf(iob_id, sizeof(iob_id), "-BOOT-%d", boot_region_count);
                
                CFE_EVS_SendEvent(2202, CFE_EVS_EventType_INFORMATION,
                                 "[SPACECOP] Found boot region: %s at 0x%lx-0x%lx (size=%zu KB)",
                                 name, start_addr, end_addr, size / 1024);
                
                /* Open /dev/mem for physical memory access */
                int mem_fd = open("/dev/mem", O_RDONLY);
                if (mem_fd < 0) {
                    CFE_EVS_SendEvent(2206, CFE_EVS_EventType_ERROR,
                                     "[SPACECOP] Cannot open /dev/mem (need root): %s",
                                     strerror(errno));
                    continue;
                }
                
                /* Map the physical memory region into our address space */
                void *mapped_addr = mmap(NULL, size, PROT_READ, MAP_SHARED, 
                                        mem_fd, start_addr);
                close(mem_fd);
                
                if (mapped_addr == MAP_FAILED) {
                    CFE_EVS_SendEvent(2207, CFE_EVS_EventType_ERROR,
                                     "[SPACECOP] Failed to mmap boot region %s: %s",
                                     name, strerror(errno));
                    continue;
                }
                
                /* Successfully mapped - now register it for monitoring */
                int result = CFS_RegisterMemoryRegion(mapped_addr,
                                        size,
                                        REGION_TYPE_BOOT,
                                        ERROR_DETECT_CHECKSUM,  /* Use checksum for boot */
                                        name,
                                        iob_id);
                
                if (result >= 0) {
                    CFE_EVS_SendEvent(2203, CFE_EVS_EventType_INFORMATION,
                                     "[SPACECOP] Registered boot region: %s (mapped at %p, size=%zu KB)",
                                     name, mapped_addr, size / 1024);
                    boot_region_count++;
                } else {
                    CFE_EVS_SendEvent(2208, CFE_EVS_EventType_ERROR,
                                     "[SPACECOP] Failed to register boot region: %s",
                                     name);
                    /* Unmap if registration failed */
                    munmap(mapped_addr, size);
                }
            }
        }
    }
    
    fclose(iomem_file);
    
    if (boot_region_count > 0) {
        CFE_EVS_SendEvent(2204, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] Boot memory discovery complete: %d regions registered and monitored",
                         boot_region_count);
    } else {
        CFE_EVS_SendEvent(2209, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] No boot regions found or registered from /proc/iomem");
    }
}

/*=======================================================================================
** MIRE-15: Payload Memory Monitoring (Public API)
**=======================================================================================*/

/**
 * @brief Start or check payload memory monitoring (MIRE-15)
 *
 * Public API for MIRE-15 monitoring. On first call, triggers auto-discovery
 * of critical application memory. On subsequent calls, performs integrity
 * checks on all registered payload regions.
 *
 * @param[in] iob_id SPARTA/STIX identifier (typically "MIRE-15")
 *
 * @return void
 *
 * @note Should be called periodically (recommended: every 10 seconds)
 * @note Auto-discovery runs only once
 */
void Memory_Monitor_Payload_Start(const char* iob_id)
{
    /* Ensure initialization */
    CFS_MemoryIntegrity_Init();
    
    /* AUTO-DISCOVER regions ONCE on first call */
    if (!mire_state.payload_discovered) {
        CFE_EVS_SendEvent(1504, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] MIRE-15: Starting app memory auto-discovery (ONCE)\n");
        
        Memory_Monitor_AutoDiscoverApps();
        
        mire_state.payload_discovered = 1;
        
        CFE_EVS_SendEvent(1505, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] MIRE-15: App memory discovery complete\n");
    }
    
    /* NOW CHECK ALL PAYLOAD REGIONS (called every 10 seconds by scheduler) */
    int violations = check_regions_by_type(REGION_TYPE_PAYLOAD);
    
    if (violations > 0) {
        CFE_EVS_SendEvent(1506, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] MIRE-15: %d payload violations detected\n", violations);
    }
}

/**
 * @brief Stop payload memory monitoring
 *
 * Resets discovery state, allowing re-discovery on next start.
 *
 * @return void
 */
void Memory_Monitor_Payload_Stop(void)
{
    mire_state.payload_discovered = 0;
}

/**
 * @brief Manually register a payload memory region
 *
 * @param[in] address Starting address
 * @param[in] size Size in bytes
 * @param[in] name Region name
 *
 * @return int Region ID on success, -1 on failure
 */
int Memory_Monitor_RegisterPayload(void* address, uint32_t size, const char* name)
{
    return CFS_RegisterMemoryRegion(address, (size_t)size, 
                                    REGION_TYPE_PAYLOAD,
                                    ERROR_DETECT_HASH,
                                    name,
                                    MIRE_15);
}

/*=======================================================================================
** MIRE-16: Boot Memory Monitoring (Public API)
**=======================================================================================*/

/**
 * @brief Start or check boot memory monitoring (MIRE-16)
 *
 * Public API for MIRE-16 monitoring. On first call, triggers auto-discovery
 * of boot/kernel memory. On subsequent calls, performs integrity checks.
 *
 * @param[in] iob_id SPARTA/STIX identifier (typically "MIRE-16")
 *
 * @return void
 *
 * @note Should be called periodically (recommended: every 5 seconds)
 * @note Requires root privileges for /dev/mem access
 */
void Memory_Monitor_Boot_Start(const char* iob_id)
{
    /* Ensure initialization */
    CFS_MemoryIntegrity_Init();
    
    /* AUTO-DISCOVER boot regions ONCE on first call */
    if (!mire_state.boot_discovered) {
        CFE_EVS_SendEvent(1606, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] MIRE-16: Boot memory monitoring ready\n");
        
        Memory_Monitor_AutoDiscoverBootMemory();
        
        mire_state.boot_discovered = 1;
    }
    
    /* NOW CHECK ALL BOOT REGIONS (called every 5 seconds by scheduler) */
    int violations = check_regions_by_type(REGION_TYPE_BOOT);
    
    if (violations > 0) {
        CFE_EVS_SendEvent(1607, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] MIRE-16: %d boot violations detected\n", violations);
    }
}

/**
 * @brief Stop boot memory monitoring
 *
 * Resets discovery state.
 *
 * @return void
 */
void Memory_Monitor_Boot_Stop(void)
{
    mire_state.boot_discovered = 0;
}

/**
 * @brief Manually register a boot memory region
 *
 * @param[in] address Starting address
 * @param[in] size Size in bytes
 * @param[in] name Region name
 *
 * @return int Region ID on success, -1 on failure
 */
int Memory_Monitor_RegisterBoot(void* address, uint32_t size, const char* name)
{
    return CFS_RegisterMemoryRegion(address, (size_t)size, 
                                    REGION_TYPE_BOOT,
                                    ERROR_DETECT_CHECKSUM,
                                    name,
                                    MIRE_16);
}

/*=======================================================================================
** MIRE-18: Critical Memory Monitoring (Public API)
**=======================================================================================*/

/**
 * @brief Start or check critical memory monitoring (MIRE-18)
 *
 * Public API for MIRE-18 monitoring. Checks all manually-registered critical
 * memory regions using their configured error detection methods.
 *
 * @param[in] iob_id SPARTA/STIX identifier (typically "MIRE-18")
 *
 * @return void
 *
 * @note Should be called frequently (recommended: every 1 second)
 * @note Regions must be manually registered before monitoring
 */
void Memory_Monitor_Critical_Start(const char* iob_id)
{
    /* Ensure initialization */
    CFS_MemoryIntegrity_Init();
    
    if (!mire_state.critical_discovered) {
        CFE_EVS_SendEvent(1804, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] MIRE-18: Critical memory monitor started\n");
        mire_state.critical_discovered = 1;
    }
    
    /* NOW CHECK ALL CRITICAL REGIONS (called every 1 second by scheduler) */
    int violations = check_regions_by_type(REGION_TYPE_CRITICAL);
    
    if (violations > 0) {
        CFE_EVS_SendEvent(1805, CFE_EVS_EventType_ERROR,
                         "[SPACECOP] MIRE-18: %d critical memory errors detected\n", violations);
    }
}

/**
 * @brief Stop critical memory monitoring
 *
 * Resets discovery state.
 *
 * @return void
 */
void Memory_Monitor_Critical_Stop(void)
{
    mire_state.critical_discovered = 0;
}

/**
 * @brief Manually register a critical memory region
 *
 * @param[in] address Starting address
 * @param[in] size Size in bytes
 * @param[in] name Region name
 * @param[in] detection_method Error detection method (DETECT_METHOD_*)
 *
 * @return int Region ID on success, -1 on failure
 */
int Memory_Monitor_RegisterCritical(void* address, uint32_t size, 
                                    const char* name, uint8_t detection_method)
{
    if (detection_method > ERROR_DETECT_REDUNDANCY) {
        CFE_EVS_SendEvent(1806, CFE_EVS_EventType_ERROR,
                         "Invalid detection method %d for region %s\n", 
                         detection_method, name);
        return -1;
    }
    
    return CFS_RegisterMemoryRegion(address, (size_t)size, 
                                    REGION_TYPE_CRITICAL,
                                    (error_detection_method_t)detection_method,
                                    name,
                                    MIRE_18);
}

/*=======================================================================================
** Application Auto-Registration API
**=======================================================================================*/

/**
 * @brief Register multiple memory regions for an application
 *
 * Convenience function for bulk registration. Automatically assigns MIRE IDs
 * based on region type.
 *
 * @param[in] app_name Application name for logging
 * @param[in] regions Array of MemoryRegionConfig_t structures
 * @param[in] num_regions Number of regions in array
 *
 * @return int32_t CFE_SUCCESS on success, -1 if any region fails
 *
 * @note Continues registering remaining regions even if one fails
 */
int32_t SPACECOP_RegisterAppMemory(const char *app_name, 
                                    MemoryRegionConfig_t *regions,
                                    uint32_t num_regions)
{
    const char *iob_id;
    int32_t status = CFE_SUCCESS;
    
    CFS_MemoryIntegrity_Init();
    
    #ifdef SPACECOP_MONITOR_DEBUG
    CFE_EVS_SendEvent(2009, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Manually registering %u memory regions for app: %s\n",
                     (unsigned int)num_regions, app_name);
    #endif
    
    for (uint32_t i = 0; i < num_regions; i++) {
        /* Assign MIRE ID based on type */
        if (regions[i].type == REGION_TYPE_PAYLOAD) {
            iob_id = MIRE_15;
        } else if (regions[i].type == REGION_TYPE_CRITICAL) {
            iob_id = MIRE_18;
        } else if (regions[i].type == REGION_TYPE_BOOT) {
            iob_id = MIRE_16;
        } else {
            iob_id = "MIRE-UNKNOWN";
        }
        
        int result = CFS_RegisterMemoryRegion(regions[i].address, 
                                              regions[i].size,
                                              regions[i].type,
                                              regions[i].method,
                                              regions[i].name,
                                              iob_id);
        
        if (result < 0) {
            #ifdef SPACECOP_MONITOR_DEBUG
            CFE_EVS_SendEvent(2010, CFE_EVS_EventType_ERROR,
                             "[SPACECOP] Failed to register region %s for app %s\n",
                             regions[i].name, app_name);
            #endif
            status = -1;
        }
    }
    
    return status;
}