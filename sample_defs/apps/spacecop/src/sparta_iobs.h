// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file sparta_iobs.h
 * @brief SPARTA Indicator of Behavior (IOB) database interface
 *
 * This header defines the interface for the SPARTA (Space Attack Research
 * and Tactic Analysis) Indicator of Behavior database. It provides:
 * - IOB structure definitions
 * - Artifact type classifications
 * - Database access functions
 * - STIX pattern integration
 *
 * **SPARTA Framework Overview:**
 * SPARTA is a comprehensive knowledge base of adversary tactics and techniques
 * targeting space systems. It is analogous to MITRE ATT&CK but specifically
 * designed for the unique threat landscape of spacecraft, ground systems,
 * and space communication networks.
 *
 * **Indicators of Behavior (IOBs):**
 * IOBs are observable patterns that indicate potential malicious activity.
 * Unlike Indicators of Compromise (IOCs) which identify known-bad artifacts
 * (file hashes, IP addresses), IOBs detect suspicious behaviors and patterns
 * that may indicate attack activity.
 *
 * **IOB vs IOC:**
 * @code
 * IOC (Indicator of Compromise):
 * - File hash: SHA256 = 3a5f8c2e...
 * - IP address: 192.168.1.100
 * - Exact match detection
 * - Brittle (easily evaded by modification)
 * 
 * IOB (Indicator of Behavior):
 * - Command executed outside authorized schedule
 * - Burn duration exceeds expected limits
 * - Pattern-based detection
 * - Resilient (detects intent, not specific artifact)
 * @endcode
 *
 * **IOB Categories:**
 * The database contains 238 IOBs organized into 10 categories:
 * - UACE: Unauthorized Command Execution
 * - UCEB: Unauthorized Cryptographic and Encryption Bypass
 * - CSNE: Communication and Satellite Network Exploitation
 * - ARFS: Authentication and RF Signal Manipulation
 * - GNTM: GNSS and Navigation Time Manipulation
 * - MIRE: Memory Integrity and Resource Exhaustion
 * - WTRE: Watchdog Timer and Register Exploitation
 * - SIUU: Software Integrity and Unauthorized Updates
 * - SMSR: Sensor Manipulation and System Resource Attacks
 * - DISE: Data Integrity and Storage Exploitation
 *
 * **STIX Pattern Language:**
 * Each IOB includes a STIX (Structured Threat Information eXpression)
 * pattern that defines the observable conditions for detection. STIX
 * provides a standardized language for describing cyber threat intelligence.
 *
 * **Example STIX Pattern:**
 * @code
 * // Detect command executed outside authorized time
 * "[x-opencti-command-log:command = 'hw_cmd_execute' AND 
 *   x-opencti-command-log:execution_time != 'authorized_time']"
 * 
 * // Components:
 * [...]                     - Pattern expression
 * x-opencti-command-log     - Observable object type
 * :command                  - Object property
 * = 'hw_cmd_execute'        - Comparison operator and value
 * AND                       - Logical operator
 * @endcode
 *
 * **Artifact Types:**
 * Each IOB is associated with a primary artifact type that indicates
 * the main source of evidence for detection:
 * - AT_NONE: Multiple sources or telemetry-based
 * - AT_FILE: File system artifacts
 * - AT_PROGRAM: Process execution artifacts
 * - AT_NETWORK: Network traffic artifacts
 * - AT_COMMAND: Command logs
 * - AT_CONFIG: Configuration files
 * - AT_MEMORY: Memory contents
 * - AT_KEY: Cryptographic keys
 * - AT_DEVICE: Hardware devices
 *
 * **Integration with SpaceCop:**
 * @code
 * // Look up IOB for rule
 * const IOBCTI *iob = FindIoB("UACE-1");
 * 
 * // Evaluate STIX pattern
 * if (evaluate_stix_pattern(iob->pattern, system_state)) {
 *     // Generate alert
 *     generate_alert(iob->iob, iob->name, iob->arttype);
 * }
 * 
 * // Include in telemetry
 * strncpy(alert_msg.iob_id, iob->iob, IOB_ID_SZ);
 * alert_msg.artifact_type = iob->arttype;
 * @endcode
 *
 * **Threat Intelligence Sharing:**
 * IOBs enable standardized threat intelligence sharing:
 * - STIX format compatible with industry tools
 * - Interoperable with ground system SIEM
 * - Supports multi-mission threat intelligence
 * - Enables collaborative defense
 *
 * **Usage Workflow:**
 * 1. Define detection rules referencing IOB identifiers
 * 2. Runtime engine looks up IOB details via FindIoB()
 * 3. STIX pattern evaluated against system state
 * 4. Alerts include IOB identifier and artifact type
 * 5. Ground systems correlate IOBs to attack campaigns
 *
 * @note IOB database is const (immutable at runtime)
 * @note STIX patterns may require mission-specific configuration
 * @note Artifact types guide forensic data collection
 *
 * @see sparta_iobs.c for complete IOB database implementation
 * @see SPARTA framework documentation for detailed threat analysis
 * @see STIX specification for pattern language details
 */

#ifndef SPARTA_IOBS_H
#define SPARTA_IOBS_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "cfe.h"
#include <string.h>

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief Maximum size of IOB identifier string
 * 
 * Defines the maximum length for IOB identifier strings including null
 * terminator. IOB identifiers follow the format "CATEGORY-NUMBER" where:
 * - CATEGORY: 4-character category code (UACE, UCEB, CSNE, etc.)
 * - Hyphen: 1 character
 * - NUMBER: 1-3 digit number
 * - Null terminator: 1 character
 * 
 * **Examples:**
 * - "UACE-1" (6 chars + null = 7)
 * - "CSNE-45" (7 chars + null = 8)
 * - "SIUU-26" (7 chars + null = 8)
 * 
 * **Current Value:** 10 bytes (provides room for future expansion)
 * 
 * @note Includes null terminator
 * @note Used for fixed-size arrays and strncmp operations
 */
#define IOB_ID_SZ 10

/**
 * @brief Total number of IOBs in the database
 * 
 * Defines the size of the iobs[] array containing all IOB definitions.
 * Must be updated whenever IOBs are added or removed from the database.
 * 
 * **Current Database Size:** 238 IOBs
 * 
 * **Category Breakdown:**
 * - UACE: 26 IOBs (Unauthorized Command Execution)
 * - UCEB: 11 IOBs (Cryptographic Bypass)
 * - CSNE: 45 IOBs (Network Exploitation)
 * - ARFS: 12 IOBs (Authentication/RF Attacks)
 * - GNTM: 12 IOBs (GNSS/Time Manipulation)
 * - MIRE: 18 IOBs (Memory/Resource Attacks)
 * - WTRE: 7 IOBs (Watchdog/Register Attacks)
 * - SIUU: 26 IOBs (Software Integrity)
 * - SMSR: 19 IOBs (Sensor/Resource Attacks)
 * - DISE: 17 IOBs (Data Integrity)
 * - Additional: 45 IOBs (Extended coverage)
 * 
 * **Maintenance:**
 * When adding IOBs:
 * 1. Add entry to iobs[] array in sparta_iobs.c
 * 2. Increment IOB_ARRAY_SIZE
 * 3. Verify array initialization compiles
 * 4. Update documentation
 * 
 * @note Must match actual array size in sparta_iobs.c
 * @note Compiler will error if mismatch occurs
 */
#define IOB_ARRAY_SIZE 238

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Artifact type classification enumeration
 * 
 * Classifies IOBs by their primary artifact type, indicating the main
 * source of evidence used for detection. This guides:
 * - Data collection priorities
 * - Forensic analysis procedures
 * - Storage requirements
 * - Evidence preservation
 *
 * **Artifact Type Descriptions:**
 *
 * **AT_NONE (0):**
 * No specific artifact or multiple artifact types.
 * - Telemetry-based detections
 * - Behavioral patterns across multiple sources
 * - Statistical anomalies
 * - Threshold violations
 * 
 * Examples:
 * - Sensor readings outside normal range
 * - CPU utilization spikes
 * - Timing anomalies
 *
 * **AT_FILE (1):**
 * File system artifacts.
 * - File paths
 * - File hashes (SHA-256)
 * - File metadata (timestamps, permissions)
 * - Directory structures
 * 
 * Examples:
 * - Modified configuration files
 * - Unauthorized file creation
 * - File integrity violations
 * - On-orbit update binaries
 *
 * **AT_PROGRAM (2):**
 * Process and program execution artifacts.
 * - Process names
 * - Executable paths
 * - Process IDs
 * - Parent-child relationships
 * - System calls
 * 
 * Examples:
 * - Malicious process execution
 * - Unauthorized binary execution
 * - Process injection
 * - Kernel module loading
 *
 * **AT_NETWORK (3):**
 * Network communication artifacts.
 * - IP addresses
 * - MAC addresses
 * - Spacecraft identifiers
 * - Ground station IDs
 * - Network protocols
 * 
 * Examples:
 * - Rogue ground station communication
 * - ARP spoofing
 * - Unauthorized crosslink traffic
 * - Data exfiltration
 *
 * **AT_COMMAND (4):**
 * Command execution artifacts.
 * - Command codes
 * - Command parameters
 * - Execution timestamps
 * - Command sources
 * - Sequence numbers
 * 
 * Examples:
 * - Unauthorized command execution
 * - Command parameter tampering
 * - Command flooding
 * - Out-of-sequence commands
 *
 * **AT_CONFIG (5):**
 * Configuration artifacts.
 * - Configuration file paths
 * - Configuration parameters
 * - Settings modifications
 * - Configuration timestamps
 * 
 * Examples:
 * - Encryption settings disabled
 * - Fault management changes
 * - Radio configuration tampering
 * - Security feature bypass
 *
 * **AT_MEMORY (6):**
 * Memory artifacts.
 * - Memory addresses
 * - Memory regions
 * - Memory table names
 * - Memory checksums
 * - Memory access patterns
 * 
 * Examples:
 * - Flash memory tampering
 * - Boot memory corruption
 * - EEPROM modifications
 * - Memory integrity violations
 *
 * **AT_KEY (7):**
 * Cryptographic key artifacts.
 * - Key identifiers
 * - Key fingerprints
 * - Key metadata
 * - Key usage logs
 * - Certificate data
 * 
 * Examples:
 * - Expired key usage
 * - Unauthorized key access
 * - Key rotation violations
 * - Certificate invalidity
 *
 * **AT_DEVICE (8):**
 * Hardware device artifacts.
 * - Device identifiers
 * - Bus addresses (CAN, SpaceWire, 1553)
 * - Subsystem IDs
 * - Hardware components
 * - Device configurations
 * 
 * Examples:
 * - Unauthorized bus controller
 * - CAN message spoofing
 * - SpaceWire routing anomalies
 * - Hardware device tampering
 *
 * **Usage in Detection:**
 * @code
 * void collect_evidence(const IOBCTI *iob) {
 *     switch (iob->arttype) {
 *         case AT_FILE:
 *             collect_file_hash();
 *             collect_file_metadata();
 *             break;
 *         case AT_NETWORK:
 *             collect_packet_capture();
 *             collect_connection_logs();
 *             break;
 *         case AT_COMMAND:
 *             collect_command_history();
 *             collect_command_parameters();
 *             break;
 *         // ... handle other types
 *     }
 * }
 * @endcode
 *
 * **Forensic Priority:**
 * Higher-value artifacts for investigation:
 * 1. AT_FILE: Persistent, hashable, verifiable
 * 2. AT_MEMORY: Critical system state
 * 3. AT_COMMAND: Direct attack evidence
 * 4. AT_KEY: Security infrastructure
 * 5. AT_PROGRAM: Execution evidence
 * 6. AT_NETWORK: Communication evidence
 * 7. AT_CONFIG: System settings
 * 8. AT_DEVICE: Hardware state
 * 9. AT_NONE: Telemetry/behavioral
 *
 * @note Multiple IOBs may share same artifact type
 * @note Artifact type guides but doesn't limit evidence collection
 * @note Some IOBs may benefit from collecting multiple artifact types
 */
typedef enum {
    AT_NONE = 0,      /**< No specific artifact or multiple sources */
    AT_FILE,          /**< File path + hash */
    AT_PROGRAM,       /**< Process/executable name */
    AT_NETWORK,       /**< IP address, MAC, spacecraft ID */
    AT_COMMAND,       /**< Specific command string */
    AT_CONFIG,        /**< Configuration file path */
    AT_MEMORY,        /**< Memory table/region identifier */
    AT_KEY,           /**< Cryptographic key ID/fingerprint */
    AT_DEVICE         /**< Hardware device identifier (bus controller, subsystem, etc.) */
} ArtifactType;

/**
 * @brief Artifact evidence structure
 * 
 * Contains detailed artifact information collected during detection.
 * Provides type-safe storage for different artifact types with
 * extensible union for artifact-specific data.
 *
 * **Structure Fields:**
 *
 * - **type:** ArtifactType enumeration indicating artifact category
 *   - Determines which union member is valid
 *   - Guides evidence processing
 *   - Used for storage and retrieval
 *
 * - **size:** Size of artifact data in bytes
 *   - For hashes: typically 32 bytes (SHA-256)
 *   - For strings: length including null terminator
 *   - For binary data: actual data size
 *   - Used for memory allocation and validation
 *
 * - **v:** Union containing artifact-specific data
 *   - Currently supports SHA-256 hash pointer
 *   - Extensible for additional artifact types
 *   - Only one member valid at a time based on type
 *
 * **Current Implementation:**
 * Currently implements SHA-256 hash storage for file artifacts.
 * Future extensions may include:
 * - IP addresses (struct in_addr)
 * - Command codes (uint32_t)
 * - Memory addresses (uintptr_t)
 * - Device identifiers (uint32_t)
 * - Process IDs (pid_t)
 *
 * **Usage Example:**
 * @code
 * // Collect file hash artifact
 * Artifact file_artifact;
 * file_artifact.type = AT_FILE;
 * file_artifact.size = 32;  // SHA-256 is 32 bytes
 * 
 * // Allocate and compute hash
 * file_artifact.v.sha256_hash = malloc(32);
 * compute_sha256(file_path, file_artifact.v.sha256_hash);
 * 
 * // Store in alert
 * store_artifact_evidence(&file_artifact);
 * 
 * // Clean up
 * free(file_artifact.v.sha256_hash);
 * @endcode
 *
 * **Memory Management:**
 * @code
 * // Caller responsible for allocation/deallocation
 * Artifact *create_file_artifact(const char *filepath) {
 *     Artifact *art = malloc(sizeof(Artifact));
 *     art->type = AT_FILE;
 *     art->size = 32;
 *     art->v.sha256_hash = malloc(32);
 *     compute_sha256(filepath, art->v.sha256_hash);
 *     return art;
 * }
 * 
 * void free_artifact(Artifact *art) {
 *     if (art->type == AT_FILE && art->v.sha256_hash != NULL) {
 *         free(art->v.sha256_hash);
 *     }
 *     free(art);
 * }
 * @endcode
 *
 * **Future Extensions:**
 * @code
 * union {
 *     char *sha256_hash;           // File hash (32 bytes)
 *     struct in_addr ip_addr;      // IP address (4 bytes)
 *     uint32_t command_code;       // Command identifier
 *     uintptr_t memory_addr;       // Memory address
 *     uint32_t device_id;          // Hardware device ID
 *     pid_t process_id;            // Process identifier
 *     uint8_t key_fingerprint[20]; // Key fingerprint (SHA-1)
 * } v;
 * @endcode
 *
 * @note Caller responsible for memory management of union members
 * @note Only one union member valid based on type field
 * @note Size field must match actual data size
 *
 * @see ArtifactType for artifact classification
 */
typedef struct 
{
    ArtifactType type;  /**< Artifact type classification */
    uint32_t size;      /**< Size of artifact data in bytes */
    union {
        char *sha256_hash;  /**< Pointer to SHA-256 hash (32 bytes) */
    } v;  /**< Artifact-specific data union */
} Artifact;

/**
 * @brief IOB Cyber Threat Intelligence structure
 * 
 * Complete definition of an Indicator of Behavior including identification,
 * description, detection pattern, and artifact classification. This structure
 * represents a single entry in the SPARTA IOB database.
 *
 * **Structure Fields:**
 *
 * **iob:** IOB identifier string (fixed-size array)
 * - Format: "CATEGORY-NUMBER"
 * - Example: "UACE-1", "CSNE-45"
 * - Fixed size: IOB_ID_SZ (10 bytes including null)
 * - Const: Cannot be modified at runtime
 * - Used as primary key for lookups
 * - Referenced in rule tables and alerts
 *
 * **name:** Human-readable IOB description
 * - Pointer to const string literal
 * - Describes the attack behavior
 * - Used in alert messages and reports
 * - Example: "Hardware Command Executed Outside Authorized Schedule"
 * - Stored in read-only memory
 *
 * **pattern:** STIX detection pattern
 * - Pointer to const STIX pattern string
 * - Defines observable conditions for detection
 * - Evaluated by pattern matching engine
 * - Example: "[x-opencti-command-log:command = 'hw_cmd_execute' AND ...]"
 * - May contain mission-specific placeholders
 * - Stored in read-only memory
 *
 * **arttype:** Primary artifact type
 * - ArtifactType enumeration value
 * - Indicates main evidence source
 * - Guides forensic data collection
 * - Example: AT_COMMAND, AT_FILE, AT_NETWORK
 * - Used for evidence prioritization
 *
 * **Usage Examples:**
 * @code
 * // Access IOB fields
 * const IOBCTI *iob = FindIoB("UACE-1");
 * printf("IOB: %s\n", iob->iob);          // "UACE-1"
 * printf("Name: %s\n", iob->name);        // "Hardware Command..."
 * printf("Pattern: %s\n", iob->pattern);  // "[x-opencti-command-log:..."
 * printf("Type: %d\n", iob->arttype);     // AT_COMMAND
 *
 * // Use in detection
 * if (evaluate_stix_pattern(iob->pattern, system_state)) {
 *     generate_alert(iob->iob, iob->name);
 *     collect_artifact(iob->arttype);
 * }
 *
 * // Include in telemetry
 * strncpy(alert_pkt.iob_id, iob->iob, IOB_ID_SZ);
 * alert_pkt.artifact_type = iob->arttype;
 * CFE_SB_SendMsg(&alert_pkt);
 * @endcode
 *
 * **Memory Layout:**
 * @code
 * struct IOBCTI {
 *     char iob[10];          // 10 bytes (inline)
 *     const char *name;      // 8 bytes (pointer)
 *     const char *pattern;   // 8 bytes (pointer)
 *     ArtifactType arttype;  // 4 bytes (enum)
 * };
 * // Total: 30 bytes per IOB
 * // Database: 238 IOBs × 30 bytes = 7,140 bytes
 * @endcode
 *
 * **Database Organization:**
 * IOBs are organized in the iobs[] array by category:
 * @code
 * const IOBCTI iobs[IOB_ARRAY_SIZE] = {
 *     // UACE category (26 entries)
 *     { .iob = "UACE-1", .name = "...", .pattern = "...", .arttype = AT_COMMAND },
 *     { .iob = "UACE-2", .name = "...", .pattern = "...", .arttype = AT_COMMAND },
 *     ...
 *     // UCEB category (11 entries)
 *     { .iob = "UCEB-1", .name = "...", .pattern = "...", .arttype = AT_KEY },
 *     ...
 * };
 * @endcode
 *
 * **Immutability:**
 * All fields are const or contain const data:
 * - Prevents accidental modification
 * - Enables storage in read-only memory
 * - Thread-safe for concurrent access
 * - Reduces memory footprint (shared strings)
 *
 * **STIX Pattern Placeholders:**
 * Patterns may contain mission-specific placeholders:
 * @code
 * // Generic pattern with placeholders
 * "[x-opencti-command-log:execution_time != 'authorized_time']"
 * 
 * // Mission-specific configuration
 * authorized_time = "2024-01-15T10:00:00Z"
 * 
 * // Runtime substitution
 * evaluate_pattern_with_config(iob->pattern, mission_config)
 * @endcode
 *
 * @note All string fields are const (immutable)
 * @note IOB identifier is fixed-size for predictable memory layout
 * @note Name and pattern are pointers to string literals
 * @note Structure size: 30 bytes on 64-bit systems
 *
 * @see ArtifactType for artifact classification
 * @see FindIoB for database lookup function
 * @see iobs for global IOB database array
 */
typedef struct 
{
    const char iob[IOB_ID_SZ];  /**< IOB identifier (e.g., "UACE-1") */
    const char* name;            /**< Human-readable IOB description */
    const char* pattern;         /**< STIX detection pattern */
    ArtifactType arttype;        /**< Primary artifact type for detection */
} IOBCTI;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Find IOB entry by identifier
 * 
 * Searches the SPARTA IOB database for an entry matching the specified
 * IOB identifier string. Returns pointer to the IOB structure if found,
 * or NULL if not found.
 *
 * **Search Algorithm:**
 * - Linear search through iobs[] array
 * - String comparison using strncmp()
 * - Case-sensitive comparison
 * - Returns first match (IOB identifiers are unique)
 *
 * **Performance:**
 * - Time complexity: O(n) where n = IOB_ARRAY_SIZE (238)
 * - Average case: ~119 comparisons
 * - Worst case: 238 comparisons
 * - Typical execution: <10 microseconds on space-grade CPU
 *
 * **Usage Examples:**
 * @code
 * // Basic lookup
 * const IOBCTI *iob = FindIoB("UACE-1");
 * if (iob != NULL) {
 *     printf("Found: %s\n", iob->name);
 * } else {
 *     printf("IOB not found\n");
 * }
 *
 * // Use in rule evaluation
 * void evaluate_rule(Rule *rule) {
 *     const IOBCTI *iob = FindIoB(rule->iob_id);
 *     if (iob == NULL) {
 *         CFE_EVS_SendEvent(ERR_EID, CFE_EVS_ERROR,
 *                          "Invalid IOB reference: %s", rule->iob_id);
 *         return;
 *     }
 *     
 *     if (evaluate_stix_pattern(iob->pattern, system_state)) {
 *         generate_alert(iob);
 *     }
 * }
 *
 * // Validate rule table
 * bool validate_rule_table(RuleTable *table) {
 *     for (int i = 0; i < table->num_rules; i++) {
 *         if (FindIoB(table->rules[i].iob_id) == NULL) {
 *             return false;
 *         }
 *     }
 *     return true;
 * }
 * @endcode
 *
 * **Error Handling:**
 * @code
 * const IOBCTI *iob = FindIoB(iob_id);
 * if (iob == NULL) {
 *     // IOB not found - handle error
 *     CFE_EVS_SendEvent(SPACECOP_IOB_NOT_FOUND_EID,
 *                      CFE_EVS_ERROR,
 *                      "IOB %s not found in database", iob_id);
 *     // Use default behavior or skip rule
 *     return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
 * }
 * // IOB found - proceed with detection
 * @endcode
 *
 * @param[in] iob_id Null-terminated IOB identifier string to search for
 *                   Format: "CATEGORY-NUMBER" (e.g., "UACE-1", "CSNE-45")
 *                   Maximum length: IOB_ID_SZ (10 bytes including null)
 *
 * @return Pointer to const IOBCTI structure if IOB found
 * @return NULL if IOB identifier not found in database
 *
 * @pre iob_id must be null-terminated string
 * @pre iob_id must not be NULL
 * @pre iob_id length should be <= IOB_ID_SZ
 * @post Return value is const (IOB data cannot be modified)
 * @post Return value valid until program termination (static storage)
 *
 * @note Comparison is case-sensitive ("UACE-1" != "uace-1")
 * @note Only compares first IOB_ID_SZ characters
 * @note Returned pointer points to static const data
 * @note Thread-safe (read-only operation)
 * @note NULL return must be checked before dereferencing
 *
 * @warning Do not free returned pointer (static storage)
 * @warning Do not modify returned structure (const data)
 * @warning Null pointer dereference if return value not checked
 *
 * @see IOBCTI for IOB structure definition
 * @see iobs for global IOB database array
 * @see IOB_ARRAY_SIZE for database size
 * @see IOB_ID_SZ for identifier maximum length
 */
const IOBCTI *FindIoB(char *iob_id);

/*=======================================================================================
** External Data Declarations
**=======================================================================================*/

/**
 * @brief Global SPARTA IOB database array
 * 
 * External declaration for the global IOB database array containing all
 * 238 IOB definitions. The actual array is defined and initialized in
 * sparta_iobs.c.
 *
 * **Array Organization:**
 * - Size: IOB_ARRAY_SIZE (238 entries)
 * - Type: const IOBCTI (immutable)
 * - Storage: Read-only memory segment
 * - Lifetime: Program duration
 * - Visibility: Global (external linkage)
 *
 * **Memory Layout:**
 * @code
 * const IOBCTI iobs[238] = {
 *     // UACE category (indices 0-25)
 *     { "UACE-1", "Hardware Command...", "[x-opencti-command-log:...", AT_COMMAND },
 *     ...
 *     // UCEB category (indices 26-36)
 *     { "UCEB-1", "Repeated Use...", "[x-opencti-cryptographic-key:...", AT_KEY },
 *     ...
 *     // ... remaining categories ...
 * };
 * @endcode
 *
 * **Access Patterns:**
 * @code
 * // Direct array access (if index known)
 * const IOBCTI *iob = &iobs[0];  // First IOB (UACE-1)
 * 
 * // Iteration over all IOBs
 * for (int i = 0; i < IOB_ARRAY_SIZE; i++) {
 *     printf("IOB %d: %s - %s\n", i, iobs[i].iob, iobs[i].name);
 * }
 * 
 * // Search by identifier (use FindIoB instead)
 * const IOBCTI *iob = FindIoB("UACE-1");
 * @endcode
 *
 * **Use Cases:**
 *
 * 1. **IOB Lookup:**
 *    @code
 *    const IOBCTI *iob = FindIoB("UACE-1");
 *    @endcode
 *
 * 2. **Database Enumeration:**
 *    @code
 *    void print_all_iobs(void) {
 *        for (int i = 0; i < IOB_ARRAY_SIZE; i++) {
 *            printf("%s: %s\n", iobs[i].iob, iobs[i].name);
 *        }
 *    }
 *    @endcode
 *
 * 3. **Category Filtering:**
 *    @code
 *    void list_command_iobs(void) {
 *        for (int i = 0; i < IOB_ARRAY_SIZE; i++) {
 *            if (iobs[i].arttype == AT_COMMAND) {
 *                printf("%s\n", iobs[i].name);
 *            }
 *        }
 *    }
 *    @endcode
 *
 * 4. **Statistics:**
 *    @code
 *    void print_iob_stats(void) {
 *        int counts[9] = {0};  // One per ArtifactType
 *        for (int i = 0; i < IOB_ARRAY_SIZE; i++) {
 *            counts[iobs[i].arttype]++;
 *        }
 *        printf("Total IOBs: %d\n", IOB_ARRAY_SIZE);
 *        printf("Command IOBs: %d\n", counts[AT_COMMAND]);
 *        // ... print other categories
 *    }
 *    @endcode
 *
 * **Memory Characteristics:**
 * - Total size: ~7,140 bytes (238 × 30 bytes per entry)
 * - Plus string literal storage for names and patterns
 * - Stored in read-only memory (.rodata section)
 * - Shared across all threads (single copy)
 * - Never deallocated (static lifetime)
 *
 * **Thread Safety:**
 * - Read-only data: inherently thread-safe
 * - No synchronization required for reads
 * - Cannot be modified at runtime (const)
 * - Safe for concurrent access from multiple tasks
 *
 * **Performance:**
 * - Linear search: O(n) time complexity
 * - Cache-friendly: sequential memory layout
 * - Const data: may be cached aggressively by CPU
 * - No allocation overhead (static storage)
 *
 * @note Array is const - cannot be modified at runtime
 * @note Defined in sparta_iobs.c with complete initialization
 * @note Size must match IOB_ARRAY_SIZE macro
 * @note Prefer FindIoB() over direct array access
 *
 * @see IOBCTI for IOB structure definition
 * @see FindIoB for recommended lookup function
 * @see IOB_ARRAY_SIZE for array size constant
 * @see sparta_iobs.c for array implementation
 */
extern const IOBCTI iobs[];

#endif /* SPARTA_IOBS_H */