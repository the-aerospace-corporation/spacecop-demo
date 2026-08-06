// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
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
 * @file spacecop_cti.h
 * @brief Cyber Threat Intelligence (CTI) processing interface for SpaceCop IDS
 *
 * This header defines data structures and functions for processing STIX-formatted
 * threat intelligence bundles. The CTI system enables SpaceCop to:
 * - Ingest threat intelligence from external sources
 * - Parse STIX 2.x bundles in JSON format
 * - Detect known malicious files via SHA-256 hash matching
 * - Associate detections with Indicator of Behavior (IOB) identifiers
 * - Generate alerts for threat matches on the file system
 *
 * **Architecture:**
 * The CTI subsystem runs as a child task that periodically:
 * 1. Scans cf/cti/ directory for new .dat files
 * 2. Parses STIX bundles to extract threat indicators
 * 3. Stores indicators in memory (deduplicated)
 * 4. Scans spacecraft file system for matches
 * 5. Generates IDS alerts for detected threats
 *
 * **STIX Bundle Format:**
 * CTI files must be STIX 2.x bundles containing:
 * - indicator objects: Define IOB identifiers (x_sparta_iob_id)
 * - file objects: Define filenames and SHA-256 hashes
 * - program objects: Define program names
 *
 * **File Format:**
 * - Extension: .dat (JSON format)
 * - Location: cf/cti/ directory
 * - Encoding: UTF-8
 *
 * **Detection Logic:**
 * File objects are associated with the most recently encountered indicator
 * object in the bundle. When a file is detected on the file system with
 * matching name and SHA-256 hash, an alert is generated with the associated
 * IOB identifier.
 *
 * **Example STIX Bundle:**
 * @code
 * {
 *   "type": "bundle",
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "x_sparta_iob_id": "MALI-1"
 *     },
 *     {
 *       "type": "file",
 *       "name": "malware.elf",
 *       "hashes": {
 *         "SHA-256": "a1b2c3d4..."
 *       }
 *     }
 *   ]
 * }
 * @endcode
 *
 * @note CTI files are loaded once and cached in memory
 * @note Duplicate indicators are automatically filtered
 * @note Only SHA-256 hashes are currently supported
 *
 * @see spacecop_cti.c for implementation details
 */

#ifndef SPACECOP_CTI_H
#define SPACECOP_CTI_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include "sparta_iobs.h"
#include "functions_file_integrity_linux.h"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief STIX object type enumeration
 *
 * Identifies the type of STIX object parsed from a threat intelligence bundle.
 * Different object types contain different fields and are processed differently.
 *
 * **Object Type Descriptions:**
 * - OBJ_UNKNOWN: Unrecognized or unparseable object type
 * - OBJ_INDICATOR: STIX indicator containing IOB identifier
 * - OBJ_FILE: File object with name and hash(es)
 * - OBJ_PROGRAM: Program/process object with name
 *
 * @note OBJ_INDICATOR objects associate IOBs with subsequent file objects
 * @note Only OBJ_FILE objects trigger file system scanning
 */
typedef enum {
	OBJ_UNKNOWN = 0,    /**< Unknown or unrecognized object type */
	OBJ_INDICATOR,      /**< STIX indicator object (contains IOB ID) */
	OBJ_FILE,           /**< STIX file object (contains hash) */
	OBJ_PROGRAM         /**< STIX program object (contains program name) */
} ObjectKind;

/**
 * @brief CTI threat indicator information
 *
 * Contains extracted information from a STIX object. The contents vary based
 * on the object kind:
 *
 * **Field Usage by Object Kind:**
 * - OBJ_INDICATOR: id field contains IOB identifier
 * - OBJ_FILE: id (inherited from indicator), name, sha256 fields populated
 * - OBJ_PROGRAM: id (inherited from indicator), name fields populated
 *
 * **IOB Association:**
 * When parsing a STIX bundle, file and program objects inherit the IOB
 * identifier from the most recently encountered indicator object.
 *
 * @note sha256 field is only valid for OBJ_FILE objects
 * @note name field is used for both files and programs
 */
typedef struct 
{
	ObjectKind kind;                              /**< Type of STIX object */
	char id[IOB_ID_SZ];                          /**< IOB identifier (e.g., "MALI-1") */
	char name[128];                              /**< Filename or program name */
	unsigned char sha256[SHA256_DIGEST_LENGTH];  /**< SHA-256 hash (32 bytes) */
} CTI_Info;

/**
 * @brief STIX bundle root structure
 *
 * Represents the parsed contents of a STIX bundle file. Contains the bundle
 * type and a dynamic array of all objects within the bundle.
 *
 * **Lifecycle:**
 * 1. Initialized by parse_root() during JSON parsing
 * 2. Objects are appended via root_objects_append()
 * 3. Freed by free_root() after processing
 *
 * **Memory Management:**
 * The objects array is dynamically allocated and grows as needed during
 * parsing. Caller must call free_root() to release memory.
 *
 * @note objects array is heap-allocated
 * @note Must call free_root() to prevent memory leak
 *
 * @see free_root()
 */
typedef struct 
{
	char kind[16];          /**< Bundle type (typically "bundle") */
	CTI_Info *objects;      /**< Dynamic array of STIX objects */
	size_t objects_count;   /**< Number of objects in array */
	size_t objects_cap;     /**< Current capacity of objects array */
} Root;

/**
 * @brief JSON parser state
 *
 * Maintains the state of the JSON parser as it processes a JSON document.
 * Uses a single-pass streaming approach with minimal memory allocation.
 *
 * **Parser Design:**
 * - Single-pass: Document is parsed once from start to end
 * - Streaming: Does not build a full DOM tree
 * - Minimal allocation: Extracts values directly into output structures
 * - Error tracking: Records position of parse errors
 *
 * **Usage Pattern:**
 * @code
 * Json j = {0};
 * j.s = json_text;
 * j.p = json_text;
 * j.end = json_text + strlen(json_text);
 * 
 * if (parse_root(&j, &root)) {
 *     // Parse succeeded
 * } else {
 *     printf("Error at offset %ld\n", j.err - j.s);
 * }
 * @endcode
 *
 * @note Parser assumes well-formed UTF-8 input
 * @note Does not support streaming/incremental parsing
 */
typedef struct 
{
	const char *s;    /**< Start of JSON document */
	const char *p;    /**< Current parse position */
	const char *end;  /**< End of JSON document (one past last char) */
	const char *err;  /**< Position of parse error (NULL if no error) */
} Json;

/**
 * @brief Global CTI data storage array
 *
 * Dynamic array containing all loaded threat indicators from processed CTI
 * files. This is the primary data structure for threat detection.
 *
 * **Contents:**
 * - All file indicators with SHA-256 hashes
 * - All program indicators with names
 * - Associated IOB identifiers
 *
 * **Deduplication:**
 * Duplicate entries (same name and hash) are automatically filtered when
 * loading CTI files.
 *
 * **Memory Management:**
 * - Initialized by CTI_InitArray()
 * - Grows automatically via store_append()
 * - Freed by CTI_FreeArray()
 *
 * **Thread Safety:**
 * Not thread-safe. Access should be serialized by caller.
 *
 * @note Initial capacity is 2, grows exponentially as needed
 * @note Must call CTI_InitArray() before use
 * @note Must call CTI_FreeArray() during shutdown
 *
 * @see CTI_InitArray()
 * @see CTI_FreeArray()
 */
typedef struct 
{
	CTI_Info *data;   /**< Dynamic array of threat indicators */
	size_t size;      /**< Number of indicators in array */
	size_t capacity;  /**< Current capacity of array */
} CTIArray;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Initialize CTI data array
 *
 * Allocates and initializes the global CTI storage array. Must be called
 * once during application initialization before any other CTI functions.
 *
 * @return void
 *
 * @note Exits program on allocation failure
 * @note Initial capacity is 2 entries
 * @note Array grows automatically as needed
 *
 * @see CTI_FreeArray()
 *
 * Example usage:
 * @code
 * CTI_InitArray();  // Called in SPACECOP_AppMain()
 * @endcode
 */
void CTI_InitArray(void);

/**
 * @brief Scan for and process new CTI data files
 *
 * Scans the cf/cti/ directory for .dat files containing STIX bundles and
 * processes any new threat intelligence. Should be called periodically by
 * the CTI child task to detect newly dropped intelligence files.
 *
 * **Operation:**
 * 1. Open cf/cti/ directory
 * 2. Iterate through directory entries
 * 3. Filter for .dat files (skip hidden files)
 * 4. Parse each STIX bundle (JSON format)
 * 5. Extract threat indicators
 * 6. Add to global storage (deduplicating)
 * 7. Print summary for new files
 *
 * **File Requirements:**
 * - Extension: .dat
 * - Format: STIX 2.x bundle (JSON)
 * - Location: cf/cti/ directory
 * - Encoding: UTF-8
 *
 * @return void
 *
 * @note Silently returns if directory cannot be opened
 * @note Skips files starting with '.'
 * @note Only processes files with .dat extension
 * @note Duplicate indicators are automatically filtered
 * @note Prints status messages to stdout
 * @note Parse errors are logged but do not stop processing
 *
 * @see process_json_file()
 * @see CTI_WorkWithData()
 *
 * Example usage:
 * @code
 * // Called periodically in RunCTILoop() child task
 * while (CFE_ES_RunLoop(&RunStatus)) {
 *     CTI_CheckForNewData();
 *     CTI_WorkWithData();
 *     OS_TaskDelay(1000);
 * }
 * @endcode
 */
void CTI_CheckForNewData(void);

/**
 * @brief Free CTI data array and release resources
 *
 * Releases all memory allocated for the global CTI storage array. Should be
 * called once during application shutdown.
 *
 * @return void
 *
 * @note Safe to call multiple times
 * @note Safe to call with uninitialized array
 * @note Sets internal pointer to NULL after freeing
 *
 * @see CTI_InitArray()
 *
 * Example usage:
 * @code
 * // Called in SPACECOP_AppMain() shutdown sequence
 * CTI_FreeArray();
 * @endcode
 */
void CTI_FreeArray(void);

/**
 * @brief Scan file system for CTI matches and generate alerts
 *
 * Scans the spacecraft file system for files matching known threat indicators
 * and generates IDS alerts for any matches. Should be called periodically by
 * the CTI child task.
 *
 * **Operation:**
 * 1. Scan cf/ directory recursively
 * 2. Scan data/ directory recursively
 * 3. Compute SHA-256 hash for each file
 * 4. Compare against loaded CTI indicators
 * 5. Generate IDS alert for matches
 * 6. Send EVS error event for matches
 *
 * **Directories Scanned:**
 * - cf/: Configuration and application files
 * - data/: Data storage directory
 *
 * **Alert Generation:**
 * For each match, generates:
 * - IDS telemetry message via SPACECOP_ReportIDSMsg()
 * - EVS error event (ID 2001)
 * - Alert includes IOB identifier, filename, and SHA-256 hash
 *
 * **Alert Format:**
 * "[SPACECOP] CTI-based Detected (SPARTA-ID {IOB}, file ({filename} (sha256={hash}))found"
 *
 * @return void
 *
 * @note Only processes OBJ_FILE indicators currently
 * @note OBJ_PROGRAM indicators are not yet implemented
 * @note Prints debug messages to stdout
 * @note May be I/O intensive on large file systems
 *
 * @see scan_root() (from functions_file_integrity_linux.h)
 * @see does_hash_exist() (from functions_file_integrity_linux.h)
 * @see SPACECOP_ReportIDSMsg()
 * @see CTI_CheckForNewData()
 *
 * Example usage:
 * @code
 * // Called periodically in RunCTILoop() child task
 * while (CFE_ES_RunLoop(&RunStatus)) {
 *     CTI_CheckForNewData();  // Load new threat intel
 *     CTI_WorkWithData();     // Scan for matches
 *     OS_TaskDelay(1000);
 * }
 * @endcode
 */
void CTI_WorkWithData(void);

#endif /* SPACECOP_CTI_H */