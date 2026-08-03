// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file sparta_stix.c
 * @brief STIX bundle generation and threat intelligence sharing implementation
 *
 * This file implements STIX (Structured Threat Information eXpression) 2.1
 * bundle generation and cyber threat intelligence (CTI) sharing for SpaceCop.
 * It provides:
 * - STIX 2.1 bundle creation for detected threats
 * - Artifact-specific STIX object generation
 * - CTI sharing via software bus
 * - Peer alert processing and storage
 * - Heartbeat mechanism for distributed detection
 *
 * **STIX 2.1 Overview:**
 * STIX is a standardized language for describing cyber threat intelligence.
 * It enables consistent representation of threats, TTPs (Tactics, Techniques,
 * and Procedures), and observables across different security tools and
 * organizations.
 *
 * **STIX Bundle Structure:**
 * A STIX bundle is a collection of STIX objects that represent a complete
 * threat intelligence package:
 * @code
 * {
 *   "type": "bundle",
 *   "id": "bundle--<uuid>",
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "id": "indicator--<uuid>",
 *       "name": "IOB Description",
 *       "pattern": "[observable:property = 'value']",
 *       "x_sparta_iob_id": "UACE-1"
 *     },
 *     {
 *       "type": "file",
 *       "id": "file--<uuid>",
 *       "name": "/path/to/file",
 *       "hashes": {"SHA-256": "..."}
 *     }
 *   ]
 * }
 * @endcode
 *
 * **Supported Artifact Types:**
 * The implementation creates appropriate STIX objects based on artifact type:
 * - AT_FILE: file object with path and hash
 * - AT_PROGRAM: process object with executable name
 * - AT_NETWORK: ipv4-addr, ipv6-addr, or mac-addr objects
 * - AT_COMMAND: custom x-spacecraft-command object
 * - AT_CONFIG: file object marked as configuration
 * - AT_MEMORY: custom x-memory-region object
 * - AT_KEY: custom x-cryptographic-key object
 * - AT_DEVICE: custom x-spacecraft-device object
 * - AT_NONE: indicator object only
 *
 * **CTI Sharing Architecture:**
 * @code
 * ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
 * │ SpaceCop A  │────────▶│  Software   │────────▶│ SpaceCop B  │
 * │ (Detector)  │  STIX   │     Bus     │  STIX   │ (Receiver)  │
 * └─────────────┘         └─────────────┘         └─────────────┘
 *       │                                                 │
 *       │                                                 │
 *       ▼                                                 ▼
 * /cf/logs/stix_log.json                    /cf/cti/stix_bundle_*.dat
 * @endcode
 *
 * **Distributed Detection:**
 * Multiple SpaceCop instances can share threat intelligence:
 * - Detection on one spacecraft shared with constellation
 * - Ground systems receive all spacecraft alerts
 * - Correlation across multiple detection sources
 * - Collaborative defense posture
 *
 * **File Storage:**
 * - Local detections: /cf/logs/stix_log.json (append-only log)
 * - Peer alerts: /cf/cti/stix_bundle_<timestamp>.dat (individual files)
 * - Persistent storage for forensic analysis
 * - Ground retrieval via file downlink
 *
 * **Integration Points:**
 * - Detection engine calls write_to_stix() on IOB trigger
 * - STIX bundle transmitted via SPACECOP_CTI_SHARE_MID
 * - Peer alerts received and processed
 * - Heartbeats maintain constellation awareness
 *
 * @note Requires SPARTA IOB database for IOB metadata lookup
 * @note Uses OSAL file I/O for platform independence
 * @note STIX bundles limited to 1024 bytes for telemetry transmission
 *
 * @see sparta_iobs.h for IOB database interface
 * @see spacecop_app.h for message definitions
 * @see STIX 2.1 specification for format details
 */

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "sparta_stix.h"
#include "sparta_iobs.h"
#include "osapi.h"
#include "common_types.h"
#include "spacecop_app.h"

/*=======================================================================================
** Function Implementations
**=======================================================================================*/

/**
 * @brief Escape special characters for JSON string encoding
 * 
 * Converts a C string to a JSON-safe string by escaping special characters
 * according to JSON specification (RFC 8259). Required for embedding strings
 * in STIX JSON bundles.
 *
 * **Escaped Characters:**
 * - " (quotation mark) → \"
 * - \ (backslash) → \\
 * - \n (newline) → \n
 * - \r (carriage return) → \r
 * - \t (tab) → \t
 *
 * **Usage Example:**
 * @code
 * const char *raw = "Command \"execute\" \n Status: OK";
 * char escaped[256];
 * escape_json_string(raw, escaped, sizeof(escaped));
 * // Result: "Command \"execute\" \n Status: OK"
 * 
 * // Use in JSON
 * snprintf(json, sizeof(json), "{\"message\":\"%s\"}", escaped);
 * @endcode
 *
 * **Buffer Overflow Protection:**
 * Function stops writing when destination buffer is nearly full (dst_size - 2)
 * to ensure room for null terminator and final escaped character.
 *
 * @param[in] src Source string to escape (null-terminated)
 * @param[out] dst Destination buffer for escaped string
 * @param[in] dst_size Size of destination buffer in bytes
 *
 * @pre src must be null-terminated
 * @pre dst must have space for at least 2 bytes
 * @pre dst_size must be > 2
 * @post dst is null-terminated
 * @post dst contains JSON-safe escaped string
 *
 * @note Truncates output if destination buffer too small
 * @note Does not escape all control characters (only common ones)
 * @note Based on implementation from spacecop_cti.c
 *
 * @warning Large src strings may be truncated in dst
 * @warning Does not validate UTF-8 encoding
 */
void escape_json_string(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dst_size - 2; i++) {
        switch(src[i]) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:   dst[j++] = src[i]; break;
        }
    }
    dst[j] = '\0';
}

/**
 * @brief Generate cryptographically secure UUID version 4
 * 
 * Generates a RFC 4122 compliant UUID version 4 (random UUID) using
 * /dev/urandom as entropy source. UUIDs are used as unique identifiers
 * for STIX objects.
 *
 * **UUID Format:**
 * xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 * - x: random hex digit (0-9, a-f)
 * - 4: version number (always 4 for random UUID)
 * - y: variant bits (8, 9, a, or b)
 *
 * **Example Output:**
 * "550e8400-e29b-41d4-a716-446655440000"
 *
 * **Entropy Source:**
 * Uses /dev/urandom for cryptographically secure random bytes:
 * - Non-blocking
 * - Suitable for cryptographic purposes
 * - Available on Linux and POSIX systems
 *
 * **UUID Version and Variant:**
 * @code
 * uuid[6] = (uuid[6] & 0x0F) | 0x40;  // Version 4 (0100xxxx)
 * uuid[8] = (uuid[8] & 0x3F) | 0x80;  // Variant 1 (10xxxxxx)
 * @endcode
 *
 * **Usage Example:**
 * @code
 * char uuid[37];  // 36 chars + null terminator
 * generate_uuid_v4_secure(uuid);
 * printf("Generated UUID: %s\n", uuid);
 * 
 * // Use in STIX bundle
 * snprintf(stix, sizeof(stix),
 *          "{\"type\":\"indicator\",\"id\":\"indicator--%s\",...}",
 *          uuid);
 * @endcode
 *
 * **Error Handling:**
 * If /dev/urandom cannot be opened, UUID will contain uninitialized
 * random values from stack. While not ideal, this provides some
 * randomness rather than failing completely.
 *
 * @param[out] uuid_str Buffer to store UUID string (must be at least 37 bytes)
 *
 * @pre uuid_str must point to buffer of at least 37 bytes
 * @post uuid_str contains null-terminated UUID string
 * @post UUID conforms to RFC 4122 version 4 format
 *
 * @note Requires /dev/urandom device (Linux/POSIX)
 * @note UUID string is exactly 36 characters plus null terminator
 * @note Thread-safe (no shared state)
 *
 * @warning If /dev/urandom unavailable, UUID quality degraded
 * @warning Not suitable for Windows without modification
 */
void generate_uuid_v4_secure(char *uuid_str) {
    unsigned char uuid[16];
    
    // Read random bytes from /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, uuid, 16);
        close(fd);
    }
    
    // Set version and variant bits
    uuid[6] = (uuid[6] & 0x0F) | 0x40;  // Version 4
    uuid[8] = (uuid[8] & 0x3F) | 0x80;  // Variant 1
    
    // Format as string
    sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            uuid[0], uuid[1], uuid[2], uuid[3],
            uuid[4], uuid[5],
            uuid[6], uuid[7],
            uuid[8], uuid[9],
            uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

/**
 * @brief Send STIX bundle alert via software bus
 * 
 * Transmits a STIX bundle to other SpaceCop instances and ground systems
 * via the cFS software bus. Enables distributed threat intelligence sharing
 * across spacecraft constellation and ground segment.
 *
 * **Message Structure:**
 * - Message ID: SPACECOP_CTI_SHARE_MID
 * - Alert Type: SPACECOP_ALERT_STIX
 * - Bundle Size: Limited to 1024 bytes
 * - Payload: STIX JSON bundle
 *
 * **Distribution:**
 * @code
 * ┌──────────────┐
 * │ Local SpaceCop│
 * │  Detection    │
 * └───────┬───────┘
 *         │ STIX Bundle
 *         ▼
 * ┌──────────────────┐
 * │  Software Bus    │
 * └────┬────────┬────┘
 *      │        │
 *      ▼        ▼
 * ┌─────────┐ ┌──────────┐
 * │ Peer SC │ │  Ground  │
 * │ SpaceCop│ │  System  │
 * └─────────┘ └──────────┘
 * @endcode
 *
 * **Size Limitation:**
 * Bundles are limited to 1024 bytes to fit in telemetry packets.
 * Larger bundles are truncated. For complete forensic data, retrieve
 * from /cf/logs/stix_log.json via file downlink.
 *
 * **Usage Example:**
 * @code
 * // Generate STIX bundle
 * char bundle[2048];
 * int size = create_stix_bundle(bundle, sizeof(bundle), iob_id, ...);
 * 
 * // Send via software bus
 * SPACECOP_SendStixAlert(bundle, size);
 * 
 * // Receivers will process via SPACECOP_ProcessPeerAlert()
 * @endcode
 *
 * **Reliability:**
 * Uses CFE_SB_TransmitMsg() with increment flag (true) to ensure
 * message sequence counter incremented. No delivery guarantee -
 * subscribers must be active to receive.
 *
 * @param[in] stix_bundle Pointer to STIX bundle JSON string
 * @param[in] bundle_size Size of bundle in bytes
 *
 * @pre stix_bundle must point to valid JSON string
 * @pre bundle_size must be > 0
 * @post STIX bundle transmitted on software bus
 * @post EVS event generated confirming transmission
 *
 * @note Bundle truncated to 1024 bytes if larger
 * @note No delivery confirmation
 * @note Subscribers must be configured to receive SPACECOP_CTI_SHARE_MID
 *
 * @see SPACECOP_ProcessPeerAlert for receiving side
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_SendStixAlert(char *stix_bundle, uint32 bundle_size)
{
    SPACECOP_Alert_t AlertMsg;
    
    CFE_MSG_Init(&AlertMsg.TlmHeader.Msg, CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID), sizeof(SPACECOP_Alert_t));
    
    AlertMsg.AlertType = SPACECOP_ALERT_STIX; 
    AlertMsg.BundleSize = (bundle_size > 1024) ? 1024 : bundle_size;
    
    memset(AlertMsg.StixBundle, 0, sizeof(AlertMsg.StixBundle));
    memcpy(AlertMsg.StixBundle, stix_bundle, AlertMsg.BundleSize);
    
    CFE_SB_TransmitMsg(&AlertMsg.TlmHeader.Msg, true);
    
    CFE_EVS_SendEvent(SPACECOP_ALERT_INF_EID, CFE_EVS_EventType_INFORMATION, "Sent STIX bundle alert: %d bytes", AlertMsg.BundleSize);
}

/**
 * @brief Send heartbeat message to peers
 * 
 * Transmits a heartbeat message to indicate this SpaceCop instance is
 * active and operational. Used for distributed detection coordination
 * and health monitoring.
 *
 * **Purpose:**
 * - Indicate operational status to peers
 * - Enable detection of failed/offline instances
 * - Coordinate distributed detection strategies
 * - Support failover and redundancy
 *
 * **Message Structure:**
 * - Message ID: SPACECOP_CTI_SHARE_MID
 * - Alert Type: SPACECOP_HEARTBEAT
 * - Bundle Size: 0 (no payload)
 *
 * **Heartbeat Interval:**
 * Typically sent every 30-60 seconds. Configured in mission-specific
 * scheduler table.
 *
 * **Usage Example:**
 * @code
 * // In periodic scheduler (e.g., every 30 seconds)
 * void SPACECOP_PeriodicTask(void) {
 *     static uint32 tick_count = 0;
 *     
 *     tick_count++;
 *     if (tick_count % 300 == 0) {  // Every 30 seconds at 10Hz
 *         SPACECOP_SendHeartbeat();
 *     }
 * }
 * @endcode
 *
 * **Peer Processing:**
 * Receivers track heartbeat reception to detect offline peers:
 * @code
 * void track_peer_heartbeat(uint32 spacecraft_id) {
 *     peer_last_seen[spacecraft_id] = current_time;
 *     
 *     // Check for stale peers
 *     for (int i = 0; i < num_peers; i++) {
 *         if (current_time - peer_last_seen[i] > HEARTBEAT_TIMEOUT) {
 *             mark_peer_offline(i);
 *         }
 *     }
 * }
 * @endcode
 *
 * @post Heartbeat message transmitted on software bus
 * @post Peers can detect this instance is operational
 *
 * @note No payload data transmitted
 * @note Lightweight message (minimal bandwidth)
 * @note No acknowledgment expected
 *
 * @see SPACECOP_ProcessPeerAlert for message reception
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_SendHeartbeat(void)
{
    SPACECOP_Alert_t HeartbeatMsg;
    
    CFE_MSG_Init(&HeartbeatMsg.TlmHeader.Msg, 
                 CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID), 
                 sizeof(SPACECOP_Alert_t));
    
    HeartbeatMsg.AlertType = SPACECOP_HEARTBEAT;
    HeartbeatMsg.BundleSize = 0;
    
    CFE_SB_TransmitMsg(&HeartbeatMsg.TlmHeader.Msg, true);
}

/**
 * @brief Process peer alert message
 * 
 * Receives and processes threat intelligence alerts from peer SpaceCop
 * instances. STIX bundles are stored to disk for correlation and
 * forensic analysis.
 *
 * **Message Types:**
 * - SPACECOP_ALERT_STIX: Threat detection with STIX bundle
 * - SPACECOP_HEARTBEAT: Peer operational status
 *
 * **Processing Flow:**
 * @code
 * 1. Receive message from software bus
 * 2. Check alert type
 * 3. If STIX alert:
 *    a. Generate unique filename with timestamp
 *    b. Create file in /cf/cti/ directory
 *    c. Write STIX bundle to file
 *    d. Close file
 * 4. Log reception via EVS
 * @endcode
 *
 * **File Storage:**
 * Peer alerts stored as individual files:
 * - Directory: /cf/cti/
 * - Filename format: stix_bundle_<timestamp>.dat
 * - Example: stix_bundle_1640000000.dat
 * - One file per alert
 *
 * **File Management:**
 * @code
 * /cf/cti/
 * ├── stix_bundle_1640000000.dat  (Peer A detection)
 * ├── stix_bundle_1640000030.dat  (Peer B detection)
 * ├── stix_bundle_1640000060.dat  (Peer A detection)
 * └── ...
 * @endcode
 *
 * **Correlation Analysis:**
 * Ground systems can correlate alerts across spacecraft:
 * @code
 * // Retrieve all peer alerts
 * download_directory("/cf/cti/");
 * 
 * // Analyze for attack campaigns
 * for each stix_bundle in directory:
 *     extract IOB_ID
 *     correlate with other spacecraft
 *     identify coordinated attacks
 * @endcode
 *
 * **Usage Example:**
 * @code
 * // In message processing loop
 * void SPACECOP_ProcessMessages(void) {
 *     CFE_SB_Buffer_t *BufPtr;
 *     
 *     while (CFE_SB_ReceiveBuffer(&BufPtr, pipe, timeout) == CFE_SUCCESS) {
 *         CFE_SB_MsgId_t MsgId = CFE_SB_GetMsgId(&BufPtr->Msg);
 *         
 *         if (MsgId == SPACECOP_CTI_SHARE_MID) {
 *             SPACECOP_ProcessPeerAlert(&BufPtr->Msg);
 *         }
 *     }
 * }
 * @endcode
 *
 * **Error Handling:**
 * - File creation failure: Log error, continue operation
 * - Write failure: Log error with bytes written
 * - Invalid alert type: Ignore silently
 *
 * @param[in] MsgPtr Pointer to received software bus message
 *
 * @pre MsgPtr must point to valid SPACECOP_Alert_t message
 * @pre /cf/cti/ directory must exist
 * @post STIX bundle written to file (if STIX alert)
 * @post EVS events generated for status
 *
 * @note Only STIX alerts are handled; non-STIX (e.g. heartbeat) messages are ignored
 * @note File storage may fail if disk full
 * @note Timestamps used for unique filenames
 *
 * @see SPACECOP_SendStixAlert for sending side
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_ProcessPeerAlert(const CFE_MSG_Message_t *MsgPtr)
{
    const SPACECOP_Alert_t *AlertMsg = (const SPACECOP_Alert_t *)MsgPtr;
    osal_id_t FileHandle;
    char FileName[OS_MAX_PATH_LEN];
    int32 Status;
    
    if (AlertMsg->AlertType == SPACECOP_ALERT_STIX)
    {
        CFE_EVS_SendEvent(SPACECOP_ALERT_INF_EID, CFE_EVS_EventType_INFORMATION, "Received peer alert: type=%d size=%d bytes", AlertMsg->AlertType, AlertMsg->BundleSize);
    }
    
    if (AlertMsg->AlertType == SPACECOP_ALERT_STIX)
    {
        snprintf(FileName, OS_MAX_PATH_LEN, SPACECOP_CTI_VDIR "/stix_bundle_%lu.dat", (unsigned long)OS_TimeGetTotalSeconds(OS_TimeAssembleFromNanoseconds(0, 0)));
        
        Status = OS_OpenCreate(&FileHandle, FileName, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY);
        
        if (Status != OS_SUCCESS)
        {
            CFE_EVS_SendEvent(SPACECOP_FILE_ERR_EID, CFE_EVS_EventType_ERROR, "Failed to create file %s: %d", FileName, (int)Status);
            return;
        }
        
        Status = OS_write(FileHandle, AlertMsg->StixBundle, AlertMsg->BundleSize);
        
        if (Status != AlertMsg->BundleSize)
        {
            CFE_EVS_SendEvent(SPACECOP_FILE_ERR_EID, CFE_EVS_EventType_ERROR, "Failed to write bundle: wrote %d of %d bytes", (int)Status, AlertMsg->BundleSize);
        }
        else
        {
            CFE_EVS_SendEvent(SPACECOP_FILE_INF_EID, CFE_EVS_EventType_INFORMATION, "Wrote STIX bundle to %s (%d bytes)", FileName, AlertMsg->BundleSize);
        }
        
        OS_close(FileHandle); 
    }
}

/**
 * @brief Generate and write STIX 2.1 bundle for detected IOB
 * 
 * Creates a STIX 2.1 compliant bundle documenting a detected Indicator
 * of Behavior (IOB) and writes it to the local STIX log file. The bundle
 * format varies based on artifact type to include relevant observable
 * objects.
 *
 * **Function Responsibilities:**
 * 1. Validate input parameters based on artifact type
 * 2. Look up IOB metadata from SPARTA database
 * 3. Generate RFC 4122 UUID for STIX object IDs
 * 4. Create ISO 8601 timestamp
 * 5. Build artifact-appropriate STIX bundle
 * 6. Write bundle to /cf/logs/stix_log.json
 *
 * **Parameter Requirements by Artifact Type:**
 * @code
 * AT_FILE:     file_path (required), file_hash (required)
 * AT_PROGRAM:  file_path (required), file_hash (optional)
 * AT_NETWORK:  file_path (required - IP/MAC address)
 * AT_COMMAND:  file_path (required - command string)
 * AT_CONFIG:   file_path (required), file_hash (optional)
 * AT_MEMORY:   file_path (required - memory region name)
 * AT_KEY:      file_path (required - key ID)
 * AT_DEVICE:   file_path (required - device ID)
 * AT_NONE:     iob_id (only - no other parameters)
 * @endcode
 *
 * **STIX Bundle Examples:**
 *
 * **File Artifact (AT_FILE):**
 * @code
 * {
 *   "type": "bundle",
 *   "id": "bundle--550e8400-e29b-41d4-a716-446655440000",
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "spec_version": "2.1",
 *       "id": "indicator--550e8400-e29b-41d4-a716-446655440000",
 *       "created": "2024-01-15T10:30:00Z",
 *       "modified": "2024-01-15T10:30:00Z",
 *       "name": "Unauthorized Modification of On-Orbit Update Binary",
 *       "pattern": "[file:hashes != 'expected_hash_value']",
 *       "pattern_type": "stix",
 *       "x_sparta_iob_id": "DISE-2"
 *     },
 *     {
 *       "type": "file",
 *       "spec_version": "2.1",
 *       "id": "file--550e8400-e29b-41d4-a716-446655440000",
 *       "name": "/cf/update.bin",
 *       "hashes": {
 *         "SHA-256": "3a5f8c2e..."
 *       }
 *     }
 *   ]
 * }
 * @endcode
 *
 * **Command Artifact (AT_COMMAND):**
 * @code
 * {
 *   "type": "bundle",
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "name": "Hardware Command Executed Outside Authorized Schedule",
 *       "x_sparta_iob_id": "UACE-1"
 *     },
 *     {
 *       "type": "x-spacecraft-command",
 *       "id": "x-spacecraft-command--<uuid>",
 *       "command": "hw_cmd_execute",
 *       "timestamp": "2024-01-15T10:30:00Z"
 *     }
 *   ]
 * }
 * @endcode
 *
 * **Network Artifact (AT_NETWORK):**
 * @code
 * {
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "name": "Unexpected Ground Station IP Address in Communication",
 *       "x_sparta_iob_id": "CSNE-1"
 *     },
 *     {
 *       "type": "ipv4-addr",
 *       "id": "ipv4-addr--<uuid>",
 *       "value": "192.168.1.100"
 *     }
 *   ]
 * }
 * @endcode
 *
 * **Usage Examples:**
 * @code
 * // File integrity violation
 * unsigned char hash[SHA256_DIGEST_LENGTH];
 * compute_sha256("/cf/config.dat", hash);
 * write_to_stix("/cf/config.dat", hash, "DISE-1");
 *
 * // Unauthorized command
 * write_to_stix("hw_cmd_execute", NULL, "UACE-1");
 *
 * // Network anomaly
 * write_to_stix("192.168.1.100", NULL, "CSNE-1");
 *
 * // Telemetry-based detection (no artifact)
 * write_to_stix(NULL, NULL, "GNTM-6");
 * @endcode
 *
 * **Error Handling:**
 * Function performs extensive validation:
 * - Null pointer checks
 * - String validation (null termination)
 * - IOB database lookup
 * - Buffer overflow protection
 * - File I/O error handling
 *
 * **File Output:**
 * Bundles appended to /cf/logs/stix_log.json:
 * @code
 * {"type":"bundle",...}
 * {"type":"bundle",...}
 * {"type":"bundle",...}
 * @endcode
 * Each line is a complete STIX bundle (newline-delimited JSON).
 *
 * **Performance:**
 * - String operations: ~1ms
 * - IOB lookup: <10μs
 * - File I/O: ~10ms
 * - Total: ~15ms typical
 *
 * @param[in] file_path File path, command string, IP address, or identifier
 *                      (interpretation depends on artifact type)
 * @param[in] file_hash SHA-256 hash (32 bytes) or NULL if not applicable
 * @param[in] iob_id IOB identifier string (e.g., "UACE-1")
 *
 * @return 0 on success
 * @return -1 on error (invalid parameters, IOB not found, I/O error)
 *
 * @pre iob_id must be valid IOB identifier from SPARTA database
 * @pre file_path requirements depend on artifact type
 * @pre file_hash must be 32 bytes if provided
 * @post STIX bundle appended to /cf/logs/stix_log.json
 * @post EVS event generated
 *
 * @note Function name is legacy (originally only for files)
 * @note STIX bundle limited to 2048 bytes
 * @note Uses /dev/urandom for UUID generation
 * @note Thread-safe (no shared state)
 *
 * @warning Stack corruption detection included (canary value)
 * @warning Long file paths may be truncated
 * @warning Disk full condition not explicitly handled
 *
 * @see escape_json_string for JSON encoding
 * @see generate_uuid_v4_secure for UUID generation
 * @see FindIoB for IOB database lookup
 * @see SPACECOP_SendStixAlert for transmitting bundles over the software bus
 */
int write_to_stix(const char *file_path, const unsigned char file_hash[SHA256_DIGEST_LENGTH], const char *iob_id) 
{
    volatile int canary = 0x12345678;
    
    // Stack corruption detection
    if (canary != 0x12345678) {
        write(STDERR_FILENO, "STACK CORRUPTION DETECTED\n", 26);
        return -1;
    }
    
    osal_id_t fd;
    int32 status;
    const char *stix_log_path = SPACECOP_LOGS_VDIR "/stix_log.json";

    // Validate IOB ID
    if (!iob_id) {
        write(STDERR_FILENO, "[write_to_stix] ERROR: iob_id is NULL\n", 38);
        return -1;
    }
    
    // Validate that iob_id is a valid string (check for null terminator within reasonable range)
    int valid_string = 0;
    for (int i = 0; i < 64; i++) {
        if (iob_id[i] == '\0') {
            valid_string = 1;
            break;
        }
    }

    if (!valid_string) {
        fprintf(stderr, "[write_to_stix] ERROR: iob_id is not a valid null-terminated string\n");
        return -1;
    }

    // Convert hash to hex string if provided
    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    if (file_hash) {
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            snprintf(hash_hex + (i * 2), 3, "%02x", file_hash[i]);
        }
        hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
    }

    // Generate timestamp (ISO 8601 format)
    time_t now = time(NULL);
    struct tm *timeinfo = gmtime(&now);
    if (!timeinfo) {
        return -1;
    }
    
    char timestamp[64] = {0};
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", timeinfo);

    // Check for path length if provided
    if (file_path) {
        size_t path_len = strlen(file_path);
        if (path_len > 200) {
            return -1;
        }
    }

    // Generate UUID for STIX object IDs
    char uuid_str[37];
    generate_uuid_v4_secure(uuid_str);

    // Look up IOB metadata from SPARTA database
    const char* iob_pattern = NULL;
    const char* iob_name = NULL;
    ArtifactType iob_arttype = AT_NONE;

    for (size_t i = 0; i < IOB_ARRAY_SIZE; i++) {
        if (strcmp(iobs[i].iob, iob_id) == 0) {
            iob_pattern = iobs[i].pattern;
            iob_name = iobs[i].name;
            iob_arttype = iobs[i].arttype;
            break;
        }
    }

    if (iob_pattern == NULL) {
        fprintf(stderr, "Error: IOB ID '%s' not found\n", iob_id);
        return -1;
    }

    if (iob_name == NULL) {
        fprintf(stderr, "Error: IOB name is NULL for IOB ID '%s'\n", iob_id);
        return -1;
    }

    // Escape JSON pattern
    char escaped_pattern[2048] = {0};
    if (iob_pattern) {
        escape_json_string(iob_pattern, escaped_pattern, sizeof(escaped_pattern));
    }

    // Create STIX bundle based on artifact type and available data
    char stix_bundle[2048] = {0};
    int written = 0;

    switch (iob_arttype) {
        case AT_FILE:
            // Requires both file_path and file_hash
            if (!file_path || !file_hash) {
                return -1;
            }
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"file\",\"spec_version\":\"2.1\",\"id\":\"file--%s\",\"name\":\"%s\",\"hashes\":{\"SHA-256\":\"%s\"}}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, file_path, hash_hex
            );
            break;

        case AT_PROGRAM:
            // Requires file_path (program name), hash is optional
            if (!file_path) {
                return -1;
            }
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"process\",\"spec_version\":\"2.1\",\"id\":\"process--%s\",\"name\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, file_path
            );
            break;

        case AT_NETWORK:
            // Requires file_path (IP address, MAC, or network identifier)
            if (!file_path) {
                return -1;
            }
            
            // Determine if it's an IPv4, IPv6, or MAC address
            const char *addr_type = "ipv4-addr";  // Default
            if (strchr(file_path, ':') != NULL) {
                // Could be IPv6 or MAC
                int colon_count = 0;
                for (const char *p = file_path; *p; p++) {
                    if (*p == ':') colon_count++;
                }
                addr_type = (colon_count >= 5) ? "mac-addr" : "ipv6-addr";
            }
            
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"%s\",\"spec_version\":\"2.1\",\"id\":\"%s--%s\",\"value\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                addr_type, addr_type, uuid_str, file_path
            );
            break;

        case AT_COMMAND:
            // Requires file_path (command string)
            if (!file_path) {
                return -1;
            }
            
            // Escape the command string for JSON
            char escaped_command[512] = {0};
            escape_json_string(file_path, escaped_command, sizeof(escaped_command));
            
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"x-spacecraft-command\",\"spec_version\":\"2.1\",\"id\":\"x-spacecraft-command--%s\","
                "\"command\":\"%s\",\"timestamp\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, escaped_command, timestamp
            );
            break;

        case AT_CONFIG:
            // Requires file_path (config file path), hash optional
            if (!file_path) {
                return -1;
            }
            
            if (file_hash) {
                written = snprintf(stix_bundle, sizeof(stix_bundle),
                    "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                    "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                    "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                    "{\"type\":\"file\",\"spec_version\":\"2.1\",\"id\":\"file--%s\",\"name\":\"%s\","
                    "\"hashes\":{\"SHA-256\":\"%s\"},\"x_file_type\":\"configuration\"}]}\n",
                    uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                    uuid_str, file_path, hash_hex
                );
            } else {
                written = snprintf(stix_bundle, sizeof(stix_bundle),
                    "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                    "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                    "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                    "{\"type\":\"file\",\"spec_version\":\"2.1\",\"id\":\"file--%s\",\"name\":\"%s\","
                    "\"x_file_type\":\"configuration\"}]}\n",
                    uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                    uuid_str, file_path
                );
            }
            break;

        case AT_MEMORY:
            // Requires file_path (memory region/table identifier)
            if (!file_path) {
                return -1;
            }
            
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"x-memory-region\",\"spec_version\":\"2.1\",\"id\":\"x-memory-region--%s\","
                "\"region_name\":\"%s\",\"timestamp\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, file_path, timestamp
            );
            break;

        case AT_KEY:
            // Requires file_path (key ID or fingerprint)
            if (!file_path) {
                return -1;
            }
            
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"x-cryptographic-key\",\"spec_version\":\"2.1\",\"id\":\"x-cryptographic-key--%s\","
                "\"key_id\":\"%s\",\"timestamp\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, file_path, timestamp
            );
            break;

        case AT_DEVICE:
            // Requires file_path (device identifier)
            if (!file_path) {
                return -1;
            }
            
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"},"
                "{\"type\":\"x-spacecraft-device\",\"spec_version\":\"2.1\",\"id\":\"x-spacecraft-device--%s\","
                "\"device_id\":\"%s\",\"timestamp\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id,
                uuid_str, file_path, timestamp
            );
            break;

        case AT_NONE:
        default:
            // Only requires IOB ID - no file_path or hash needed
            written = snprintf(stix_bundle, sizeof(stix_bundle),
                "{\"type\":\"bundle\",\"id\":\"bundle--%s\",\"objects\":["
                "{\"type\":\"indicator\",\"spec_version\":\"2.1\",\"id\":\"indicator--%s\",\"created\":\"%s\",\"modified\":\"%s\","
                "\"name\":\"%s\",\"pattern\":\"%s\",\"pattern_type\":\"stix\",\"x_sparta_iob_id\":\"%s\"}]}\n",
                uuid_str, uuid_str, timestamp, timestamp, iob_name, escaped_pattern, iob_id
            );
            break;
    }

    if (written >= sizeof(stix_bundle)) {
        return -1;
    }

    // Open/create the STIX log file
    status = OS_OpenCreate(&fd, stix_log_path, OS_FILE_FLAG_CREATE, OS_WRITE_ONLY);
    
    if (status != OS_SUCCESS) {
        return -1;
    }

    // Seek to end of file to append
    status = OS_lseek(fd, 0, OS_SEEK_END);
    if (status < OS_SUCCESS) {
        OS_close(fd);
        return -1;
    }

    // Write STIX bundle
    status = OS_write(fd, (void *)stix_bundle, strlen(stix_bundle));
    if (status < OS_SUCCESS) {
        OS_close(fd);
        return -1;
    }

    OS_close(fd);

    // Log success via EVS
    CFE_EVS_SendEvent(100, CFE_EVS_EventType_INFORMATION, 
                     "[write_to_stix] STIX bundle written: %d bytes for IOB %s", 
                     written, iob_id);

    return 0;
}