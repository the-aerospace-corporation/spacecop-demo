// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
// All rights reserved.
//
// This software is provided "as is" without any warranty of any kind either express, implied, or statutory, including, but not
// limited to, any warranty that the software will conform to specifications any implied warranties of merchantability, fitness
// for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
// any warranty that the software will be error free.
//
// In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
// arising out of, resulting from, or in any way connected with the software or its documentation. Whether or not based upon warranty,
// contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
// documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

/**
 * @file sparta_stix.h
 * @brief STIX 2.1 bundle generation and CTI sharing interface
 *
 * This header defines the interface for STIX (Structured Threat Information
 * eXpression) 2.1 bundle generation and cyber threat intelligence (CTI)
 * sharing in SpaceCop. It provides:
 * - STIX bundle generation for detected IOBs
 * - Software bus messaging for CTI distribution
 * - Peer alert processing
 * - Heartbeat mechanism for distributed detection
 *
 * **STIX 2.1 Integration:**
 * SpaceCop uses STIX 2.1 as the standard format for representing threat
 * intelligence. STIX provides:
 * - Standardized threat description language
 * - Interoperability with industry security tools
 * - Machine-readable threat intelligence
 * - Support for complex relationships between objects
 *
 * **Threat Intelligence Workflow:**
 * @code
 * 1. Detection Engine → IOB triggered
 * 2. write_to_stix() → Create STIX bundle
 * 3. SPACECOP_SendStixAlert() → Transmit via software bus
 * 4. Peer receives → SPACECOP_ProcessPeerAlert()
 * 5. Ground system → Correlate and analyze
 * @endcode
 *
 * **CTI Sharing Architecture:**
 * @code
 * ┌──────────────────────────────────────────────────────────┐
 * │                    Spacecraft Constellation               │
 * │                                                           │
 * │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
 * │  │ Spacecraft A│    │ Spacecraft B│    │ Spacecraft C│ │
 * │  │  SpaceCop   │◄──►│  SpaceCop   │◄──►│  SpaceCop   │ │
 * │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘ │
 * │         │                  │                  │         │
 * └─────────┼──────────────────┼──────────────────┼─────────┘
 *           │                  │                  │
 *           └──────────────────┼──────────────────┘
 *                              │
 *                     ┌────────▼────────┐
 *                     │  Ground System  │
 *                     │   SIEM / SOC    │
 *                     └─────────────────┘
 * @endcode
 *
 * **Message Types:**
 * - SPACECOP_ALERT_STIX: Threat detection with STIX bundle
 * - SPACECOP_HEARTBEAT: Operational status indicator
 *
 * **File Storage:**
 * - Local detections: /cf/logs/stix_log.json
 * - Peer alerts: /cf/cti/stix_bundle_<timestamp>.dat
 * - Persistent storage for forensic analysis
 * - Ground-retrievable via file downlink
 *
 * **STIX Bundle Contents:**
 * Each bundle contains:
 * - Indicator object (IOB description and pattern)
 * - Observable objects (file, process, network, etc.)
 * - Timestamps (ISO 8601 format)
 * - Unique identifiers (RFC 4122 UUIDs)
 * - SPARTA IOB reference
 *
 * **Usage Example:**
 * @code
 * // Detection triggers STIX generation
 * void on_iob_detected(const char *iob_id, const char *artifact) {
 *     // Generate STIX bundle
 *     unsigned char hash[SHA256_DIGEST_LENGTH];
 *     compute_sha256(artifact, hash);
 *     
 *     // Write to local log
 *     write_to_stix(artifact, hash, iob_id);
 *     
 *     // Optionally share with peers
 *     char bundle[2048];
 *     create_bundle(bundle, sizeof(bundle), iob_id, artifact, hash);
 *     SPACECOP_SendStixAlert(bundle, strlen(bundle));
 * }
 * 
 * // Peer processes received alert
 * void message_handler(const CFE_MSG_Message_t *msg) {
 *     CFE_SB_MsgId_t msg_id = CFE_SB_GetMsgId(msg);
 *     
 *     if (msg_id == SPACECOP_CTI_SHARE_MID) {
 *         SPACECOP_ProcessPeerAlert(msg);
 *     }
 * }
 * @endcode
 *
 * **Benefits of STIX Integration:**
 * - **Standardization:** Industry-standard threat intelligence format
 * - **Interoperability:** Compatible with ground SIEM systems
 * - **Correlation:** Link detections across multiple spacecraft
 * - **Forensics:** Complete audit trail of threats
 * - **Automation:** Machine-readable for automated response
 *
 * **Distributed Detection:**
 * Multiple SpaceCop instances share intelligence:
 * - Spacecraft A detects attack → broadcasts STIX
 * - Spacecraft B receives alert → updates threat model
 * - Ground system correlates → identifies campaign
 * - Coordinated defense across constellation
 *
 * @note STIX bundles limited to 1024 bytes for telemetry
 * @note Requires OpenSSL for SHA-256 hashing
 * @note Uses OSAL for platform-independent file I/O
 *
 * @see sparta_stix.c for implementation details
 * @see sparta_iobs.h for IOB database
 * @see STIX 2.1 specification for format details
 */

#ifndef SPACECOP_STIX_WRITER_H
#define SPACECOP_STIX_WRITER_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "osapi.h"
#include "cfe.h"
#include <openssl/sha.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief STIX alert message type identifier
 * 
 * Identifies software bus messages containing STIX threat intelligence
 * bundles. Used in SPACECOP_Alert_t.AlertType field to distinguish
 * STIX alerts from other message types.
 *
 * **Usage:**
 * @code
 * SPACECOP_Alert_t alert;
 * alert.AlertType = SPACECOP_ALERT_STIX;
 * alert.BundleSize = strlen(stix_bundle);
 * memcpy(alert.StixBundle, stix_bundle, alert.BundleSize);
 * CFE_SB_TransmitMsg(&alert.TlmHeader.Msg, true);
 * @endcode
 *
 * @see SPACECOP_Alert_t for message structure
 * @see SPACECOP_HEARTBEAT for alternative message type
 */
#define SPACECOP_ALERT_STIX         1

/**
 * @brief Heartbeat message type identifier
 * 
 * Identifies software bus messages containing operational heartbeats.
 * Used to indicate SpaceCop instance is active and operational.
 *
 * **Purpose:**
 * - Distributed health monitoring
 * - Peer availability tracking
 * - Failover coordination
 * - Network presence indication
 *
 * **Usage:**
 * @code
 * SPACECOP_Alert_t heartbeat;
 * heartbeat.AlertType = SPACECOP_HEARTBEAT;
 * heartbeat.BundleSize = 0;  // No payload
 * CFE_SB_TransmitMsg(&heartbeat.TlmHeader.Msg, true);
 * @endcode
 *
 * @see SPACECOP_SendHeartbeat for heartbeat transmission
 * @see SPACECOP_ALERT_STIX for alternative message type
 */
#define SPACECOP_HEARTBEAT          2

/**
 * @brief Event ID for STIX alert information messages
 * 
 * Event identifier for informational EVS messages related to STIX
 * alert generation, transmission, and reception.
 *
 * **Example Events:**
 * - "Sent STIX bundle alert: 512 bytes"
 * - "Received peer alert: type=1 size=512 bytes"
 * - "STIX bundle written: 512 bytes for IOB UACE-1"
 *
 * **Usage:**
 * @code
 * CFE_EVS_SendEvent(SPACECOP_ALERT_INF_EID, 
 *                  CFE_EVS_EventType_INFORMATION,
 *                  "Sent STIX bundle alert: %d bytes", 
 *                  bundle_size);
 * @endcode
 *
 * @see CFE_EVS_SendEvent for event generation
 */
#define SPACECOP_ALERT_INF_EID      100

/**
 * @brief Event ID for file operation error messages
 * 
 * Event identifier for error EVS messages related to file I/O
 * operations during STIX bundle storage.
 *
 * **Example Events:**
 * - "Failed to create file /cf/cti/stix_bundle_1640000000.dat: -1"
 * - "Failed to write bundle: wrote 256 of 512 bytes"
 * - "OS_OpenCreate failed with status=-1"
 *
 * **Usage:**
 * @code
 * if (OS_OpenCreate(&fd, filename, flags, mode) != OS_SUCCESS) {
 *     CFE_EVS_SendEvent(SPACECOP_FILE_ERR_EID,
 *                      CFE_EVS_EventType_ERROR,
 *                      "Failed to create file %s: %d",
 *                      filename, status);
 * }
 * @endcode
 *
 * @see OS_OpenCreate for file operations
 */
#define SPACECOP_FILE_ERR_EID       101

/**
 * @brief Event ID for file operation information messages
 * 
 * Event identifier for informational EVS messages related to successful
 * file I/O operations during STIX bundle storage.
 *
 * **Example Events:**
 * - "Wrote STIX bundle to /cf/cti/stix_bundle_1640000000.dat (512 bytes)"
 * - "STIX log file created successfully"
 * - "Peer alert stored to disk"
 *
 * **Usage:**
 * @code
 * if (OS_write(fd, bundle, size) == size) {
 *     CFE_EVS_SendEvent(SPACECOP_FILE_INF_EID,
 *                      CFE_EVS_EventType_INFORMATION,
 *                      "Wrote STIX bundle to %s (%d bytes)",
 *                      filename, size);
 * }
 * @endcode
 *
 * @see OS_write for file write operations
 */
#define SPACECOP_FILE_INF_EID       102

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief STIX alert telemetry message structure
 * 
 * Software bus message structure for transmitting STIX threat intelligence
 * bundles and heartbeat messages between SpaceCop instances.
 *
 * **Structure Fields:**
 *
 * **TlmHeader:** cFE telemetry message header
 * - Contains message ID (SPACECOP_CTI_SHARE_MID)
 * - Message length
 * - Sequence counter
 * - Timestamp
 * - Standard cFE message infrastructure
 *
 * **AlertType:** Message type identifier
 * - SPACECOP_ALERT_STIX (1): STIX bundle alert
 * - SPACECOP_HEARTBEAT (2): Heartbeat message
 * - Future types can be added
 *
 * **BundleSize:** Size of STIX bundle payload in bytes
 * - 0 for heartbeat messages
 * - 1-1024 for STIX bundles
 * - Indicates valid data in StixBundle field
 *
 * **StixBundle:** STIX JSON bundle payload
 * - Maximum 1024 bytes
 * - Contains complete STIX 2.1 bundle
 * - Null-terminated JSON string
 * - Unused bytes should be zeroed
 *
 * **Message Size:**
 * @code
 * sizeof(SPACECOP_Alert_t) = 
 *     sizeof(CFE_MSG_TelemetryHeader_t) +  // ~12 bytes
 *     sizeof(uint8) +                       // 1 byte
 *     sizeof(uint32) +                      // 4 bytes
 *     1024                                  // 1024 bytes
 *     = ~1041 bytes total
 * @endcode
 *
 * **Usage Examples:**
 *
 * **Sending STIX Alert:**
 * @code
 * SPACECOP_Alert_t alert;
 * 
 * // Initialize message header
 * CFE_MSG_Init(&alert.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID),
 *              sizeof(SPACECOP_Alert_t));
 * 
 * // Set alert fields
 * alert.AlertType = SPACECOP_ALERT_STIX;
 * alert.BundleSize = strlen(stix_bundle);
 * memset(alert.StixBundle, 0, sizeof(alert.StixBundle));
 * memcpy(alert.StixBundle, stix_bundle, alert.BundleSize);
 * 
 * // Transmit
 * CFE_SB_TransmitMsg(&alert.TlmHeader.Msg, true);
 * @endcode
 *
 * **Sending Heartbeat:**
 * @code
 * SPACECOP_Alert_t heartbeat;
 * 
 * CFE_MSG_Init(&heartbeat.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID),
 *              sizeof(SPACECOP_Alert_t));
 * 
 * heartbeat.AlertType = SPACECOP_HEARTBEAT;
 * heartbeat.BundleSize = 0;  // No payload
 * 
 * CFE_SB_TransmitMsg(&heartbeat.TlmHeader.Msg, true);
 * @endcode
 *
 * **Receiving and Processing:**
 * @code
 * void process_message(const CFE_MSG_Message_t *msg) {
 *     const SPACECOP_Alert_t *alert = (const SPACECOP_Alert_t *)msg;
 *     
 *     switch (alert->AlertType) {
 *         case SPACECOP_ALERT_STIX:
 *             // Process STIX bundle
 *             store_bundle(alert->StixBundle, alert->BundleSize);
 *             analyze_threat(alert->StixBundle);
 *             break;
 *             
 *         case SPACECOP_HEARTBEAT:
 *             // Update peer status
 *             update_peer_timestamp(spacecraft_id);
 *             break;
 *             
 *         default:
 *             // Unknown message type
 *             break;
 *     }
 * }
 * @endcode
 *
 * **Size Limitation:**
 * The 1024-byte bundle size limit is imposed by:
 * - Telemetry packet size constraints
 * - Software bus message limits
 * - Bandwidth considerations
 *
 * For complete forensic data exceeding 1024 bytes, retrieve from
 * /cf/logs/stix_log.json via file downlink.
 *
 * **Alignment Considerations:**
 * Structure may have padding for alignment. Use sizeof() for actual size.
 * Do not assume field offsets.
 *
 * @note StixBundle is not guaranteed to be null-terminated
 * @note Use BundleSize to determine valid data length
 * @note Message must be initialized with CFE_MSG_Init()
 * @note Maximum bundle size is 1024 bytes
 *
 * @see SPACECOP_SendStixAlert for sending alerts
 * @see SPACECOP_ProcessPeerAlert for receiving alerts
 * @see SPACECOP_SendHeartbeat for sending heartbeats
 */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;  /**< cFE telemetry message header */
    
    uint8  AlertType;                     /**< Message type (STIX alert or heartbeat) */
    uint32 BundleSize;                    /**< Size of STIX bundle in bytes (0 for heartbeat) */
    char   StixBundle[1024];              /**< STIX JSON bundle payload (max 1024 bytes) */
    
} SPACECOP_Alert_t;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Send STIX bundle alert via software bus
 * 
 * Transmits a STIX 2.1 bundle to peer SpaceCop instances and ground systems
 * via the cFS software bus. Enables distributed threat intelligence sharing
 * across spacecraft constellation.
 *
 * **Functionality:**
 * - Initializes telemetry message header
 * - Copies STIX bundle to message (up to 1024 bytes)
 * - Transmits via SPACECOP_CTI_SHARE_MID
 * - Generates EVS event confirming transmission
 *
 * **Bundle Size Handling:**
 * If bundle_size > 1024, bundle is truncated to 1024 bytes.
 * Complete bundle still available in /cf/logs/stix_log.json.
 *
 * **Usage Example:**
 * @code
 * // Generate STIX bundle
 * char bundle[2048];
 * int size = snprintf(bundle, sizeof(bundle),
 *                    "{\"type\":\"bundle\",\"id\":\"bundle--%s\",...}",
 *                    uuid);
 * 
 * // Send to peers
 * SPACECOP_SendStixAlert(bundle, size);
 * 
 * // Peers will receive via SPACECOP_ProcessPeerAlert()
 * @endcode
 *
 * @param[in] stix_bundle Pointer to STIX JSON bundle string
 * @param[in] bundle_size Size of bundle in bytes
 *
 * @pre stix_bundle must point to valid JSON string
 * @pre bundle_size must be > 0
 * @post STIX alert transmitted on software bus
 * @post EVS information event generated
 *
 * @note Bundle truncated to 1024 bytes if larger
 * @note No delivery guarantee (software bus best-effort)
 * @note Subscribers must be configured for SPACECOP_CTI_SHARE_MID
 *
 * @see SPACECOP_ProcessPeerAlert for receiving side
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_SendStixAlert(char *stix_bundle, uint32 bundle_size);

/**
 * @brief Process received peer alert message
 * 
 * Receives and processes threat intelligence alerts from peer SpaceCop
 * instances. STIX bundles are stored to /cf/cti/ for correlation and
 * forensic analysis.
 *
 * **Processing:**
 * - Extracts alert type and bundle from message
 * - For STIX alerts:
 *   - Generates unique filename with timestamp
 *   - Creates file in /cf/cti/ directory
 *   - Writes bundle to disk
 *   - Generates EVS events
 * - For heartbeats:
 *   - Logs reception (optional)
 *   - Updates peer tracking (optional)
 *
 * **File Storage:**
 * - Directory: /cf/cti/
 * - Filename: stix_bundle_<timestamp>.dat
 * - Format: Raw STIX JSON bundle
 * - One file per alert
 *
 * **Usage Example:**
 * @code
 * // In message processing loop
 * void handle_messages(void) {
 *     CFE_SB_Buffer_t *buf;
 *     
 *     while (CFE_SB_ReceiveBuffer(&buf, pipe, timeout) == CFE_SUCCESS) {
 *         CFE_SB_MsgId_t msg_id = CFE_SB_GetMsgId(&buf->Msg);
 *         
 *         if (msg_id == SPACECOP_CTI_SHARE_MID) {
 *             SPACECOP_ProcessPeerAlert(&buf->Msg);
 *         }
 *     }
 * }
 * @endcode
 *
 * @param[in] MsgPtr Pointer to received software bus message
 *
 * @pre MsgPtr must point to valid SPACECOP_Alert_t message
 * @pre /cf/cti/ directory must exist
 * @post STIX bundle written to file (if STIX alert)
 * @post EVS events generated
 *
 * @note File creation may fail if disk full
 * @note Heartbeats logged but not stored
 * @note Thread-safe (uses OSAL file I/O)
 *
 * @see SPACECOP_SendStixAlert for sending side
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_ProcessPeerAlert(const CFE_MSG_Message_t *MsgPtr);

/**
 * @brief Send operational heartbeat message
 * 
 * Transmits a heartbeat message indicating this SpaceCop instance is
 * operational. Used for distributed health monitoring and peer tracking.
 *
 * **Purpose:**
 * - Indicate operational status
 * - Enable peer failure detection
 * - Support distributed coordination
 * - Maintain constellation awareness
 *
 * **Heartbeat Interval:**
 * Typically sent every 30-60 seconds via scheduler table.
 *
 * **Usage Example:**
 * @code
 * // In periodic scheduler (10Hz)
 * void periodic_task(void) {
 *     static uint32 tick = 0;
 *     tick++;
 *     
 *     if (tick % 300 == 0) {  // Every 30 seconds
 *         SPACECOP_SendHeartbeat();
 *     }
 * }
 * @endcode
 *
 * @post Heartbeat message transmitted on software bus
 * @post Peers can detect operational status
 *
 * @note No payload transmitted (lightweight message)
 * @note No acknowledgment expected
 * @note Minimal bandwidth usage
 *
 * @see SPACECOP_ProcessPeerAlert for reception
 * @see SPACECOP_Alert_t for message structure
 */
void SPACECOP_SendHeartbeat(void);

/**
 * @brief Generate and write STIX 2.1 bundle for detected IOB
 * 
 * Creates a STIX 2.1 compliant bundle documenting a detected Indicator
 * of Behavior and writes it to /cf/logs/stix_log.json. The bundle format
 * adapts based on artifact type to include appropriate observable objects.
 *
 * **Function Capabilities:**
 * - Generates STIX 2.1 compliant JSON bundles
 * - Supports all SPARTA artifact types
 * - Includes IOB metadata from database
 * - Creates unique UUIDs for STIX objects
 * - Appends to persistent log file
 * - Validates inputs based on artifact type
 *
 * **Parameter Usage by Artifact Type:**
 * @code
 * AT_FILE:     file_path + file_hash required
 * AT_PROGRAM:  file_path required, file_hash optional
 * AT_NETWORK:  file_path required (IP/MAC address)
 * AT_COMMAND:  file_path required (command string)
 * AT_CONFIG:   file_path required, file_hash optional
 * AT_MEMORY:   file_path required (memory region)
 * AT_KEY:      file_path required (key identifier)
 * AT_DEVICE:   file_path required (device ID)
 * AT_NONE:     iob_id only (no other parameters)
 * @endcode
 *
 * **STIX Bundle Structure:**
 * @code
 * {
 *   "type": "bundle",
 *   "id": "bundle--<uuid>",
 *   "objects": [
 *     {
 *       "type": "indicator",
 *       "spec_version": "2.1",
 *       "id": "indicator--<uuid>",
 *       "created": "2024-01-15T10:30:00Z",
 *       "modified": "2024-01-15T10:30:00Z",
 *       "name": "IOB Description",
 *       "pattern": "[observable:property = 'value']",
 *       "pattern_type": "stix",
 *       "x_sparta_iob_id": "UACE-1"
 *     },
 *     {
 *       // Artifact-specific object (file, process, etc.)
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
 * // Unauthorized command execution
 * write_to_stix("hw_cmd_execute", NULL, "UACE-1");
 *
 * // Network anomaly
 * write_to_stix("192.168.1.100", NULL, "CSNE-1");
 *
 * // Telemetry-based detection
 * write_to_stix(NULL, NULL, "GNTM-6");
 * @endcode
 *
 * **File Output:**
 * Bundles appended to /cf/logs/stix_log.json as newline-delimited JSON:
 * @code
 * {"type":"bundle","id":"bundle--...","objects":[...]}
 * {"type":"bundle","id":"bundle--...","objects":[...]}
 * {"type":"bundle","id":"bundle--...","objects":[...]}
 * @endcode
 *
 * **Error Handling:**
 * Returns -1 if:
 * - iob_id is NULL or invalid
 * - Required parameters missing for artifact type
 * - IOB not found in SPARTA database
 * - File I/O error
 * - Buffer overflow would occur
 *
 * @param[in] file_path File path, command string, IP address, or identifier
 *                      (interpretation depends on IOB artifact type)
 * @param[in] file_hash SHA-256 hash (32 bytes) or NULL if not applicable
 * @param[in] iob_id IOB identifier string (e.g., "UACE-1", "DISE-2")
 *
 * @return 0 on success
 * @return -1 on error (invalid parameters, IOB not found, I/O failure)
 *
 * @pre iob_id must be valid SPARTA IOB identifier
 * @pre file_path requirements depend on artifact type
 * @pre file_hash must be SHA256_DIGEST_LENGTH bytes if provided
 * @post STIX bundle appended to /cf/logs/stix_log.json
 * @post EVS information event generated
 *
 * @note Function name is legacy (originally file-specific)
 * @note Supports all SPARTA artifact types
 * @note Bundle size limited to 2048 bytes
 * @note Uses /dev/urandom for UUID generation
 * @note Thread-safe (uses OSAL file I/O)
 *
 * @warning Disk full condition not explicitly handled
 * @warning Long strings may be truncated
 * @warning Requires OpenSSL for SHA-256 support
 *
 * @see sparta_iobs.h for IOB database
 * @see ArtifactType for artifact type enumeration
 * @see SPACECOP_SendStixAlert for optional transmission to peers
 */
int write_to_stix(const char *file_path, const unsigned char file_hash[SHA256_DIGEST_LENGTH], const char *iob_id);

#endif /* SPACECOP_STIX_WRITER_H */