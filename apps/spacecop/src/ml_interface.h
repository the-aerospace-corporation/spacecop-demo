// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file ml_interface.h
 * @brief Machine Learning bridge interface for SpaceCop IDS
 *
 * This header provides function prototypes and data structures for interfacing
 * with an external machine learning anomaly detection system. The ML bridge
 * enables SpaceCop to:
 * - Send telemetry data to ML models for analysis
 * - Receive anomaly alerts from ML models
 * - Parse and classify ML-detected anomalies
 * - Generate IDS alerts based on ML findings
 *
 * **Architecture:**
 * - UDP socket communication with ML server (localhost)
 * - Send port 9111: SpaceCop → ML server
 * - Receive port 9112: ML server → SpaceCop
 * - JSON-based alert protocol
 * - Asynchronous alert reception
 *
 * **Supported Alert Types:**
 * - ML Anomaly: Statistical deviations detected by ML models
 * - Command Flooding: Excessive command rates
 * - Replay Attack: Duplicate command patterns
 *
 * **Key Features:**
 * - Real-time telemetry streaming to ML models
 * - JSON alert parsing
 * - IOB (Indicator of Behavior) mapping
 * - Configurable monitor enable/disable
 * - Integration with STIX reporting
 */

#ifndef ML_INTERFACE_H
#define ML_INTERFACE_H

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include "cfe.h"
#include "cfe_sb.h"
#include <stdint.h>
#include <stdbool.h>
#include "spacecop_external_imports.h"
#include "spacecop_ids_helper.h"

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/** @brief UDP port for sending data to ML server */
#define ML_SEND_PORT 9111

/** @brief UDP port for receiving alerts from ML server */
#define ML_RECV_PORT 9112

/** @brief IP address of ML server (localhost) */
#define ML_SERVER_IP "127.0.0.1"

/** @brief Maximum buffer size for socket communications */
#define BUFFER_SIZE 8192

/** @brief Maximum number of telemetry subscriptions for ML monitoring */
#define MAX_SUBSCRIPTIONS 50

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief ML Bridge application data structure
 *
 * Contains the runtime state of the ML bridge including socket file
 * descriptors and run status.
 */
typedef struct {
    int32_t send_sockfd;    /**< Socket file descriptor for sending to ML server */
    int32_t recv_sockfd;    /**< Socket file descriptor for receiving from ML server */
    uint32_t RunStatus;     /**< Application run status flag */
} MLBridge_AppData_t;

/**
 * @brief ML monitor configuration structure
 *
 * Tracks the monitoring state and identifiers for ML-based detection
 * of specific message types.
 */
typedef struct 
{
    int8_t enabled;         /**< Monitor enabled flag (0=disabled, 1=enabled) */
    char iob[10];           /**< IOB identifier (e.g., "MLAD-1") */
    char mid[64];           /**< Message ID being monitored */
} MLMonitorInfo;

/**
 * @brief Alert type enumeration
 *
 * Classifies the type of anomaly detected by the ML system.
 */
typedef enum {
    ALERT_TYPE_UNKNOWN = 0,         /**< Unknown or unparseable alert type */
    ALERT_TYPE_ML_ANOMALY,          /**< Statistical anomaly detected by ML model */
    ALERT_TYPE_COMMAND_FLOODING,    /**< Excessive command rate detected */
    ALERT_TYPE_REPLAY_ATTACK        /**< Duplicate command pattern detected */
} AlertType_t;

/**
 * @brief Parsed alert structure
 *
 * Contains structured information extracted from a JSON alert message
 * received from the ML server.
 */
typedef struct {
    AlertType_t alert_type;         /**< Type of alert */
    char severity[16];              /**< Severity level (e.g., "high", "medium", "low") */
    char stix_pattern[64];          /**< STIX pattern identifier */
    char description[256];          /**< Human-readable alert description */
    char hex[512];                  /**< Hexadecimal representation of anomalous data */
    char system[64];                /**< System or component that generated the data */
    char data_type[16];             /**< Type of data (e.g., "command", "telemetry") */
    int current_rate;               /**< Current rate (for flooding detection) */
    int threshold;                  /**< Threshold value (for flooding detection) */
    double mse;                     /**< Mean squared error (for ML anomaly) */
    char responsible_feature[128];  /**< Feature responsible for anomaly */
} ParsedAlert_t;

/*=======================================================================================
** Socket Communication Functions
**=======================================================================================*/

/**
 * @brief Initialize UDP sockets for ML communication
 *
 * Creates and configures UDP sockets for bidirectional communication with
 * the ML server. Sets up:
 * - Send socket bound to ML_SEND_PORT
 * - Receive socket bound to ML_RECV_PORT
 * - Non-blocking mode for asynchronous reception
 *
 * @return int32_t CFE_SUCCESS on success, error code on failure
 *
 * @note Sockets connect to ML_SERVER_IP (127.0.0.1)
 * @note Must be called before sending/receiving data
 * @note Prints diagnostic messages on failure
 *
 * @see MLBridge_Cleanup()
 */
int32_t MLBridge_InitSockets(void);

/**
 * @brief Send raw telemetry data to ML server as hexadecimal
 *
 * Converts binary telemetry data to hexadecimal string format and sends it
 * to the ML server via UDP. The ML server uses this data to train models
 * and detect anomalies.
 *
 * @param[in] data Pointer to binary telemetry data
 * @param[in] length Length of data in bytes
 * @param[in] msg_id cFE Software Bus Message ID
 *
 * @return int32_t CFE_SUCCESS on success, error code on failure
 *
 * @note Data is converted to hex string before transmission
 * @note Includes message ID in transmission for ML model routing
 * @note Non-blocking send operation
 *
 * Example usage:
 * @code
 * uint8_t tlm_data[64];
 * CFE_SB_MsgId_t msg_id = CFE_SB_ValueToMsgId(0x0880);
 * MLBridge_SendRawHex(tlm_data, sizeof(tlm_data), msg_id);
 * @endcode
 */
int32_t MLBridge_SendRawHex(const uint8_t *data, size_t length, CFE_SB_MsgId_t msg_id);

/**
 * @brief Check for and process alerts from ML server
 *
 * Non-blocking check for incoming JSON alert messages from the ML server.
 * If an alert is received, it is parsed and processed to generate appropriate
 * IDS alerts.
 *
 * @return void
 *
 * @note Non-blocking operation (returns immediately if no data)
 * @note Should be called periodically in main loop
 * @note Automatically parses and handles received alerts
 *
 * @see MLBridge_ParseAlert()
 * @see MLBridge_HandleAlert()
 */
void MLBridge_CheckForResponse(void);

/**
 * @brief Clean up ML bridge resources
 *
 * Closes socket file descriptors and releases any allocated resources.
 * Should be called during application shutdown.
 *
 * @return void
 *
 * @note Safe to call multiple times
 * @note Closes both send and receive sockets
 */
void MLBridge_Cleanup(void);

/*=======================================================================================
** Alert Parsing and Handling Functions
**=======================================================================================*/

/**
 * @brief Parse JSON alert message from ML server
 *
 * Extracts structured information from a JSON-formatted alert message
 * received from the ML server. Populates a ParsedAlert_t structure with
 * the parsed data.
 *
 * JSON format expected:
 * @code
 * {
 *   "alert_type": "ml_anomaly",
 *   "severity": "high",
 *   "stix_pattern": "MLAD-1",
 *   "description": "Anomaly detected in telemetry",
 *   "mse": 0.95,
 *   "responsible_feature": "temperature"
 * }
 * @endcode
 *
 * @param[in] json_buffer Pointer to JSON string buffer
 * @param[out] alert Pointer to ParsedAlert_t structure to populate
 *
 * @return AlertType_t Type of alert parsed, or ALERT_TYPE_UNKNOWN on error
 *
 * @note Handles missing or malformed JSON fields gracefully
 * @note Supports multiple alert types (anomaly, flooding, replay)
 * @note Prints warnings for unparseable fields
 */
AlertType_t MLBridge_ParseAlert(const char* json_buffer, ParsedAlert_t* alert);

/**
 * @brief Handle a parsed alert by generating IDS alerts
 *
 * Processes a parsed alert structure and generates appropriate IDS alerts
 * via multiple channels:
 * - IDS telemetry messages
 * - STIX reports
 * - System log entries (via CFE_ES_WriteToSysLog)
 *
 * @param[in] alert Pointer to parsed alert structure
 *
 * @return void
 *
 * @note Alert content varies based on alert type
 * @note Includes relevant details (MSE, rates, features) in messages
 */
void MLBridge_HandleAlert(const ParsedAlert_t* alert);

/*=======================================================================================
** IOB Mapping Functions
**=======================================================================================*/

/**
 * @brief Extract IOB identifier from JSON response
 *
 * Parses a JSON response to extract the STIX pattern/IOB identifier.
 *
 * @param[in] json_buffer Pointer to JSON string buffer
 *
 * @return const char* IOB identifier string, or "UNKNOWN" if not found
 *
 * @note Looks for "stix_pattern" field in JSON
 * @note Returns static string - do not free
 */
const char* MLBridge_GetIOBFromResponse(const char* json_buffer);

/**
 * @brief Map alert type to IOB identifier
 *
 * Converts an AlertType_t enumeration value to the corresponding IOB
 * identifier string.
 *
 * @param[in] alert_type Alert type enumeration value
 *
 * @return const char* IOB identifier string
 *
 * Mappings:
 * - ALERT_TYPE_ML_ANOMALY → "MLAD-1"
 * - ALERT_TYPE_COMMAND_FLOODING → "MLAD-2"
 * - ALERT_TYPE_REPLAY_ATTACK → "MLAD-3"
 * - ALERT_TYPE_UNKNOWN → "UNKNOWN"
 *
 * @note Returns static string - do not free
 */
const char* MLBridge_GetIOBFromAlertType(AlertType_t alert_type);

/*=======================================================================================
** Monitor Control Functions
**=======================================================================================*/

/**
 * @brief Toggle ML monitoring on/off for a specific IOB
 *
 * Enables or disables ML-based monitoring for the specified IOB identifier.
 * When disabled, telemetry is not sent to the ML server for that IOB.
 *
 * @param[in] iob IOB identifier string (e.g., "MLAD-1")
 *
 * @return void
 *
 * @note Toggles between enabled and disabled states
 * @note Does not affect already-queued telemetry
 */
void Toggle_MLMonitor(const char *iob);

/*=======================================================================================
** Legacy Functions
**=======================================================================================*/

/**
 * @brief Handle ML anomaly alert (legacy function)
 *
 * Legacy function for handling ML anomaly alerts. Kept for backwards
 * compatibility with older ML server implementations.
 *
 * @param[in] json_buffer Pointer to JSON alert string
 * @param[in] iob_name IOB identifier string
 *
 * @return void
 *
 * @deprecated Use MLBridge_ParseAlert() and MLBridge_HandleAlert() instead
 *
 * @note Provided for backwards compatibility only
 * @note New code should use the newer parsing functions
 */
void MLBridge_HandleAnomaly(const char* json_buffer, const char* iob_name);

#endif /* ML_INTERFACE_H */