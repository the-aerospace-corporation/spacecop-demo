// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_mission_specific.h
 * @brief Mission-specific type definitions and interfaces for SpaceCop IDS
 *
 * This header defines mission-specific data structures and functions that adapt
 * SpaceCop to particular cFS environments and mission configurations. It provides:
 * - Command monitoring table structures
 * - Time abstraction layer
 * - Message-to-IOB mapping interfaces
 * - Mission-specific action definitions
 *
 * **Mission Adaptation:**
 * When porting SpaceCop to a new mission, this file requires modification to:
 * - Update message IDs (ActionOnMid, DeactivateOnMid)
 * - Update command codes (ActionOnCommandCode, DeactivateOnCommandCode)
 * - Adjust COMMAND_MONITOR_ENTRY_COUNT for table size
 * - Configure STIX IOB mappings
 * - Add mission-specific includes
 *
 * **Command Monitoring:**
 * The command monitoring table defines which Software Bus messages trigger
 * detection rules. Each entry specifies:
 * - Activation trigger (MID + command code)
 * - Optional deactivation trigger
 * - Associated STIX IOB identifier
 * - Monitoring action type
 * - ML integration flag
 *
 * **Generic vs Mission-Specific:**
 * - Generic: Time abstraction, action enums, result types
 * - Mission-Specific: Message IDs, command codes, table size
 *
 * @note This file must be customized for each mission/cFS configuration
 * @see spacecop_mission_specific.c for implementation
 */

#ifndef _SPACECOP_MISSION_SPECIFIC_H_
#define _SPACECOP_MISSION_SPECIFIC_H_

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_stix_components.h"
#include "spacecop_typing.h"
#include <stdint.h>

/*=======================================================================================
** Generic Type Definitions
** 
** These types are mission-independent and provide abstraction for portability.
**=======================================================================================*/

/**
 * @brief Command monitoring action types
 *
 * Defines the type of action to take when a monitored command or telemetry
 * message is received. Different actions support different detection strategies.
 *
 * **Action Types:**
 * - COUNT_DURATION: Count occurrences within a time window (rate limiting)
 * - COUNT_TOTAL: Count total occurrences (threshold detection)
 * - STORE_PACKET: Store packet for later analysis (sequence detection)
 * - ALERT_IMMEDIATELY: Generate immediate alert (critical commands)
 *
 * **Use Cases:**
 * - COUNT_DURATION: Detect command flooding attacks
 * - COUNT_TOTAL: Detect excessive usage over mission lifetime
 * - STORE_PACKET: Detect unauthorized command sequences
 * - ALERT_IMMEDIATELY: Alert on any occurrence of critical commands
 *
 * @see CommandMonitorEntry_t
 */
typedef enum {
	COUNT_DURATION,      /**< Count occurrences within time window */
	COUNT_TOTAL,         /**< Count total occurrences */
	STORE_PACKET,        /**< Store packet for sequence analysis */
	ALERT_IMMEDIATELY    /**< Generate immediate alert */
} CommandMonitorAction_t;

/**
 * @brief Generic time element structure
 *
 * Mission-independent time representation that abstracts cFS-specific time
 * formats. Enables SpaceCop to work across different missions with varying
 * time representations.
 *
 * **Time Format:**
 * - Seconds: Whole seconds (typically since epoch or mission start)
 * - Microseconds: Fractional seconds (0-999999)
 *
 * **Conversion:**
 * Populated by SPACECOP_GetTime() which converts from cFS CFE_TIME_SysTime_t
 * to this generic format.
 *
 * @note Time is spacecraft time, not UTC or GPS
 * @see SPACECOP_GetTime()
 */
typedef struct {
	uint32_t Seconds;       /**< Whole seconds component */
	uint32_t Microseconds;  /**< Microseconds component (0-999999) */
} TimeElement_t;

/**
 * @brief STIX IOB identifier with associated action
 *
 * Associates a STIX Indicator of Behavior (IOB) identifier with a monitoring
 * action. Used in command monitoring table entries to define detection behavior.
 *
 * **Components:**
 * - Action: What to do when message is received (count, store, alert)
 * - StixId: STIX IOB identifier for alert correlation and reporting
 *
 * **Example:**
 * @code
 * StixIdAction_t action = {
 *     .Action = ALERT_IMMEDIATELY,
 *     .StixId = STIX_UACC_1  // Unauthorized Access
 * };
 * @endcode
 *
 * @see CommandMonitorAction_t
 * @see StixComponentId_t
 */
typedef struct {
	CommandMonitorAction_t Action;  /**< Monitoring action to perform */
	const StixComponentId_t StixId; /**< Associated STIX IOB identifier */
} StixIdAction_t;

/*=======================================================================================
** Mission-Specific Type Definitions
** 
** These types require mission-specific configuration for message IDs and
** command codes.
**=======================================================================================*/

/**
 * @brief Command monitoring table entry
 *
 * Defines a single entry in the command monitoring table. Each entry specifies
 * a message to monitor, the conditions that trigger detection, and the action
 * to take.
 *
 * **Entry Configuration:**
 * 1. Set Command flag (1=command, 0=telemetry)
 * 2. Configure activation trigger (MID + optional command code)
 * 3. Optionally configure deactivation trigger
 * 4. Assign STIX IOB and action type
 * 5. Enable/disable ML integration
 *
 * **Activation vs Deactivation:**
 * - Activation: Triggers detection rule (potential violation)
 * - Deactivation: Disables detection rule (valid state change)
 *
 * **Example - Command Entry:**
 * @code
 * {
 *     .Command = 1,
 *     .ActionOnMid = CFE_ES_CMD_MID,
 *     .ActionOnCommandCode = CFE_ES_START_APP_CC,
 *     .HaveDeactivate = 0,
 *     .StixInfo = {ALERT_IMMEDIATELY, STIX_UACC_1},
 *     .enableML = 0
 * }
 * @endcode
 *
 * **Example - Telemetry Entry:**
 * @code
 * {
 *     .Command = 0,
 *     .ActionOnMid = SENSOR_TLM_MID,
 *     .HaveDeactivate = 0,
 *     .StixInfo = {COUNT_DURATION, STIX_ANOM_1},
 *     .enableML = 1
 * }
 * @endcode
 *
 * @note ActionOnCommandCode ignored if Command = 0 (telemetry)
 * @note DeactivateOn* fields only used if HaveDeactivate = 1
 * @note ML-enabled entries are routed to MonitorMLPipe for ML processing
 */
typedef struct {
	/**
	 * @brief Message type flag
	 * 
	 * Indicates whether this entry monitors a command or telemetry message:
	 * - 1: Command message (has command code)
	 * - 0: Telemetry message (no command code)
	 */
	uint8_t Command;
	
	/**
	 * @brief Activation trigger Message ID
	 * 
	 * Software Bus Message ID that triggers the detection rule.
	 * For commands, must match in combination with ActionOnCommandCode.
	 * For telemetry, matches on MID alone.
	 */
	CFE_SB_MsgId_t ActionOnMid;
	
	/**
	 * @brief Activation trigger command code
	 * 
	 * Command code (function code) that triggers the detection rule.
	 * Only used when Command = 1 (command messages).
	 * Ignored for telemetry messages.
	 */
	CFE_MSG_FcnCode_t ActionOnCommandCode;
	
	/**
	 * @brief Deactivation trigger presence flag
	 * 
	 * Indicates whether this entry has a deactivation trigger:
	 * - 1: Has deactivation trigger (use DeactivateOn* fields)
	 * - 0: No deactivation trigger (rule always active)
	 * 
	 * Deactivation triggers are used for state-based monitoring where
	 * a command is only unauthorized in certain system states.
	 */
	int8_t HaveDeactivate;
	
	/**
	 * @brief Deactivation trigger Message ID
	 * 
	 * Software Bus Message ID that deactivates the detection rule.
	 * Only used when HaveDeactivate = 1.
	 * For commands, must match in combination with DeactivateOnCommandCode.
	 */
	CFE_SB_MsgId_t DeactivateOnMid;
	
	/**
	 * @brief Deactivation trigger command code
	 * 
	 * Command code that deactivates the detection rule.
	 * Only used when HaveDeactivate = 1 and Command = 1.
	 */
	CFE_MSG_FcnCode_t DeactivateOnCommandCode;
	
	/**
	 * @brief STIX IOB and monitoring action
	 * 
	 * Specifies the STIX Indicator of Behavior identifier and the action
	 * to take when the message is received.
	 */
	StixIdAction_t StixInfo;
	
	/**
	 * @brief Machine learning integration flag
	 * 
	 * Controls whether this message is forwarded to ML models:
	 * - 1: Forward to ML bridge (MonitorMLPipe)
	 * - 0: Process with rule-based detection (MonitorCmdPipe)
	 * 
	 * ML-enabled entries are sent to the ML server for anomaly detection
	 * instead of (or in addition to) rule-based monitoring.
	 */
	uint8_t enableML;
} CommandMonitorEntry_t;

/**
 * @brief Maximum number of command monitoring entries
 *
 * Defines the maximum size of the command monitoring table. This value should
 * be set based on the number of messages to monitor in the mission.
 *
 * **Sizing Considerations:**
 * - Each entry consumes memory
 * - Larger tables increase search time
 * - Should accommodate all monitored commands + telemetry
 * - Typical range: 10-100 entries
 *
 * @note Increase this value if monitoring more messages
 * @note Must match table file configuration
 */
#define COMMAND_MONITOR_ENTRY_COUNT 64

/**
 * @brief Command monitoring table structure
 *
 * Contains the complete command monitoring table with all entries and a count
 * of active entries. This structure is loaded from a table file during
 * initialization.
 *
 * **Table Loading:**
 * - Loaded from /cf/spacecop_cmdmon.tbl at startup
 * - Registered with cFE Table Services
 * - Can be updated via table update commands
 *
 * **Usage:**
 * @code
 * CommandMonitorEntryTable_t* table;
 * CFE_TBL_GetAddress((void*)&table, table_handle);
 * 
 * for (int i = 0; i < table->CommandMonitorEntryCount; i++) {
 *     // Process each entry
 * }
 * @endcode
 *
 * @note CommandMonitorEntryCount should be <= COMMAND_MONITOR_ENTRY_COUNT
 * @see SPACECOP_AppInit() for table loading
 */
typedef struct {
	/**
	 * @brief Number of active entries in table
	 * 
	 * Indicates how many entries in the CommandMonitorEntries array are
	 * valid and should be processed. Allows partial table population.
	 */
	unsigned short CommandMonitorEntryCount;
	
	/**
	 * @brief Array of command monitoring entries
	 * 
	 * Fixed-size array containing all monitoring entries. Only the first
	 * CommandMonitorEntryCount entries are valid.
	 */
	CommandMonitorEntry_t CommandMonitorEntries[COMMAND_MONITOR_ENTRY_COUNT];
} CommandMonitorEntryTable_t;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Get current spacecraft time in generic format
 *
 * Retrieves the current spacecraft time from cFE Time Services and converts
 * it to a mission-independent generic time format.
 *
 * @param[out] generic_time Pointer to TimeElement_t structure to populate
 *
 * @return void
 *
 * @note Returns immediately if generic_time is NULL
 * @note Time is spacecraft time (not UTC or GPS)
 *
 * @see TimeElement_t
 */
void SPACECOP_GetTime(TimeElement_t* generic_time);

/**
 * @brief Convert command message to STIX IOB identifier
 *
 * Searches the command monitoring table for an entry matching the received
 * command message. Returns the matching entry and indicates whether the
 * message triggers activation or deactivation.
 *
 * @param[in] tbl Pointer to command monitoring table
 * @param[in] MonitorMsgPtr Pointer to received Software Bus message
 * @param[out] ResultType Result of search (ACTIVATE, DEACTIVATE, or ERROR)
 * @param[in,out] offset Starting index for search; updated to next index on match
 *
 * @return CommandMonitorEntry_t* Pointer to matching entry, or NULL if no match
 *
 * @note Only processes entries where Command = 1 (command messages)
 * @note Sets ResultType to ERROR if no match found
 * @note Offset enables finding multiple matches in table
 *
 * @see CommandMonitorEntry_t
 * @see Result_t
 */
CommandMonitorEntry_t* SPACECOP_ConvertCommandToStixId(CommandMonitorEntryTable_t* tbl, 
                                                        CFE_MSG_Message_t* MonitorMsgPtr, 
                                                        Result_t* ResultType, 
                                                        uint8_t* offset);

/**
 * @brief Convert telemetry message to STIX IOB identifier
 *
 * Searches the command monitoring table for an entry matching the received
 * telemetry message. Returns the matching entry (telemetry only supports
 * activation, not deactivation).
 *
 * @param[in] tbl Pointer to command monitoring table
 * @param[in] MonitorMsgPtr Pointer to received Software Bus message
 * @param[out] ResultType Result of search (ACTIVATE or ERROR)
 * @param[in,out] offset Starting index for search; updated to next index on match
 *
 * @return CommandMonitorEntry_t* Pointer to matching entry, or NULL if no match
 *
 * @note Only processes entries where Command = 0 (telemetry messages)
 * @note Sets ResultType to ERROR if no match found
 * @note Offset enables finding multiple matches in table
 * @note Telemetry matches on MID only (no command code)
 *
 * @see CommandMonitorEntry_t
 * @see Result_t
 */
CommandMonitorEntry_t* SPACECOP_ConvertTelemetryToStixId(CommandMonitorEntryTable_t* tbl, 
                                                          CFE_MSG_Message_t* MonitorMsgPtr, 
                                                          Result_t* ResultType, 
                                                          uint8_t* offset);

/*=======================================================================================
** Mission-Specific Includes
** 
** Include mission-specific headers required for time services and other
** cFS interfaces.
**=======================================================================================*/

/**
 * @brief cFE Time Services interface
 * 
 * Provides access to CFE_TIME_GetTime() and time conversion functions
 * used by SPACECOP_GetTime().
 */
#include "cfe_time.h"

#endif /* _SPACECOP_MISSION_SPECIFIC_H_ */