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
 * @file functions_command_monitors.h
 * @brief Command and telemetry monitoring functions for SpaceCop IDS
 *
 * This header provides data structures and function prototypes for monitoring
 * command execution, tracking telemetry latency, and managing event counters
 * with duration tracking. It supports thread-safe operation and automatic
 * cleanup of expired tracking entries.
 */

#ifndef _SPACECOP_FUNCTION_COMMAND_MONITORS_H_
#define _SPACECOP_FUNCTION_COMMAND_MONITORS_H_

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include <stdlib.h>
#include "spacecop_mission_specific.h"
#include "spacecop_stix_components.h"
#include "spacecop_mission_specific.h"
#include "spacecop_app.h"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Status enumeration for count/duration tracking entries
 */
typedef enum {
    ACTIVE,      /**< Entry is currently active and being tracked */
    INACTIVE     /**< Entry has ended and is awaiting cleanup */
} Status_t;

/**
 * @brief Entry structure for tracking event counts and durations
 *
 * This structure maintains timing information and event counts for a specific
 * STIX component reference. Entries form a linked list for efficient management.
 */
typedef struct CountDurationEntry {
    TimeElement_t CountStartTime;        /**< Time when counting/tracking started */
    TimeElement_t CountEndTime;          /**< Time when entry was set to INACTIVE */
    TimeElement_t LastTriggerTime;       /**< Most recent trigger time for timeout detection */
    int32_t CountTotal;                  /**< Total count of events for this reference */
    StixComponentId_t ReferenceId;       /**< STIX component ID being tracked */
    Status_t Status;                     /**< Current status (ACTIVE or INACTIVE) */
    struct CountDurationEntry* Next;     /**< Pointer to next entry in linked list */
} CountDurationEntry_t;

/**
 * @brief Individual telemetry packet entry for latency tracking
 *
 * Stores metadata about a received telemetry packet including generation time
 * and receipt time for latency calculation.
 */
typedef struct PacketEntry {
    uint32_t PacketGenTime_sec;          /**< Packet generation time (seconds only) */
    CFE_TIME_SysTime_t ReceiptTime;      /**< Time packet was received (full precision) */
    CFE_SB_MsgId_t MsgId;                /**< cFE Software Bus Message ID */
    struct PacketEntry *Next;            /**< Pointer to next packet in list */
} PacketEntry_t;

/**
 * @brief Telemetry tracker for monitoring packet latency
 *
 * Maintains a list of recent packets (up to 2) for a specific message ID
 * to enable latency delta calculations between consecutive packets.
 */
typedef struct TlmTracker {
    CFE_SB_MsgId_t MsgId;                /**< Message ID being tracked */
    StixComponentId_t ReferenceId;       /**< Associated STIX reference ID */
    PacketEntry_t *PacketListHead;       /**< Head of packet list (most recent first) */
    uint32_t PacketCount;                /**< Number of packets stored (max 2) */
    struct TlmTracker *Next;             /**< Pointer to next tracker in list */
} TlmTracker_t;

/**
 * @brief Reporter configuration for IOB (Indicator of Behavior) alerts
 *
 * Controls whether specific IOB types should trigger reports and alerts.
 */
typedef struct {
    int8_t enabled;                      /**< Flag indicating if reporter is enabled */
    char iob[10];                        /**< IOB identifier string (e.g., "SMSR-3") */
} ReportInfo;

/*=======================================================================================
** Count/Duration Tracking Functions
**=======================================================================================*/

/**
 * @brief Start duration tracking for a STIX component
 *
 * Creates a new tracking entry and records the start time. Only one active
 * entry per STIX ID is maintained. If an active entry already exists, the
 * function returns without creating a duplicate.
 *
 * @param[in] reference STIX component ID to track
 *
 * @return void
 *
 * @note Must call SPACECOP_RemoveCountDurationIfInactive() before starting
 *       a new duration for the same reference ID
 *
 * @see SPACECOP_RemoveCountDurationIfInactive()
 * @see spacecop_stix_components.h for available STIX component IDs
 */
void SPACECOP_StartCountDuration(StixComponentId_t reference);

/**
 * @brief Calculate duration and remove inactive tracking entry
 *
 * Calculates the time delta between the start time and end time (or current time
 * if still active), then removes the entry from the tracking list if it is INACTIVE.
 * Active entries are not removed but their current duration is still returned.
 *
 * @param[in] reference STIX component ID to find and remove
 *
 * @return TimeElement_t Duration delta, or zero-initialized struct if not found
 *
 * @note Only removes entries with Status == INACTIVE
 *
 * @see SPACECOP_StartCountDuration()
 * @see SPACECOP_SetEntryInactive()
 */
TimeElement_t SPACECOP_RemoveCountDurationIfInactive(StixComponentId_t reference);

/**
 * @brief Check current duration without removing entry
 *
 * Calculates the current duration for a tracking entry without modifying or
 * removing it from the list. Uses CountEndTime if INACTIVE, or current time
 * if still ACTIVE.
 *
 * @param[in] reference STIX component ID to query
 *
 * @return TimeElement_t Current duration delta, or zero if not found
 *
 * @see SPACECOP_StartCountDuration()
 */
TimeElement_t SPACECOP_CheckCountDuration(StixComponentId_t reference);

/**
 * @brief Mark a tracking entry as inactive
 *
 * Sets the status of the specified entry to INACTIVE and records the current
 * time as the end time. This prepares the entry for removal by
 * SPACECOP_RemoveCountDurationIfInactive().
 *
 * @param[in] reference STIX component ID to mark inactive
 *
 * @return void
 *
 * @see SPACECOP_RemoveCountDurationIfInactive()
 */
void SPACECOP_SetEntryInactive(StixComponentId_t reference);

/*=======================================================================================
** Event Counting Functions
**=======================================================================================*/

/**
 * @brief Increment total event count for a STIX component
 *
 * Increments the event counter for the specified reference ID. Creates a new
 * entry if one doesn't exist. Resets the last trigger time to detect timeouts.
 *
 * @param[in] reference STIX component ID to increment
 *
 * @return void
 *
 * @see SPACECOP_GetCountTotal()
 */
void SPACECOP_StartCountTotal(StixComponentId_t reference);

/**
 * @brief Get total event count for a STIX component
 *
 * Returns the current event count for the specified reference. If more than
 * 60 seconds have elapsed since the last trigger, the count is reset to 0.
 *
 * @param[in] reference STIX component ID to query
 *
 * @return int32_t Current event count, or 0 if not found or timed out
 *
 * @note Timeout period is 60 seconds from last trigger
 *
 * @see SPACECOP_StartCountTotal()
 */
int32_t SPACECOP_GetCountTotal(StixComponentId_t reference);

/**
 * @brief Remove expired counter entries
 *
 * Scans the counter list and removes entries that have not been triggered
 * for more than 120 seconds. Should be called periodically to prevent
 * memory leaks from stale entries.
 *
 * @return void
 *
 * @note Cleanup timeout is 120 seconds
 */
void SPACECOP_CleanupExpiredCounters(void);

/*=======================================================================================
** Telemetry Latency Tracking Functions
**=======================================================================================*/

/**
 * @brief Store a telemetry packet for latency tracking
 *
 * Stores packet metadata (generation time, receipt time) for latency analysis.
 * Maintains up to 2 packets per message ID, automatically removing the oldest
 * when a third packet arrives.
 *
 * @param[in] reference STIX component reference ID
 * @param[in] msgid cFE Software Bus Message ID
 * @param[in] packet Pointer to pointer to packet buffer
 *
 * @return void
 *
 * @note Maximum 2 packets are stored per MsgId (most recent)
 *
 * @see SPACECOP_EvaluateLatency()
 */
void SPACECOP_StorePacket(StixComponentId_t reference, CFE_SB_MsgId_t msgid, CFE_SB_Buffer_t **packet);

/**
 * @brief Calculate latency delta between two most recent packets
 *
 * Computes the absolute difference in latency (receipt time - generation time)
 * between the two most recent packets for the specified reference. Automatically
 * removes the older packet after calculation.
 *
 * @param[in] reference STIX component reference ID
 *
 * @return uint32_t Latency delta in seconds, or 0 if insufficient packets
 *
 * @note Requires at least 2 stored packets to calculate delta
 * @note Older packet is removed after evaluation
 *
 * @see SPACECOP_StorePacket()
 */
uint32_t SPACECOP_EvaluateLatency(StixComponentId_t reference);

/**
 * @brief Remove stale telemetry trackers
 *
 * Removes trackers whose most recent packet is older than 120 seconds.
 * Should be called periodically to free memory from inactive trackers.
 *
 * @return void
 *
 * @note Cleanup timeout is 120 seconds
 */
void SPACECOP_CleanupTrackers(void);

/*=======================================================================================
** IOB Reporting Functions
**=======================================================================================*/

/**
 * @brief Toggle IOB reporter enable/disable state
 *
 * Toggles the enabled flag for the specified IOB reporter. When disabled,
 * the reporter will not generate alerts for that IOB type.
 *
 * @param[in] iob IOB identifier string (e.g., "SMSR-3")
 *
 * @return void
 */
void Toggle_Reporter(const char *iob);

/**
 * @brief Process and report command messages immediately
 *
 * Monitors specific cFE Executive Services commands (app start/stop/restart/reload)
 * and generates IDS alerts if the corresponding reporter is enabled. Writes
 * STIX reports and sends event messages for detected IOBs.
 *
 * @param[in] MonitorMsgPtr Pointer to cFE message to analyze
 *
 * @return void
 *
 * @note Currently monitors CFE_ES_CMD_MID messages with SMSR-3 IOB reporting
 */
void SPACECOP_ReportImmediately(CFE_MSG_Message_t* MonitorMsgPtr);

/**
 * @brief Placeholder for generic thruster command processing
 *
 * Reserved for future implementation of thruster command monitoring.
 *
 * @return void
 */
void SPACECOP_ProcessGenericThrusterCmd(void);

#endif /* _SPACECOP_FUNCTION_COMMAND_MONITORS_H_ */