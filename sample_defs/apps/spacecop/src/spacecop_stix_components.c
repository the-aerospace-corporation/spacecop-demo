// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_stix_components.c
 * @brief STIX component registry and state tracking for SpaceCop IDS
 *
 * This file implements the STIX (Structured Threat Information eXpression)
 * component registry that tracks runtime state for command monitoring and
 * detection rules. It provides:
 * - Global registry of STIX components
 * - Runtime state storage for each component
 * - Type-safe value storage
 * - IOB identifier mapping
 *
 * **STIX Components:**
 * Each component represents a trackable entity in the IDS system:
 * - Propulsion burn duration: Tracks thruster firing time
 * - Time adjustment count: Tracks time manipulation attempts
 * - Telemetry downlink latency: Tracks telemetry delays
 * - State change events: Tracks system state transitions
 *
 * **Component Structure:**
 * Each component contains:
 * - StixId: Numeric identifier (enum)
 * - StixIdString: Human-readable IOB identifier string
 * - Kind: Data type (ARG_U32, ARG_I32, ARG_F32, etc.)
 * - Value: Current tracked value (union)
 *
 * **Usage Pattern:**
 * Components are accessed by StixComponentId_t enum:
 * @code
 * // Get propulsion burn duration component
 * StixComponentValue_t* comp = &StixComponents[propulsion_burn_duration_id];
 * 
 * // Update value
 * comp->Value.u32 = 120;  // 120 seconds
 * 
 * // Check value in rule
 * if (comp->Value.u32 > threshold) {
 *     // Generate alert
 * }
 * @endcode
 *
 * **Thread Safety:**
 * This global array is accessed by multiple child tasks. Callers must ensure
 * appropriate synchronization when reading/writing values.
 *
 * @note Component count must match STIX_COMPONENT_COUNT
 * @note Values are initialized to zero
 * @note Additional components can be added by updating enum and array
 *
 * @see spacecop_stix_components.h for type definitions
 * @see functions_command_monitors.c for component manipulation
 */

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_stix_components.h"

/*=======================================================================================
** Global STIX Component Registry
**=======================================================================================*/

/**
 * @brief Global STIX component registry array
 *
 * Central registry containing all STIX components tracked by SpaceCop.
 * Each entry represents a distinct trackable entity with its current state.
 *
 * **Array Organization:**
 * - Index: StixComponentId_t enum value
 * - Entry: StixComponentValue_t structure with current state
 * - Size: STIX_COMPONENT_COUNT elements
 *
 * **Component Descriptions:**
 *
 * 1. Propulsion Burn Duration (propulsion_burn_duration_id)
 *    - IOB: "PROP-1" (or similar)
 *    - Type: ARG_U32 (unsigned 32-bit integer)
 *    - Tracks: Accumulated thruster firing time in seconds
 *    - Use: Detect excessive propulsion usage
 *    - Rule: Alert if burn duration exceeds safe limits
 *
 * 2. Time Adjustment Count (adjust_time_id)
 *    - IOB: "TMAN-1" (Time Manipulation)
 *    - Type: ARG_U32 (unsigned 32-bit integer)
 *    - Tracks: Number of time adjustment commands
 *    - Use: Detect time manipulation attacks
 *    - Rule: Alert if adjustments exceed threshold
 *
 * 3. Telemetry Downlink Latency (tlm_downlink_id)
 *    - IOB: "TDEL-1" (Telemetry Delay)
 *    - Type: ARG_U32 (unsigned 32-bit integer)
 *    - Tracks: Telemetry transmission delay in seconds
 *    - Use: Detect telemetry suppression or routing attacks
 *    - Rule: Alert if latency exceeds acceptable delay
 *
 * 4. State Change Events (state_change_id)
 *    - IOB: "STCH-1" (State Change)
 *    - Type: ARG_U32 (unsigned 32-bit integer)
 *    - Tracks: System state transition events
 *    - Use: Detect unauthorized state changes
 *    - Rule: Alert on unexpected state transitions
 *
 * **Value Initialization:**
 * All values are initialized to zero via {0} initializer. This ensures:
 * - Numeric values start at 0
 * - Pointers are NULL
 * - Strings are empty
 * - Structures are zeroed
 *
 * **Adding New Components:**
 * To add a new component:
 * 1. Add enum value to StixComponentId_t in header
 * 2. Add string constant for IOB identifier
 * 3. Add entry to this array
 * 4. Increment STIX_COMPONENT_COUNT
 * 5. Implement tracking functions in functions_command_monitors.c
 *
 * **Example Usage:**
 * @code
 * // Access propulsion burn duration
 * StixComponentValue_t* prop_comp = &StixComponents[propulsion_burn_duration_id];
 * 
 * // Update value (from command monitor)
 * prop_comp->Value.u32 += burn_duration_sec;
 * 
 * // Check value (from rule evaluation)
 * if (prop_comp->Value.u32 > MAX_BURN_DURATION) {
 *     char msg[256];
 *     snprintf(msg, sizeof(msg), 
 *             "[SPACECOP] IOB Detected: %s - Burn duration %u exceeds limit",
 *             prop_comp->StixIdString, prop_comp->Value.u32);
 *     SPACECOP_ReportIDSMsg(msg);
 * }
 * @endcode
 *
 * **Thread Safety Considerations:**
 * This array is accessed by:
 * - Main task (initialization)
 * - SCCmdRun task (command monitoring updates)
 * - SCRuleTable task (rule evaluation reads)
 * - Trigger tasks (various updates)
 *
 * Synchronization is handled at the function level in:
 * - functions_command_monitors.c (uses mutexes where needed)
 * - spacecop_table_runtime.c (read-only access during evaluation)
 *
 * @note Array size must match STIX_COMPONENT_COUNT exactly
 * @note Enum values used as array indices - must be sequential
 * @note Values persist for lifetime of application
 * @note No dynamic allocation - fixed-size array
 *
 * @see StixComponentValue_t for structure definition
 * @see StixComponentId_t for component identifiers
 * @see STIX_COMPONENT_COUNT for array size
 * @see functions_command_monitors.c for manipulation functions
 */
StixComponentValue_t StixComponents[STIX_COMPONENT_COUNT] = {
	{
		.StixId = propulsion_burn_duration_id,           /**< Numeric component ID */
		.StixIdString = propulsion_burn_duration_str,    /**< IOB identifier string */
		.Kind = ARG_U32,                                 /**< Value type (unsigned 32-bit) */
		.Value = {0}                                     /**< Initial value (0 seconds) */
	},
	{
		.StixId = adjust_time_id,                        /**< Numeric component ID */
		.StixIdString = adjust_time_str,                 /**< IOB identifier string */
		.Kind = ARG_U32,                                 /**< Value type (unsigned 32-bit) */
		.Value = {0}                                     /**< Initial value (0 adjustments) */
	},
	{
		.StixId = tlm_downlink_id,                       /**< Numeric component ID */
		.StixIdString = tlm_downlink_str,                /**< IOB identifier string */
		.Kind = ARG_U32,                                 /**< Value type (unsigned 32-bit) */
		.Value = {0}                                     /**< Initial value (0 seconds delay) */
	},
	{
		.StixId = state_change_id,                       /**< Numeric component ID */
		.StixIdString = state_change_str,                /**< IOB identifier string */
		.Kind = ARG_U32,                                 /**< Value type (unsigned 32-bit) */
		.Value = {0}                                     /**< Initial value (0 state changes) */
	}
};