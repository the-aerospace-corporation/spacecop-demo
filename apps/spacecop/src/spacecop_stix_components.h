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
 * @file spacecop_stix_components.h
 * @brief STIX component definitions and registry interface for SpaceCop IDS
 *
 * This header defines the STIX (Structured Threat Information eXpression)
 * component system used by SpaceCop for tracking runtime state of monitored
 * entities. It provides:
 * - Component identifier definitions
 * - Component registry structure
 * - Type-safe value storage
 * - IOB (Indicator of Behavior) string mappings
 *
 * **STIX Component System:**
 * The STIX component system enables SpaceCop to track dynamic state for
 * detection rules. Each component represents a trackable entity such as:
 * - Command execution counts
 * - Duration measurements
 * - Latency metrics
 * - State transition counters
 *
 * **Component Lifecycle:**
 * 1. Component defined with ID and string (this file)
 * 2. Component initialized in StixComponents array (spacecop_stix_components.c)
 * 3. Component updated by command monitors (functions_command_monitors.c)
 * 4. Component read by rule evaluator (spacecop_table_runtime.c)
 * 5. Component used in alert generation (IOB identifier)
 *
 * **IOB Identifier Format:**
 * IOB strings follow the pattern: "category:specific"
 * - propulsion:burn_duration - Propulsion system burn time
 * - time_controller:adjust_time - Time adjustment commands
 * - network-traffic:downlink - Telemetry downlink metrics
 * - state:change - System state transitions
 *
 * **Adding New Components:**
 * To add a new STIX component:
 * 1. Define component ID constant (e.g., #define my_component_id 4)
 * 2. Define IOB string constant (e.g., #define my_component_str "category:name")
 * 3. Add entry to StixComponents array in spacecop_stix_components.c
 * 4. Increment STIX_COMPONENT_COUNT
 * 5. Implement tracking functions in functions_command_monitors.c
 * 6. Add rule entries to rule table
 *
 * @note Component IDs must be sequential starting from 0
 * @note IOB strings must be unique within system
 * @note Component count must match array size
 *
 * @see spacecop_stix_components.c for component initialization
 * @see functions_command_monitors.c for state manipulation
 * @see spacecop_table_runtime.c for rule evaluation
 */

#ifndef _SPACECOP_STIX_COMPONENT_H_
#define _SPACECOP_STIX_COMPONENT_H_

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_table_defs.h"

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief Maximum length of STIX component identifier strings
 * 
 * Defines the maximum length (including null terminator) for IOB identifier
 * strings. Current format "category:specific" requires less than 32 characters.
 * 
 * @note Includes null terminator
 * @note Increase if longer identifiers needed
 */
#define MAX_STIX_COMPONENT_LEN 32

/**
 * @brief Total number of STIX components in registry
 * 
 * Defines the size of the StixComponents array. Must match the actual number
 * of components defined in spacecop_stix_components.c.
 * 
 * **Current Components:**
 * - 0: propulsion_burn_duration_id
 * - 1: adjust_time_id
 * - 2: tlm_downlink_id
 * - 3: state_change_id
 * - 4-9: Reserved for future use
 * 
 * @note Must be updated when adding/removing components
 * @note Array size in .c file must match this value
 */
#define STIX_COMPONENT_COUNT 10

/*=======================================================================================
** Component Identifier Definitions
** 
** Each component has two definitions:
** - Numeric ID: Used as array index for fast access
** - String ID: Used in IOB identifiers and STIX reports
**=======================================================================================*/

/**
 * @brief Propulsion burn duration component ID
 * 
 * Numeric identifier for propulsion burn duration tracking component.
 * Used to access component in StixComponents array.
 */
#define propulsion_burn_duration_id 0

/**
 * @brief Propulsion burn duration IOB string
 * 
 * Human-readable IOB identifier for propulsion burn duration alerts.
 * Format: "propulsion:burn_duration"
 * 
 * **Usage:**
 * - Alert messages
 * - STIX reports
 * - EVS events
 * - Ground system displays
 * 
 * **Detection:**
 * Tracks accumulated thruster firing time. Alerts generated when:
 * - Burn duration exceeds safe limits
 * - Unexpected propulsion activity detected
 * - Thruster usage pattern anomalies
 */
#define propulsion_burn_duration_str "propulsion:burn_duration"

/**
 * @brief Time adjustment command count component ID
 * 
 * Numeric identifier for time adjustment command tracking component.
 * Used to access component in StixComponents array.
 */
#define adjust_time_id 1

/**
 * @brief Time adjustment command count IOB string
 * 
 * Human-readable IOB identifier for time manipulation alerts.
 * Format: "time_controller:adjust_time"
 * 
 * **Usage:**
 * - Alert messages
 * - STIX reports
 * - Time manipulation detection
 * 
 * **Detection:**
 * Tracks number of time adjustment commands. Alerts generated when:
 * - Excessive time adjustments detected
 * - Unauthorized time manipulation attempted
 * - Time synchronization anomalies
 * 
 * **Relevant Commands:**
 * - CFE_TIME_SET_TIME_CC
 * - CFE_TIME_SET_MET_CC
 * - CFE_TIME_ADD_ADJUST_CC
 * - CFE_TIME_SUB_ADJUST_CC
 */
#define adjust_time_str "time_controller:adjust_time"

/**
 * @brief Telemetry downlink latency component ID
 * 
 * Numeric identifier for telemetry downlink latency tracking component.
 * Used to access component in StixComponents array.
 */
#define tlm_downlink_id 2

/**
 * @brief Telemetry downlink latency IOB string
 * 
 * Human-readable IOB identifier for telemetry delay alerts.
 * Format: "network-traffic:downlink"
 * 
 * **Usage:**
 * - Alert messages
 * - STIX reports
 * - Network anomaly detection
 * 
 * **Detection:**
 * Tracks telemetry transmission delays. Alerts generated when:
 * - Downlink latency exceeds threshold
 * - Telemetry suppression detected
 * - Routing attacks suspected
 * - Communication anomalies detected
 * 
 * **Measurement:**
 * Latency calculated as time difference between:
 * - Telemetry generation timestamp
 * - Expected downlink time
 */
#define tlm_downlink_str "network-traffic:downlink"

/**
 * @brief State change event component ID
 * 
 * Numeric identifier for system state change tracking component.
 * Used to access component in StixComponents array.
 */
#define state_change_id 3

/**
 * @brief State change event IOB string
 * 
 * Human-readable IOB identifier for state transition alerts.
 * Format: "state:change"
 * 
 * **Usage:**
 * - Alert messages
 * - STIX reports
 * - State transition monitoring
 * 
 * **Detection:**
 * Tracks system state transitions. Alerts generated when:
 * - Unauthorized state changes detected
 * - Unexpected mode transitions occur
 * - State change patterns anomalous
 * - Critical state entered without authorization
 * 
 * **Monitored States:**
 * - Operational modes (SAFE, NORMAL, etc.)
 * - Application states (INIT, RUN, SHUTDOWN)
 * - Hardware states (ENABLED, DISABLED)
 * - Mission phases
 */
#define state_change_str "state:change"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief STIX component identifier type
 * 
 * Type for component numeric identifiers. Used as index into StixComponents
 * array for fast component access.
 * 
 * **Valid Range:** 0 to (STIX_COMPONENT_COUNT - 1)
 * 
 * **Usage:**
 * @code
 * StixComponentId_t comp_id = propulsion_burn_duration_id;
 * StixComponentValue_t* comp = &StixComponents[comp_id];
 * @endcode
 * 
 * @note Values must be sequential starting from 0
 * @note Used as array index - must be within bounds
 */
typedef unsigned short StixComponentId_t;

/**
 * @brief STIX component IOB identifier string type
 * 
 * Type for fixed-length IOB identifier strings. Provides compile-time
 * size checking for string literals.
 * 
 * **Format:** "category:specific"
 * **Max Length:** MAX_STIX_COMPONENT_LEN (including null terminator)
 * 
 * **Examples:**
 * - "propulsion:burn_duration"
 * - "time_controller:adjust_time"
 * - "network-traffic:downlink"
 * 
 * @note Const qualifier prevents modification
 * @note Fixed size array for predictable memory layout
 */
typedef const char StixIdentifier_t[MAX_STIX_COMPONENT_LEN];

/**
 * @brief STIX component value structure
 * 
 * Contains all information for a single STIX component including its
 * identifier, current value, and type information.
 * 
 * **Structure Fields:**
 * 
 * - StixId: Numeric component identifier
 *   - Used for array indexing
 *   - Fast lookup and access
 *   - Must be unique within registry
 * 
 * - StixIdString: Human-readable IOB identifier
 *   - Used in alert messages
 *   - Used in STIX reports
 *   - Used in ground system displays
 *   - Format: "category:specific"
 * 
 * - Value: Current component value
 *   - Union type for multiple value types
 *   - Members: i32, u32, f32, str64
 *   - Active member determined by Kind field
 * 
 * - Kind: Value type identifier
 *   - ARG_NONE: No value
 *   - ARG_U32: Unsigned 32-bit integer
 *   - ARG_I32: Signed 32-bit integer
 *   - ARG_F32: 32-bit floating point
 *   - ARG_STR64: 64-character string
 *
 * **Usage Example:**
 * @code
 * // Access component
 * StixComponentValue_t* comp = &StixComponents[propulsion_burn_duration_id];
 * 
 * // Read value (based on Kind)
 * if (comp->Kind == ARG_U32) {
 *     uint32_t duration = comp->Value.u32;
 *     printf("Burn duration: %u seconds\n", duration);
 * }
 * 
 * // Update value
 * comp->Value.u32 += additional_burn_time;
 * 
 * // Generate alert with IOB string
 * if (comp->Value.u32 > threshold) {
 *     char msg[256];
 *     snprintf(msg, sizeof(msg), 
 *             "[SPACECOP] IOB Detected: %s - Value %u exceeds threshold",
 *             comp->StixIdString, comp->Value.u32);
 *     SPACECOP_ReportIDSMsg(msg);
 * }
 * @endcode
 *
 * **Type Safety:**
 * The Kind field provides runtime type information for safe value access.
 * Always check Kind before accessing Value union members:
 * @code
 * switch (comp->Kind) {
 *     case ARG_U32:
 *         process_u32(comp->Value.u32);
 *         break;
 *     case ARG_F32:
 *         process_f32(comp->Value.f32);
 *         break;
 *     default:
 *         // Handle error
 *         break;
 * }
 * @endcode
 *
 * **Thread Safety:**
 * Components may be accessed by multiple tasks:
 * - Read access: Generally safe (atomic reads on most platforms)
 * - Write access: Requires synchronization
 * - Read-modify-write: Requires mutex protection
 * 
 * Synchronization provided by functions in functions_command_monitors.c
 *
 * @note StixId and StixIdString are const (immutable)
 * @note Value and Kind can be modified at runtime
 * @note Only one Value union member should be accessed based on Kind
 *
 * @see ArgBlobValue for Value union definition
 * @see ArgKind for Kind enumeration
 * @see StixComponents for global component array
 */
typedef struct {
	const StixComponentId_t StixId;    /**< Numeric component identifier (array index) */
	StixIdentifier_t StixIdString;     /**< IOB identifier string for alerts */
	ArgBlobValue Value;                /**< Current component value (typed union) */
	ArgKind Kind;                      /**< Value type identifier */
} StixComponentValue_t;

/*=======================================================================================
** External Data Declarations
**=======================================================================================*/

/**
 * @brief Global STIX component registry array
 * 
 * External declaration for the global component registry array. The actual
 * array is defined and initialized in spacecop_stix_components.c.
 * 
 * **Array Organization:**
 * - Index: StixComponentId_t value (0 to STIX_COMPONENT_COUNT-1)
 * - Element: StixComponentValue_t structure
 * - Size: STIX_COMPONENT_COUNT elements
 * 
 * **Access Pattern:**
 * @code
 * // Direct access by component ID
 * StixComponentValue_t* prop_comp = &StixComponents[propulsion_burn_duration_id];
 * 
 * // Iteration over all components
 * for (int i = 0; i < STIX_COMPONENT_COUNT; i++) {
 *     StixComponentValue_t* comp = &StixComponents[i];
 *     // Process component
 * }
 * @endcode
 * 
 * **Initialization:**
 * Components are initialized in spacecop_stix_components.c with:
 * - StixId: Component identifier constant
 * - StixIdString: IOB identifier string constant
 * - Kind: Value type (ARG_U32, etc.)
 * - Value: Initial value (typically 0)
 * 
 * **Lifetime:**
 * - Created: During application initialization
 * - Exists: Throughout application lifetime
 * - Destroyed: When application terminates
 * 
 * **Thread Safety:**
 * Multiple tasks may access this array:
 * - Main task: Initialization
 * - SCCmdRun: Command monitoring (write)
 * - SCRuleTable: Rule evaluation (read)
 * - Trigger tasks: Various updates (read/write)
 * 
 * Synchronization is responsibility of accessor functions in
 * functions_command_monitors.c
 * 
 * @note Array is global - visible to all source files
 * @note Defined in spacecop_stix_components.c
 * @note Size must match STIX_COMPONENT_COUNT
 * @note Component IDs used as array indices must be valid
 * 
 * @see spacecop_stix_components.c for array definition
 * @see StixComponentValue_t for element structure
 * @see STIX_COMPONENT_COUNT for array size
 */
extern StixComponentValue_t StixComponents[STIX_COMPONENT_COUNT];

#endif /* _SPACECOP_STIX_COMPONENT_H_ */