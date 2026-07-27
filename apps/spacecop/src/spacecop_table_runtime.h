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
 * @file spacecop_table_runtime.h
 * @brief Runtime rule evaluation and monitoring engine for SpaceCop IDS
 *
 * This header defines the runtime execution system for SpaceCop's intrusion
 * detection capabilities. It provides:
 * - Rule table initialization and execution
 * - Periodic rule evaluation engine
 * - Command monitoring and interception
 * - Machine learning integration
 * - Trigger-based detection workers
 * - Runtime state management
 *
 * **SpaceCop Runtime Architecture:**
 * The runtime system operates in multiple execution contexts:
 * 
 * 1. **Periodic Evaluation:**
 *    - Rules evaluated on fixed time intervals
 *    - Stateful detection across multiple cycles
 *    - Cooldown periods to prevent alert flooding
 * 
 * 2. **Command Monitoring:**
 *    - Real-time command interception
 *    - Command whitelist enforcement
 *    - Parameter validation
 *    - Execution context tracking
 * 
 * 3. **Trigger Workers:**
 *    - Asynchronous rule evaluation
 *    - Event-driven detection
 *    - Background threat analysis
 * 
 * 4. **ML Integration:**
 *    - Machine learning model inference
 *    - Anomaly detection
 *    - Behavioral analysis
 *
 * **Rule Evaluation Flow:**
 * @code
 * 1. SPACECOP_InitRuleRuntime()          - Initialize runtime state
 * 2. SPACECOP_StartTriggerWorker()       - Start background workers
 * 3. [Periodic]
 *    SPACECOP_ExecutePeriodicRuleTable() - Evaluate time-based rules
 * 4. [On Command]
 *    SPACECOP_ExecuteCommandTableMonitor() - Check command rules
 * 5. [On ML Event]
 *    SPACECOP_ExecuteMLTableMonitor()    - Process ML detections
 * @endcode
 *
 * **Detection Categories:**
 * 
 * - **Signature-Based:** Known attack patterns from rule tables
 * - **Anomaly-Based:** Statistical deviations from normal behavior
 * - **Behavioral:** Temporal patterns and state sequences
 * - **Whitelist:** Enforcement of authorized operations only
 * - **ML-Based:** Neural network and machine learning models
 *
 * **Runtime State Management:**
 * Each rule maintains runtime state including:
 * - Execution timing (ticks_until_due)
 * - Alert suppression (report_cooldown_ticks)
 * - Historical values (StoredValue)
 * - Evaluation results (CallResult)
 *
 * **Thread Safety:**
 * Runtime functions may be called from multiple contexts:
 * - Main application task
 * - Trigger worker child tasks
 * - Command monitoring callbacks
 * - ML inference threads
 * 
 * Synchronization is handled internally by the runtime engine.
 *
 * **Performance Considerations:**
 * - Rule evaluation is time-critical
 * - Minimize allocations in hot paths
 * - Use cooldown periods to reduce overhead
 * - Cache frequently accessed values
 * - Optimize rule ordering (fast-fail first)
 *
 * @note Rule tables must be initialized before execution
 * @note Command monitoring operates in real-time (low latency required)
 * @note ML monitoring may have higher latency
 *
 * @see spacecop_table_defs.h for rule table structure definitions
 * @see spacecop_registry.h for command registry
 * @see functions_command_monitors.h for command tracking
 */

#ifndef SPACECOP_TABLE_RUNTIME_H
#define SPACECOP_TABLE_RUNTIME_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "cfe.h"
#include "spacecop_table_defs.h"
#include "helpers_unpackers.h"
#include "spacecop_registry.h"
#include "helpers_whitelist_funcs.h"
#include "spacecop_ids_helper.h"
#include "spacecop_mission_specific.h"
#include "functions_command_monitors.h"

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief Maximum number of concurrent jobs in the runtime engine
 * 
 * Defines the maximum number of rules that can be scheduled for concurrent
 * evaluation in the runtime system. This limits memory usage and prevents
 * resource exhaustion.
 * 
 * **Usage:**
 * - Job queue sizing
 * - Worker thread allocation
 * - Memory pool sizing
 * 
 * **Considerations:**
 * - Higher values: More concurrent detection, higher memory usage
 * - Lower values: Less concurrency, lower memory usage
 * - Must be >= number of trigger-based rules
 * 
 * @note Increase if you have more than 128 concurrent rules
 * @note Each job consumes memory for runtime state
 */
#define MAX_JOB 128

/**
 * @brief Context identifier for command offender tracking (Version 1)
 * 
 * Unique identifier used to mark the execution context when a command
 * violates detection rules. Used for:
 * - Alert correlation
 * - Forensic analysis
 * - Attack attribution
 * - Event logging
 * 
 * **Version History:**
 * - V1 (1001): Initial implementation
 * 
 * **Usage:**
 * When a command triggers a detection rule, the runtime engine tags
 * the event with this context ID to enable:
 * - Tracking attack progression
 * - Identifying compromised components
 * - Correlating related violations
 * - Generating detailed forensic reports
 * 
 * @note Value chosen to avoid conflicts with other context IDs
 * @note Future versions may use different values
 */
#define CTX_PROC_OFFENDER_V1 1001

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Runtime value container with type information
 * 
 * Provides type-safe storage for values of different types during rule
 * evaluation. The type field indicates which union member is valid.
 * 
 * **Supported Types:**
 * - i32: Signed 32-bit integer (counters, deltas, signed metrics)
 * - u32: Unsigned 32-bit integer (counts, IDs, unsigned metrics)
 * - f32: 32-bit floating point (ratios, percentages, measurements)
 * - str32: 32-character string (identifiers, short messages)
 * 
 * **Usage Example:**
 * @code
 * Value result;
 * result.type = VAL_U32;
 * result.v.u32 = command_count;
 * 
 * // Type-safe access
 * if (result.type == VAL_U32) {
 *     uint32_t count = result.v.u32;
 *     printf("Command count: %u\n", count);
 * }
 * @endcode
 * 
 * **Type Safety:**
 * Always check the type field before accessing union members:
 * @code
 * switch (val.type) {
 *     case VAL_I32:
 *         process_int(val.v.i32);
 *         break;
 *     case VAL_F32:
 *         process_float(val.v.f32);
 *         break;
 *     case VAL_STR32:
 *         process_string(val.v.str32);
 *         break;
 *     default:
 *         // Handle error
 *         break;
 * }
 * @endcode
 * 
 * @note Union size is determined by largest member (str32 = 32 bytes)
 * @note Only one union member should be accessed based on type field
 * @note String values must be null-terminated within STR32_MAX bytes
 * 
 * @see ValType for type enumeration
 */
typedef struct 
{
	ValType type;  /**< Type identifier indicating which union member is valid */
	union {
		int32_t i32;              /**< Signed 32-bit integer value */
		float f32;                /**< 32-bit floating point value */
		char str32[STR32_MAX];    /**< 32-character string value (null-terminated) */
		uint32_t u32;             /**< Unsigned 32-bit integer value */
	} v;  /**< Value union - access member corresponding to type field */
} Value;

/**
 * @brief Trigger-based rule with runtime scheduling state
 * 
 * Extends the base Rule structure with runtime scheduling information
 * for trigger-based (event-driven) detection rules. These rules execute
 * asynchronously in response to events rather than on fixed intervals.
 * 
 * **Trigger Rule Lifecycle:**
 * 1. Rule loaded from table
 * 2. Trigger worker initialized
 * 3. Worker waits for trigger event
 * 4. Event occurs -> ticks_until_due = 0
 * 5. Rule evaluated immediately
 * 6. If triggered: alert generated, cooldown activated
 * 7. Cooldown period prevents alert flooding
 * 8. Worker returns to waiting state
 * 
 * **Scheduling Fields:**
 * 
 * - **ticks_until_due:** Countdown timer for next evaluation
 *   - 0: Evaluate immediately
 *   - >0: Decrement each tick, evaluate when reaches 0
 *   - Used for delayed evaluation after trigger
 * 
 * - **report_cooldown_ticks:** Alert suppression timer
 *   - Prevents repeated alerts for same condition
 *   - Decrements each tick after alert
 *   - New alerts blocked until reaches 0
 *   - Reduces alert fatigue and log flooding
 * 
 * **Example Trigger Rules:**
 * - Command sequence violations
 * - Unauthorized state transitions
 * - Threshold crossings
 * - Timing anomalies
 * - Resource exhaustion
 * 
 * **Usage:**
 * @code
 * TriggerRule trig_rule;
 * trig_rule.rule = rule_from_table;
 * trig_rule.ticks_until_due = 0;  // Evaluate on next cycle
 * trig_rule.report_cooldown_ticks = 100;  // 100 tick cooldown after alert
 * 
 * // In trigger worker loop
 * if (event_occurred) {
 *     trig_rule.ticks_until_due = 0;  // Schedule immediate evaluation
 * }
 * 
 * if (trig_rule.ticks_until_due == 0) {
 *     bool detected = evaluate_rule(&trig_rule.rule);
 *     if (detected && trig_rule.report_cooldown_ticks == 0) {
 *         generate_alert(&trig_rule.rule);
 *         trig_rule.report_cooldown_ticks = 100;  // Activate cooldown
 *     }
 * }
 * @endcode
 * 
 * @note Trigger rules run in separate child tasks
 * @note Cooldown prevents alert storms
 * @note Multiple triggers can share same rule definition
 * 
 * @see Rule for base rule structure
 * @see SPACECOP_StartTriggerWorker for trigger initialization
 */
typedef struct 
{
	uint16_t ticks_until_due;        /**< Ticks remaining until next evaluation (0 = evaluate now) */
	uint16_t report_cooldown_ticks;  /**< Alert suppression countdown (0 = can report) */
	Rule rule;                       /**< Base rule definition and detection logic */
} TriggerRule;

/**
 * @brief Runtime state for periodic rule evaluation
 * 
 * Maintains timing and scheduling state for rules evaluated on fixed
 * periodic intervals. This is a lightweight structure containing only
 * the runtime state, while the rule definition is stored separately.
 * 
 * **Periodic Evaluation:**
 * Periodic rules execute on fixed time intervals (e.g., every 10 seconds)
 * to detect:
 * - Gradual resource depletion
 * - Long-term behavioral anomalies
 * - Statistical deviations over time
 * - Threshold violations
 * 
 * **Scheduling Mechanism:**
 * @code
 * // Initialization
 * RuleRt rt_state;
 * rt_state.ticks_until_due = rule_period;  // e.g., 100 ticks
 * rt_state.report_cooldown_ticks = 0;
 * 
 * // Each tick
 * if (rt_state.ticks_until_due > 0) {
 *     rt_state.ticks_until_due--;
 * }
 * 
 * // Evaluation
 * if (rt_state.ticks_until_due == 0) {
 *     bool detected = evaluate_rule(rule);
 *     rt_state.ticks_until_due = rule_period;  // Reset for next cycle
 *     
 *     if (detected && rt_state.report_cooldown_ticks == 0) {
 *         generate_alert(rule);
 *         rt_state.report_cooldown_ticks = cooldown_period;
 *     }
 * }
 * 
 * // Cooldown management
 * if (rt_state.report_cooldown_ticks > 0) {
 *     rt_state.report_cooldown_ticks--;
 * }
 * @endcode
 * 
 * **Memory Efficiency:**
 * This structure is intentionally minimal (4 bytes) to enable efficient
 * storage of runtime state for large numbers of rules. The full rule
 * definition (which may be large) is stored once in the rule table.
 * 
 * **Cooldown Behavior:**
 * - Prevents alert flooding for persistent conditions
 * - Allows periodic reminders (alert every N cycles)
 * - Reduces log volume and operator fatigue
 * - Configurable per-rule cooldown periods
 * 
 * @note Separate from rule definition for memory efficiency
 * @note One RuleRt instance per periodic rule
 * @note Cooldown is independent of evaluation period
 * 
 * @see TriggerRule for event-driven rules with embedded rule definitions
 * @see SPACECOP_ExecutePeriodicRuleTable for periodic evaluation loop
 */
typedef struct 
{
	uint16_t ticks_until_due;        /**< Countdown to next scheduled evaluation */
	uint16_t report_cooldown_ticks;  /**< Alert suppression countdown */
} RuleRt;

/**
 * @brief Result of rule evaluation with variable-length data
 * 
 * Contains the result of a rule evaluation including any contextual data
 * needed for alert generation or forensic analysis. The variable-length
 * bytes array can contain:
 * - Serialized detection context
 * - Offending command parameters
 * - State snapshots
 * - Evidence data
 * 
 * **Result Structure:**
 * - **len:** Number of valid bytes in the bytes array
 * - **bytes:** Variable-length payload data
 * 
 * **Common Uses:**
 * 
 * 1. **Command Context:**
 *    - Command code that triggered detection
 *    - Parameter values
 *    - Timestamp
 *    - Source identifier
 * 
 * 2. **State Evidence:**
 *    - STIX component values at detection time
 *    - System state snapshot
 *    - Historical values
 * 
 * 3. **Alert Metadata:**
 *    - Severity level
 *    - Confidence score
 *    - Recommended actions
 * 
 * **Usage Example:**
 * @code
 * CallResult result;
 * result.len = 0;
 * 
 * // Serialize detection context
 * memcpy(&result.bytes[result.len], &command_code, sizeof(command_code));
 * result.len += sizeof(command_code);
 * 
 * memcpy(&result.bytes[result.len], &timestamp, sizeof(timestamp));
 * result.len += sizeof(timestamp);
 * 
 * // Use in alert generation
 * if (result.len > 0) {
 *     generate_alert_with_context(&result);
 * }
 * @endcode
 * 
 * **Size Limit:**
 * Maximum payload size is CALL_RULE_MAX bytes. If more data is needed,
 * consider:
 * - Storing full context elsewhere and including reference
 * - Compressing data
 * - Storing only essential information
 * - Using multiple CallResult structures
 * 
 * @note len must be <= CALL_RULE_MAX
 * @note bytes array contains raw binary data (not null-terminated)
 * @note Serialization format is implementation-defined
 * 
 * @see CALL_RULE_MAX for maximum payload size
 * @see StoredValue for persistent value storage
 */
typedef struct 
{
	uint16_t len;              /**< Number of valid bytes in payload */
	uint8_t bytes[CALL_RULE_MAX];  /**< Variable-length result payload */
} CallResult;

/**
 * @brief Persistent value storage with validity tracking
 * 
 * Provides persistent storage for values that need to be retained across
 * rule evaluations. Used for:
 * - Historical value comparison
 * - Trend analysis
 * - State tracking
 * - Baseline establishment
 * 
 * **Validity Flag:**
 * The valid field indicates whether the stored value is initialized and
 * meaningful:
 * - 0: No valid data stored (uninitialized)
 * - 1: Valid data present
 * 
 * This enables detection of:
 * - First-time rule execution
 * - Missing historical data
 * - Reset conditions
 * 
 * **Storage Lifecycle:**
 * @code
 * StoredValue history;
 * history.valid = 0;  // Initially invalid
 * 
 * // First evaluation
 * if (!history.valid) {
 *     // No historical data - establish baseline
 *     serialize_current_state(history.bytes, &history.len);
 *     history.valid = 1;
 *     return NO_DETECTION;  // Can't detect without history
 * }
 * 
 * // Subsequent evaluations
 * if (history.valid) {
 *     // Compare current state to historical
 *     uint32_t old_value = deserialize_value(history.bytes);
 *     uint32_t new_value = get_current_value();
 *     
 *     if (new_value - old_value > threshold) {
 *         // Anomaly detected
 *         generate_alert();
 *     }
 *     
 *     // Update history for next evaluation
 *     serialize_value(history.bytes, &history.len, new_value);
 * }
 * @endcode
 * 
 * **Use Cases:**
 * 
 * 1. **Trend Detection:**
 *    - Store previous value
 *    - Compare to current value
 *    - Detect rapid changes
 * 
 * 2. **Baseline Tracking:**
 *    - Store normal operating values
 *    - Detect deviations from baseline
 *    - Adaptive baseline updates
 * 
 * 3. **State History:**
 *    - Track state transitions
 *    - Detect invalid sequences
 *    - Enforce state machine rules
 * 
 * 4. **Accumulation:**
 *    - Sum values over time
 *    - Detect threshold crossings
 *    - Reset on boundaries
 * 
 * **Memory Considerations:**
 * - Each StoredValue is (3 + CALL_RULE_MAX) bytes
 * - Allocated per rule requiring history
 * - Consider storage limits for large rule sets
 * 
 * **Thread Safety:**
 * If multiple threads access the same StoredValue:
 * - Use atomic operations for valid flag
 * - Protect read-modify-write with mutex
 * - Consider lock-free alternatives for high-frequency access
 * 
 * @note valid should be checked before accessing bytes
 * @note len must be <= CALL_RULE_MAX when valid == 1
 * @note bytes format is implementation-defined
 * 
 * @see CallResult for evaluation results
 * @see CALL_RULE_MAX for maximum storage size
 */
typedef struct 
{
	uint8_t valid;             /**< Validity flag: 0 = invalid, 1 = valid data present */
	uint16_t len;              /**< Number of valid bytes in storage */
	uint8_t bytes[CALL_RULE_MAX];  /**< Persistent value storage buffer */
} StoredValue;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Initialize runtime state for rule table
 * 
 * Initializes all runtime state structures for the given rule table,
 * preparing the detection engine for execution. Must be called before
 * any rule evaluation functions.
 * 
 * **Initialization Steps:**
 * 1. Allocate runtime state arrays
 * 2. Initialize timing counters
 * 3. Clear cooldown timers
 * 4. Reset stored values
 * 5. Validate rule definitions
 * 6. Set up evaluation scheduling
 * 
 * **What Gets Initialized:**
 * - RuleRt structures for each periodic rule
 * - TriggerRule structures for event-driven rules
 * - StoredValue buffers for stateful rules
 * - Scheduling queues
 * - Performance counters
 * 
 * @param[in,out] tbl Pointer to rule table to initialize
 * 
 * @pre tbl must point to valid, loaded rule table
 * @pre Rule table must pass validation
 * @post Runtime state ready for evaluation
 * @post All counters initialized to zero
 * 
 * @note Call once during application initialization
 * @note Safe to call multiple times (reinitializes state)
 * @note Does not modify rule definitions, only runtime state
 * 
 * @warning Reinitializing clears all accumulated state
 * 
 * @see SPACECOP_ExecutePeriodicRuleTable for rule evaluation
 * @see RuleTable for table structure
 */
void SPACECOP_InitRuleRuntime(RuleTable* tbl);

/**
 * @brief Execute all periodic rules in the rule table
 * 
 * Evaluates all periodic (time-based) rules in the table, generating
 * alerts for any detections. Called on a fixed interval (typically
 * 1Hz - 10Hz) to provide continuous monitoring.
 * 
 * **Execution Flow:**
 * 1. Decrement all tick counters
 * 2. For each rule where ticks_until_due == 0:
 *    a. Evaluate rule condition
 *    b. If detected and not in cooldown:
 *       - Generate alert with context
 *       - Activate cooldown period
 *    c. Reset ticks_until_due to rule period
 * 3. Decrement all cooldown counters
 * 4. Update performance metrics
 * 
 * **Rule Evaluation:**
 * Each rule is evaluated against current system state:
 * - STIX component values
 * - Command history
 * - Telemetry data
 * - Stored historical values
 * 
 * **Alert Generation:**
 * When a rule triggers:
 * - IOB identifier included
 * - Detection context serialized
 * - EVS event generated
 * - Alert logged to file
 * - Ground notification sent
 * 
 * **Performance:**
 * - Execution time proportional to number of rules
 * - Fast-fail optimization for rule ordering
 * - Cooldown reduces repeated evaluations
 * - Typical: <10ms for 100 rules on space-grade CPU
 * 
 * @param[in,out] tbl Pointer to rule table with initialized runtime state
 * 
 * @return CFE_SUCCESS on successful execution
 * @return Error code on failure
 * 
 * @pre SPACECOP_InitRuleRuntime() must be called first
 * @pre Rule table must be valid and loaded
 * @post All due rules evaluated
 * @post Alerts generated for detections
 * @post Timers updated for next cycle
 * 
 * @note Call periodically from main application loop
 * @note Execution time varies with number of rules
 * @note Safe to call from multiple tasks with different tables
 * 
 * @warning Do not call faster than minimum rule period
 * 
 * @see SPACECOP_InitRuleRuntime for initialization
 * @see RuleTable for table structure
 */
int32 SPACECOP_ExecutePeriodicRuleTable(RuleTable* tbl);

/**
 * @brief Monitor and validate commands against command monitor table
 * 
 * Real-time command interception and validation function. Examines each
 * command received on the software bus, validates it against the command
 * monitor table, and generates alerts for violations.
 * 
 * **Command Monitoring:**
 * For each intercepted command:
 * 1. Extract command code and parameters
 * 2. Look up command in registry
 * 3. Check against whitelist (if enabled)
 * 4. Validate parameters against constraints
 * 5. Check execution context (authorized source)
 * 6. Evaluate command-specific rules
 * 7. Generate alerts for violations
 * 
 * **Validation Types:**
 * 
 * - **Whitelist:** Command allowed/denied
 * - **Parameter Range:** Values within acceptable bounds
 * - **Sequence:** Valid command ordering
 * - **Rate Limit:** Command frequency constraints
 * - **Context:** Authorized source/destination
 * - **State:** Valid in current system state
 * 
 * **Detection Examples:**
 * - Unauthorized command execution
 * - Parameter out of safe range
 * - Command sent from wrong source
 * - Excessive command rate
 * - Invalid command sequence
 * - Commands in wrong system state
 * 
 * **Integration with STIX:**
 * Command monitoring updates STIX components:
 * - Command execution counts
 * - Parameter values
 * - Timing information
 * - State transitions
 * 
 * These updates feed into periodic rule evaluation.
 * 
 * **Performance:**
 * - Must complete before command execution
 * - Typical latency: <1ms per command
 * - Optimized lookup tables
 * - Minimal allocations
 * 
 * @param[in] tbl Pointer to command monitor entry table
 * @param[in] MonitorMsgPtr Pointer to intercepted command message
 * @param[in] MonitorCmdPipe Pipe ID where command was received
 * 
 * @pre Command monitor table must be initialized
 * @pre MonitorMsgPtr must point to valid CFE message
 * @pre MonitorCmdPipe must be valid pipe ID
 * @post Command validated against rules
 * @post STIX components updated
 * @post Alerts generated for violations
 * 
 * @note Called from command pipe processing loop
 * @note Must be low-latency (command path is critical)
 * @note Does not block command execution
 * 
 * @warning High-frequency commands may impact performance
 * 
 * @see CommandMonitorEntryTable_t for table structure
 * @see spacecop_registry.h for command registry
 * @see functions_command_monitors.h for STIX updates
 */
void SPACECOP_ExecuteCommandTableMonitor(CommandMonitorEntryTable_t* tbl, 
                                          CFE_MSG_Message_t* MonitorMsgPtr, 
                                          CFE_SB_PipeId_t MonitorCmdPipe);

/**
 * @brief Start trigger-based rule evaluation worker task
 * 
 * Spawns a child task to handle trigger-based (event-driven) rule
 * evaluation. Trigger rules execute asynchronously in response to
 * events rather than on fixed intervals.
 * 
 * **Worker Task Operation:**
 * 1. Initialize trigger rule list
 * 2. Enter event wait loop
 * 3. On trigger event:
 *    - Wake up worker
 *    - Evaluate associated rules
 *    - Generate alerts if needed
 *    - Return to waiting
 * 
 * **Trigger Types:**
 * - Command events (specific commands executed)
 * - State transitions (mode changes, app lifecycle)
 * - Threshold crossings (component value exceeds limit)
 * - Time events (specific time reached)
 * - External signals (ground commands, autonomy)
 * 
 * **Advantages of Trigger Workers:**
 * - Immediate response to events (no polling delay)
 * - Lower CPU usage (sleep when no events)
 * - Separate priority from main task
 * - Parallel evaluation of independent rules
 * 
 * **Worker Lifecycle:**
 * @code
 * // Start worker
 * int32 status = SPACECOP_StartTriggerWorker(&rule_table);
 * if (status != CFE_SUCCESS) {
 *     // Handle error
 * }
 * 
 * // Worker runs independently
 * // Main task continues other processing
 * 
 * // Worker automatically terminates when:
 * // - Application exits
 * // - Critical error occurs
 * // - Explicit shutdown requested
 * @endcode
 * 
 * **Task Priority:**
 * Worker task priority should be:
 * - Higher than periodic monitoring (faster response)
 * - Lower than critical flight software (safety)
 * - Configurable based on mission requirements
 * 
 * @param[in] tbl Pointer to rule table containing trigger rules
 * 
 * @return CFE_SUCCESS if worker started successfully
 * @return CFE_ES_ERR_CHILD_TASK_CREATE if task creation failed
 * @return Error code on other failures
 * 
 * @pre Rule table must be initialized
 * @pre Sufficient system resources for child task
 * @post Worker task running and waiting for events
 * @post Trigger rules ready for evaluation
 * 
 * @note Call once during application initialization
 * @note Worker task runs until application terminates
 * @note Multiple workers can run for different rule sets
 * 
 * @warning Worker consumes system resources (task, stack, CPU)
 * @warning Ensure adequate system resources before calling
 * 
 * @see TriggerRule for trigger rule structure
 * @see SPACECOP_InitRuleRuntime for rule initialization
 */
int32 SPACECOP_StartTriggerWorker(RuleTable* tbl);

/**
 * @brief Execute machine learning model monitoring
 * 
 * Processes machine learning inference results and evaluates ML-based
 * detection rules. Integrates neural network and statistical models
 * into the SpaceCop detection framework.
 * 
 * **ML Integration:**
 * 1. Receive inference results from ML pipe
 * 2. Deserialize model outputs
 * 3. Apply threshold logic
 * 4. Evaluate ML-specific rules
 * 5. Generate alerts for anomalies
 * 6. Update STIX components with ML results
 * 
 * **Supported ML Models:**
 * - Anomaly detection (autoencoders, isolation forests)
 * - Behavioral classification (neural networks)
 * - Time series prediction (LSTM, GRU)
 * - Clustering (k-means, DBSCAN)
 * 
 * **ML Detection Flow:**
 * @code
 * 1. Flight software generates telemetry
 * 2. ML inference engine processes data
 * 3. Results published to ML pipe
 * 4. SPACECOP_ExecuteMLTableMonitor() receives results
 * 5. Thresholds applied (e.g., anomaly score > 0.8)
 * 6. Rules evaluated (e.g., sustained anomalies)
 * 7. Alerts generated for significant detections
 * @endcode
 * 
 * **Integration with Other Detection:**
 * ML results can be combined with signature-based detection:
 * - ML provides anomaly score
 * - Signature rules provide context
 * - Combined confidence for alert
 * 
 * **Performance:**
 * - Inference latency depends on model complexity
 * - Monitoring overhead is minimal (<1ms)
 * - Asynchronous processing prevents blocking
 * 
 * @param[in] MLPipe Pipe ID for receiving ML inference results
 * 
 * @pre ML inference engine running and publishing results
 * @pre MLPipe must be valid and subscribed to ML messages
 * @pre ML table initialized
 * @post ML results processed
 * @post Alerts generated for ML detections
 * @post STIX components updated with ML metrics
 * 
 * @note Call periodically or from ML result callback
 * @note May have higher latency than command monitoring
 * @note ML models must be validated before deployment
 * 
 * @warning ML false positive rate may be higher than signatures
 * @warning Ensure ML models are trained on representative data
 * 
 * @see SPACECOP_MLMonitor for ML monitoring task
 */
void SPACECOP_ExecuteMLTableMonitor(CFE_SB_PipeId_t MLPipe);

/**
 * @brief Main machine learning monitoring task
 * 
 * Entry point for the machine learning monitoring child task. Runs
 * continuously, processing ML inference results and evaluating ML-based
 * detection rules.
 * 
 * **Task Operation:**
 * @code
 * void SPACECOP_MLMonitor(void) {
 *     // Initialize ML monitoring
 *     initialize_ml_pipe();
 *     load_ml_models();
 *     
 *     // Main monitoring loop
 *     while (1) {
 *         // Wait for ML inference results
 *         wait_for_ml_message();
 *         
 *         // Process results
 *         SPACECOP_ExecuteMLTableMonitor(ml_pipe);
 *         
 *         // Sleep or wait for next message
 *     }
 * }
 * @endcode
 * 
 * **Task Lifecycle:**
 * 1. Spawned during SpaceCop initialization
 * 2. Initializes ML infrastructure
 * 3. Enters message processing loop
 * 4. Runs until application termination
 * 
 * **Message Processing:**
 * - Receives ML inference results via software bus
 * - Processes results through ML table monitor
 * - Generates alerts for anomalies
 * - Updates performance metrics
 * 
 * **Task Priority:**
 * Should be lower priority than:
 * - Critical flight software
 * - Command monitoring
 * - Safety-critical tasks
 * 
 * Can be same or lower priority than:
 * - Periodic rule evaluation
 * - Telemetry processing
 * - Housekeeping
 * 
 * @pre ML models deployed and initialized
 * @pre ML pipe created and subscribed
 * @pre Sufficient system resources
 * @post ML monitoring active
 * @post Processing ML inference results
 * 
 * @note Runs as separate child task
 * @note Terminates when parent application exits
 * @note May have longer latency than real-time monitoring
 * 
 * @warning ML inference may be computationally expensive
 * @warning Monitor CPU usage and adjust task priority as needed
 * 
 * @see SPACECOP_ExecuteMLTableMonitor for ML processing logic
 */
void SPACECOP_MLMonitor(void);

#endif /* SPACECOP_TABLE_RUNTIME_H */