// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_typing.h
 * @brief Common type definitions for SpaceCop IDS
 *
 * This header provides fundamental type definitions used throughout the
 * SpaceCop intrusion detection system. It defines common enumerations and
 * types that provide consistent interfaces across modules.
 *
 * **Purpose:**
 * - Standardize return codes across SpaceCop functions
 * - Provide clear semantic meaning for operation results
 * - Enable consistent error handling patterns
 * - Support rule activation/deactivation workflows
 *
 * **Design Philosophy:**
 * SpaceCop uses simple, explicit result types rather than overloading
 * integer return codes. This provides:
 * - Type safety (compiler catches misuse)
 * - Self-documenting code (ACTIVATE vs 1)
 * - Clear success/failure semantics
 * - Easy extension for future states
 *
 * **Usage Patterns:**
 * @code
 * // Function returning operation result
 * Result_t enable_detection_rule(uint32_t rule_id) {
 *     if (rule_id >= MAX_RULES) {
 *         return ERROR;
 *     }
 *     
 *     rule_table[rule_id].enabled = true;
 *     return ACTIVATE;
 * }
 * 
 * // Caller checking result
 * Result_t result = enable_detection_rule(rule_id);
 * switch (result) {
 *     case ACTIVATE:
 *         CFE_EVS_SendEvent(INFO_EID, CFE_EVS_INFORMATION,
 *                          "Rule %u activated successfully", rule_id);
 *         break;
 *     case ERROR:
 *         CFE_EVS_SendEvent(ERR_EID, CFE_EVS_ERROR,
 *                          "Failed to activate rule %u", rule_id);
 *         break;
 *     default:
 *         // Unexpected result
 *         break;
 * }
 * @endcode
 *
 * **Integration:**
 * This header is included by most SpaceCop modules and provides the
 * foundation for consistent type usage across:
 * - Rule management functions
 * - Detection engine operations
 * - Command handlers
 * - Configuration interfaces
 *
 * @note Keep this header minimal - only fundamental types
 * @note Mission-specific types should go in spacecop_mission_specific.h
 *
 * @see spacecop_mission_specific.h for mission-specific type definitions
 */

#ifndef _SPACECOP_TYPING_H_
#define _SPACECOP_TYPING_H_

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_mission_specific.h"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Operation result type for activation/deactivation operations
 * 
 * Enumeration representing the result of operations that activate, deactivate,
 * or modify the state of SpaceCop components. Used throughout the system for
 * consistent result reporting.
 *
 * **Enumeration Values:**
 *
 * - **ACTIVATE:** Operation succeeded and component is now active
 *   - Rule enabled successfully
 *   - Monitor started
 *   - Feature turned on
 *   - Detection engine running
 *   - Resource allocated and ready
 *
 * - **DEACTIVATE:** Operation succeeded and component is now inactive
 *   - Rule disabled successfully
 *   - Monitor stopped
 *   - Feature turned off
 *   - Detection engine paused
 *   - Resource deallocated
 *
 * - **ERROR:** Operation failed
 *   - Invalid parameters
 *   - Resource unavailable
 *   - System in wrong state
 *   - Permission denied
 *   - Internal failure
 *
 * **Common Usage Scenarios:**
 *
 * 1. **Rule Management:**
 *    @code
 *    Result_t toggle_rule(uint32_t rule_id, bool enable) {
 *        if (!validate_rule_id(rule_id)) {
 *            return ERROR;
 *        }
 *        
 *        if (enable) {
 *            rule_table[rule_id].active = true;
 *            return ACTIVATE;
 *        } else {
 *            rule_table[rule_id].active = false;
 *            return DEACTIVATE;
 *        }
 *    }
 *    @endcode
 *
 * 2. **Monitor Control:**
 *    @code
 *    Result_t start_command_monitor(void) {
 *        if (monitor_already_running) {
 *            return ERROR;  // Already active
 *        }
 *        
 *        if (initialize_monitor() != SUCCESS) {
 *            return ERROR;  // Initialization failed
 *        }
 *        
 *        monitor_running = true;
 *        return ACTIVATE;
 *    }
 *    @endcode
 *
 * 3. **Feature Toggles:**
 *    @code
 *    Result_t set_ml_detection(bool enabled) {
 *        if (!ml_models_loaded) {
 *            return ERROR;  // Prerequisites not met
 *        }
 *        
 *        ml_detection_enabled = enabled;
 *        return enabled ? ACTIVATE : DEACTIVATE;
 *    }
 *    @endcode
 *
 * 4. **Command Handlers:**
 *    @code
 *    void SPACECOP_EnableRuleCmd(CFE_SB_Buffer_t *BufPtr) {
 *        SPACECOP_EnableRule_t *cmd = (SPACECOP_EnableRule_t *)BufPtr;
 *        
 *        Result_t result = enable_detection_rule(cmd->RuleId);
 *        
 *        if (result == ACTIVATE) {
 *            SPACECOP_HkTelemetryPkt.CmdCounter++;
 *            CFE_EVS_SendEvent(SPACECOP_ENABLE_RULE_INF_EID, 
 *                             CFE_EVS_INFORMATION,
 *                             "Rule %u enabled", cmd->RuleId);
 *        } else {
 *            SPACECOP_HkTelemetryPkt.ErrCounter++;
 *            CFE_EVS_SendEvent(SPACECOP_ENABLE_RULE_ERR_EID,
 *                             CFE_EVS_ERROR,
 *                             "Failed to enable rule %u", cmd->RuleId);
 *        }
 *    }
 *    @endcode
 *
 * **Error Handling Best Practices:**
 *
 * Always handle all three cases:
 * @code
 * Result_t result = perform_operation();
 * 
 * switch (result) {
 *     case ACTIVATE:
 *         // Handle successful activation
 *         log_activation();
 *         update_telemetry();
 *         break;
 *         
 *     case DEACTIVATE:
 *         // Handle successful deactivation
 *         log_deactivation();
 *         update_telemetry();
 *         break;
 *         
 *     case ERROR:
 *         // Handle error condition
 *         log_error();
 *         increment_error_counter();
 *         notify_ground();
 *         break;
 *         
 *     default:
 *         // Should never happen - log critical error
 *         CFE_EVS_SendEvent(CRITICAL_EID, CFE_EVS_CRITICAL,
 *                          "Invalid Result_t value: %d", result);
 *         break;
 * }
 * @endcode
 *
 * **Comparison with CFE Return Codes:**
 * SpaceCop uses Result_t for internal operations while CFE functions
 * return int32 status codes:
 * @code
 * // CFE function returns int32
 * int32 cfe_status = CFE_TBL_Load(table_handle, ...);
 * if (cfe_status != CFE_SUCCESS) {
 *     return ERROR;  // Convert to Result_t
 * }
 * 
 * // SpaceCop function returns Result_t
 * Result_t sc_result = activate_rule(rule_id);
 * @endcode
 *
 * **Thread Safety:**
 * Result_t is a simple enumeration and can be safely copied between
 * threads. However, the operations that return Result_t may require
 * synchronization depending on what they modify.
 *
 * **Future Extensions:**
 * If additional states are needed, add them to this enumeration:
 * @code
 * typedef enum {
 *     ACTIVATE,
 *     DEACTIVATE,
 *     ERROR,
 *     PENDING,      // Operation in progress
 *     SUSPENDED,    // Temporarily paused
 *     UNAVAILABLE   // Resource not present
 * } Result_t;
 * @endcode
 *
 * @note Values are implicitly assigned (ACTIVATE=0, DEACTIVATE=1, ERROR=2)
 * @note Do not rely on specific numeric values - use enumeration names
 * @note ERROR should always indicate a failure condition
 *
 * @see spacecop_mission_specific.h for mission-specific result types
 */
typedef enum {
	ACTIVATE,    /**< Operation successful - component now active/enabled */
	DEACTIVATE,  /**< Operation successful - component now inactive/disabled */
	ERROR        /**< Operation failed - component state unchanged or unknown */
} Result_t;

#endif /* _SPACECOP_TYPING_H_ */