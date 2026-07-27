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
 * @file spacecop_invoke_defs.h
 * @brief Core type definitions for SpaceCop rule table and expression evaluation
 *
 * This header defines the fundamental data structures and types used by the
 * SpaceCop rule execution engine. It provides:
 * - Rule table structure definitions
 * - Expression evaluation types (operands, operators, literals)
 * - Function invocation argument and return types
 * - Rule execution mode specifications
 * - Value type system for type-safe expression evaluation
 *
 * **Architecture Overview:**
 * The rule system uses a Lisp-like expression evaluation model where:
 * - Rules contain expressions with left-hand side (LHS) and right-hand side (RHS)
 * - LHS typically calls a detection function (e.g., CPU usage check)
 * - RHS is a literal value or another function call
 * - Operator compares LHS and RHS (>, <, ==, !=, etc.)
 * - Tolerance value provides threshold for fuzzy comparisons
 *
 * **Rule Execution Modes:**
 * - RULE_PERIODIC: Execute at fixed intervals (period_ticks)
 * - RULE_ON_COMMAND: Execute when specific command received
 * - RULE_TRIGGER: Execute when trigger condition met
 * - RULE_ONEANDDONE: Execute once and disable
 * - RULE_ML: Machine learning integration rule
 *
 * **Type System:**
 * The system uses a tagged union approach for type safety:
 * - ValType: Identifies the type of a value
 * - Union: Contains the actual value in appropriate type
 * - Runtime validation ensures type consistency
 *
 * **Example Rule Expression:**
 * @code
 * // Alert if CPU usage > 80.0%
 * (> (procmon-cpu-check 80.0) 0)
 * 
 * // LHS: Call procmon-cpu-check with arg 80.0
 * // Operator: > (greater than)
 * // RHS: Literal 0
 * @endcode
 *
 * @note All structures are designed for table file serialization
 * @note Fixed-size arrays used for predictable memory layout
 * @note Type safety enforced at runtime during rule evaluation
 *
 * @see spacecop_table_runtime.c for rule execution logic
 * @see spacecop_registry.c for function implementations
 */

#ifndef SPACECOP_INVOKE_DEFS_H
#define SPACECOP_INVOKE_DEFS_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "cfe.h"
#include <stdint.h>

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief Maximum length of 64-character strings
 * 
 * Used for string arguments and return values in function calls.
 * Includes null terminator.
 */
#define STR64_MAX 64

/**
 * @brief Maximum length of 32-character strings
 * 
 * Used for shorter string values in expressions.
 * Includes null terminator.
 */
#define STR32_MAX 32

/**
 * @brief Maximum length of IOB identifier strings
 * 
 * IOB (Indicator of Behavior) identifiers are short strings like "UACC-1".
 * Includes null terminator.
 */
#define IOB_MAX 10

/**
 * @brief Maximum number of function calls in a single rule
 * 
 * Limits complexity of rule expressions. Typical rules use 1-3 calls.
 */
#define CALL_MAX 32

/**
 * @brief Maximum number of rules in rule table
 * 
 * Total capacity of the rule table. Each rule occupies one slot.
 */
#define CALL_RULE_MAX 256

/**
 * @brief Maximum number of rule tables
 * 
 * Reserved for future multi-table support. Currently only one table used.
 */
#define CALL_TABLE_MAX 16

/*=======================================================================================
** Argument Type Definitions
**=======================================================================================*/

/**
 * @brief Argument kind bitmask type
 * 
 * Used for functions that accept multiple argument types.
 * Each bit represents a different ArgKind.
 */
typedef uint32_t ArgKindMask;

/**
 * @brief Argument value union
 * 
 * Tagged union containing the actual argument value in one of several types.
 * The active member is determined by the ArgKind field in the containing
 * structure.
 *
 * **Type Members:**
 * - i32: 32-bit signed integer (-2,147,483,648 to 2,147,483,647)
 * - f32: 32-bit IEEE 754 floating point
 * - str64: 64-character null-terminated string
 * - u32: 32-bit unsigned integer (0 to 4,294,967,295)
 *
 * **Usage:**
 * @code
 * ArgBlobValue val;
 * val.f32 = 80.5;  // For ARG_F32
 * val.u32 = 100;   // For ARG_U32
 * val.i32 = -42;   // For ARG_I32
 * strncpy(val.str64, "test", STR64_MAX);  // For ARG_STR64
 * @endcode
 *
 * @note Only one member should be accessed based on ArgKind
 * @note str64 may be replaced with pointer in future for efficiency
 */
typedef union
{
	int32_t i32;            /**< Signed 32-bit integer value */
	float f32;              /**< 32-bit floating point value */
	char str64[STR64_MAX];  /**< 64-character string value */
	uint32_t u32;           /**< Unsigned 32-bit integer value */
} ArgBlobValue;

/**
 * @brief Argument kind enumeration
 * 
 * Identifies the type of argument passed to a function. Used for runtime
 * type validation and correct union member access.
 *
 * **Bit Flags:**
 * Each value is a bit flag to support future multi-type arguments.
 * - ARG_NONE: No argument (bit 0)
 * - ARG_F32: Float argument (bit 1)
 * - ARG_STR64: String argument (bit 2)
 * - ARG_U32: Unsigned int argument (bit 3)
 *
 * **Usage in Function Registry:**
 * @code
 * SymEntry entry = {
 *     .expected_args = ARG_F32,  // Function expects float
 *     ...
 * };
 * @endcode
 *
 * @note Bit flag design allows future OR combinations (e.g., ARG_F32|ARG_U32)
 * @note ARG_I32 not currently defined but could be added
 */
typedef enum 
{ 
	ARG_NONE = 0,        /**< No argument required */
	ARG_F32 = 1u << 1,   /**< 32-bit float argument */
	ARG_STR64 = 1u << 2, /**< 64-char string argument */
	ARG_U32 = 1u << 3    /**< 32-bit unsigned int argument */
} ArgKind;

/**
 * @brief Argument blob for function invocation
 * 
 * Contains all information needed to invoke a registered function:
 * - IOB identifier for alert generation
 * - Typed argument value
 *
 * **Structure Layout:**
 * @code
 * ArgBlob {
 *     iob_id: "UACC-1"     // For alert correlation
 *     a: {                 // Argument value
 *         f32: 80.5        // Active member determined by ArgKind
 *     }
 * }
 * @endcode
 *
 * **Usage in Function Calls:**
 * @code
 * ArgBlob args;
 * strncpy(args.iob_id, "CPUH-1", IOB_MAX);
 * args.a.f32 = 80.0;
 * 
 * const SymEntry* sym = FindSym(call_index);
 * sym->fn(&args, ret_buf, ret_buf_len, &ret_len);
 * @endcode
 *
 * @note iob_id may be empty string if function doesn't need IOB
 * @note Only one member of 'a' union should be accessed
 */
typedef struct 
{
	char iob_id[IOB_MAX];  /**< IOB identifier for alerts (e.g., "UACC-1") */
	ArgBlobValue a;        /**< Argument value in appropriate type */
} ArgBlob;

/*=======================================================================================
** Expression Evaluation Types
**=======================================================================================*/

/**
 * @brief Source kind for operand values
 * 
 * Identifies where an operand value comes from in a rule expression.
 * Determines how the operand is evaluated during rule execution.
 *
 * **Source Types:**
 * - SRC_CALL_NEW: Result of current function call (LHS)
 * - SRC_CALL_OLD: Result of previous function call (cached)
 * - SRC_LIT: Literal constant value
 * - SRC_EVENT: Value from event/message
 * - SRC_TOL: Tolerance value for comparison
 *
 * **Typical Usage:**
 * @code
 * // (> (cpu-check) 80)
 * // LHS: SRC_CALL_NEW - call cpu-check
 * // RHS: SRC_LIT - literal value 80
 * @endcode
 *
 * @note SRC_CALL_OLD enables caching for expensive operations
 * @note SRC_TOL used for fuzzy comparisons with threshold
 */
typedef enum 
{ 
	SRC_CALL_NEW = 0, /**< Result of new function call */
	SRC_CALL_OLD,     /**< Result of previous/cached call */
	SRC_LIT,          /**< Literal constant value */
	SRC_EVENT,        /**< Value from event/message */
	SRC_TOL           /**< Tolerance threshold value */
} ScrKind;

/**
 * @brief Value type enumeration
 * 
 * Identifies the type of a value in an expression. Used for type checking
 * and correct interpretation of union members.
 *
 * **Supported Types:**
 * - VT_I32: 32-bit signed integer
 * - VT_F32: 32-bit floating point
 * - VT_STR64: 64-character string
 * - VT_STR32: 32-character string
 * - VT_U32: 32-bit unsigned integer
 * - VT_I8: 8-bit signed integer
 *
 * **Type Coercion:**
 * The rule evaluator may perform automatic type coercion:
 * - Integer to float: Safe, no precision loss for small values
 * - Float to integer: Truncates, may lose precision
 * - String comparisons: Lexicographic ordering
 *
 * @note VT_STR32 and VT_STR64 are distinct for size optimization
 * @note VT_I8 used for boolean-like values (0/1)
 */
typedef enum 
{ 
	VT_I32 = 0, /**< 32-bit signed integer */
	VT_F32,     /**< 32-bit floating point */
	VT_STR64,   /**< 64-character string */
	VT_STR32,   /**< 32-character string */
	VT_U32,     /**< 32-bit unsigned integer */
	VT_I8       /**< 8-bit signed integer */
} ValType;

/**
 * @brief Literal constant value
 * 
 * Represents a compile-time constant value in a rule expression.
 * Used for RHS operands and tolerance values.
 *
 * **Structure:**
 * - type: Identifies which union member is active
 * - v: Union containing the actual value
 *
 * **Example:**
 * @code
 * Literal lit = {
 *     .type = VT_F32,
 *     .v.f32 = 80.5
 * };
 * @endcode
 *
 * @note Only types with union members are supported (I32, F32, U32)
 * @note String literals not currently supported
 */
typedef struct 
{
	ValType type;  /**< Type of literal value */
	union
	{
		int32_t i32;   /**< Signed integer value */
		float f32;     /**< Floating point value */
		uint32_t u32;  /**< Unsigned integer value */
	} v;           /**< Literal value union */
} Literal;

/**
 * @brief Expression operand descriptor
 * 
 * Describes an operand in a rule expression (LHS or RHS).
 * Contains information about where the value comes from and its type.
 *
 * **Fields:**
 * - kind: Source of operand value (function call, literal, etc.)
 * - type: Data type of operand value
 *
 * **Usage in Rule:**
 * @code
 * Rule rule = {
 *     .lhs = { .kind = SRC_CALL_NEW, .type = VT_F32 },  // Function returns float
 *     .rhs = { .kind = SRC_LIT, .type = VT_F32 }        // Compare to float literal
 * };
 * @endcode
 *
 * @note Type must be compatible with operator
 * @note Rule evaluator validates type consistency
 */
typedef struct 
{
	ScrKind kind;  /**< Source of operand value */
	ValType type;  /**< Type of operand value */
} Operand;

/**
 * @brief Comparison operator enumeration
 * 
 * Defines the comparison operators available in rule expressions.
 * Each operator compares LHS and RHS operands.
 *
 * **Operators:**
 * - OP_NEQ: Not equal (!=)
 * - OP_ABS_DIFF_GT: Absolute difference greater than (|LHS - RHS| > TOL)
 * - OP_EQ: Equal (==)
 * - OP_NOT_IN_LIST: Not in list (for set membership)
 * - OP_GT: Greater than (>)
 *
 * **Example Usage:**
 * @code
 * // (> (cpu-usage) 80.0)
 * rule.op = OP_GT;
 * 
 * // (= (mode) "SAFE")
 * rule.op = OP_EQ;
 * 
 * // Fuzzy comparison with tolerance
 * rule.op = OP_ABS_DIFF_GT;
 * rule.tol.v.f32 = 0.1;  // Alert if |actual - expected| > 0.1
 * @endcode
 *
 * @note OP_ABS_DIFF_GT requires tolerance value
 * @note OP_NOT_IN_LIST not fully implemented yet
 * @note Additional operators can be added (OP_LT, OP_GTE, etc.)
 */
typedef enum
{
	OP_NEQ = 0,        /**< Not equal (!=) */
	OP_ABS_DIFF_GT,    /**< Absolute difference > tolerance */
	OP_EQ,             /**< Equal (==) */
	OP_NOT_IN_LIST,    /**< Not in set (membership test) */
	OP_GT              /**< Greater than (>) */
} Operator;

/*=======================================================================================
** Rule Execution Mode Definitions
**=======================================================================================*/

/**
 * @brief Rule execution mode enumeration
 * 
 * Defines when and how a rule should be executed. Different modes support
 * different detection strategies.
 *
 * **Execution Modes:**
 * 
 * - RULE_PERIODIC: Execute at fixed intervals
 *   - Controlled by period_ticks field
 *   - Example: Check CPU every 10 seconds
 *   - Use for: Resource monitoring, periodic scans
 * 
 * - RULE_ON_COMMAND: Execute when specific command received
 *   - Triggered by cmd_mid and cmd_code
 *   - Example: Check propulsion after thruster fire command
 *   - Use for: Command validation, state-based detection
 * 
 * - RULE_TRIGGER: Execute when trigger condition met
 *   - Activated/deactivated by other rules or commands
 *   - Example: Monitor mode after mode change command
 *   - Use for: State-dependent monitoring
 * 
 * - RULE_ONEANDDONE: Execute once and disable
 *   - Runs on first evaluation, then disables itself
 *   - Example: Initialization checks, one-time validation
 *   - Use for: Startup validation, one-time scans
 * 
 * - RULE_ML: Machine learning integration
 *   - Forwards data to ML models for analysis
 *   - Example: Send telemetry to anomaly detector
 *   - Use for: ML-based anomaly detection
 *
 * **Mode Selection Guidelines:**
 * - High-frequency checks: RULE_PERIODIC with short period
 * - Command validation: RULE_ON_COMMAND
 * - State-based: RULE_TRIGGER
 * - Expensive operations: RULE_ONEANDDONE or long period
 * - Anomaly detection: RULE_ML
 *
 * @note Multiple rules can have same mode
 * @note Mode can be changed via table update
 */
typedef enum
{
	RULE_PERIODIC = 1,  /**< Execute at fixed interval (period_ticks) */
	RULE_ON_COMMAND,    /**< Execute when command received (cmd_mid/cmd_code) */
	RULE_TRIGGER,       /**< Execute when triggered by condition */
	RULE_ONEANDDONE,    /**< Execute once and disable */
	RULE_ML             /**< Machine learning integration mode */
} RuleMode;

/**
 * @brief Return type enumeration for function calls
 * 
 * Specifies the type of value returned by a registered function.
 * Used for type validation and correct interpretation of return buffer.
 *
 * **Return Types:**
 * - RT_RAW: Raw bytes (no interpretation)
 * - RT_I32: 32-bit signed integer
 * - RT_U32: 32-bit unsigned integer
 * - RT_F32: 32-bit floating point
 * - RT_F64: 64-bit floating point (double)
 * - RT_SYSTIME: cFE system time structure
 * - RT_STR64: 64-character string
 *
 * **Type Validation:**
 * The rule evaluator validates:
 * - Return buffer size matches ret_size
 * - Return type compatible with operand type
 * - Type coercion rules are followed
 *
 * **Example:**
 * @code
 * SymEntry entry = {
 *     .ret_type = RT_F32,
 *     .ret_size = sizeof(float),
 *     ...
 * };
 * @endcode
 *
 * @note RT_SYSTIME requires special handling for time comparisons
 * @note RT_RAW should be avoided unless necessary
 */
typedef enum {
	RT_RAW = 0,  /**< Raw bytes (uninterpreted) */
	RT_I32,      /**< 32-bit signed integer */
	RT_U32,      /**< 32-bit unsigned integer */
	RT_F32,      /**< 32-bit floating point */
	RT_F64,      /**< 64-bit floating point */
	RT_SYSTIME,  /**< cFE system time structure */
	RT_STR64     /**< 64-character string */
} RetType;

/*=======================================================================================
** Rule Table Definitions
**=======================================================================================*/

/**
 * @brief Rule table entry
 * 
 * Defines a single detection rule including execution conditions, function
 * call, and expression evaluation criteria.
 *
 * **Rule Structure:**
 * A rule consists of:
 * 1. Execution control: When to run (mode, period, command trigger)
 * 2. Function call: What to check (call_index)
 * 3. Expression: How to evaluate (lhs op rhs)
 * 4. Alert: What to report (iob_id)
 *
 * **Field Descriptions:**
 * 
 * - enabled: Rule activation flag
 *   - 0: Rule disabled (skipped during evaluation)
 *   - 1: Rule enabled (evaluated according to mode)
 * 
 * - iob_id: IOB identifier for alerts
 *   - Example: "CPUH-1", "UACC-2"
 *   - Used in alert messages and STIX reports
 * 
 * - call_index: Function to invoke
 *   - Lookup key for FindSym()
 *   - Must exist in function registry
 * 
 * - mode: Execution mode (RULE_PERIODIC, etc.)
 *   - Determines when rule is evaluated
 * 
 * - period_ticks: Period for RULE_PERIODIC mode
 *   - Number of scheduler ticks between executions
 *   - 0 = every tick, 10 = every 10 ticks
 * 
 * - cmd_any: Match any command code flag
 *   - 0: Match specific cmd_code
 *   - 1: Match any command with cmd_mid
 * 
 * - cmd_mid: Message ID for RULE_ON_COMMAND mode
 *   - Software Bus Message ID to trigger on
 *   - Example: CFE_ES_CMD_MID
 * 
 * - cmd_code: Command code for RULE_ON_COMMAND mode
 *   - Function code within message
 *   - Ignored if cmd_any = 1
 * 
 * - lhs: Left-hand side operand
 *   - Typically result of function call
 *   - Type must be compatible with operator
 * 
 * - op: Comparison operator
 *   - OP_GT, OP_EQ, OP_NEQ, etc.
 *   - Determines how LHS and RHS are compared
 * 
 * - rhs: Right-hand side operand
 *   - Typically literal value
 *   - Type must be compatible with LHS and operator
 * 
 * - tol: Tolerance for fuzzy comparisons
 *   - Used with OP_ABS_DIFF_GT
 *   - Provides threshold for alerting
 *
 * **Example Rules:**
 * @code
 * // Periodic CPU check: Alert if CPU > 80%
 * Rule cpu_rule = {
 *     .enabled = 1,
 *     .iob_id = "CPUH-1",
 *     .call_index = 1,  // procmon-cpu-check
 *     .mode = RULE_PERIODIC,
 *     .period_ticks = 10,
 *     .lhs = { .kind = SRC_CALL_NEW, .type = VT_F32 },
 *     .op = OP_GT,
 *     .rhs = { .kind = SRC_LIT, .type = VT_F32 },
 *     .tol = { .type = VT_F32, .v.f32 = 80.0 }
 * };
 * 
 * // Command-triggered: Alert on unauthorized app start
 * Rule app_start_rule = {
 *     .enabled = 1,
 *     .iob_id = "UACC-1",
 *     .call_index = 14,  // state-change
 *     .mode = RULE_ON_COMMAND,
 *     .cmd_mid = CFE_ES_CMD_MID,
 *     .cmd_code = CFE_ES_START_APP_CC,
 *     .cmd_any = 0,
 *     .lhs = { .kind = SRC_EVENT, .type = VT_U32 },
 *     .op = OP_GT,
 *     .rhs = { .kind = SRC_LIT, .type = VT_U32 },
 *     .tol = { .type = VT_U32, .v.u32 = 0 }
 * };
 * @endcode
 *
 * @note All fields must be initialized in table file
 * @note Unused fields should be set to 0 or empty
 * @note Rule validation performed at load time
 *
 * @see RuleMode for execution mode details
 * @see Operator for comparison operator details
 * @see spacecop_table_runtime.c for rule execution logic
 */
typedef struct 
{
	uint8_t enabled;          /**< Rule enabled flag (0=disabled, 1=enabled) */

	char iob_id[IOB_MAX];     /**< IOB identifier for alerts */

	uint16_t call_index;      /**< Function registry lookup index */

	RuleMode mode;            /**< Rule execution mode */
	uint8_t period_ticks;     /**< Period for RULE_PERIODIC (in ticks) */

	uint8_t cmd_any;          /**< Match any command code flag */
	uint16_t cmd_mid;         /**< Command Message ID for RULE_ON_COMMAND */
	uint8_t cmd_code;         /**< Command code for RULE_ON_COMMAND */

	Operand lhs;              /**< Left-hand side operand */
	Operator op;              /**< Comparison operator */
	Operand rhs;              /**< Right-hand side operand */
	Literal tol;              /**< Tolerance value for fuzzy comparisons */
} Rule;

/**
 * @brief Rule table structure
 * 
 * Contains the complete set of detection rules for SpaceCop.
 * Loaded from table file at startup.
 *
 * **Table Layout:**
 * - num_rules: Number of active rules in table
 * - rules: Fixed-size array of rule entries
 *
 * **Table Management:**
 * - Loaded from /cf/spacecop_rule.tbl
 * - Registered with cFE Table Services
 * - Can be updated via table update commands
 * - Validated at load time
 *
 * **Usage:**
 * @code
 * RuleTable* table;
 * CFE_TBL_GetAddress((void*)&table, table_handle);
 * 
 * for (int i = 0; i < table->num_rules; i++) {
 *     if (table->rules[i].enabled) {
 *         // Evaluate rule
 *     }
 * }
 * @endcode
 *
 * @note num_rules must be <= CALL_RULE_MAX
 * @note Unused rule slots should have enabled = 0
 * @note Table updates require validation
 *
 * @see Rule for individual rule structure
 * @see SPACECOP_AppInit() for table loading
 * @see spacecop_table_runtime.c for rule execution
 */
typedef struct 
{
	uint16_t num_rules;            /**< Number of active rules in table */
	Rule rules[CALL_RULE_MAX];     /**< Array of rule entries */
} RuleTable;

#endif /* SPACECOP_INVOKE_DEFS_H */