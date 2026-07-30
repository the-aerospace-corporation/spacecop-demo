// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_registry.h
 * @brief Function registry and dispatch system interface for SpaceCop rule execution
 *
 * This header defines the function registry system that enables dynamic dispatch
 * of detection functions from rule table entries. The registry provides:
 * - Symbolic function name to implementation mapping
 * - Type-safe function invocation interface
 * - Argument and return value specifications
 * - Runtime function lookup by call index
 *
 * **Architecture:**
 * The registry uses a symbol table that maps function identifiers to their
 * implementations. Each function has:
 * - A unique string name (used in rule table definitions)
 * - A unique numeric call index (for fast lookup)
 * - A function pointer to the implementation
 * - Type information for arguments and return values
 * - Metadata about IOB requirements
 *
 * **Function Invocation Model:**
 * 1. Rule table contains function call_index and arguments
 * 2. Rule executor calls FindSym() to locate function
 * 3. Executor validates argument types against expected_args
 * 4. Function is invoked via fn pointer with ArgBlob
 * 5. Return value is validated against ret_type/ret_size
 * 6. Return value is used in rule expression evaluation
 *
 * **Adding New Functions:**
 * To add a new detection function:
 * 1. Implement function with GenericInvokeFn signature
 * 2. Add SymEntry to kSyms table in spacecop_registry.c
 * 3. Assign unique call_index
 * 4. Specify argument and return types
 * 5. Set need_iob flag if IOB identifier required
 * 6. Update rule table to reference new function
 *
 * **Type Safety:**
 * The registry enforces type safety through:
 * - ArgKind: Specifies expected argument type
 * - RetType: Specifies return value type
 * - ret_size: Specifies return value size in bytes
 * - Runtime validation in rule executor
 *
 * @note All registered functions must follow GenericInvokeFn signature
 * @note Call indices must be unique within the registry
 * @note Function implementations should be thread-safe or use locking
 *
 * @see spacecop_registry.c for function implementations
 * @see spacecop_table_runtime.c for rule execution logic
 * @see spacecop_table_defs.h for ArgBlob and type definitions
 */

#ifndef SPACECOP_REGISTRY_H
#define SPACECOP_REGISTRY_H

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "cfe.h"
#include "spacecop_table_defs.h"
#include "spacecop_app.h"

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Generic function invocation signature
 *
 * Standard function signature for all registry-callable functions. Provides
 * a uniform interface for function invocation with type-erased arguments
 * and return values.
 *
 * **Parameter Usage:**
 * - args: Contains function arguments in type-erased form
 *   - args->a: Union containing typed argument value (i32, u32, f32)
 *   - args->iob_id: IOB identifier string (if need_iob = 1)
 * 
 * - ret_buf: Buffer to receive return value
 *   - Must be at least ret_size bytes
 *   - Caller allocates, callee populates
 *   - May be NULL if function returns no value
 * 
 * - ret_buf_len: Size of ret_buf in bytes
 *   - Used to prevent buffer overflow
 *   - Must be >= ret_size from SymEntry
 * 
 * - ret_len: Actual bytes written to ret_buf
 *   - Set by callee to indicate return value size
 *   - May be NULL if function returns no value
 *
 * **Return Value:**
 * - CFE_SUCCESS: Function executed successfully
 * - CFE_ES_BAD_ARGUMENT: Invalid arguments or buffer
 * - Other: Function-specific error codes
 *
 * **Implementation Requirements:**
 * - Validate all pointer parameters
 * - Check ret_buf_len before writing
 * - Set *ret_len to actual bytes written
 * - Return CFE_SUCCESS on success
 * - Use static flags to prevent concurrent execution if needed
 * - Generate IDS alerts via SPACECOP_ReportIDSMsg() if appropriate
 *
 * **Example Implementation:**
 * @code
 * static int32 INVOKE_MyFunction(const ArgBlob* args, 
 *                                uint8_t* ret_buf, 
 *                                uint16_t ret_buf_len, 
 *                                uint16_t* ret_len)
 * {
 *     // Validate parameters
 *     if (!ret_buf || !ret_len) return CFE_ES_BAD_ARGUMENT;
 *     if (ret_buf_len < sizeof(uint32_t)) return CFE_ES_BAD_ARGUMENT;
 *     
 *     // Perform operation
 *     uint32_t result = DoSomething(args->a.u32, args->iob_id);
 *     
 *     // Write return value
 *     memcpy(ret_buf, &result, sizeof(result));
 *     *ret_len = sizeof(result);
 *     
 *     return CFE_SUCCESS;
 * }
 * @endcode
 *
 * @param[in] args Pointer to argument blob containing function parameters
 * @param[out] ret_buf Buffer to receive return value (may be NULL)
 * @param[in] ret_buf_len Size of return buffer in bytes
 * @param[out] ret_len Pointer to receive actual return value size (may be NULL)
 *
 * @return int32 CFE_SUCCESS on success, error code on failure
 *
 * @note Functions with no return value should ignore ret_buf/ret_len
 * @note Functions should validate args pointer before dereferencing
 * @note Thread safety is responsibility of implementation
 *
 * @see ArgBlob in spacecop_table_defs.h
 * @see SymEntry for function metadata
 */
typedef int32 (*GenericInvokeFn)(const ArgBlob* args, 
                                  uint8_t* ret_buf, 
                                  uint16_t ret_buf_len, 
                                  uint16_t* ret_len);

/**
 * @brief Symbol table entry for registered function
 *
 * Describes a registered function including its name, implementation, type
 * information, and invocation requirements. Used by the rule executor to
 * locate and validate function calls.
 *
 * **Field Descriptions:**
 * - name: Human-readable function name used in rule table
 *   - Must be unique within registry
 *   - Used for debugging and rule authoring
 *   - Example: "procmon-cpu-check"
 * 
 * - call_index: Numeric function identifier
 *   - Must be unique within registry
 *   - Used for fast lookup in FindSym()
 *   - Stored in compiled rule table
 * 
 * - fn: Function pointer to implementation
 *   - Must follow GenericInvokeFn signature
 *   - Invoked by rule executor
 *   - NULL indicates reserved/unimplemented function
 * 
 * - ret_type: Return value type
 *   - RT_NONE: Function returns no value (void)
 *   - RT_U32: Returns 32-bit unsigned integer
 *   - RT_I32: Returns 32-bit signed integer
 *   - RT_F32: Returns 32-bit floating point
 * 
 * - ret_size: Return value size in bytes
 *   - Must match ret_type size
 *   - Used to validate ret_buf_len
 *   - 0 for RT_NONE
 * 
 * - expected_args: Argument type specification
 *   - ARG_NONE: Function takes no arguments
 *   - ARG_U32: Takes 32-bit unsigned integer
 *   - ARG_I32: Takes 32-bit signed integer
 *   - ARG_F32: Takes 32-bit floating point
 * 
 * - need_iob: IOB identifier requirement flag
 *   - 0: Function does not use IOB identifier
 *   - 1: Function requires IOB identifier in args->iob_id
 *   - Used for detection functions that generate alerts
 *
 * **Example Entries:**
 * @code
 * // Function with no args, returns U32
 * { .name = "time-controller",
 *   .call_index = 0,
 *   .fn = INVOKE_CFE_TIME_GetTime,
 *   .ret_type = RT_U32,
 *   .ret_size = sizeof(uint32_t),
 *   .expected_args = ARG_NONE,
 *   .need_iob = 0 }
 * 
 * // Function with F32 arg, needs IOB, no return
 * { .name = "procmon-cpu-check",
 *   .call_index = 1,
 *   .fn = INVOKE_PROCMon_CPU_Check,
 *   .ret_type = RT_NONE,
 *   .ret_size = 0,
 *   .expected_args = ARG_F32,
 *   .need_iob = 1 }
 * @endcode
 *
 * **Validation:**
 * The rule executor validates:
 * - Argument type matches expected_args
 * - Return buffer size >= ret_size
 * - IOB identifier present if need_iob = 1
 * - Return value type matches ret_type
 *
 * @note All fields except fn can be used for validation
 * @note name is primarily for debugging/documentation
 * @note call_index is the primary lookup key
 *
 * @see GenericInvokeFn for function signature
 * @see FindSym() for registry lookup
 * @see ArgBlob in spacecop_table_defs.h
 * @see RetType in spacecop_table_defs.h
 * @see ArgKind in spacecop_table_defs.h
 */
typedef struct {
	const char* name;           /**< Function name (for debugging/rules) */
	uint16_t call_index;        /**< Unique numeric identifier */
	GenericInvokeFn fn;         /**< Function pointer to implementation */
	RetType ret_type;           /**< Return value type (RT_NONE, RT_U32, etc.) */
	uint16 ret_size;            /**< Return value size in bytes */
	ArgKind expected_args;      /**< Expected argument type (ARG_NONE, ARG_U32, etc.) */
	uint8_t need_iob;           /**< IOB identifier required flag (0=no, 1=yes) */
} SymEntry;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Find symbol entry by call index
 *
 * Searches the function registry for an entry with the specified call index.
 * Used by the rule executor to locate function implementations during rule
 * evaluation.
 *
 * **Lookup Process:**
 * 1. Linear search through symbol table (kSyms)
 * 2. Compare call_index with each entry
 * 3. Return pointer to matching entry
 * 4. Return NULL if not found
 *
 * **Performance:**
 * - Time complexity: O(n) where n is number of registered functions
 * - Typically n < 20, so linear search is acceptable
 * - For larger registries, consider hash table or binary search
 *
 * **Usage Pattern:**
 * @code
 * // In rule executor
 * const SymEntry* sym = FindSym(rule->call_index);
 * if (sym == NULL) {
 *     // Function not found - invalid rule table
 *     return ERROR;
 * }
 * 
 * // Validate argument type
 * if (sym->expected_args != rule->arg_kind) {
 *     // Type mismatch - invalid rule table
 *     return ERROR;
 * }
 * 
 * // Invoke function
 * int32 status = sym->fn(&args, ret_buf, ret_buf_len, &ret_len);
 * @endcode
 *
 * @param[in] call_index Numeric function identifier from rule table
 *
 * @return const SymEntry* Pointer to symbol entry, or NULL if not found
 * @retval NULL Function with specified call_index not registered
 * @retval non-NULL Pointer to matching symbol entry
 *
 * @note Return value is pointer to static data - do not free
 * @note Return value is const - do not modify
 * @note NULL return indicates invalid rule table or registry
 *
 * @warning Rule table must be validated to ensure all call_index values exist
 * @warning Do not cache result - registry is static and never changes
 *
 * @see SymEntry for symbol entry structure
 * @see spacecop_registry.c for symbol table definition (kSyms)
 */
const SymEntry *FindSym(uint16_t call_index);

#endif /* SPACECOP_REGISTRY_H */