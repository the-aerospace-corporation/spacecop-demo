// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_table_runtime.c
 * @brief Rule table execution engine for SpaceCop IDS
 *
 * This file implements the core rule execution engine that evaluates detection
 * rules from the rule table. It provides:
 * - Rule expression evaluation (LHS operator RHS)
 * - Periodic rule execution scheduling
 * - Command-triggered rule execution
 * - Trigger-based rule execution via child tasks
 * - One-time rule execution
 * - Machine learning integration
 * - Result caching for multi-rule optimization
 *
 * **Execution Model:**
 * The engine supports multiple execution modes:
 * 
 * 1. RULE_PERIODIC: Time-based execution
 *    - Rules execute at fixed intervals (period_ticks)
 *    - Scheduler tracks time until next execution
 *    - Multiple rules can share function call results (caching)
 * 
 * 2. RULE_ON_COMMAND: Event-driven execution
 *    - Rules execute when specific commands received
 *    - Monitors Software Bus for trigger messages
 *    - Supports activation/deactivation patterns
 * 
 * 3. RULE_TRIGGER: Continuous background execution
 *    - Rules execute in dedicated child tasks
 *    - Run continuously at specified intervals
 *    - Used for expensive operations (file scans, etc.)
 * 
 * 4. RULE_ONEANDDONE: Single execution
 *    - Rules execute once at startup
 *    - Used for initialization checks
 * 
 * 5. RULE_ML: Machine learning integration
 *    - Forwards telemetry to ML models
 *    - Receives and processes ML alerts
 *
 * **Expression Evaluation:**
 * Rules contain expressions of the form: LHS operator RHS
 * - LHS: Typically result of function call
 * - Operator: Comparison (>, ==, !=, etc.)
 * - RHS: Literal value or another function call
 * - Result: Boolean (true = alert, false = no alert)
 *
 * **Optimization:**
 * The engine optimizes execution through:
 * - Call result caching (SRC_CALL_OLD)
 * - Batch function execution (call_mask)
 * - Adaptive tick scheduling (SMALLEST_TICK_COUNT)
 * - Child task parallelization
 *
 * **Alert Generation:**
 * When a rule evaluates to true:
 * - IDS message sent via SPACECOP_ReportIDSMsg()
 * - STIX report generated via write_to_stix()
 * - EVS error event sent
 * - Alert includes IOB identifier
 *
 * @note This is performance-critical code
 * @note Careful with memory allocations in hot paths
 * @note Child tasks run indefinitely until app shutdown
 *
 * @see spacecop_table_defs.h for data structure definitions
 * @see spacecop_registry.c for function implementations
 */

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_table_runtime.h"

/*=======================================================================================
** File-Scope Global Variables
**=======================================================================================*/

/**
 * @brief Cached function call results from previous execution
 * 
 * Stores results of function calls for use in subsequent rule evaluations.
 * Enables SRC_CALL_OLD operand type for referencing previous values.
 * 
 * Array index corresponds to rule index in rule table.
 */
static StoredValue g_prev[CALL_RULE_MAX] = {0};

/**
 * @brief Runtime state for each rule
 * 
 * Tracks execution state for periodic rules including:
 * - ticks_until_due: Countdown to next execution
 * - last_result: Previous evaluation result
 * 
 * Array index corresponds to rule index in rule table.
 */
static RuleRt g_rule_rt[CALL_RULE_MAX];

/**
 * @brief Trigger rules for child task execution
 * 
 * Contains rules that execute continuously in dedicated child tasks.
 * Each entry represents a RULE_TRIGGER mode rule.
 */
static TriggerRule g_trigger_rules[CALL_RULE_MAX];

/**
 * @brief Number of trigger rules (child tasks)
 * 
 * Count of rules with RULE_TRIGGER mode. Determines how many child
 * tasks are created during initialization.
 */
static int16_t g_num_jobs = 0;

/**
 * @brief Current trigger context index
 * 
 * Index into g_trigger_rules for child task creation. Incremented
 * as each trigger task is spawned.
 */
static uint16_t g_trigger_ctx_count = 0;

/**
 * @brief Smallest period across all periodic rules
 * 
 * Determines the scheduler tick rate. Updated dynamically as rules
 * are evaluated to optimize scheduling efficiency.
 * 
 * Initial value: 1000 (1 second assuming 1ms ticks)
 */
static uint16_t SMALLEST_TICK_COUNT = 1000;

/*=======================================================================================
** Internal Helper Functions - Operand Resolution
**=======================================================================================*/

/**
 * @brief Resolve operand value from various sources
 *
 * Extracts the actual value of an operand based on its source kind.
 * Handles type conversion and validation.
 *
 * **Source Resolution:**
 * - SRC_CALL_NEW: Use result from current function call (results array)
 * - SRC_CALL_OLD: Use cached result from previous call (g_prev array)
 * - SRC_TOL: Use tolerance value from rule
 * - SRC_LIT: Use literal value (not implemented here)
 * - SRC_EVENT: Use event value (not implemented here)
 *
 * **Type Unpacking:**
 * Results are stored as byte arrays and must be unpacked to typed values:
 * - VT_I32: 32-bit signed integer
 * - VT_U32: 32-bit unsigned integer
 * - VT_F32: 32-bit floating point
 *
 * @param[in] rule Pointer to rule being evaluated
 * @param[in] results Array of function call results
 * @param[in] idx Index into results/g_prev arrays
 * @param[in] op Operand to resolve
 * @param[out] out Resolved value
 *
 * @return int 1 on success, 0 on failure
 *
 * @note Returns 0 if cached value not valid (SRC_CALL_OLD)
 * @note Type mismatch returns 0
 * @note Null pointer parameters return 0
 *
 * @see UnpackI32(), UnpackU32(), UnpackF32() for type conversion
 */
static int ResolveOperand(const Rule* rule, const CallResult* results, uint16_t idx, const Operand* op, Value* out)
{
	/* Validate input parameters */
	if (!rule || !results || !op || !out) return 0;
	
	/* Set output type from operand */
	out->type = op->type;
	
	switch (op->kind)
	{
		case SRC_CALL_NEW:
		{
			/* Use result from current function call */
			if (op->type == VT_I32) 
				return UnpackI32(results[idx].bytes, results[idx].len, &out->v.i32);
			else if (op->type == VT_U32) 
				return UnpackU32(results[idx].bytes, results[idx].len, &out->v.u32);
			else if (op->type == VT_F32) 
				return UnpackF32(results[idx].bytes, results[idx].len, &out->v.f32);
			else 
				return 0;

			return 1;
		}

		case SRC_CALL_OLD:
		{
			/* Use cached result from previous call */
			
			/* Check if cached value is valid */
			if (!g_prev[idx].valid) return 0;

			/* Unpack cached value based on type */
			if (op->type == VT_I32) 
				return UnpackI32(g_prev[idx].bytes, g_prev[idx].len, &out->v.i32);
			else if (op->type == VT_U32) 
				return UnpackU32(g_prev[idx].bytes, g_prev[idx].len, &out->v.u32);
			else if (op->type == VT_F32) 
				return UnpackF32(g_prev[idx].bytes, g_prev[idx].len, &out->v.f32);
			else 
				return 0;
			
			return 1;
		}
		
		case SRC_TOL:
		{
			/* Use tolerance value from rule */
			if (op->type == VT_I32) 
				out->v.i32 = rule->tol.v.i32;
			else if (op->type == VT_U32) 
				out->v.u32 = rule->tol.v.u32;
			else if (op->type == VT_F32) 
				out->v.f32 = rule->tol.v.f32;
			else 
				return 0;
			return 1;
		}

		default:
			return 0;
	}
}

/**
 * @brief Resolve tolerance literal value
 *
 * Extracts tolerance value from literal structure. Used for fuzzy
 * comparisons with OP_ABS_DIFF_GT operator.
 *
 * @param[in] lit Pointer to literal tolerance value
 * @param[out] out Resolved tolerance value
 *
 * @return int 1 on success, 0 on failure
 *
 * @note Only supports VT_I32, VT_F32, VT_U32 types
 * @note Null pointer parameters return 0
 */
static int ResolveTolerance(const Literal* lit, Value* out)
{
	/* Validate input parameters */
	if (!lit || !out) return 0;
	
	/* Set output type from literal */
	out->type = lit->type;
	
	switch (lit->type)
	{
		case VT_I32:
		{
			out->v.i32 = lit->v.i32;
			return 1;
		}
		case VT_F32:
		{
			out->v.f32 = lit->v.f32;
			return 1;
		}
		case VT_U32:
		{
			out->v.u32 = lit->v.u32;
			return 1;
		}
		default:
			return 0;
	}
}

/*=======================================================================================
** Internal Helper Functions - Rule Evaluation
**=======================================================================================*/

/**
 * @brief Evaluate rule expression
 *
 * Evaluates a rule's boolean expression (LHS operator RHS) and returns
 * whether the rule condition is satisfied.
 *
 * **Evaluation Steps:**
 * 1. Check if rule is enabled
 * 2. Resolve LHS operand value
 * 3. Resolve RHS operand value (if needed)
 * 4. Apply operator to compare LHS and RHS
 * 5. Return boolean result
 *
 * **Supported Operators:**
 * - OP_EQ: Equal (==)
 * - OP_NEQ: Not equal (!=)
 * - OP_GT: Greater than (>)
 * - OP_ABS_DIFF_GT: Absolute difference > tolerance
 *
 * **Type Safety:**
 * - LHS and RHS must have compatible types
 * - Type coercion not performed
 * - Type mismatch returns false (0)
 *
 * **Examples:**
 * @code
 * // (> (cpu-usage) 80.0)
 * // LHS: 85.5, RHS: 80.0, Operator: OP_GT
 * // Result: true (85.5 > 80.0)
 * 
 * // (= (mode) 1)
 * // LHS: 1, RHS: 1, Operator: OP_EQ
 * // Result: true (1 == 1)
 * @endcode
 *
 * @param[in] tbl Pointer to rule table
 * @param[in] results Array of function call results
 * @param[in] r Pointer to rule to evaluate
 *
 * @return int 1 if rule condition satisfied, 0 otherwise
 *
 * @note Disabled rules return 0
 * @note Resolution failures return 0
 * @note Type mismatches return 0
 *
 * @see ResolveOperand() for operand value extraction
 * @see ResolveTolerance() for tolerance value extraction
 */
static int EvalRule(RuleTable* tbl, const CallResult* results, const Rule* r)
{
	/* Skip disabled rules */
	if (!r->enabled) return 0;

	Value lhs={0}, rhs={0}, tol={0};

	/* Resolve left-hand side operand */
	if (!ResolveOperand(r, results, r->call_index, &r->lhs, &lhs)) return 0;

	switch (r->op)
	{
		case OP_EQ:
		case OP_NEQ:
		{
			/* Resolve right-hand side operand */
			if (!ResolveOperand(r, results, r->call_index, &r->rhs, &rhs)) return 0;
			
			/* Type must match for equality comparison */
			if (lhs.type != rhs.type) return 0;

			/* Perform type-specific equality check */
			int equal = 0;
			if (lhs.type == VT_I32) 
				equal = (lhs.v.i32 == rhs.v.i32);
			else if (lhs.type == VT_U32) 
				equal = (lhs.v.u32 == rhs.v.u32);
			else if (lhs.type == VT_F32) 
				equal = (lhs.v.f32 == rhs.v.f32);
			else 
				return 0;

			/* Return result based on operator */
			return (r->op == OP_EQ) ? equal : !equal;
		}
		
		case OP_GT:
		{
			/* Resolve right-hand side operand */
			if (!ResolveOperand(r, results, r->call_index, &r->rhs, &rhs)) return 0;

			/* Type must match for comparison */
			if (lhs.type != rhs.type) return 0;
			
			/* Perform type-specific greater-than check */
			if (lhs.type == VT_I32) 
			{
				return (lhs.v.i32 > rhs.v.i32);
			}
			if (lhs.type == VT_U32) 
			{
				return (lhs.v.u32 > rhs.v.u32);
			}
			if (lhs.type == VT_F32) 
			{
				return (lhs.v.f32 > rhs.v.f32);
			}
			return 0;
		}
		
		case OP_ABS_DIFF_GT:
		{
			/* Resolve right-hand side operand and tolerance */
			if (!ResolveOperand(r, results, r->call_index, &r->rhs, &rhs)) return 0;
			if (!ResolveTolerance(&r->tol, &tol)) return 0;
			
			/* All types must match */
			if (lhs.type != rhs.type) return 0;
			if (tol.type != lhs.type) return 0;

			/* Calculate absolute difference and compare to tolerance */
			if (lhs.type == VT_I32)
			{
				int32_t diff = lhs.v.i32 - rhs.v.i32;
				if (diff < 0) diff = -diff;
				return (diff > tol.v.i32);
			}
			if (lhs.type == VT_U32)
			{
				uint32_t diff = lhs.v.u32 - rhs.v.u32;
				if (diff < 0) diff = -diff;
				return (diff > tol.v.u32);
			}
			if (lhs.type == VT_F32)
			{
				float diff = lhs.v.f32 - rhs.v.f32;
				if (diff < 0) diff = -diff;
				return (diff > tol.v.f32);
			}
			return 0;
		}
		
		default:
			return 0;
	}
}

/*=======================================================================================
** Internal Helper Functions - Child Task Entry Points
**=======================================================================================*/

/**
 * @brief Child task entry point for trigger rules
 *
 * Executes a trigger rule continuously in a dedicated child task.
 * Runs indefinitely until application shutdown.
 *
 * **Operation:**
 * 1. Delay by rule's period_ticks
 * 2. Look up function in registry
 * 3. Prepare arguments (IOB, parameters)
 * 4. Invoke function
 * 5. Check for errors
 * 6. Repeat indefinitely
 *
 * **Task Context:**
 * - Runs in separate task context
 * - Has own stack (8192 bytes)
 * - Priority 50 (same as main task)
 * - Accesses global g_trigger_rules array
 *
 * @return void (never returns - runs until task deleted)
 *
 * @note Infinite loop - only exits on task deletion
 * @note Errors logged via CFE_EVS_SendEvent()
 * @note Task delay in milliseconds (period_ticks * 1000)
 *
 * @see SPACECOP_StartTriggerWorker() for task creation
 */
static void t_RunTriggerForever(void)
{
	/* Get trigger rule for this task */
	TriggerRule *job = &g_trigger_rules[g_trigger_ctx_count];
	
	/* Run indefinitely */
	while (1)
	{
		/* Delay until next execution */
		OS_TaskDelay(job->rule.period_ticks*1000);
		
		/* Look up function in registry */
		const SymEntry* sym = FindSym(job->rule.call_index);
		if (!sym) continue;

		/* Prepare function arguments */
		ArgBlob args;

		if (sym->need_iob)
		{
			strncpy(args.iob_id, job->rule.iob_id, IOB_MAX);
		}

		if (sym->expected_args & ARG_F32)
		{
			args.a.f32 = job->rule.tol.v.f32;	
		}

		if (sym->expected_args & ARG_U32)
		{
			args.a.u32 = job->rule.tol.v.u32;
		}

		/* Invoke function */
		int32 status = sym->fn(&args, 0, 0, 0);

		/* Check for errors */
		if (status != OS_SUCCESS)
		{
			CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
			                 "Trigger for SPARTA ID=%s failed", job->rule.iob_id);
		}
	}
}

/**
 * @brief Execute one-and-done rule
 *
 * Executes a rule exactly once. Used for initialization checks and
 * one-time validation operations.
 *
 * **Operation:**
 * 1. Look up function in registry
 * 2. Prepare arguments (IOB, parameters)
 * 3. Invoke function once
 * 4. Check for errors
 * 5. Return (rule will not execute again)
 *
 * @param[in] r Pointer to rule to execute
 *
 * @return void
 *
 * @note Function is called synchronously (blocks until complete)
 * @note Errors logged via CFE_EVS_SendEvent()
 * @note Rule should be disabled after execution
 *
 * @see SPACECOP_InitRuleRuntime() for invocation
 */
static void t_RunOneAndDone(Rule* r)
{
	/* Look up function in registry */
	const SymEntry* sym = FindSym(r->call_index);
	if (!sym) return;

	/* Prepare function arguments */
	ArgBlob args;
	strncpy(args.iob_id, r->iob_id, IOB_MAX);
	args.a.i32 = r->tol.v.i32;

	/* Invoke function once */
	int32 status = sym->fn(&args, 0, 0, 0);

	/* Check for errors */
	if (status != OS_SUCCESS)
	{
		CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
		                 "OneAndDone for SPARTA ID=%s failed", r->iob_id);
	}
}

/**
 * @brief Execute ML integration rule
 *
 * Initializes ML monitoring for a rule. Typically creates child task
 * or configures ML bridge for telemetry forwarding.
 *
 * **Operation:**
 * 1. Look up function in registry
 * 2. Prepare arguments (IOB, parameters)
 * 3. Invoke function (usually starts ML monitoring)
 * 4. Check for errors
 *
 * @param[in] r Pointer to ML rule to execute
 *
 * @return void
 *
 * @note Function may create child tasks
 * @note Errors logged via CFE_EVS_SendEvent()
 *
 * @see SPACECOP_InitRuleRuntime() for invocation
 * @see INVOKE_MLMonitor() in spacecop_registry.c
 */
static void t_RunML(Rule* r)
{
	/* Look up function in registry */
	const SymEntry* sym = FindSym(r->call_index);
	if (!sym) return;

	/* Prepare function arguments */
	ArgBlob args;
	strncpy(args.iob_id, r->iob_id, IOB_MAX);
	args.a.i32 = r->tol.v.i32;

	/* Invoke ML initialization function */
	int32 status = sym->fn(&args, 0, 0, 0);

	/* Check for errors */
	if (status != OS_SUCCESS)
	{
		CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
		                 "ML Monitor for SPARTA ID=%s failed", r->iob_id);
	}
}

/*=======================================================================================
** Public API Functions - Initialization
**=======================================================================================*/

/**
 * @brief Initialize rule runtime engine
 *
 * Initializes the rule execution engine and processes all rules in the table.
 * Sets up periodic scheduling, creates trigger tasks, and executes one-time rules.
 *
 * **Initialization Steps:**
 * 1. Scan all rules in table
 * 2. For RULE_PERIODIC: Initialize tick counters
 * 3. For RULE_TRIGGER: Add to trigger list
 * 4. For RULE_ONEANDDONE: Execute immediately
 * 5. For RULE_ML: Initialize ML integration
 * 6. Create child tasks for trigger rules
 *
 * **Periodic Rule Setup:**
 * - Calculates SMALLEST_TICK_COUNT for scheduler optimization
 * - Initializes ticks_until_due for each periodic rule
 * - Enables adaptive scheduling based on rule periods
 *
 * **Trigger Rule Setup:**
 * - Builds g_trigger_rules array
 * - Increments g_num_jobs counter
 * - Tasks created by SPACECOP_StartTriggerWorker()
 *
 * @param[in] tbl Pointer to rule table
 *
 * @return void
 *
 * @note Must be called once during application initialization
 * @note Creates multiple child tasks (one per trigger rule)
 * @note One-and-done rules execute synchronously during init
 * @note ML rules may create additional child tasks
 *
 * @see SPACECOP_StartTriggerWorker() for child task creation
 * @see SPACECOP_ExecutePeriodicRuleTable() for periodic execution
 */
void SPACECOP_InitRuleRuntime(RuleTable* tbl)
{
	/* Process each rule in table */
	for (uint16_t i = 0; i < tbl->num_rules && i < CALL_RULE_MAX; i++)
	{
		/* Skip disabled rules */
		if (!tbl->rules[i].enabled) continue;
		
		if (tbl->rules[i].mode == RULE_PERIODIC)
		{
			/* Initialize periodic rule scheduling */
			if (tbl->rules[i].period_ticks < SMALLEST_TICK_COUNT)
				SMALLEST_TICK_COUNT = tbl->rules[i].period_ticks;
			g_rule_rt[i].ticks_until_due = tbl->rules[i].period_ticks;
		}
		else if (tbl->rules[i].mode == RULE_TRIGGER)
		{
			/* Add to trigger rule list */
			g_trigger_rules[g_num_jobs].rule = tbl->rules[i];
			g_trigger_rules[g_num_jobs].ticks_until_due = 1;
			g_trigger_rules[g_num_jobs].report_cooldown_ticks = tbl->rules[i].period_ticks;
			g_num_jobs++;
		}
		else if (tbl->rules[i].mode == RULE_ONEANDDONE)
		{
			/* Execute one-time rule immediately */
			t_RunOneAndDone(&tbl->rules[i]);
		}
		else if (tbl->rules[i].mode == RULE_ML)
		{
			/* Initialize ML integration */
			t_RunML(&tbl->rules[i]);
		}
	}

	/* Create child tasks for trigger rules */
	SPACECOP_StartTriggerWorker(tbl);
}

/**
 * @brief Create child tasks for trigger rules
 *
 * Creates one child task for each RULE_TRIGGER mode rule. Each task
 * runs t_RunTriggerForever() in an infinite loop.
 *
 * **Task Creation:**
 * - Task name: IOB identifier from rule
 * - Stack size: 8192 bytes
 * - Priority: 50 (same as main task)
 * - Entry point: t_RunTriggerForever()
 * - Task ID: Sequential (0, 1, 2, ...)
 *
 * **Delay Between Tasks:**
 * 5 second delay between task creations to prevent resource contention
 * during initialization.
 *
 * @param[in] tbl Pointer to rule table
 *
 * @return int32 1 on success, CFE_STATUS_EXTERNAL_RESOURCE_FAIL if too many tasks
 *
 * @note Maximum tasks limited by CALL_RULE_MAX
 * @note Task creation failures logged via CFE_EVS_SendEvent()
 * @note 5 second delay between task creations
 * @note Tasks run indefinitely until app shutdown
 *
 * @see t_RunTriggerForever() for task entry point
 * @see SPACECOP_InitRuleRuntime() for invocation
 */
int32 SPACECOP_StartTriggerWorker(RuleTable* tbl)
{
	if (tbl)
	{
		/* Create child task for each trigger rule */
		for (uint16_t i = 0; i < g_num_jobs; i++)
		{
			/* Check task limit */
			if (g_trigger_ctx_count >= CALL_RULE_MAX) 
				return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
			
			g_trigger_ctx_count = i;

			/* Create child task */
			CFE_ES_TaskId_t task_id = i;
			int32 status = CFE_ES_CreateChildTask(&task_id, 
			                                      g_trigger_rules[i].rule.iob_id, 
			                                      t_RunTriggerForever, 
			                                      NULL, 
			                                      8192, 50, 0);

			if (status != OS_SUCCESS)
			{
				CFE_EVS_SendEvent(1001, CFE_EVS_EventType_ERROR, 
				                 "Unable to create task in SPACECOP_TRIGGER");
			}
			
			/* Delay to prevent resource contention */
			OS_TaskDelay(5*1000);
		}
	}
	return 1;
}

/*=======================================================================================
** Public API Functions - Periodic Rule Execution
**=======================================================================================*/

/**
 * @brief Execute periodic rules from rule table
 *
 * Main periodic rule execution function. Evaluates all RULE_PERIODIC rules
 * whose execution time has arrived. Optimizes performance through:
 * - Batch function execution
 * - Result caching
 * - Adaptive tick scheduling
 *
 * **Execution Flow:**
 * 1. Decrement tick counters for all periodic rules
 * 2. Build call_mask of functions to execute
 * 3. Execute all needed functions (batch)
 * 4. Cache results for SRC_CALL_OLD
 * 5. Evaluate all due rules
 * 6. Generate alerts for satisfied rules
 * 7. Reset tick counters
 * 8. Delay until next tick
 *
 * **Optimization - Call Mask:**
 * Multiple rules can reference the same function. The call_mask tracks
 * which functions need execution, avoiding duplicate calls.
 *
 * **Optimization - Result Caching:**
 * Function results are cached in g_prev array for use by SRC_CALL_OLD
 * operands in subsequent evaluations.
 *
 * **Adaptive Scheduling:**
 * SMALLEST_TICK_COUNT is dynamically updated to match the shortest period,
 * optimizing scheduler granularity.
 *
 * **Alert Generation:**
 * When a rule evaluates to true:
 * - IDS message: SPACECOP_ReportIDSMsg()
 * - STIX report: write_to_stix()
 * - EVS event: CFE_EVS_SendEvent()
 *
 * @param[in] tbl Pointer to rule table
 *
 * @return int32 CFE_SUCCESS on success, error code on failure
 * @retval CFE_SUCCESS Rules evaluated successfully
 * @retval CFE_ES_BAD_ARGUMENT Invalid table or num_rules
 * @retval CFE_STATUS_EXTERNAL_RESOURCE_FAIL Function lookup failed
 *
 * @note Called periodically by SCRuleTable child task
 * @note Blocks for SMALLEST_TICK_COUNT milliseconds
 * @note Performance-critical code path
 * @note Function call batching reduces overhead
 *
 * @see SPACECOP_InitRuleRuntime() for initialization
 * @see EvalRule() for rule evaluation logic
 * @see FindSym() for function lookup
 */
int32 SPACECOP_ExecutePeriodicRuleTable(RuleTable* tbl)
{
	/* Validate table pointer */
	if (!tbl) return CFE_ES_BAD_ARGUMENT;

	/* Validate rule count */
	if (tbl->num_rules > CALL_RULE_MAX)
	{
		return CFE_ES_BAD_ARGUMENT;
	}

	uint16_t rule_due[CALL_RULE_MAX] = {0};
	uint32_t call_mask = 0;

	uint16_t curr_tick_count = SMALLEST_TICK_COUNT;

	/*
	** Phase 1: Decrement tick counters and build call mask
	** Determine which rules are due and which functions need execution
	*/
	for (uint16_t i = 0; i < tbl->num_rules; i++)
	{
		const Rule* r = &tbl->rules[i];
		
		/* Skip non-periodic or disabled rules */
		if (!r->enabled) continue;
		if (r->mode != RULE_PERIODIC) continue;

		/* Decrement tick counter */
		if (g_rule_rt[i].ticks_until_due > 0)
			g_rule_rt[i].ticks_until_due = g_rule_rt[i].ticks_until_due - curr_tick_count;

		/* Check if rule is due for execution */
		if (g_rule_rt[i].ticks_until_due <= 0)
		{
			/* Mark rule as due */
			rule_due[i] = 1;
			
			/* Reset tick counter */
			g_rule_rt[i].ticks_until_due = r->period_ticks;
			
			/* Add function calls to execution mask */
			if (r->lhs.kind == SRC_CALL_NEW && r->call_index < CALL_MAX)
				call_mask |= (1U << r->call_index);
			if (r->rhs.kind == SRC_CALL_NEW && r->call_index < CALL_MAX)
				call_mask |= (1U << r->call_index);
		}

		/* Update SMALLEST_TICK_COUNT for adaptive scheduling */
		if (g_rule_rt[i].ticks_until_due < SMALLEST_TICK_COUNT && 
		    g_rule_rt[i].ticks_until_due <= 0)
			SMALLEST_TICK_COUNT = g_rule_rt[i].ticks_until_due;
	}

	/* Early exit if no functions need execution */
	if (call_mask == 0) return CFE_SUCCESS;

	/*
	** Phase 2: Execute all needed functions (batch execution)
	** Call each function once and store results
	*/
	CallResult results[CALL_MAX] = {0};

	for (uint16_t i = 0; i < tbl->num_rules; i++)
	{
		/* Skip functions not in call mask */
		if (!(call_mask & (1U << i))) continue;

		/* Look up function in registry */
		const SymEntry* sym = FindSym(i);
		if (!sym) return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;

		/* Prepare arguments (empty for most periodic functions) */
		uint16_t ret_len = 0;
		ArgBlob args;

		/* Invoke function */
		int32 status = sym->fn(&args, results[i].bytes, sizeof(results[i].bytes), &ret_len);
		if (status != CFE_SUCCESS) return status;

		/* Store result length */
		results[i].len = ret_len;

		/* Validate return size matches expected */
		if (sym->ret_size != 0 && results[i].len != sym->ret_size) 
			return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
	}

	/*
	** Phase 3: Evaluate all due rules and generate alerts
	*/
	for (uint16_t i = 0; i < tbl->num_rules; i++)
	{
		/* Skip rules not due for execution */
		if (!rule_due[i]) continue;

		const Rule* r = &tbl->rules[i];

		/* Safely copy IOB identifier (null-terminated) */
		char safe_iob_id[IOB_MAX];
		memset(safe_iob_id, 0, sizeof(safe_iob_id));
		memcpy(safe_iob_id, r->iob_id, IOB_MAX - 1);
		safe_iob_id[IOB_MAX - 1] = '\0';
		
		/* Evaluate rule expression */
		int passed = EvalRule(tbl, results, r);

		if (passed)
		{
			/* Rule condition satisfied - generate alert */
			char message[IDS_REPORT_MESSAGE_LEN];
			memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
			snprintf(message, IDS_REPORT_MESSAGE_LEN, 
			        "[SPACECOP] IOB Detected: SPARTA ID=%s", safe_iob_id);
			
			/* Send alert via multiple channels */
			SPACECOP_ReportIDSMsg(message);           /* IDS telemetry */
			write_to_stix(NULL, NULL, safe_iob_id);   /* STIX report */
			CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
			                 "[SPACECOP] IOB Detected: SPARTA ID=%s", safe_iob_id);
		}
		continue;
	}

	/*
	** Phase 4: Cache results for next evaluation (SRC_CALL_OLD)
	*/
	for (uint16_t i = 0; i < tbl->num_rules; i++)
	{
		/* Skip functions not executed */
		if (!(call_mask & (1U << i))) continue;
		
		/* Mark result as valid and cache it */
		g_prev[i].valid = 1;
		g_prev[i].len = results[i].len;
		memcpy(g_prev[i].bytes, results[i].bytes, results[i].len);
	}

	/* Delay until next scheduler tick */
	OS_TaskDelay(SMALLEST_TICK_COUNT*1000);
	return CFE_SUCCESS;
}

/*=======================================================================================
** Public API Functions - Command Monitoring
**=======================================================================================*/

/**
 * @brief Execute command monitoring table
 *
 * Monitors Software Bus for commands defined in command monitoring table.
 * Processes activation/deactivation triggers and generates alerts for
 * unauthorized commands.
 *
 * **Operation:**
 * 1. Block on MonitorCmdPipe for next message
 * 2. Search command monitoring table for matches
 * 3. Process activation triggers (COUNT_DURATION, COUNT_TOTAL, ALERT_IMMEDIATELY)
 * 4. Process deactivation triggers
 * 5. Search for telemetry matches (STORE_PACKET)
 * 6. Return (called repeatedly by SCCmdRun child task)
 *
 * **Command Actions:**
 * - COUNT_DURATION: Track duration between activation and deactivation
 * - COUNT_TOTAL: Count total occurrences
 * - ALERT_IMMEDIATELY: Generate immediate alert
 *
 * **Telemetry Actions:**
 * - STORE_PACKET: Store packet for sequence analysis
 *
 * **Multiple Matches:**
 * A single message may match multiple table entries. The offset parameter
 * enables iteration through all matches.
 *
 * @param[in] tbl Pointer to command monitoring table
 * @param[in,out] MonitorMsgPtr Pointer to received message pointer
 * @param[in] MonitorCmdPipe Pipe to receive messages from
 *
 * @return void
 *
 * @note Blocks indefinitely on CFE_SB_ReceiveBuffer()
 * @note Called repeatedly by SCCmdRun child task
 * @note Handles both command and telemetry messages
 *
 * @see SPACECOP_ConvertCommandToStixId() for command matching
 * @see SPACECOP_ConvertTelemetryToStixId() for telemetry matching
 * @see SPACECOP_StartCountDuration() for duration tracking
 * @see SPACECOP_StartCountTotal() for occurrence counting
 */
void SPACECOP_ExecuteCommandTableMonitor(CommandMonitorEntryTable_t* tbl, 
                                         CFE_MSG_Message_t* MonitorMsgPtr, 
                                         CFE_SB_PipeId_t MonitorCmdPipe)
{
	uint8_t offset;
	int32 status;
	CommandMonitorEntry_t* MonitorEntry;
	Result_t ResultIndicator;

	offset = 0;
	#ifdef SPACECOP_MONITOR_DEBUG
	printf("SPACECOP: Entering Loop!\n");
	#endif
	
	MonitorEntry = NULL;
	
	/* Block waiting for next message */
	status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&MonitorMsgPtr, MonitorCmdPipe, CFE_SB_PEND_FOREVER);
	
	if (status == CFE_SUCCESS)
	{
		#ifdef SPACECOP_MONITOR_DEBUG
		printf("SPACECOP: FOUND COMMAND\n");
		#endif

		/*
		** Process all matching command entries
		*/
		while((MonitorEntry = SPACECOP_ConvertCommandToStixId(tbl, MonitorMsgPtr, &ResultIndicator, &offset)) != NULL)
		{
			switch(MonitorEntry->StixInfo.Action)
			{
				case COUNT_DURATION:
					if(ResultIndicator == ACTIVATE)
					{
						#ifdef SPACECOP_MONITOR_DEBUG
						printf("SPACECOP: Found activate command for %d\n", MonitorEntry->StixInfo.StixId);
						#endif
						SPACECOP_StartCountDuration(MonitorEntry->StixInfo.StixId);
					}
					else if (ResultIndicator == DEACTIVATE)
					{
						#ifdef SPACECOP_MONITOR_DEBUG
						printf("SPACECOP: Found deactivate command for %d\n", MonitorEntry->StixInfo.StixId);
						#endif
						SPACECOP_SetEntryInactive(MonitorEntry->StixInfo.StixId);
					}
					else
					{
						printf("SPACECOP: Somehow found ERROR command for %d\n", MonitorEntry->StixInfo.StixId);	
					}
					break;
					
				case COUNT_TOTAL:
					if(ResultIndicator == ACTIVATE)
					{
						#ifdef SPACECOP_MONITOR_DEBUG
						printf("SPACECOP: Found activate command for %d\n", MonitorEntry->StixInfo.StixId);
						#endif
						SPACECOP_StartCountTotal(MonitorEntry->StixInfo.StixId);
					}
					break;
					
				case ALERT_IMMEDIATELY:
					if(ResultIndicator == ACTIVATE)
					{
						SPACECOP_ReportImmediately(MonitorMsgPtr);
					}
					break;
					
				default:
					break;
			}
		}
		
		/*
		** Process all matching telemetry entries
		*/
		while ((MonitorEntry = SPACECOP_ConvertTelemetryToStixId(tbl, MonitorMsgPtr, &ResultIndicator, &offset)) != NULL)
		{
			switch(MonitorEntry->StixInfo.Action)
			{
				case STORE_PACKET:
					if(ResultIndicator == ACTIVATE)
					{
						#ifdef SPACECOP_MONITOR_DEBUG
						printf("SPACECOP: Found packet to store %d\n", MonitorEntry->StixInfo.StixId);
						#endif
						SPACECOP_StorePacket(MonitorEntry->StixInfo.StixId, 
						                    MonitorEntry->ActionOnMid, 
						                    (CFE_SB_Buffer_t **)&MonitorMsgPtr);
					}
					break;
					
				default:
					break;
			}
		}
	}
}

/*=======================================================================================
** Public API Functions - ML Integration
**=======================================================================================*/

/**
 * @brief Execute ML telemetry monitoring
 *
 * Monitors Software Bus for telemetry messages configured for ML processing.
 * Forwards messages to ML server for anomaly detection.
 *
 * **Operation:**
 * 1. Block on MLPipe for next message
 * 2. Extract message ID and size
 * 3. Get pointer to raw message data
 * 4. Forward to ML server via MLBridge_SendRawHex()
 * 5. Return (called repeatedly by SCMLRun child task)
 *
 * **Message Format:**
 * Messages are sent to ML server as hexadecimal strings with:
 * - Message ID for routing
 * - Complete message including header
 * - All fields in network byte order
 *
 * @param[in] MLPipe Pipe to receive ML messages from
 *
 * @return void
 *
 * @note Blocks indefinitely on CFE_SB_ReceiveBuffer()
 * @note Called repeatedly by SCMLRun child task
 * @note Forwards all received messages to ML server
 * @note Errors logged to stdout (commented out for production)
 *
 * @see MLBridge_SendRawHex() in ml_interface.c
 * @see SPACECOP_ExecuteMLTableMonitor() for invocation
 */
void SPACECOP_ExecuteMLTableMonitor(CFE_SB_PipeId_t MLPipe)
{
	int32_t status;
	CFE_SB_Buffer_t *SBBufPtr = NULL;
	CFE_MSG_Message_t *MLMsgPtr;
	CFE_SB_MsgId_t MsgId;
	CFE_MSG_Size_t MsgSize;
	uint8_t *raw_data;
	
	/* Block waiting for next message */
	status = CFE_SB_ReceiveBuffer(&SBBufPtr, MLPipe, CFE_SB_PEND_FOREVER);
	
	if (status == CFE_SUCCESS)
	{
		/* Validate buffer pointer */
		if (SBBufPtr == NULL)
		{
			return;
		}
		
		/* Get message from buffer */
		MLMsgPtr = &SBBufPtr->Msg;
		
		/* Extract message ID and size */
		CFE_MSG_GetMsgId(MLMsgPtr, &MsgId);
		CFE_MSG_GetSize(MLMsgPtr, &MsgSize);
		
		/* Get pointer to raw message data */
		raw_data = (uint8_t *)MLMsgPtr;
		
		/* Forward to ML server */
		status = MLBridge_SendRawHex(raw_data, MsgSize, MsgId);
		
		/* Error logging commented out for production */
		/*
		if (status != CFE_SUCCESS) {
			printf("[SPACECOP] Failed to send MsgId 0x%04X to ML server\n", 
			       CFE_SB_MsgIdToValue(MsgId));
			fflush(stdout);
		}
		*/
	}
	else
	{
		printf("[SPACECOP] ML Monitor receive error: %d\n", status);
		fflush(stdout);
	}
}

/**
 * @brief Check for ML anomaly alerts
 *
 * Polls ML bridge for incoming anomaly alerts from ML server.
 * Wrapper function for MLBridge_CheckForResponse().
 *
 * **Operation:**
 * 1. Check ML bridge for incoming alerts (non-blocking)
 * 2. Parse JSON alert messages
 * 3. Generate IDS alerts for ML-detected anomalies
 *
 * @return void
 *
 * @note Called periodically by SCMLRep child task
 * @note Non-blocking operation
 * @note Processes all available alerts
 *
 * @see MLBridge_CheckForResponse() in ml_interface.c
 */
void SPACECOP_MLMonitor(void)
{
	MLBridge_CheckForResponse();
}