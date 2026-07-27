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
 * @file spacecop_perfids.h
 * @brief SpaceCop performance monitoring identifier definitions
 *
 * This header defines performance monitoring identifiers (Performance IDs)
 * used by SpaceCop for cFE performance metrics collection. Performance IDs
 * enable detailed timing analysis and performance profiling of SpaceCop
 * operations.
 *
 * **cFE Performance Monitoring:**
 * The cFE Performance Monitor provides a lightweight mechanism for measuring
 * execution time and CPU utilization of applications and specific code
 * segments. It uses performance markers to track:
 * - Application main loop timing
 * - Function execution duration
 * - Task scheduling latency
 * - CPU utilization per application
 * - System-wide performance metrics
 *
 * **Performance Marker Usage:**
 * Performance markers are inserted at entry and exit points of code segments
 * to measure execution time:
 * @code
 * void SPACECOP_AppMain(void) {
 *     // Mark entry into main loop
 *     CFE_ES_PerfLogEntry(SPACECOP_PERF_ID);
 *     
 *     // Application processing
 *     SPACECOP_ProcessMessages();
 *     SPACECOP_EvaluateRules();
 *     
 *     // Mark exit from main loop
 *     CFE_ES_PerfLogExit(SPACECOP_PERF_ID);
 *     
 *     // Wait for next wakeup
 *     OS_TaskDelay(100);
 * }
 * @endcode
 *
 * **Performance Data Collection:**
 * The cFE Performance Monitor collects timing data in a circular buffer:
 * @code
 * Performance Log Entry:
 * ┌──────────────┬──────────────┬──────────────┐
 * │  Timestamp   │  Perf ID     │  Entry/Exit  │
 * ├──────────────┼──────────────┼──────────────┤
 * │  1234567890  │  500         │  ENTRY       │
 * │  1234567895  │  500         │  EXIT        │
 * │  1234567900  │  500         │  ENTRY       │
 * │  ...         │  ...         │  ...         │
 * └──────────────┴──────────────┴──────────────┘
 * @endcode
 *
 * **Performance Analysis:**
 * Collected performance data can be analyzed to determine:
 * - Average execution time per iteration
 * - Maximum execution time (worst-case)
 * - Minimum execution time (best-case)
 * - CPU utilization percentage
 * - Execution frequency
 * - Performance trends over time
 *
 * **Ground System Integration:**
 * Performance data is retrieved via cFE commands and analyzed on ground:
 * @code
 * # Start performance data collection
 * CFE_ES_START_PERF_DATA_CC
 * 
 * # Run system for analysis period
 * wait(60 seconds)
 * 
 * # Stop collection and retrieve data
 * CFE_ES_STOP_PERF_DATA_CC
 * CFE_ES_WRITE_PERF_DATA_CC filename="/cf/perf_data.dat"
 * 
 * # Download and analyze
 * download_file("/cf/perf_data.dat")
 * analyze_performance(perf_data, SPACECOP_PERF_ID)
 * @endcode
 *
 * **Performance ID Assignment:**
 * Performance IDs must be unique across all cFS applications to avoid
 * conflicts in performance analysis. SpaceCop uses ID 500, which is
 * typically in the mission-specific application range.
 *
 * **ID Range Conventions:**
 * @code
 * 0-99:    Reserved for cFE core services
 * 100-199: Standard cFS applications (TO, CI, SCH, etc.)
 * 200-499: Mission-specific core applications
 * 500-999: Mission-specific payload applications
 * 
 * SpaceCop: 500 (mission-specific security application)
 * @endcode
 *
 * **Multiple Performance IDs:**
 * Complex applications may use multiple performance IDs to track different
 * components:
 * @code
 * #define SPACECOP_PERF_ID              500  // Main loop
 * #define SPACECOP_PERF_ID_RULE_EVAL    501  // Rule evaluation
 * #define SPACECOP_PERF_ID_CMD_MON      502  // Command monitoring
 * #define SPACECOP_PERF_ID_STIX_GEN     503  // STIX generation
 * 
 * // Usage
 * void SPACECOP_EvaluateRules(void) {
 *     CFE_ES_PerfLogEntry(SPACECOP_PERF_ID_RULE_EVAL);
 *     // Rule evaluation code
 *     CFE_ES_PerfLogExit(SPACECOP_PERF_ID_RULE_EVAL);
 * }
 * @endcode
 *
 * **Performance Overhead:**
 * Performance monitoring has minimal overhead:
 * - Entry/Exit calls: ~1-2 microseconds each
 * - Memory: Circular buffer (configurable size)
 * - CPU: <1% impact typical
 * - Can be disabled via cFE configuration
 *
 * **Typical Performance Metrics:**
 * Expected SpaceCop performance characteristics:
 * @code
 * Main Loop (SPACECOP_PERF_ID):
 * - Average: 5-10 ms per iteration
 * - Maximum: 50 ms (with detection events)
 * - Minimum: 1-2 ms (idle)
 * - Frequency: 10 Hz (100ms period)
 * - CPU Utilization: 5-10% typical
 * 
 * Rule Evaluation:
 * - Average: 2-5 ms
 * - Maximum: 20 ms (complex rules)
 * - Depends on rule count and complexity
 * @endcode
 *
 * **Performance Troubleshooting:**
 * Use performance data to identify issues:
 * @code
 * // Detect excessive execution time
 * if (max_execution_time > threshold) {
 *     // Investigate:
 *     // - Rule complexity too high?
 *     // - Too many active rules?
 *     // - File I/O blocking?
 *     // - Network delays?
 * }
 * 
 * // Detect timing anomalies
 * if (execution_time_variance > threshold) {
 *     // Investigate:
 *     // - Interrupt storms?
 *     // - Priority inversion?
 *     // - Resource contention?
 * }
 * @endcode
 *
 * **Integration with Other Tools:**
 * Performance data complements other diagnostic tools:
 * - EVS events: Functional behavior
 * - Housekeeping: Status and counters
 * - Performance: Timing and CPU usage
 * - Memory pool stats: Memory usage
 * - Stack usage: Stack consumption
 *
 * **Example Analysis:**
 * @code
 * # Python performance analysis
 * import cfe_perf_analyzer
 * 
 * # Load performance data
 * perf_data = cfe_perf_analyzer.load("perf_data.dat")
 * 
 * # Analyze SpaceCop performance
 * spacecop_stats = perf_data.analyze(SPACECOP_PERF_ID)
 * 
 * print(f"Average execution time: {spacecop_stats.avg_time_us} µs")
 * print(f"Maximum execution time: {spacecop_stats.max_time_us} µs")
 * print(f"CPU utilization: {spacecop_stats.cpu_percent}%")
 * print(f"Execution count: {spacecop_stats.count}")
 * 
 * # Plot timing histogram
 * spacecop_stats.plot_histogram()
 * @endcode
 *
 * **Best Practices:**
 * - Use consistent entry/exit pairs
 * - Minimize markers in hot paths
 * - Choose representative code segments
 * - Avoid nested markers with same ID
 * - Document performance requirements
 * - Monitor trends over time
 *
 * @note Performance IDs must be unique across all applications
 * @note ID 500 chosen to avoid conflicts with core cFS apps
 * @note Performance monitoring can be disabled if not needed
 * @note Minimal overhead (<1% CPU typical)
 *
 * @see CFE_ES_PerfLogEntry for performance marker entry
 * @see CFE_ES_PerfLogExit for performance marker exit
 * @see cFE Performance Monitor documentation for analysis tools
 */

/*******************************************************************************
** File:
**   $Id: spacecop_perfids.h $
**
** Purpose:
**  Define SPACECOP Performance IDs
**
** Notes:
**
*************************************************************************/
#ifndef _SPACECOP_PERFIDS_H_
#define _SPACECOP_PERFIDS_H_

/*=======================================================================================
** Performance ID Definitions
**=======================================================================================*/

/**
 * @brief SpaceCop main application performance ID
 * 
 * Performance identifier for SpaceCop's main application loop. Used to
 * measure execution time, CPU utilization, and scheduling behavior of
 * the primary SpaceCop task.
 *
 * **Purpose:**
 * Tracks performance of SpaceCop's main processing cycle including:
 * - Message reception and processing
 * - Rule evaluation
 * - Command monitoring
 * - Alert generation
 * - Housekeeping updates
 *
 * **ID Value: 500**
 * Chosen to avoid conflicts with:
 * - cFE core services (0-99)
 * - Standard cFS apps (100-199)
 * - Mission core apps (200-499)
 *
 * **Instrumentation Example:**
 * @code
 * void SPACECOP_AppMain(void) {
 *     int32 Status;
 *     
 *     while (CFE_ES_RunLoop(&RunStatus) == true) {
 *         // Mark entry into processing cycle
 *         CFE_ES_PerfLogEntry(SPACECOP_PERF_ID);
 *         
 *         // Process software bus messages
 *         Status = CFE_SB_ReceiveBuffer(&SBBufPtr,
 *                                       SPACECOP_CommandPipe,
 *                                       CFE_SB_PEND_FOREVER);
 *         
 *         if (Status == CFE_SUCCESS) {
 *             SPACECOP_ProcessCommandPacket(SBBufPtr);
 *         }
 *         
 *         // Evaluate detection rules
 *         SPACECOP_ExecutePeriodicRuleTable(&RuleTable);
 *         
 *         // Mark exit from processing cycle
 *         CFE_ES_PerfLogExit(SPACECOP_PERF_ID);
 *     }
 * }
 * @endcode
 *
 * **Performance Expectations:**
 * @code
 * Nominal Performance:
 * - Execution Time: 5-10 ms per cycle
 * - Frequency: 10 Hz (100 ms period)
 * - CPU Utilization: 5-10%
 * 
 * Peak Performance (during detection):
 * - Execution Time: 20-50 ms per cycle
 * - CPU Utilization: 15-20%
 * 
 * Warning Thresholds:
 * - Execution Time > 80 ms: Investigate performance
 * - CPU Utilization > 25%: Consider optimization
 * @endcode
 *
 * **Performance Analysis:**
 * @code
 * # Retrieve performance data
 * CFE_ES_WRITE_PERF_DATA_CC filename="/cf/spacecop_perf.dat"
 * 
 * # Analyze on ground
 * perf_data = load_perf_data("spacecop_perf.dat")
 * spacecop_metrics = perf_data.filter(perf_id=500)
 * 
 * # Calculate statistics
 * avg_time = spacecop_metrics.mean_execution_time()
 * max_time = spacecop_metrics.max_execution_time()
 * cpu_util = spacecop_metrics.cpu_utilization()
 * 
 * print(f"SpaceCop Performance:")
 * print(f"  Average: {avg_time:.2f} ms")
 * print(f"  Maximum: {max_time:.2f} ms")
 * print(f"  CPU: {cpu_util:.1f}%")
 * @endcode
 *
 * **Optimization Guidance:**
 * If performance is outside expected range:
 * @code
 * High Execution Time:
 * - Reduce number of active rules
 * - Optimize rule evaluation logic
 * - Reduce file I/O operations
 * - Minimize STIX bundle generation
 * 
 * High CPU Utilization:
 * - Increase main loop period
 * - Reduce rule evaluation frequency
 * - Optimize hot paths
 * - Consider background processing
 * 
 * High Variance:
 * - Check for priority inversion
 * - Investigate interrupt storms
 * - Look for resource contention
 * - Review task scheduling
 * @endcode
 *
 * **Nested Performance Tracking:**
 * For detailed analysis, add sub-component markers:
 * @code
 * void SPACECOP_AppMain(void) {
 *     CFE_ES_PerfLogEntry(SPACECOP_PERF_ID);
 *     
 *     // Track message processing separately
 *     CFE_ES_PerfLogEntry(SPACECOP_PERF_ID_MSG_PROC);
 *     SPACECOP_ProcessMessages();
 *     CFE_ES_PerfLogExit(SPACECOP_PERF_ID_MSG_PROC);
 *     
 *     // Track rule evaluation separately
 *     CFE_ES_PerfLogEntry(SPACECOP_PERF_ID_RULES);
 *     SPACECOP_EvaluateRules();
 *     CFE_ES_PerfLogExit(SPACECOP_PERF_ID_RULES);
 *     
 *     CFE_ES_PerfLogExit(SPACECOP_PERF_ID);
 * }
 * @endcode
 *
 * **Conflict Avoidance:**
 * Ensure ID 500 is not used by other applications:
 * @code
 * // System performance ID allocation
 * CFE Core:        0-99
 * TO App:          100
 * CI App:          101
 * SCH App:         102
 * Sample App:      200
 * SpaceCop:        500  ← This application
 * Payload App 1:   501
 * Payload App 2:   502
 * @endcode
 *
 * **Runtime Control:**
 * Performance monitoring can be controlled at runtime:
 * @code
 * # Start performance data collection
 * CFE_ES_START_PERF_DATA_CC
 * 
 * # Stop performance data collection
 * CFE_ES_STOP_PERF_DATA_CC
 * 
 * # Set filter mask to collect only specific IDs
 * CFE_ES_SET_PERF_FILTER_MASK_CC mask=0x00000001 id=500
 * @endcode
 *
 * @note Value: 500
 * @note Must be unique across all cFS applications
 * @note Used with CFE_ES_PerfLogEntry/Exit functions
 * @note Performance monitoring has <1% overhead
 *
 * @see CFE_ES_PerfLogEntry for marking entry points
 * @see CFE_ES_PerfLogExit for marking exit points
 * @see cFE Performance Monitor documentation for analysis
 *
 * @warning Ensure no other application uses ID 500
 * @warning Always pair Entry with Exit calls
 * @warning Excessive markers can impact performance
 */
#define SPACECOP_PERF_ID          500

#endif /* _SPACECOP_PERFIDS_H_ */