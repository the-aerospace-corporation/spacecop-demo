// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_registry.c
 * @brief Function registry and dispatch system for SpaceCop rule execution
 *
 * This file implements the function registry that maps symbolic function names
 * to their implementations. It provides the runtime dispatch mechanism for
 * executing detection functions from rule table entries.
 *
 * **Architecture:**
 * The registry uses a symbol table (kSyms) that associates:
 * - Function names (strings from rule table)
 * - Call indices (numeric identifiers)
 * - Function pointers (actual implementations)
 * - Argument specifications
 * - Return type information
 * - IOB requirements
 *
 * **Function Categories:**
 * - Time functions: Spacecraft time queries
 * - Process monitoring: CPU and process checks
 * - File integrity: Hash-based file verification
 * - System call monitoring: Kernel-level syscall tracking
 * - Memory monitoring: RAM usage and corruption detection
 * - Disk monitoring: Storage space checks
 * - Command tracking: Propulsion, time adjustment tracking
 * - ML integration: Machine learning bridge functions
 * - State tracking: System state change detection
 *
 * **Execution Model:**
 * 1. Rule table contains function name and arguments
 * 2. FindSym() looks up function by call_index
 * 3. Rule executor validates arguments
 * 4. Function is invoked with ArgBlob
 * 5. Return value is processed by rule evaluator
 *
 * **Thread Safety:**
 * Many functions use static flags to prevent concurrent execution. This
 * ensures only one instance runs at a time, preventing race conditions and
 * resource conflicts.
 *
 * @note Function implementations may create child tasks
 * @note Some functions have significant performance impact
 * @note Concurrent execution is prevented via static flags
 *
 * @see spacecop_registry.h for data structure definitions
 * @see spacecop_table_runtime.c for rule execution logic
 */

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "spacecop_registry.h"
#include "spacecop_stix_components.h"
#include "spacecop_mission_specific.h"

#include "cfe.h"
#include <string.h>

/* Detection function implementations */
#include "functions_procmon_linux.h"
#include "functions_file_integrity_linux.h"
#include "functions_syscall_kernel_module.h"
#include "functions_memory_mon.h"
#include "functions_command_monitors.h"
#include "functions_disk_linux.h"

/*=======================================================================================
** Time Query Functions
**=======================================================================================*/

/**
 * @brief Get current spacecraft time (seconds component only)
 *
 * Retrieves the current spacecraft time from cFE Time Services and returns
 * only the seconds component. Used in rule expressions for time-based
 * comparisons.
 *
 * **Usage in Rules:**
 * @code
 * (> (time-controller) 1000000)  // Check if time > 1M seconds
 * @endcode
 *
 * @param[in] args Argument blob (unused)
 * @param[out] ret_buf Buffer to receive return value (uint32_t seconds)
 * @param[in] ret_buf_len Length of return buffer
 * @param[out] ret_len Actual length of return data
 *
 * @return int32 CFE_SUCCESS on success, CFE_ES_BAD_ARGUMENT on error
 *
 * @note Returns only seconds component (subseconds discarded)
 * @note Return value is 32-bit unsigned integer
 */
static int32 INVOKE_CFE_TIME_GetTime(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	(void)args;  /* Unused parameter */
	
	/* Validate output parameters */
	if (!ret_buf || !ret_len) return CFE_ES_BAD_ARGUMENT;
	if (ret_buf_len < sizeof(CFE_TIME_SysTime_t)) return CFE_ES_BAD_ARGUMENT;

	/* Get current spacecraft time */
	CFE_TIME_SysTime_t t = CFE_TIME_GetTime();
	
	/* Copy seconds component to return buffer */
	memcpy(ret_buf, &t.Seconds, sizeof(t.Seconds));
	*ret_len = sizeof(uint32_t);
	
	return CFE_SUCCESS;
}

/*=======================================================================================
** Process Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for CPU check */
static int procmon_cpu_check_running = 0;

/**
 * @brief Check CPU usage against threshold
 *
 * Monitors system CPU usage and generates alerts if usage exceeds the
 * specified threshold. Uses /proc/stat to calculate CPU utilization.
 *
 * **Operation:**
 * 1. Read CPU statistics from /proc/stat
 * 2. Calculate CPU utilization percentage
 * 3. Compare against threshold
 * 4. Generate alert if threshold exceeded
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution. If already running,
 * returns immediately without error.
 *
 * **Usage in Rules:**
 * @code
 * (procmon-cpu-check 80.0)  // Alert if CPU > 80%
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->a.f32: CPU threshold percentage (0.0-100.0)
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 * @note Requires /proc filesystem access
 * @note May be CPU-intensive
 *
 * @see PROCMon_CPU_Check() in functions_procmon_linux.c
 */
static int32 INVOKE_PROCMon_CPU_Check(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (procmon_cpu_check_running == 0)
	{
		procmon_cpu_check_running = 1;
		
		/* Initialize process monitor */
		PROCMon_Init();
		
		/* Perform CPU usage check */
		PROCMon_CPU_Check(args->a.f32, args->iob_id);
		
		procmon_cpu_check_running = 0;
	}

	return CFE_SUCCESS;
}

/** @brief Concurrency control flag for process check */
static int procmon_process_check_running = 0;

/**
 * @brief Check for unauthorized processes
 *
 * Scans running processes and compares against whitelist/blacklist.
 * Generates alerts for unauthorized processes.
 *
 * **Operation:**
 * 1. Enumerate running processes via /proc
 * 2. Read process name and command line
 * 3. Compare against authorized process list
 * 4. Generate alert for unauthorized processes
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (procmon-process-check)  // Check for unauthorized processes
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 * @note Requires /proc filesystem access
 * @note Process list configured in functions_procmon_linux.c
 *
 * @see PROCMon_Process_Check() in functions_procmon_linux.c
 */
static int32 INVOKE_PROCMon_Process_Check(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (procmon_process_check_running == 0)
	{
		procmon_process_check_running = 1;
		
		/* Initialize process monitor */
		PROCMon_Init();
		
		/* Perform process authorization check */
		PROCMon_Process_Check(args->iob_id);
		
		procmon_process_check_running = 0;
	}
	
	return CFE_SUCCESS;
}

/*=======================================================================================
** File Integrity Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for file integrity check */
static int file_integrity_check = 0;

/**
 * @brief Verify file integrity via SHA-256 hashing
 *
 * Scans critical file systems and verifies file integrity by comparing
 * SHA-256 hashes against baseline. Detects:
 * - Modified files
 * - Deleted files
 * - New unauthorized files
 *
 * **Operation:**
 * 1. Scan cf/ and data/ directories recursively
 * 2. Compute SHA-256 hash for each file
 * 3. Compare against baseline hashes
 * 4. Generate alert for mismatches
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (file-integrity)  // Check file system integrity
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 * @note I/O intensive operation
 * @note Baseline configured in functions_file_integrity_linux.c
 *
 * @see RunFileIntegrity() in functions_file_integrity_linux.c
 */
static int32 INVOKE_FileIntegrity_Check(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (file_integrity_check == 0)
	{
		file_integrity_check = 1;
		
		/* Initialize file integrity subsystem */
		Init_FileIntegrity();
		
		/* Perform integrity check */
		RunFileIntegrity(args->iob_id);
		
		file_integrity_check = 0;
	}

	return CFE_SUCCESS;
}

/*=======================================================================================
** System Call Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for syscall monitor */
static int sysmonitor_running = 0;

/**
 * @brief Start kernel-level system call monitoring
 *
 * Initializes and starts a child task that monitors system calls via kernel
 * module. Detects anomalous syscall patterns that may indicate:
 * - Privilege escalation attempts
 * - Unauthorized file access
 * - Network activity anomalies
 * - Process manipulation
 *
 * **Operation:**
 * 1. Toggle monitoring for specified IOB
 * 2. Set anomaly detection tolerance
 * 3. Create child task for continuous monitoring
 * 4. Task reads syscall data from kernel module
 * 5. Analyzes patterns and generates alerts
 *
 * **Child Task:**
 * - Name: "SyscallMonitor"
 * - Stack: 8192 bytes
 * - Priority: 50
 * - Runs continuously until app shutdown
 *
 * **Concurrency:**
 * Only one instance can run. Uses static flag to prevent multiple tasks.
 *
 * **Usage in Rules:**
 * @code
 * (syscall-monitor)  // Start syscall monitoring
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 *                 - args->a.i32: Tolerance threshold for anomaly detection
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS on success, error code on task creation failure
 *
 * @note Creates long-running child task
 * @note Requires kernel module loaded
 * @note High performance impact
 * @note Only one instance allowed per application
 *
 * @see SYSCALL_Monitor() in functions_syscall_kernel_module.c
 */
static int32 INVOKE_SyscallMonitor(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Configure monitoring for this IOB */
	Toggle_Monitor(args->iob_id);
	Set_Tolerance(args->iob_id, args->a.i32);
	
	int32 status = OS_SUCCESS;
	
	/* Check if monitor task already running */
	if (sysmonitor_running == 0)
	{
		sysmonitor_running = 1;
		
		/* Initialize syscall monitoring subsystem */
		Init_Syscall();
		
		/* Create child task for continuous monitoring */
		CFE_ES_TaskId_t task_id = 1096;
		status = CFE_ES_CreateChildTask(&task_id, "SyscallMonitor", 
		                                SYSCALL_Monitor, NULL, 
		                                8192, 50, 0);

		if (status != OS_SUCCESS)
		{
			CFE_EVS_SendEvent(1001, CFE_EVS_EventType_ERROR, 
			                 "Unable to create task in SPACECOP_TRIGGER");
			sysmonitor_running = 0;
		}
	}
	
	return status;
}

/*=======================================================================================
** Memory Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for memory monitor */
static int memory_mon_check_running = 0;

/**
 * @brief Check system memory usage
 *
 * Monitors system memory usage and generates alerts if usage exceeds
 * specified threshold. Checks:
 * - Total RAM usage
 * - Available free memory
 * - Memory pressure indicators
 *
 * **Operation:**
 * 1. Read memory statistics from /proc/meminfo
 * 2. Calculate memory usage percentage
 * 3. Compare against threshold
 * 4. Generate alert if threshold exceeded
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (memory-monitor 90)  // Alert if memory usage > 90%
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->a.u32: Memory threshold percentage (0-100)
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 * @note Requires /proc/meminfo access
 *
 * @see Memory_Monitor_Start() in functions_memory_mon.c
 */
static int32 INVOKE_Memory_Mon_Check(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (memory_mon_check_running == 0)
	{
		memory_mon_check_running = 1;
		
		/* Start memory monitoring */
		Memory_Monitor_Start(args->a.u32, args->iob_id);
		
		memory_mon_check_running = 0;
	}

	return CFE_SUCCESS;
}

/*=======================================================================================
** Command Tracking Functions
**=======================================================================================*/

/**
 * @brief Get propulsion burn duration
 *
 * Retrieves the accumulated duration of propulsion burns since the last
 * deactivation trigger. Used to detect excessive propulsion usage.
 *
 * **Operation:**
 * 1. Check if propulsion burn is active
 * 2. If inactive, calculate duration since activation
 * 3. Return duration in seconds
 * 4. Clear duration counter
 *
 * **Usage in Rules:**
 * @code
 * (> (propulsion-burn-dur) 300)  // Alert if burn > 5 minutes
 * @endcode
 *
 * @param[in] args Argument blob (unused)
 * @param[out] ret_buf Buffer to receive duration (uint32_t seconds)
 * @param[in] ret_buf_len Length of return buffer
 * @param[out] ret_len Actual length of return data
 *
 * @return int32 CFE_SUCCESS on success, CFE_ES_BAD_ARGUMENT on error
 *
 * @note Returns 0 if burn is still active
 * @note Duration is cleared after retrieval
 *
 * @see SPACECOP_RemoveCountDurationIfInactive() in spacecop_table_runtime.c
 */
static int32 INVOKE_PropulsionBurnDuration(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	TimeElement_t delta;
	
	/* Validate output parameters */
	if (!ret_buf || !ret_len) return CFE_ES_BAD_ARGUMENT;
	if (ret_buf_len < sizeof(uint32_t)) return CFE_ES_BAD_ARGUMENT;

	/* Get burn duration if inactive */
	delta = SPACECOP_RemoveCountDurationIfInactive(propulsion_burn_duration_id);

	/* Copy seconds to return buffer */
	memcpy(ret_buf, &delta.Seconds, sizeof(delta.Seconds));
	*ret_len = sizeof(delta.Seconds);
	
	return CFE_SUCCESS;
}

/**
 * @brief Get time adjustment command count
 *
 * Retrieves the total number of time adjustment commands received within
 * the monitoring window. Used to detect time manipulation attacks.
 *
 * **Operation:**
 * 1. Get count of time adjustment commands
 * 2. Clean up expired counters
 * 3. Return total count
 *
 * **Usage in Rules:**
 * @code
 * (> (time-controller-adjust-time) 5)  // Alert if > 5 adjustments
 * @endcode
 *
 * @param[in] args Argument blob (unused)
 * @param[out] ret_buf Buffer to receive count (int32_t)
 * @param[in] ret_buf_len Length of return buffer
 * @param[out] ret_len Actual length of return data
 *
 * @return int32 CFE_SUCCESS on success, CFE_ES_BAD_ARGUMENT on error
 *
 * @note Count includes all adjustments in time window
 * @note Expired counters are automatically cleaned up
 *
 * @see SPACECOP_GetCountTotal() in spacecop_table_runtime.c
 */
static int32 INVOKE_AdjustTimeDuration(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	int32_t total;
	
	/* Validate output parameters */
	if (!ret_buf || !ret_len) return CFE_ES_BAD_ARGUMENT;
	if (ret_buf_len < sizeof(uint32_t)) return CFE_ES_BAD_ARGUMENT;

	/* Get total count of time adjustments */
	total = SPACECOP_GetCountTotal(adjust_time_id);
	
	/* Clean up expired counters */
	SPACECOP_CleanupExpiredCounters();

	/* Copy count to return buffer */
	memcpy(ret_buf, &total, sizeof(total));
	*ret_len = sizeof(total);
	
	return CFE_SUCCESS;
}

/*=======================================================================================
** Disk Space Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for disk space check */
static int disk_space_check_running = 0;

/**
 * @brief Check disk space usage
 *
 * Monitors file system disk space usage and generates alerts if usage
 * exceeds specified threshold. Checks:
 * - Total disk space
 * - Available free space
 * - Usage percentage
 *
 * **Operation:**
 * 1. Query file system statistics via statvfs()
 * 2. Calculate disk usage percentage
 * 3. Compare against threshold
 * 4. Generate alert if threshold exceeded
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (disk-space 90.0)  // Alert if disk usage > 90%
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->a.f32: Disk usage threshold percentage (0.0-100.0)
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 * @note Checks root file system by default
 *
 * @see CheckDiskSpace() in functions_disk_linux.c
 */
static int32 INVOKE_Disk_Space_Check(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (disk_space_check_running == 0)
	{
		disk_space_check_running = 1;
		
		/* Perform disk space check */
		CheckDiskSpace(args->a.f32, args->iob_id);
		
		disk_space_check_running = 0;
	}

	return CFE_SUCCESS;
}

/*=======================================================================================
** Memory Region Monitoring Functions
**=======================================================================================*/

/** @brief Concurrency control flag for payload memory monitor */
static int payload_monitor_running = 0;

/**
 * @brief Monitor payload memory region
 *
 * Monitors the payload memory region for unauthorized modifications.
 * Detects memory corruption in payload data structures.
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (memory-monitor-payload)  // Check payload memory integrity
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 *
 * @see Memory_Monitor_Payload_Start() in functions_memory_mon.c
 */
static int32 INVOKE_Memory_Monitor_Payload(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (payload_monitor_running == 0)
	{
		payload_monitor_running = 1;
		
		/* Start payload memory monitoring */
		Memory_Monitor_Payload_Start(args->iob_id);
		
		payload_monitor_running = 0;
	}
	
	return CFE_SUCCESS;
}

/** @brief Concurrency control flag for boot memory monitor */
static int boot_monitor_running = 0;

/**
 * @brief Monitor boot memory region
 *
 * Monitors the boot memory region for unauthorized modifications.
 * Detects memory corruption in boot code and data structures.
 *
 * **Concurrency:**
 * Uses static flag to prevent concurrent execution.
 *
 * **Usage in Rules:**
 * @code
 * (memory-monitor-boot)  // Check boot memory integrity
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note Non-blocking if already running
 *
 * @see Memory_Monitor_Boot_Start() in functions_memory_mon.c
 */
static int32 INVOKE_Memory_Monitor_Boot(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Check if already running (prevent concurrent execution) */
	if (boot_monitor_running == 0)
	{
		boot_monitor_running = 1;
		
		/* Start boot memory monitoring */
		Memory_Monitor_Boot_Start(args->iob_id);
		
		boot_monitor_running = 0;
	}
	
	return CFE_SUCCESS;
}

/**
 * @brief Register critical memory regions for monitoring
 *
 * Registers application-critical memory regions with the memory monitor.
 * Enables detection of unauthorized modifications to critical data structures.
 *
 * **Registered Regions:**
 * - Command counter: Uses parity-based detection
 * - Error counter: Uses checksum-based detection
 *
 * **Detection Methods:**
 * - DETECT_METHOD_PARITY: Fast single-bit error detection
 * - DETECT_METHOD_CHECKSUM: More robust multi-bit error detection
 *
 * @return void
 *
 * @note Called once during initialization
 * @note Sends EVS events for each registration
 * @note Add additional regions as needed
 *
 * @see Memory_Monitor_RegisterCritical() in functions_memory_mon.c
 */
static void SPACECOP_RegisterCriticalMemory(void)
{
    int result;
    
    CFE_EVS_SendEvent(3000, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Registering critical memory regions...");
    
    /* Register command counter with parity-based detection */
    result = Memory_Monitor_RegisterCritical(
        &SPACECOP_AppData.HkTelemetryPkt.CommandCount,
        sizeof(SPACECOP_AppData.HkTelemetryPkt.CommandCount),
        "SPACECOP_CmdCounter",
        DETECT_METHOD_PARITY
    );
    
    if (result >= 0) {
        CFE_EVS_SendEvent(3001, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] Registered: SPACECOP_CmdCounter (region %d)", result);
    }
    
    /* Register error counter with checksum-based detection */
    result = Memory_Monitor_RegisterCritical(
        &SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount,
        sizeof(SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount),
        "SPACECOP_ErrCounter",
        DETECT_METHOD_CHECKSUM
    );
    
    if (result >= 0) {
        CFE_EVS_SendEvent(3002, CFE_EVS_EventType_INFORMATION,
                         "[SPACECOP] Registered: SPACECOP_ErrCounter (region %d)", result);
    }
    
    CFE_EVS_SendEvent(3005, CFE_EVS_EventType_INFORMATION,
                     "[SPACECOP] Critical memory registration complete");
}

/** @brief Concurrency control flag for critical memory monitor */
static int critical_monitor_running = 0;

/** @brief Initialization flag for critical memory registration */
static int critical_monitor_init = 0;

/**
 * @brief Monitor critical memory regions
 *
 * Monitors registered critical memory regions for unauthorized modifications.
 * Detects memory corruption using configured detection methods (parity,
 * checksum, etc.).
 *
 * **Operation:**
 * 1. On first call: Register critical memory regions
 * 2. Verify integrity of all registered regions
 * 3. Generate alerts for detected corruption
 *
 * **Concurrency:**
 * Uses static flags for initialization and execution control.
 *
 * **Usage in Rules:**
 * @code
 * (memory-monitor-critical)  // Check critical memory integrity
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 CFE_SUCCESS always
 *
 * @note First call performs registration
 * @note Non-blocking if already running
 *
 * @see SPACECOP_RegisterCriticalMemory()
 * @see Memory_Monitor_Critical_Start() in functions_memory_mon.c
 */
static int32 INVOKE_Memory_Monitor_Critical(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Initialize critical memory regions on first call */
	if (critical_monitor_init == 0)
	{
		SPACECOP_RegisterCriticalMemory();
		critical_monitor_init = 1;
	}

	/* Check if already running (prevent concurrent execution) */
	if (critical_monitor_running == 0)
	{
		critical_monitor_running = 1;
		
		/* Start critical memory monitoring */
		Memory_Monitor_Critical_Start(args->iob_id);
		
		critical_monitor_running = 0;
	}
	
	return CFE_SUCCESS;
}

/*=======================================================================================
** Telemetry Latency Tracking Functions
**=======================================================================================*/

/**
 * @brief Calculate telemetry downlink latency
 *
 * Measures the time delay between telemetry generation and downlink.
 * Used to detect telemetry suppression or routing attacks.
 *
 * **Operation:**
 * 1. Track telemetry packet timestamps
 * 2. Compare against expected downlink time
 * 3. Calculate latency delta
 * 4. Periodically clean up old trackers
 *
 * **Usage in Rules:**
 * @code
 * (> (tlm-downlink) 10)  // Alert if latency > 10 seconds
 * @endcode
 *
 * @param[in] args Argument blob (unused)
 * @param[out] ret_buf Buffer to receive latency (uint32_t seconds)
 * @param[in] ret_buf_len Length of return buffer
 * @param[out] ret_len Actual length of return data
 *
 * @return int32 CFE_SUCCESS on success, CFE_ES_BAD_ARGUMENT on error
 *
 * @note Cleanup performed every 20 calls
 * @note Debug output available via SPACECOP_MONITOR_DEBUG
 *
 * @see SPACECOP_EvaluateLatency() in spacecop_table_runtime.c
 */
static int32 INVOKE_TlmDownlinkDelay(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len) 
{
	/* Validate output parameters */
	if (!ret_buf || !ret_len) {
        return CFE_ES_BAD_ARGUMENT;
    }
    if (ret_buf_len < sizeof(uint32_t)) {
        return CFE_ES_BAD_ARGUMENT;
    }
   
    /* Evaluate telemetry latency */
    uint32_t latency_delta_sec = SPACECOP_EvaluateLatency(tlm_downlink_id);
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: INVOKE_TlmDownlinkDelay returned delta=%u sec\n", latency_delta_sec);
    #endif
    
    /* Copy latency to return buffer */
    memcpy(ret_buf, &latency_delta_sec, sizeof(latency_delta_sec));
    *ret_len = sizeof(latency_delta_sec);
    
    /* Periodically clean up old trackers */
    static uint32_t cleanup_counter = 0;
    if (++cleanup_counter % 20 == 0) {
        SPACECOP_CleanupTrackers();
    }
    
    return CFE_SUCCESS;
}

/*=======================================================================================
** Machine Learning Integration Functions
**=======================================================================================*/

/**
 * @brief Enable ML anomaly monitoring for an IOB
 *
 * Toggles ML monitoring for the specified IOB. The ML alert receive loop
 * (MLBridge_CheckForResponse) is NOT started here -- it is owned by the
 * dedicated RunMLResp child task, created once at app init and always running.
 * This action only updates which IOB is ML-monitored, so a rule may invoke it
 * repeatedly without spawning duplicate accept() loops on ML_RECV_PORT (9112).
 *
 * **Usage in Rules:**
 * @code
 * (ml-monitor)  // Enable ML monitoring for this IOB
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for alerts
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 OS_SUCCESS
 *
 * @note Does NOT create a task; the accept loop runs in RunMLResp.
 * @note Requires the ML bridge initialized (InitSockets at app init).
 *
 * @see MLBridge_CheckForResponse() in ml_interface.c (run by RunMLResp)
 */
static int32 INVOKE_MLMonitor(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	(void)ret_buf;
	(void)ret_buf_len;
	(void)ret_len;

	/* Configure which IOB is ML-monitored. The ML alert receive loop
	** (MLBridge_CheckForResponse) is owned by the dedicated RunMLResp child
	** task -- created once at app init and always running -- so do NOT spawn a
	** second task running it here. Two tasks accept()ing on ML_RECV_PORT (9112)
	** race on socket setup and re-bind the port repeatedly. */
	Toggle_MLMonitor(args->iob_id);

	return OS_SUCCESS;
}

/*=======================================================================================
** State Change Tracking Functions
**=======================================================================================*/

/**
 * @brief Toggle state change reporter
 *
 * Enables or disables state change reporting for the specified IOB.
 * Used to track system state transitions.
 *
 * **Usage in Rules:**
 * @code
 * (state-change)  // Toggle state change reporting
 * @endcode
 *
 * @param[in] args Argument blob containing:
 *                 - args->iob_id: IOB identifier for state tracking
 * @param[out] ret_buf Return buffer (unused)
 * @param[in] ret_buf_len Return buffer length (unused)
 * @param[out] ret_len Return length (unused)
 *
 * @return int32 OS_SUCCESS always
 *
 * @see Toggle_Reporter() in functions_command_monitors.c
 */
static int32 INVOKE_StateChange(const ArgBlob* args, uint8_t* ret_buf, uint16_t ret_buf_len, uint16_t* ret_len)
{
	/* Toggle state change reporter for this IOB */
	Toggle_Reporter(args->iob_id);

	return OS_SUCCESS;
}

/*=======================================================================================
** Function Registry Symbol Table
**=======================================================================================*/

/**
 * @brief Function registry symbol table
 *
 * Maps function names and call indices to their implementations. Each entry
 * specifies:
 * - name: String identifier used in rule table
 * - call_index: Numeric identifier for fast lookup
 * - fn: Function pointer to implementation
 * - ret_type: Return type (RT_NONE, RT_U32, RT_I32, RT_F32)
 * - ret_size: Size of return value in bytes
 * - expected_args: Argument type (ARG_NONE, ARG_U32, ARG_I32, ARG_F32)
 * - need_iob: Whether function requires IOB identifier
 *
 * **Adding New Functions:**
 * 1. Implement function following INVOKE_* naming convention
 * 2. Add entry to kSyms table
 * 3. Assign unique call_index
 * 4. Specify argument and return types
 * 5. Set need_iob flag if IOB required
 *
 * @note Keep call_index values unique
 * @note Update table size if adding many functions
 */
static const SymEntry kSyms[] =
{
	{ .name = "time-controller", .call_index = 0, .fn = INVOKE_CFE_TIME_GetTime, .ret_type = RT_U32, .ret_size = sizeof(uint32_t), .expected_args = ARG_NONE },
	{ .name = "procmon-cpu-check", .call_index = 1, .fn = INVOKE_PROCMon_CPU_Check, .expected_args = ARG_F32, .need_iob = 1 },
	{ .name = "procmon-process-check", .call_index = 2, .fn = INVOKE_PROCMon_Process_Check, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "file-integrity", .call_index = 3, .fn = INVOKE_FileIntegrity_Check, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "syscall-monitor", .call_index = 4, .fn = INVOKE_SyscallMonitor, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "memory-monitor", .call_index = 5, .fn = INVOKE_Memory_Mon_Check, .expected_args = ARG_U32, .need_iob = 1},
	{ .name = "propulsion-burn-dur", .call_index = 6, .fn = INVOKE_PropulsionBurnDuration, .expected_args = ARG_NONE, .need_iob = 0, .ret_type=RT_U32, .ret_size = sizeof(uint32_t)},
	{ .name = "disk-space", .call_index = 7, .fn = INVOKE_Disk_Space_Check, .expected_args = ARG_F32, .need_iob = 1},
	{ .name = "time-controller-adjust-time", .call_index = 8, .fn = INVOKE_AdjustTimeDuration, .expected_args = ARG_NONE, .need_iob = 0, .ret_type=RT_U32, .ret_size = sizeof(uint32_t)},
	{ .name = "memory-monitor-payload", .call_index = 9, .fn = INVOKE_Memory_Monitor_Payload, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "memory-monitor-boot", .call_index = 10, .fn = INVOKE_Memory_Monitor_Boot, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "memory-monitor-critical", .call_index = 11, .fn = INVOKE_Memory_Monitor_Critical, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "tlm-downlink", .call_index = 12, .fn = INVOKE_TlmDownlinkDelay, .expected_args = ARG_NONE, .need_iob = 0, .ret_type=RT_U32, .ret_size = sizeof(uint32_t)},
	{ .name = "ml-monitor", .call_index = 13, .fn = INVOKE_MLMonitor, .expected_args = ARG_NONE, .need_iob = 1},
	{ .name = "state-change", .call_index = 14, .fn = INVOKE_StateChange, .expected_args = ARG_NONE, .need_iob = 1},
};

/*=======================================================================================
** Function Registry Lookup
**=======================================================================================*/

/**
 * @brief Find symbol entry by call index
 *
 * Searches the function registry for an entry with the specified call index.
 * Used by rule executor to locate function implementations.
 *
 * @param[in] call_index Numeric function identifier
 *
 * @return const SymEntry* Pointer to symbol entry, or NULL if not found
 *
 * @note Linear search - O(n) complexity
 * @note Consider hash table for large registries
 *
 * Example usage:
 * @code
 * const SymEntry* sym = FindSym(3);
 * if (sym != NULL) {
 *     // Call function via sym->fn
 * }
 * @endcode
 */
const SymEntry* FindSym(uint16_t call_index)
{
	for (uint32_t i = 0; i < (sizeof(kSyms)/sizeof(kSyms[0])); i++)
	{
		if (kSyms[i].call_index == call_index)
			return &kSyms[i];
	}
	return NULL;
}