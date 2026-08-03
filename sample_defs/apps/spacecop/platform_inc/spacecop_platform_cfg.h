// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_platform_cfg.h
 * @brief SpaceCop platform-specific configuration parameters
 *
 * This header defines platform-specific configuration parameters for SpaceCop
 * that may vary between different deployment environments, hardware platforms,
 * and mission configurations. These parameters are compile-time constants that
 * tailor SpaceCop to specific hardware and operational requirements.
 *
 * **Configuration Philosophy:**
 * SpaceCop separates configuration into two categories:
 * - **Platform Configuration (this file):** Hardware-specific settings that
 *   vary by deployment platform (processor, I/O devices, interfaces)
 * - **Mission Configuration:** Operational parameters that vary by mission
 *   (detection rules, thresholds, policies)
 *
 * **Platform vs. Mission Configuration:**
 * @code
 * Platform Config (spacecop_platform_cfg.h):
 * - UART device names and handles
 * - Baud rates and timing
 * - Hardware interface parameters
 * - Debug flags
 * - Compile-time hardware settings
 *
 * Mission Config (tables, runtime):
 * - Detection rule thresholds
 * - IOB enable/disable
 * - Alert policies
 * - Network addresses
 * - Operational schedules
 * @endcode
 *
 * **Deployment Environments:**
 * SpaceCop supports multiple deployment environments:
 *
 * 1. **NOS3 (NASA Operational Simulator for Small Satellites):**
 *    - Software-in-the-loop simulation
 *    - Virtual UART devices
 *    - Development and testing environment
 *    - Default configuration provided
 *
 * 2. **Flight Hardware:**
 *    - Real spacecraft processors
 *    - Actual UART/serial interfaces
 *    - Mission-specific hardware
 *    - Requires custom configuration
 *
 * 3. **Hardware-in-the-Loop (HITL):**
 *    - Real flight hardware
 *    - Simulated environment
 *    - Integration testing
 *    - May use flight or simulation config
 *
 * **Configuration Override:**
 * Platform configuration can be overridden at compile time:
 * @code
 * # Override via compiler flags
 * gcc -DSPACECOP_CFG_BAUDRATE_HZ=9600 ...
 * 
 * # Override via build system
 * set(SPACECOP_CFG_BAUDRATE_HZ 9600)
 * 
 * # Override via separate header
 * #define SPACECOP_CFG
 * #include "mission_specific_config.h"
 * @endcode
 *
 * **NOS3 Integration:**
 * NOS3 is NASA's open-source small satellite simulator. SpaceCop's default
 * configuration targets NOS3 for development and testing:
 * - Virtual UART device simulation
 * - Matching handle and bus number requirements
 * - Standard baud rates for simulation
 * - Reasonable timeouts for virtual hardware
 *
 * **UART Configuration:**
 * SpaceCop may use UART interfaces for:
 * - External sensor integration
 * - Hardware security module communication
 * - Debug output
 * - Legacy device monitoring
 *
 * **Usage Example:**
 * @code
 * // In SpaceCop initialization
 * void SPACECOP_InitHardware(void) {
 *     // Open UART device
 *     int32 status = UART_Init(SPACECOP_CFG_STRING,
 *                              SPACECOP_CFG_HANDLE,
 *                              SPACECOP_CFG_BAUDRATE_HZ);
 *     
 *     if (status != SUCCESS) {
 *         CFE_EVS_SendEvent(SPACECOP_UART_ERR_EID,
 *                          CFE_EVS_ERROR,
 *                          "Failed to initialize UART %s: %d",
 *                          SPACECOP_CFG_STRING, status);
 *         return;
 *     }
 *     
 *     // Set timeout
 *     UART_SetTimeout(SPACECOP_CFG_HANDLE, SPACECOP_CFG_MS_TIMEOUT);
 *     
 *     #ifdef SPACECOP_CFG_DEBUG
 *     CFE_EVS_SendEvent(SPACECOP_DEBUG_EID, CFE_EVS_DEBUG,
 *                      "UART initialized: %s @ %d baud",
 *                      SPACECOP_CFG_STRING,
 *                      SPACECOP_CFG_BAUDRATE_HZ);
 *     #endif
 * }
 * @endcode
 *
 * **Mission-Specific Configuration:**
 * To create mission-specific configuration:
 * @code
 * // mission_platform_cfg.h
 * #ifndef SPACECOP_CFG
 * #define SPACECOP_CFG
 * 
 * // Mission-specific UART settings
 * #define SPACECOP_CFG_STRING           "/dev/ttyS2"
 * #define SPACECOP_CFG_HANDLE           2
 * #define SPACECOP_CFG_BAUDRATE_HZ      57600
 * #define SPACECOP_CFG_MS_TIMEOUT       100
 * 
 * // Enable debug for ground testing
 * #define SPACECOP_CFG_DEBUG
 * 
 * #endif
 * 
 * // In CMakeLists.txt
 * target_compile_definitions(spacecop PRIVATE
 *     -DSPACECOP_CFG
 *     -include mission_platform_cfg.h
 * )
 * @endcode
 *
 * **Debug Flag:**
 * SPACECOP_CFG_DEBUG enables additional diagnostic output:
 * - Verbose EVS events
 * - Detailed error messages
 * - Performance timing
 * - State transition logging
 *
 * Should be disabled for flight to reduce:
 * - EVS message volume
 * - CPU overhead
 * - Telemetry bandwidth
 *
 * **Validation:**
 * Configuration parameters should be validated at compile time:
 * @code
 * #if SPACECOP_CFG_BAUDRATE_HZ < 9600
 * #error "SPACECOP_CFG_BAUDRATE_HZ too low (minimum 9600)"
 * #endif
 * 
 * #if SPACECOP_CFG_MS_TIMEOUT > 255
 * #error "SPACECOP_CFG_MS_TIMEOUT exceeds maximum (255)"
 * #endif
 * @endcode
 *
 * @note Configuration is compile-time only (not runtime configurable)
 * @note Changes require recompilation
 * @note Default configuration targets NOS3 simulator
 * @note Flight missions should create custom configuration
 *
 * @see spacecop_mission_cfg.h for mission-specific parameters
 * @see NOS3 documentation for simulator configuration
 */

/************************************************************************
** File:
**   $Id: spacecop_platform_cfg.h  $
**
** Purpose:
**  Define spacecop Platform Configuration Parameters
**
** Notes:
**
*************************************************************************/
#ifndef _SPACECOP_PLATFORM_CFG_H_
#define _SPACECOP_PLATFORM_CFG_H_

/*=======================================================================================
** Deploy Filesystem Layout
**
** Physical (host) paths, split by trust level for the flight deploy:
**   - CF   : read-only code/tables/kernel-module + config (whitelist). Mounted
**            read-only at runtime; only the deploy process writes it.
**   - DATA : writable picture storage.
**   - LOGS : writable IDS + application logs.
**   - CTI  : writable threat-intel sharing (untrusted peer input).
** DATA/LOGS/CTI should be a separate, noexec,nosuid,nodev mount from CF.
**
** These are used by RAW POSIX access (fopen/open/opendir/system) which does
** NOT go through the OSAL virtual filesystem. They MUST match the
** OS_FileSysAddFixedMap() targets in psp/fsw/pc-linux/src/cfe_psp_start.c.
**=======================================================================================*/
#define SPACECOP_CF_DIR    "/opt/pisat/cf"     /**< read-only: .so/.tbl/.ko/whitelist */
#define SPACECOP_DATA_DIR  "/var/pisat/data"   /**< writable: pictures                */
#define SPACECOP_LOGS_DIR  "/var/pisat/logs"   /**< writable: IDS + app logs          */
#define SPACECOP_CTI_DIR   "/var/pisat/cti"    /**< writable: threat-intel sharing    */

/*
** Virtual (OSAL) mount points - used by OSAL access (OS_OpenCreate/OS_write) and
** cFE Table Services, which resolve through the PSP FixedMap to the physical
** paths above. "/cf" is a cFE convention (app/table/startup loads) and is kept.
*/
#define SPACECOP_CF_VDIR   "/cf"
#define SPACECOP_LOGS_VDIR "/logs"
#define SPACECOP_CTI_VDIR  "/cti"

/*=======================================================================================
** Platform Configuration Parameters
**=======================================================================================*/

/**
 * @brief Default SpaceCop platform configuration
 * 
 * Provides default platform configuration parameters optimized for NOS3
 * (NASA Operational Simulator for Small Satellites) development environment.
 * These settings can be overridden by defining SPACECOP_CFG before including
 * this header.
 *
 * **Configuration Guard:**
 * The #ifndef SPACECOP_CFG guard allows mission-specific configurations to
 * override these defaults by defining SPACECOP_CFG and providing alternative
 * values before this header is included.
 *
 * **Override Example:**
 * @code
 * // In mission-specific header included before this file
 * #define SPACECOP_CFG
 * #define SPACECOP_CFG_STRING "/dev/ttyS1"
 * #define SPACECOP_CFG_HANDLE 1
 * // ... other overrides
 * @endcode
 */
#ifndef SPACECOP_CFG

    /**
     * @brief UART device string identifier
     * 
     * Specifies the UART device name/path for SpaceCop hardware communication.
     * Format and naming convention depends on the operating system and
     * hardware abstraction layer.
     *
     * **Platform-Specific Formats:**
     * 
     * - **NOS3 (Default):** "usart_N" where N is the UART number
     *   - Example: "usart_16"
     *   - Virtual UART device in simulator
     *   - Must match SPACECOP_CFG_HANDLE
     * 
     * - **Linux:** "/dev/ttyS_N" or "/dev/ttyUSB_N"
     *   - Example: "/dev/ttyS2"
     *   - Standard Linux serial device paths
     * 
     * - **VxWorks:** "/tyCo/N"
     *   - Example: "/tyCo/1"
     *   - VxWorks serial device naming
     * 
     * - **RTEMS:** "/dev/console" or "/dev/ttyS_N"
     *   - Example: "/dev/ttyS1"
     *   - RTEMS device paths
     *
     * **NOS3 Requirements:**
     * In NOS3, the UART device string must follow the "usart_N" format
     * where N matches the SPACECOP_CFG_HANDLE value. This is a NOS3-specific
     * requirement for proper device simulation.
     *
     * **Usage:**
     * @code
     * // Open UART device
     * int fd = open(SPACECOP_CFG_STRING, O_RDWR);
     * if (fd < 0) {
     *     CFE_EVS_SendEvent(ERR_EID, CFE_EVS_ERROR,
     *                      "Failed to open UART: %s", SPACECOP_CFG_STRING);
     * }
     * @endcode
     *
     * @note NOS3 requires matching handle and bus number
     * @note Linux paths typically require root or dialout group membership
     * @note Maximum length should not exceed OS path limits
     *
     * @see SPACECOP_CFG_HANDLE for associated handle number
     */
    #define SPACECOP_CFG_STRING           "usart_16"

    /**
     * @brief UART device handle number
     * 
     * Numeric identifier for the UART device. Used for device indexing and
     * in NOS3 simulation, must match the number in SPACECOP_CFG_STRING.
     *
     * **Handle Assignment:**
     * - Should be unique within the system
     * - Typically corresponds to hardware UART number
     * - In NOS3, must match the number in "usart_N"
     * - Range: 0-255 (hardware dependent)
     *
     * **NOS3 Matching Requirement:**
     * @code
     * // Correct NOS3 configuration
     * #define SPACECOP_CFG_STRING "usart_16"
     * #define SPACECOP_CFG_HANDLE 16        // Matches!
     * 
     * // Incorrect NOS3 configuration
     * #define SPACECOP_CFG_STRING "usart_16"
     * #define SPACECOP_CFG_HANDLE 2         // Mismatch - will fail!
     * @endcode
     *
     * **Usage:**
     * @code
     * // Initialize UART with handle
     * status = UART_Init(SPACECOP_CFG_STRING, 
     *                   SPACECOP_CFG_HANDLE,
     *                   SPACECOP_CFG_BAUDRATE_HZ);
     * 
     * // Use handle for operations
     * UART_Write(SPACECOP_CFG_HANDLE, data, length);
     * UART_Read(SPACECOP_CFG_HANDLE, buffer, size);
     * @endcode
     *
     * **Handle Conflicts:**
     * Ensure handle does not conflict with other applications:
     * @code
     * // Check for conflicts in system integration
     * App A: UART Handle 1
     * App B: UART Handle 2
     * SpaceCop: UART Handle 16  // No conflict
     * @endcode
     *
     * @note Must match number in SPACECOP_CFG_STRING for NOS3
     * @note Should be unique across all applications
     * @note Hardware-dependent valid range
     *
     * @see SPACECOP_CFG_STRING for device path
     */
    #define SPACECOP_CFG_HANDLE           16

    /**
     * @brief UART baud rate in Hz
     * 
     * Specifies the serial communication baud rate (bits per second) for
     * UART communication. Must match the baud rate of connected devices.
     *
     * **Standard Baud Rates:**
     * - 9600: Low-speed, high reliability
     * - 19200: Moderate speed
     * - 38400: Common for industrial devices
     * - 57600: Higher speed, good reliability
     * - 115200: High-speed (default), widely supported
     * - 230400: Very high-speed
     * - 460800: Maximum for many devices
     *
     * **Default: 115200 baud**
     * - Good balance of speed and reliability
     * - Widely supported by hardware
     * - Suitable for most applications
     * - Works well in NOS3 simulation
     *
     * **Baud Rate Selection:**
     * @code
     * // Low-speed, maximum reliability
     * #define SPACECOP_CFG_BAUDRATE_HZ 9600
     * 
     * // Standard speed (default)
     * #define SPACECOP_CFG_BAUDRATE_HZ 115200
     * 
     * // High-speed for high data rate
     * #define SPACECOP_CFG_BAUDRATE_HZ 460800
     * @endcode
     *
     * **Considerations:**
     * - Higher baud rates more susceptible to noise
     * - Cable length limits increase at lower baud rates
     * - Must match connected device baud rate exactly
     * - Simulation (NOS3) less sensitive to baud rate
     * - Flight hardware may have limitations
     *
     * **Error Detection:**
     * @code
     * // Validate baud rate at compile time
     * #if SPACECOP_CFG_BAUDRATE_HZ < 9600
     * #warning "Baud rate very low - may impact performance"
     * #endif
     * 
     * #if SPACECOP_CFG_BAUDRATE_HZ > 460800
     * #error "Baud rate exceeds typical hardware limits"
     * #endif
     * @endcode
     *
     * **Usage:**
     * @code
     * // Configure UART baud rate
     * UART_SetBaudRate(SPACECOP_CFG_HANDLE, SPACECOP_CFG_BAUDRATE_HZ);
     * 
     * // Log configuration
     * CFE_EVS_SendEvent(INFO_EID, CFE_EVS_INFORMATION,
     *                  "UART configured: %d baud", 
     *                  SPACECOP_CFG_BAUDRATE_HZ);
     * @endcode
     *
     * @note Must match connected device baud rate
     * @note Higher rates require better signal quality
     * @note Simulation less sensitive to baud rate choice
     *
     * @see SPACECOP_CFG_MS_TIMEOUT for related timing parameter
     */
    #define SPACECOP_CFG_BAUDRATE_HZ      115200

    /**
     * @brief UART read/write timeout in milliseconds
     * 
     * Specifies the maximum time to wait for UART read/write operations
     * to complete before timing out. Prevents indefinite blocking on
     * unresponsive devices.
     *
     * **Default: 50 milliseconds**
     * - Reasonable for most devices
     * - Prevents excessive blocking
     * - Works well in simulation
     * - Balances responsiveness and reliability
     *
     * **Timeout Selection:**
     * @code
     * // Very short timeout (responsive but may miss data)
     * #define SPACECOP_CFG_MS_TIMEOUT 10
     * 
     * // Standard timeout (default, recommended)
     * #define SPACECOP_CFG_MS_TIMEOUT 50
     * 
     * // Long timeout (for slow devices)
     * #define SPACECOP_CFG_MS_TIMEOUT 200
     * @endcode
     *
     * **Timeout Considerations:**
     * - Too short: May timeout before device responds
     * - Too long: May block application too long
     * - Should account for device response time
     * - Should account for message transmission time
     * - Simulation may need different timeout than flight
     *
     * **Transmission Time Calculation:**
     * @code
     * // Calculate minimum timeout for message
     * message_bits = (data_bytes + overhead) * 10;  // 10 bits per byte
     * min_timeout_ms = (message_bits * 1000) / SPACECOP_CFG_BAUDRATE_HZ;
     * 
     * // Example: 100 bytes at 115200 baud
     * message_bits = 100 * 10 = 1000 bits
     * min_timeout_ms = (1000 * 1000) / 115200 = ~8.7 ms
     * 
     * // Add margin for device processing
     * recommended_timeout = min_timeout_ms * 5 = ~45 ms
     * @endcode
     *
     * **Hardware Limitation:**
     * Maximum value is 255 milliseconds due to hardware/driver constraints.
     * Longer timeouts require multiple timeout periods or alternative
     * timeout mechanisms.
     *
     * **Usage:**
     * @code
     * // Set timeout on UART device
     * UART_SetTimeout(SPACECOP_CFG_HANDLE, SPACECOP_CFG_MS_TIMEOUT);
     * 
     * // Read with timeout
     * int32 bytes = UART_Read(SPACECOP_CFG_HANDLE, buffer, size);
     * if (bytes < 0) {
     *     if (errno == ETIMEDOUT) {
     *         // Timeout occurred
     *         CFE_EVS_SendEvent(WARN_EID, CFE_EVS_WARNING,
     *                          "UART read timeout after %d ms",
     *                          SPACECOP_CFG_MS_TIMEOUT);
     *     }
     * }
     * @endcode
     *
     * **Timeout vs. Polling:**
     * @code
     * // Blocking read with timeout (preferred)
     * bytes = UART_Read(handle, buffer, size);  // Returns after timeout
     * 
     * // Non-blocking poll (alternative)
     * while (!UART_DataAvailable(handle) && elapsed < timeout) {
     *     OS_TaskDelay(10);
     *     elapsed += 10;
     * }
     * @endcode
     *
     * @note Maximum value is 255 milliseconds
     * @note Applies to both read and write operations
     * @note Should be tuned for specific hardware
     * @note Simulation may tolerate shorter timeouts
     *
     * @see SPACECOP_CFG_BAUDRATE_HZ for baud rate setting
     */
    #define SPACECOP_CFG_MS_TIMEOUT       50

    /**
     * @brief Debug flag for verbose diagnostic output
     * 
     * When defined, enables additional diagnostic and debug output throughout
     * SpaceCop. Useful for development, testing, and troubleshooting but
     * should be disabled for flight to reduce overhead.
     *
     * **Debug Features Enabled:**
     * - Verbose EVS events
     * - Detailed error messages
     * - State transition logging
     * - Performance timing output
     * - Parameter validation messages
     * - Function entry/exit tracing
     * - Memory operation logging
     *
     * **Default: Disabled (commented out)**
     * Debug output is disabled by default to:
     * - Reduce EVS message volume
     * - Minimize CPU overhead
     * - Decrease telemetry bandwidth usage
     * - Avoid log file bloat
     * - Meet flight performance requirements
     *
     * **Enabling Debug:**
     * @code
     * // Method 1: Uncomment in this file
     * #define SPACECOP_CFG_DEBUG
     * 
     * // Method 2: Compiler flag
     * gcc -DSPACECOP_CFG_DEBUG ...
     * 
     * // Method 3: CMake
     * target_compile_definitions(spacecop PRIVATE SPACECOP_CFG_DEBUG)
     * @endcode
     *
     * **Usage in Code:**
     * @code
     * void SPACECOP_ProcessCommand(void) {
     *     #ifdef SPACECOP_CFG_DEBUG
     *     CFE_EVS_SendEvent(DEBUG_EID, CFE_EVS_DEBUG,
     *                      "Processing command: FC=%d", function_code);
     *     #endif
     *     
     *     // Process command
     *     
     *     #ifdef SPACECOP_CFG_DEBUG
     *     CFE_EVS_SendEvent(DEBUG_EID, CFE_EVS_DEBUG,
     *                      "Command processing complete: status=%d", status);
     *     #endif
     * }
     * 
     * // Performance timing
     * #ifdef SPACECOP_CFG_DEBUG
     * uint32 start_time = OS_TimeGetTotalMilliseconds();
     * #endif
     * 
     * execute_detection_rules();
     * 
     * #ifdef SPACECOP_CFG_DEBUG
     * uint32 elapsed = OS_TimeGetTotalMilliseconds() - start_time;
     * CFE_EVS_SendEvent(DEBUG_EID, CFE_EVS_DEBUG,
     *                  "Rule evaluation took %u ms", elapsed);
     * #endif
     * @endcode
     *
     * **Debug Levels:**
     * @code
     * // Basic debug (function entry/exit)
     * #define SPACECOP_CFG_DEBUG
     * 
     * // Verbose debug (detailed tracing)
     * #define SPACECOP_CFG_DEBUG
     * #define SPACECOP_CFG_DEBUG_VERBOSE
     * 
     * // Performance profiling
     * #define SPACECOP_CFG_DEBUG
     * #define SPACECOP_CFG_DEBUG_PERFORMANCE
     * @endcode
     *
     * **Impact Analysis:**
     * @code
     * Debug Overhead:
     * - CPU: +5-10% (EVS message generation)
     * - Memory: +2-5% (debug strings)
     * - Telemetry: +20-50% (additional events)
     * - Log files: +100-300% (verbose output)
     * @endcode
     *
     * **When to Enable:**
     * - Development and unit testing
     * - Integration testing
     * - Troubleshooting anomalies
     * - Performance profiling
     * - Ground system testing
     *
     * **When to Disable:**
     * - Flight builds (always)
     * - Performance testing
     * - Long-duration testing
     * - Telemetry bandwidth limited
     * - Production releases
     *
     * **Compile-Time Removal:**
     * When disabled, debug code is completely removed by preprocessor,
     * resulting in zero runtime overhead:
     * @code
     * // With SPACECOP_CFG_DEBUG undefined
     * #ifdef SPACECOP_CFG_DEBUG
     * expensive_debug_operation();  // Completely removed from binary
     * #endif
     * @endcode
     *
     * @note Disabled by default (commented out)
     * @note Should always be disabled for flight
     * @note Zero overhead when disabled (preprocessor removal)
     * @note Can significantly increase EVS message volume
     *
     * @warning Do not enable for flight builds
     * @warning May impact real-time performance if enabled
     * @warning Debug output may contain sensitive information
     */
    //#define SPACECOP_CFG_DEBUG

#endif /* SPACECOP_CFG */

#endif /* _SPACECOP_PLATFORM_CFG_H_ */