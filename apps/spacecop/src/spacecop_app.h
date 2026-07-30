// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_app.h
 * @brief Main header file for the SpaceCop Intrusion Detection System application
 *
 * This header file contains the core data structures, constants, and function
 * prototypes for the SpaceCop IDS application. SpaceCop provides multi-layered
 * threat detection for spacecraft flight software through:
 * - Rule-based intrusion detection
 * - Machine learning anomaly detection
 * - Command monitoring and validation
 * - Cyber Threat Intelligence (CTI) sharing
 * - STIX-formatted alert reporting
 *
 * **Key Components:**
 * - Application data structures and state management
 * - Software Bus pipe definitions
 * - Function prototypes for command/telemetry processing
 * - Integration points for detection subsystems
 *
 * **Architecture:**
 * SpaceCop operates as a cFS application with multiple child tasks for parallel
 * monitoring of different threat vectors. The main task handles ground commands
 * and housekeeping while child tasks execute detection logic.
 *
 * @note This header should be included by all SpaceCop source files
 * @see spacecop_app.c for implementation details
 */

#ifndef _SPACECOP_APP_H_
#define _SPACECOP_APP_H_

/*=======================================================================================
** Include Files
**=======================================================================================*/

/* Standard C library headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>

/* Cryptography headers */
#include <openssl/evp.h>

/* Networking headers */
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>

/* cFE headers */
#include "cfe.h"

/* SpaceCop component headers */
#include "spacecop_events.h"           /* Event message IDs */
#include "spacecop_platform_cfg.h"     /* Platform-specific configuration */
#include "spacecop_perfids.h"          /* Performance monitoring IDs */
#include "spacecop_msg.h"              /* Message structure definitions */
#include "spacecop_msgids.h"           /* Software Bus Message IDs */
#include "spacecop_version.h"          /* Version information */
#include "spacecop_table_runtime.h"    /* Runtime table management */
#include "spacecop_table_defs.h"       /* Table structure definitions */
#include "spacecop_ids_helper.h"       /* IDS utility functions */
#include "spacecop_mission_specific.h" /* Mission-specific customizations */
#include "spacecop_typing.h"           /* Type definitions */
#include "sparta_stix.h"               /* STIX reporting interface */
#include "ml_interface.h"              /* Machine learning bridge interface */

/*=======================================================================================
** Compile-Time Configuration
**=======================================================================================*/

/**
 * @brief Enable debug output for command monitoring
 * 
 * When defined, enables verbose debug output for command monitoring operations
 * including subscription details and message routing information.
 * 
 * @note Comment out for production builds to reduce console output
 */
//#define SPACECOP_MONITOR_DEBUG

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/**
 * @brief Software Bus pipe depth
 * 
 * Maximum number of messages that can be queued in each Software Bus pipe.
 * This depth applies to:
 * - CmdPipe (ground commands and housekeeping)
 * - MonitorCmdPipe (command monitoring messages)
 * - MonitorMLPipe (ML monitoring messages)
 * 
 * Increasing this value allows more messages to be buffered during high-load
 * conditions but increases memory usage.
 * 
 * @note Value must be between 1 and OS_QUEUE_MAX_DEPTH
 * @note Must also be <= CFE_PLATFORM_SB_MAX_PIPE_DEPTH (50 in this build).
 *       CFE_SB_CreatePipe() rejects a deeper request with CFE_SB_BAD_ARGUMENT
 *       (0xCA000003) "Bad Input Arg ... depth=N,maxdepth=50". 50 is the deepest
 *       allowed here; raise CFE_PLATFORM_SB_MAX_PIPE_DEPTH first if more is
 *       needed mission-wide.
 */
#define SPACECOP_PIPE_DEPTH            50

/**
 * @brief Per-MsgId message limit used for all SpaceCop subscriptions.
 *
 * The max number of messages of a SINGLE MsgId allowed to sit queued on a pipe
 * at once. Plain CFE_SB_Subscribe() uses the cFE default of
 * CFE_PLATFORM_SB_DEFAULT_MSG_LIMIT (4), which is too low for monitored
 * high-rate / bursty streams and produces "Msg Limit Err" events (the SB drops
 * the excess for our pipe -- the message still reaches its real destination, we
 * just miss monitoring it). SpaceCop subscribes with CFE_SB_SubscribeEx() using
 * this value instead. Must be <= SPACECOP_PIPE_DEPTH.
 *
 * NOTE: raising this absorbs BURSTS; a sustained publish rate faster than the
 * pipe is drained still needs the drain itself sped up (see the ML monitor
 * path). Tune here without touching each subscription call.
 */
#define SPACECOP_MSG_LIMIT            16

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief SPACECOP global data structure
 * 
 * Central data structure containing all runtime state for the SpaceCop application.
 * Following cFE convention, all global application data is consolidated into a
 * single structure with one global instance defined in spacecop_app.c.
 * 
 * **Structure Contents:**
 * - Housekeeping telemetry packet for status reporting
 * - Software Bus pipe identifiers for message reception
 * - Message pointers for command/telemetry processing
 * - Application run status for lifecycle management
 * 
 * **Thread Safety:**
 * This structure is primarily accessed by the main application task. Child tasks
 * access only the RunStatus field for shutdown coordination. The IDS reporting
 * functions use mutex protection when accessing shared resources.
 * 
 * @note Only one instance of this structure exists per application
 * @note Extern declaration provided for Unit Test Framework access
 * 
 * @see SPACECOP_AppData (global instance in spacecop_app.c)
 */
typedef struct
{
    /**
     * @brief Housekeeping telemetry packet
     * 
     * Contains application status telemetry including:
     * - CommandCount: Number of valid commands received
     * - CommandErrorCount: Number of invalid commands received
     * - Additional app-specific telemetry points
     * 
     * Transmitted in response to SPACECOP_REQ_HK_MID messages.
     */
    SPACECOP_Hk_tlm_t   HkTelemetryPkt;
    
    /*
    ** Operational data - not reported in housekeeping
    */
    
    /**
     * @brief Pointer to message received on Software Bus
     * 
     * Points to the most recently received message on CmdPipe. Used by command
     * and telemetry processing functions to access message content.
     * 
     * @note Do not free - managed by Software Bus
     */
    CFE_MSG_Message_t * MsgPtr;
    
    /**
     * @brief Software Bus pipe for ground commands and housekeeping
     * 
     * Receives the following message types:
     * - SPACECOP_CMD_MID: Ground commands (NOOP, RESET, etc.)
     * - SPACECOP_REQ_HK_MID: Housekeeping requests
     * - SPACECOP_CTI_SHARE_MID: CTI alerts from peers
     * - SPACECOP_HB_MID: Heartbeat requests
     */
    CFE_SB_PipeId_t CmdPipe;
    
    /**
     * @brief Software Bus pipe for command monitoring (rule-based detection)
     * 
     * Receives command messages configured in the command monitoring table
     * with enableML=false. These messages are processed by the rule-based
     * detection engine running in the SCCmdRun child task.
     * 
     * @see RunCmdTable()
     * @see SPACECOP_ExecuteCommandTableMonitor()
     */
    CFE_SB_PipeId_t MonitorCmdPipe;
    
    /**
     * @brief Software Bus pipe for ML monitoring
     * 
     * Receives telemetry messages configured in the command monitoring table
     * with enableML=true. These messages are forwarded to the ML server for
     * anomaly detection by the SCMLRun child task.
     * 
     * @see RunMLTable()
     * @see SPACECOP_ExecuteMLTableMonitor()
     */
    CFE_SB_PipeId_t MonitorMLPipe;
    
    /**
     * @brief Pointer to message received on monitoring pipes
     * 
     * Used by child tasks to access messages received on MonitorCmdPipe
     * and MonitorMLPipe.
     * 
     * @note Do not free - managed by Software Bus
     */
    CFE_MSG_Message_t* MonitorMsgPtr;
    
    /**
     * @brief Application run status
     * 
     * Controls the application lifecycle and is checked by CFE_ES_RunLoop()
     * to determine if the application should continue running. Also used by
     * child tasks for shutdown coordination.
     * 
     * **Valid Values:**
     * - CFE_ES_RunStatus_APP_RUN: Normal operation
     * - CFE_ES_RunStatus_APP_EXIT: Graceful shutdown requested
     * - CFE_ES_RunStatus_APP_ERROR: Error condition - shutdown required
     * - CFE_ES_RunStatus_SYS_DELETE: System requested deletion
     * - CFE_ES_RunStatus_SYS_RESTART: System requested restart
     * - CFE_ES_RunStatus_SYS_RELOAD: System requested reload
     * 
     * @note Shared between main task and all child tasks
     * @note Modified by cFE Executive Services during shutdown
     */
    uint32 RunStatus;
     
} SPACECOP_AppData_t;

/*=======================================================================================
** Exported Data
**=======================================================================================*/

/**
 * @brief Global SpaceCop application data instance
 * 
 * Single global instance of the application data structure. Defined in spacecop_app.c
 * and declared extern here for access by other source files and the Unit Test Framework.
 * 
 * @note Do not create additional instances of this structure
 * @note Initialized in SPACECOP_AppInit()
 */
extern SPACECOP_AppData_t SPACECOP_AppData;

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Main application entry point and processing loop
 * 
 * Primary entry point for the SpaceCop application. Initializes the application,
 * spawns child tasks for parallel monitoring, and enters the main command processing
 * loop. On shutdown, generates exit report and cleans up resources.
 * 
 * @return void (does not return - exits via CFE_ES_ExitApp)
 * 
 * @note This function does not return under normal operation
 * @note Creates 5 child tasks for detection subsystems
 * @note Generates SMSR-3 IOB alert on shutdown
 * 
 * @see SPACECOP_AppInit()
 * @see SPACECOP_ProcessCommandPacket()
 */
void  SPACECOP_AppMain(void);

/**
 * @brief Initialize SpaceCop application
 * 
 * Performs complete application initialization including Event Services registration,
 * table loading, pipe creation, message subscriptions, and subsystem initialization.
 * 
 * @return int32 CFE_SUCCESS on success, error code on failure
 * @retval CFE_SUCCESS All initialization completed successfully
 * @retval CFE_EVS_REGISTER_ERR Failed to register with Event Services
 * @retval CFE_TBL_ERR_* Table operation failed
 * @retval CFE_SB_BAD_ARGUMENT Pipe creation failed
 * 
 * @note Called once during application startup
 * @note Loads tables from /cf directory
 * @note Sends startup event on success
 * 
 * @see SPACECOP_AppMain()
 */
int32 SPACECOP_AppInit(void);

/**
 * @brief Process packets received on the command pipe
 * 
 * Examines the Message ID of received packets and routes them to appropriate
 * handler functions. Handles ground commands, housekeeping requests, CTI messages,
 * and heartbeat requests.
 * 
 * @return void
 * 
 * @note Called from main loop for each received message
 * @note Invalid MIDs increment CommandErrorCount
 * 
 * @see SPACECOP_ProcessGroundCommand()
 * @see SPACECOP_ProcessTelemetryRequest()
 */
void  SPACECOP_ProcessCommandPacket(void);

/**
 * @brief Process ground commands
 * 
 * Processes ground commands received via SPACECOP_CMD_MID. Extracts command code,
 * verifies command length, and executes the requested action.
 * 
 * **Supported Commands:**
 * - SPACECOP_NOOP_CC: No operation (comm check)
 * - SPACECOP_RESET_COUNTERS_CC: Reset telemetry counters
 * 
 * @return void
 * 
 * @note Each command generates an event message
 * @note Invalid commands increment CommandErrorCount
 * 
 * @see SPACECOP_VerifyCmdLength()
 * @see SPACECOP_ResetCounters()
 */
void  SPACECOP_ProcessGroundCommand(void);

/**
 * @brief Process telemetry requests
 * 
 * Processes telemetry requests received via SPACECOP_REQ_HK_MID. Examines the
 * command code to determine which telemetry packet to transmit.
 * 
 * @return void
 * 
 * @note Currently supports housekeeping telemetry only
 * @note Invalid command codes increment CommandErrorCount
 * 
 * @see SPACECOP_ReportHousekeeping()
 */
void  SPACECOP_ProcessTelemetryRequest(void);

/**
 * @brief Report application housekeeping telemetry
 * 
 * Timestamps and transmits the housekeeping telemetry packet containing
 * application status information.
 * 
 * @return void
 * 
 * @note Called in response to housekeeping requests
 * @note Packet includes CommandCount and CommandErrorCount
 * 
 * @see SPACECOP_ProcessTelemetryRequest()
 */
void  SPACECOP_ReportHousekeeping(void);

/**
 * @brief Reset all global counter variables
 * 
 * Resets CommandCount and CommandErrorCount to zero. Called during initialization
 * and in response to SPACECOP_RESET_COUNTERS_CC command.
 * 
 * @return void
 * 
 * @note Does not reset detection state or rule counters
 * @note Changes visible in next housekeeping packet
 * 
 * @see SPACECOP_AppInit()
 * @see SPACECOP_ProcessGroundCommand()
 */
void  SPACECOP_ResetCounters(void);

/**
 * @brief Verify command packet length matches expected
 * 
 * Validates that the received command packet length matches the expected length
 * for the command code. Increments CommandCount on success or CommandErrorCount
 * on failure.
 * 
 * @param[in] msg Pointer to command message
 * @param[in] expected_length Expected message length in bytes
 * 
 * @return int32 OS_SUCCESS if length matches, OS_ERROR otherwise
 * @retval OS_SUCCESS Command length is correct
 * @retval OS_ERROR Command length mismatch
 * 
 * @note Should be called for every ground command
 * @note Generates error event with diagnostic info on failure
 * 
 * @see SPACECOP_ProcessGroundCommand()
 */
int32 SPACECOP_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length);

#endif /* _SPACECOP_APP_H_ */