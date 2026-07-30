// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_app.c
 * @brief Main application file for SpaceCop Intrusion Detection System
 *
 * This file contains the core application logic for the SpaceCop IDS, including:
 * - Application initialization and main loop
 * - Command and telemetry processing
 * - Multi-threaded monitoring subsystems
 * - Software Bus message handling
 * - Table management (rules, command monitoring)
 * - Integration with ML bridge and CTI systems
 *
 * **Architecture:**
 * SpaceCop uses a multi-threaded architecture with the following child tasks:
 * - SCRuleTable: Executes periodic rule-based detection logic
 * - SCCTIRun: Processes Cyber Threat Intelligence data
 * - SCCmdRun: Monitors command messages for anomalies
 * - SCMLRun: Forwards telemetry to ML models
 * - SCMLRep: Receives and processes ML anomaly alerts
 *
 * **Key Features:**
 * - Rule-based intrusion detection
 * - Command monitoring with configurable tables
 * - Machine learning integration for anomaly detection
 * - CTI data sharing between SpaceCop instances
 * - STIX-formatted alert reporting
 * - cFS Software Bus integration
 */

/*=======================================================================================
** Include Files
**=======================================================================================*/
#include <arpa/inet.h>
#include <pthread.h>
#include "spacecop_app.h"
#include "spacecop_cti.h"

/*=======================================================================================
** Global Data
**=======================================================================================*/

/** @brief Main application data structure containing runtime state */
SPACECOP_AppData_t SPACECOP_AppData;

/** @brief Pointer to rule table containing detection rules */
RuleTable * SPACECOP_RuleTablePtr;

/** @brief Pointer to command monitoring table */
CommandMonitorEntryTable_t * SPACECOP_CommandMonTblPtr;

/** @brief Table handle for command monitoring table */
CFE_TBL_Handle_t SPACECOP_CommandMonTblHandle;

/** @brief Table handle for rule table */
CFE_TBL_Handle_t SPACECOP_RuleTblHandle;

/*=======================================================================================
** Child Task Functions
**=======================================================================================*/

/**
 * @brief Child task that executes periodic rule-based detection
 *
 * This task runs the rule table engine at 1 Hz, evaluating all configured
 * detection rules against the current system state. Rules can detect patterns
 * such as:
 * - Unauthorized command sequences
 * - Telemetry value violations
 * - Timing-based anomalies
 *
 * @return void
 *
 * @note Runs as child task "SCRuleTable" (Task ID 49442)
 * @note Executes at 1 Hz (1000ms delay between iterations)
 * @note Registers with EVS for event message support
 *
 * @see SPACECOP_ExecutePeriodicRuleTable()
 */
static void RunRuleTable(void)
{
    int32_t status;
    
    /* Register with Event Services for this child task */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        printf("[SPACECOP] RunRuleTable: Failed to register with EVS: %d\n", status);
        printf("[SPACECOP] RunRuleTable: Continuing without EVS support\n");
        fflush(stdout);
    }
    else {
        printf("[SPACECOP] RunRuleTable: Successfully registered with EVS\n");
        fflush(stdout);
    }
    
    /* Main rule execution loop - runs until app shutdown */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {
        SPACECOP_ExecutePeriodicRuleTable(SPACECOP_RuleTablePtr);
        OS_TaskDelay(1000);  /* 1 second delay */
    }
}

/**
 * @brief Child task that processes Cyber Threat Intelligence data
 *
 * This task manages CTI data sharing between SpaceCop instances, enabling
 * distributed threat detection across multiple spacecraft or ground systems.
 * It checks for incoming CTI alerts and processes them for local detection.
 *
 * @return void
 *
 * @note Runs as child task "SCCTIRun" (Task ID 49443)
 * @note Executes at 1 Hz
 * @note Handles peer-to-peer threat intelligence sharing
 *
 * @see CTI_CheckForNewData()
 * @see CTI_WorkWithData()
 */
static void RunCTILoop(void)
{
    int32_t status;
    
    /* Register with Event Services for this child task */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        printf("[SPACECOP] RunCTILoop: Failed to register with EVS: %d\n", status);
        printf("[SPACECOP] RunCTILoop: Continuing without EVS support\n");
        fflush(stdout);
    }
    else {
        printf("[SPACECOP] RunCTILoop: Successfully registered with EVS\n");
        fflush(stdout);
    }
    
    /* Main CTI processing loop */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {
        CTI_CheckForNewData();  /* Check for new CTI messages */
        CTI_WorkWithData();     /* Process received CTI data */
        OS_TaskDelay(1*1000);   /* 1 second delay */
    }
}

/**
 * @brief Child task that monitors command messages for anomalies
 *
 * This task monitors Software Bus messages defined in the command monitoring
 * table. It detects anomalies such as:
 * - Unauthorized commands
 * - Commands sent out of sequence
 * - Commands with invalid parameters
 * - Rate-based command flooding
 *
 * @return void
 *
 * @note Runs as child task "SCCmdRun" (Task ID 49444)
 * @note Blocks on Software Bus pipe (no fixed rate)
 * @note Uses MonitorCmdPipe for message reception
 *
 * @see SPACECOP_ExecuteCommandTableMonitor()
 */
static void RunCmdTable(void)
{
    int32_t status;
    
    /* Register with Event Services for this child task */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        printf("[SPACECOP] RunCmdTable: Failed to register with EVS: %d\n", status);
        printf("[SPACECOP] RunCmdTable: Continuing without EVS support\n");
        fflush(stdout);
    }
    else {
        printf("[SPACECOP] RunCmdTable: Successfully registered with EVS\n");
        fflush(stdout);
    }
    
    /* Main command monitoring loop - blocks on pipe receive */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {
        SPACECOP_ExecuteCommandTableMonitor(SPACECOP_CommandMonTblPtr, 
                                           SPACECOP_AppData.MonitorMsgPtr, 
                                           SPACECOP_AppData.MonitorCmdPipe);
    }
}

/**
 * @brief Child task that forwards telemetry to ML models
 *
 * This task receives telemetry messages configured for ML monitoring and
 * forwards them to the external ML server for anomaly detection. The ML
 * models analyze the telemetry for statistical deviations and behavioral
 * anomalies.
 *
 * @return void
 *
 * @note Runs as child task "SCMLRun" (Task ID 49445)
 * @note Uses MonitorMLPipe for message reception
 * @note Messages are sent as hexadecimal to ML server on port 9111
 *
 * @see SPACECOP_ExecuteMLTableMonitor()
 * @see MLBridge_SendRawHex()
 */
static void RunMLTable(void)
{
    int32_t status;
    
    /* Register with Event Services for this child task */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        printf("[SPACECOP] RunMLTable: Failed to register with EVS: %d\n", status);
        printf("[SPACECOP] RunMLTable: Continuing without EVS support\n");
        fflush(stdout);
    }
    else {
        printf("[SPACECOP] RunMLTable: Successfully registered with EVS\n");
        fflush(stdout);
    }
    
    /* Main ML telemetry forwarding loop */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {
        SPACECOP_ExecuteMLTableMonitor(SPACECOP_AppData.MonitorMLPipe);
    }
}

/**
 * @brief Child task that receives ML anomaly alerts
 *
 * This task polls the ML bridge for incoming anomaly alerts from the ML
 * server. When alerts are received, they are parsed and converted into
 * SpaceCop IDS alerts with appropriate IOB identifiers and STIX reporting.
 *
 * @return void
 *
 * @note Runs as child task "SCMLRep" (Task ID 49446)
 * @note Executes at 1 Hz
 * @note Receives JSON-formatted alerts on UDP port 9112
 *
 * @see SPACECOP_MLMonitor()
 * @see MLBridge_CheckForResponse()
 */
static void RunMLResp(void)
{
    int32_t status;
    
    /* Register with Event Services for this child task */
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        printf("[SPACECOP] RunMLResp: Failed to register with EVS: %d\n", status);
        printf("[SPACECOP] RunMLResp: Continuing without EVS support\n");
        fflush(stdout);
    }
    else {
        printf("[SPACECOP] RunMLResp: Successfully registered with EVS\n");
        fflush(stdout);
    }
    
    /* Main ML response monitoring loop */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {
        SPACECOP_MLMonitor();      /* Check for and process ML alerts */
        OS_TaskDelay(1*1000);      /* 1 second delay */
    }
}

/*=======================================================================================
** Application Entry Point and Main Loop
**=======================================================================================*/

/**
 * @brief Main application entry point and processing loop
 *
 * This is the main entry point for the SpaceCop application. It performs the
 * following operations:
 * 1. Initializes the application (tables, pipes, sockets)
 * 2. Spawns five child tasks for parallel monitoring
 * 3. Enters main loop to process ground commands and housekeeping requests
 * 4. On shutdown, generates exit report with IOB SMSR-3
 * 5. Cleans up resources and exits
 *
 * **Main Loop Operation:**
 * The main task blocks on the command pipe waiting for:
 * - Ground commands (SPACECOP_CMD_MID)
 * - Housekeeping requests (SPACECOP_REQ_HK_MID)
 * - CTI sharing messages (SPACECOP_CTI_SHARE_MID)
 * - Heartbeat requests (SPACECOP_HB_MID)
 *
 * **Child Tasks Created:**
 * - Task 49442: SCRuleTable (rule-based detection)
 * - Task 49443: SCCTIRun (CTI processing)
 * - Task 49444: SCCmdRun (command monitoring)
 * - Task 49445: SCMLRun (ML telemetry forwarding)
 * - Task 49446: SCMLRep (ML alert reception)
 *
 * @return void (does not return - exits via CFE_ES_ExitApp)
 *
 * @note This function does not return under normal operation
 * @note Performance logging enabled via CFE_ES_PerfLogEntry/Exit
 * @note Generates SMSR-3 IOB alert on shutdown with exit reason
 *
 * @see SPACECOP_AppInit()
 * @see SPACECOP_ProcessCommandPacket()
 */
void SPACECOP_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /* Create the first Performance Log entry */
    CFE_ES_PerfLogEntry(SPACECOP_PERF_ID);

    /* Perform application initialization */
    status = SPACECOP_AppInit();
    if (status != CFE_SUCCESS)
    {
        SPACECOP_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    printf("[SPACECOP] Starting main loop with run status %d\n", SPACECOP_AppData.RunStatus);

    /* Initialize CTI data structures */
    CTI_InitArray();

    /* Initialize runtime state for rule table */
    SPACECOP_InitRuleRuntime(SPACECOP_RuleTablePtr);

    /* Create child task for rule table execution */
    CFE_ES_TaskId_t task_id = 49442;
    CFE_ES_CreateChildTask(&task_id, "SCRuleTable", RunRuleTable, NULL, 65536, 50, 0);

    /* Create child task for CTI processing */
    CFE_ES_TaskId_t task_id2 = 49443;
    CFE_ES_CreateChildTask(&task_id2, "SCCTIRun", RunCTILoop, NULL, 8192, 50, 0);

    /* Create child task for command monitoring */
    CFE_ES_TaskId_t task_id3 = 49444;
    CFE_ES_CreateChildTask(&task_id3, "SCCmdRun", RunCmdTable, NULL, 8192, 50, 0);

    /* Set up the ML bridge sockets BEFORE starting the ML tasks that use them,
    ** so RunMLResp's accept() never runs on an unset socket (fd 0 = stdin, which
    ** gives "Socket operation on non-socket" / ENOTSOCK). */
    MLBridge_InitSockets();

    /* Create child task for ML telemetry forwarding */
    CFE_ES_TaskId_t task_id4 = 49445;
    /* Priority 60: high enough that this task actually gets scheduled to DRAIN
    ** MonitorMLPipe (at 130 it was starved -> "Pipe Overflow"). Because the
    ** forward send is now non-blocking, this task is bursty (drain, then block
    ** on the empty pipe), so it does not sustainably starve the main task. */
    CFE_ES_CreateChildTask(&task_id4, "SCMLRun", RunMLTable, NULL, 8192, 60, 0);

    /* Create child task for ML alert reception */
    CFE_ES_TaskId_t task_id5 = 49446;
    /* Priority 130 (below the main task's 81): ML alert reception is best-effort. */
    CFE_ES_CreateChildTask(&task_id5, "SCMLRep", RunMLResp, NULL, 8192, 130, 0);

    /*
    ** Main application loop
    ** Processes ground commands, housekeeping requests, and other messages
    */
    while (CFE_ES_RunLoop(&SPACECOP_AppData.RunStatus) == true)
    {   
        /* Performance log exit stamp */
        CFE_ES_PerfLogExit(SPACECOP_PERF_ID);

        /* 
        ** Pend on the arrival of the next Software Bus message
        ** Note that this is the standard, but timeouts are available
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SPACECOP_AppData.MsgPtr,  
                                      SPACECOP_AppData.CmdPipe,  
                                      CFE_SB_PEND_FOREVER);
        
        /* 
        ** Begin performance metrics on anything after this line. This will help to determine
        ** where we are spending most of the time during this app execution.
        */
        CFE_ES_PerfLogEntry(SPACECOP_PERF_ID);

        /*
        ** If the CFE_SB_ReceiveBuffer was successful, then continue to process the command packet
        ** If not, then exit the application in error.
        ** Note that a SB read error should not always result in an app quitting.
        */
        if (status == CFE_SUCCESS)
        {
            SPACECOP_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SPACECOP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, 
                             "SPACECOP: SB Pipe Read Error = %d", (int) status);
            SPACECOP_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Application shutdown sequence
    ** Generate SMSR-3 IOB alert with appropriate exit reason
    */
    char message[IDS_REPORT_MESSAGE_LEN];
    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
    
    switch (SPACECOP_AppData.RunStatus)
    {
        case CFE_ES_RunStatus_APP_EXIT:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: Normal shutdown requested");
            break;
            
        case CFE_ES_RunStatus_APP_ERROR:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: Exiting due to error condition");
            break;
            
        case CFE_ES_RunStatus_SYS_DELETE:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: System requested deletion");
            break;
            
        case CFE_ES_RunStatus_SYS_RESTART:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: System requested restart");
            break;
            
        case CFE_ES_RunStatus_SYS_RELOAD:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: System requested reload");
            break;
            
        default:
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                    "[SPACECOP] (SMSR-3) Exiting for reason: Unknown exit status = 0x%08X", 
                    (unsigned int)SPACECOP_AppData.RunStatus);
            break;
    }
    
    /* Report shutdown via multiple channels */
    SPACECOP_ReportIDSMsg(message);      /* Send IDS telemetry message */
    write_to_stix(message, NULL, "SMSR-3");  /* Write STIX-formatted report */
    printf("%s\n", message);             /* Log to console */

    /* Release table addresses */
    CFE_TBL_ReleaseAddress(SPACECOP_RuleTblHandle);
    
    /* Performance log exit stamp */
    CFE_ES_PerfLogExit(SPACECOP_PERF_ID);

    /* Clean up synchronization primitives */
    SPACECOP_DestroyReportLock();

    /* Free CTI data structures */
    CTI_FreeArray();

    /* Clean up ML bridge sockets */
    MLBridge_Cleanup();

    /* Exit the application */
    CFE_ES_ExitApp(SPACECOP_AppData.RunStatus);
} 

/*=======================================================================================
** Application Initialization
**=======================================================================================*/

/**
 * @brief Initialize SpaceCop application
 *
 * Performs complete application initialization including:
 * 1. Event Services registration
 * 2. Rule table registration and loading
 * 3. Command monitoring table registration and loading
 * 4. Software Bus pipe creation (command, monitor, ML)
 * 5. Message subscriptions for all monitored MIDs
 * 6. Housekeeping telemetry packet initialization
 * 7. IDS reporting initialization
 * 8. ML bridge socket initialization
 * 9. Counter reset
 *
 * **Table Loading:**
 * - Rule table loaded from /cf/spacecop_rule.tbl
 * - Command monitoring table loaded from /cf/spacecop_cmdmon.tbl
 *
 * **Pipe Creation:**
 * - CmdPipe: Ground commands and housekeeping requests
 * - MonitorCmdPipe: Command messages for rule-based monitoring
 * - MonitorMLPipe: Telemetry messages for ML monitoring
 *
 * **Subscriptions:**
 * The function subscribes to all MIDs defined in the command monitoring table,
 * routing them to either MonitorCmdPipe or MonitorMLPipe based on the enableML flag.
 *
 * @return int32 CFE_SUCCESS on success, error code on failure
 * @retval CFE_SUCCESS All initialization completed successfully
 * @retval CFE_EVS_REGISTER_ERR Failed to register with Event Services
 * @retval CFE_TBL_ERR_* Table registration/loading failed
 * @retval CFE_SB_BAD_ARGUMENT Pipe creation failed
 * @retval CFE_SB_MAX_MSGS_MET Subscription failed
 *
 * @note On failure, appropriate error events are generated
 * @note Sends SPACECOP_STARTUP_INF_EID event on successful init
 * @note Version information included in startup event
 *
 * @see SPACECOP_AppMain()
 */
int32 SPACECOP_AppInit(void)
{
    int32 status = OS_SUCCESS;

    SPACECOP_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /*
    ** Register the events
    */ 
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);    /* as default, no filters are used */
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SPACECOP: Error registering for event services: 0x%08X\n", (unsigned int) status);
       return status;
    }
    
    /*
    ** Register Main Rule Table
    ** This table contains the detection rules for rule-based IDS monitoring
    */
    status = CFE_TBL_Register(&SPACECOP_RuleTblHandle, 
                             "SC_RuleTbl", 
                             sizeof(*SPACECOP_RuleTablePtr), 
                             CFE_TBL_OPT_DEFAULT, 
                             NULL);

    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't register table status %i",
                         __LINE__, (int)status);
        return status;
    }

    /* Load rule table from file system */
    status = CFE_TBL_Load(SPACECOP_RuleTblHandle, CFE_TBL_SRC_FILE, "/cf/spacecop_rule.tbl");

    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't load table status %i", __LINE__,
                         (int)status);
        return status;
    }

    /* Get pointer to loaded table data */
    status = CFE_TBL_GetAddress((void *)&SPACECOP_RuleTablePtr, SPACECOP_RuleTblHandle);

    if (status != CFE_SUCCESS && status != CFE_TBL_INFO_UPDATED)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't get table addr status %i",
                         __LINE__, (int)status);
        return status;
    }

    /*
    ** Create Software Bus pipes for monitoring
    */
    
    /* Create pipe for command monitoring (rule-based detection) */
    status = CFE_SB_CreatePipe(&SPACECOP_AppData.MonitorCmdPipe, 
                               SPACECOP_PIPE_DEPTH, 
                               "SPACECOP_MONITOR");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "SPACECOP: Error Creating Monitor SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }

    /* Create pipe for ML monitoring (ML-based detection) */
    status = CFE_SB_CreatePipe(&SPACECOP_AppData.MonitorMLPipe, 
                               SPACECOP_PIPE_DEPTH, 
                               "SPACECOP_MLM");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "SPACECOP: Error Creating ML Monitor SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }

    /*
    ** Register Command Monitoring Table
    ** This table defines which commands/telemetry to monitor and how
    */
    status = CFE_TBL_Register(&SPACECOP_CommandMonTblHandle, 
                             "SC_CmdMonTbl", 
                             sizeof(*SPACECOP_CommandMonTblPtr), 
                             CFE_TBL_OPT_DEFAULT, 
                             NULL);

    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't register table status %i",
                         __LINE__, (int)status);
        return status;
    }

    /* Load command monitoring table from file system */
    status = CFE_TBL_Load(SPACECOP_CommandMonTblHandle, CFE_TBL_SRC_FILE, "/cf/spacecop_cmdmon.tbl");

    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't load table status %i", __LINE__,
                         (int)status);
        return status;
    }

    /* Get pointer to loaded table data */
    status = CFE_TBL_GetAddress((void *)&SPACECOP_CommandMonTblPtr, SPACECOP_CommandMonTblHandle);

    if (status != CFE_SUCCESS && status != CFE_TBL_INFO_UPDATED)
    {
        CFE_EVS_SendEvent(SPACECOP_TBL_ERR_EID, CFE_EVS_EventType_ERROR, 
                         "%d SPACECOP Can't get table addr status %i",
                         __LINE__, (int)status);
        return status;
    }

    /*
    ** Subscribe to messages defined in Command Monitor Table
    ** Each entry specifies a MID to monitor and whether to use ML or rule-based detection
    */
    CommandMonitorEntry_t* current;
    for (int i = 0; i < SPACECOP_CommandMonTblPtr->CommandMonitorEntryCount; i++){
        current = &(SPACECOP_CommandMonTblPtr->CommandMonitorEntries[i]);

        /* Debug output for table entry */
        printf("[SPACECOP] Entry %d: ActionOnMid = 0x%04X with enableML %d\n", 
           i, CFE_SB_MsgIdToValue(current->ActionOnMid), current->enableML);
        fflush(stdout);
        
        if (current->enableML) {
            /* Subscribe to ML pipe for ML-based monitoring */
            printf("[SPACECOP] Subscribing to ML\n");
            status = CFE_SB_SubscribeEx(current->ActionOnMid, SPACECOP_AppData.MonitorMLPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
            if (status != CFE_SUCCESS)
            {
                #ifdef SPACECOP_MONITOR_DEBUG
                printf("[SPACECOP] Error on Subscribing to ActionOnMid %d for ML\n", status);
                #endif

                return status;
            }
        } else {
            /* Subscribe to command pipe for rule-based monitoring */
            status = CFE_SB_SubscribeEx(current->ActionOnMid, SPACECOP_AppData.MonitorCmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
            if (status != CFE_SUCCESS)
            {
                #ifdef SPACECOP_MONITOR_DEBUG
                printf("[SPACECOP] Error on Subscribing to ActionOnMid %d\n", status);
                #endif
                return status;
            }

            #ifdef SPACECOP_MONITOR_DEBUG
            printf("[SPACECOP] HaveDeactivate %d\n", current->HaveDeactivate);
            #endif
            
            /* 
            ** If this entry has a deactivation MID, subscribe to it as well
            ** Deactivation MIDs are used to disable monitoring based on system state
            */
            if (current->HaveDeactivate)
            {
                if(CFE_SB_MsgId_Equal(current->ActionOnMid, current->DeactivateOnMid))
                {
                    /* ActionOnMid and DeactivateOnMid are the same - no additional subscription needed */
                    #ifdef SPACECOP_MONITOR_DEBUG
                    printf("My ActionOnMid [0x%04X] and DeactivateOnMid [0x%04X] are the same\n", 
                          CFE_SB_MsgIdToValue(current->ActionOnMid), 
                          CFE_SB_MsgIdToValue(current->DeactivateOnMid));
                    #endif
                }
                else
                {
                    /* Subscribe to separate deactivation MID */
                    #ifdef SPACECOP_MONITOR_DEBUG
                    printf("My ActionOnMid [0x%04X] and DeactivateOnMid [0x%04X]\n", 
                          CFE_SB_MsgIdToValue(current->ActionOnMid), 
                          CFE_SB_MsgIdToValue(current->DeactivateOnMid));
                    #endif
                    status = CFE_SB_SubscribeEx(current->DeactivateOnMid, SPACECOP_AppData.MonitorCmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
                    if (status != CFE_SUCCESS)
                    {
                        #ifdef SPACECOP_MONITOR_DEBUG
                        printf("[SPACECOP] Error on Subscribing to DeactivateOnMid %d\n", status);
                        #endif
                        return status;
                    }
                }
            }
        }
        
    }

    /*
    ** Create the Software Bus command pipe for ground commands and housekeeping
    */
    status = CFE_SB_CreatePipe(&SPACECOP_AppData.CmdPipe, SPACECOP_PIPE_DEPTH, "SPACECOP_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Creating SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }
    
    /*
    ** Subscribe to ground commands
    */
    status = CFE_SB_SubscribeEx(CFE_SB_ValueToMsgId(SPACECOP_CMD_MID), SPACECOP_AppData.CmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Gnd Cmds, MID=0x%04X, RC=0x%08X",
            SPACECOP_CMD_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to housekeeping (hk) message requests
    */
    status = CFE_SB_SubscribeEx(CFE_SB_ValueToMsgId(SPACECOP_REQ_HK_MID), SPACECOP_AppData.CmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Request, MID=0x%04X, RC=0x%08X",
            SPACECOP_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to CTI sharing messages from peer SpaceCop instances
    */
    status = CFE_SB_SubscribeEx(CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID), SPACECOP_AppData.CmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to CTI TLM, MID=0x%04X, RC=0x%08X",
            SPACECOP_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to heartbeat messages
    */
    status = CFE_SB_SubscribeEx(CFE_SB_ValueToMsgId(SPACECOP_HB_MID), SPACECOP_AppData.CmdPipe, CFE_SB_DEFAULT_QOS, SPACECOP_MSG_LIMIT);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SPACECOP_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HB, MID=0x%04X, RC=0x%08X",
            SPACECOP_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /* 
    ** Initialize the published HK message - this HK message will contain the 
    ** telemetry that has been defined in the SPACECOP_HkTelemetryPkt for this app.
    */
    CFE_MSG_Init(CFE_MSG_PTR(SPACECOP_AppData.HkTelemetryPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(SPACECOP_HK_TLM_MID),
                   SPACECOP_HK_TLM_LNGTH);

    /* Initialize IDS reporting packet */
    SPACECOP_IDS_InitPkt();

    /* Initialize mutex for thread-safe IDS reporting */
    SPACECOP_InitReportLock();

    /* (ML bridge sockets are initialized earlier, before the ML child tasks.) */

    /*
    ** Always reset all counters during application initialization
    */
    SPACECOP_ResetCounters();

    /* 
     ** Send an information event that the app has initialized. 
     ** This is useful for debugging the loading of individual applications.
     */
    status = CFE_EVS_SendEvent(SPACECOP_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
               "SPACECOP App Initialized. Version %d.%d.%d.%d",
                SPACECOP_MAJOR_VERSION,
                SPACECOP_MINOR_VERSION, 
                SPACECOP_REVISION, 
                SPACECOP_MISSION_REV);  
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SPACECOP: Error sending initialization event: 0x%08X\n", (unsigned int) status);
    }
    return status;
} 

/*=======================================================================================
** Command and Message Processing
**=======================================================================================*/

/**
 * @brief Process packets received on the SPACECOP command pipe
 *
 * This function is called from the main loop whenever a message is received
 * on the command pipe. It examines the Message ID and routes the message to
 * the appropriate handler function.
 *
 * **Supported Message IDs:**
 * - SPACECOP_CMD_MID: Ground commands (NOOP, RESET, etc.)
 * - SPACECOP_REQ_HK_MID: Housekeeping telemetry requests
 * - SPACECOP_CTI_SHARE_MID: CTI alerts from peer instances
 * - SPACECOP_HB_MID: Heartbeat requests
 *
 * @return void
 *
 * @note Invalid MIDs increment the command error counter
 * @note Error events generated for unrecognized messages
 *
 * @see SPACECOP_ProcessGroundCommand()
 * @see SPACECOP_ProcessTelemetryRequest()
 * @see SPACECOP_ProcessPeerAlert()
 * @see SPACECOP_SendHeartbeat()
 */
void SPACECOP_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(SPACECOP_AppData.MsgPtr, &MsgId);
    CFE_MSG_FcnCode_t CommandCode = 0;
    
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        /*
        ** Ground Commands with command codes fall under the SPACECOP_CMD_MID (Message ID)
        */
        case SPACECOP_CMD_MID:
            SPACECOP_ProcessGroundCommand();
            break;

        /*
        ** Housekeeping telemetry request
        */
        case SPACECOP_REQ_HK_MID:
            SPACECOP_ProcessTelemetryRequest();
            break;

        /*
        ** CTI sharing message from peer SpaceCop instance
        */
        case SPACECOP_CTI_SHARE_MID:
            SPACECOP_ProcessPeerAlert(SPACECOP_AppData.MsgPtr);
            break;

        /*
        ** Heartbeat request
        */
        case SPACECOP_HB_MID:
            SPACECOP_SendHeartbeat();
            break;
            
        /*
        ** All other invalid messages that this app doesn't recognize, 
        ** increment the command error counter and log as an error event.  
        */
        default:
            CFE_MSG_GetFcnCode(SPACECOP_AppData.MsgPtr, &CommandCode);
            SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SPACECOP_PROCESS_CMD_ERR_EID,CFE_EVS_EventType_ERROR, 
                             "SPACECOP: Invalid command packet, MID = 0x%x", 
                             CFE_SB_MsgIdToValue(MsgId));
            break;
    }
    return;
} 

/**
 * @brief Process ground commands
 *
 * Processes ground commands received via SPACECOP_CMD_MID. Each command has
 * a unique command code that determines the action to take.
 *
 * **Supported Command Codes:**
 * - SPACECOP_NOOP_CC: No operation (used for comm check)
 * - SPACECOP_RESET_COUNTERS_CC: Reset telemetry counters
 *
 * **Command Processing Steps:**
 * 1. Extract command code from message
 * 2. Verify command length matches expected size
 * 3. Execute command action
 * 4. Increment appropriate counter (command or error)
 *
 * @return void
 *
 * @note Invalid command codes increment CommandErrorCount
 * @note Each command generates an informational event on success
 * @note Command verification handles counter updates
 *
 * @see SPACECOP_VerifyCmdLength()
 * @see SPACECOP_ResetCounters()
 */
void SPACECOP_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(SPACECOP_AppData.MsgPtr, &MsgId);

    /*
    ** Ground Commands, by definition, have a command code (_CC) associated with them
    ** Pull this command code from the message and then process
    */
    CFE_MSG_GetFcnCode(SPACECOP_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        /*
        ** NOOP Command
        ** Used to verify command interface is operational
        */
        case SPACECOP_NOOP_CC:
            /*
            ** First, verify the command length immediately after CC identification 
            ** Note that VerifyCmdLength handles the command and command error counters
            */
            if (SPACECOP_VerifyCmdLength(SPACECOP_AppData.MsgPtr, sizeof(SPACECOP_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                /* Second, send EVS event on successful receipt ground commands*/
                CFE_EVS_SendEvent(SPACECOP_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, 
                                 "SPACECOP: NOOP command received");
                /* Third, do the desired command action if applicable, in the case of NOOP it is no operation */
            }
            break;

        /*
        ** Reset Counters Command
        ** Resets CommandCount and CommandErrorCount to zero
        */
        case SPACECOP_RESET_COUNTERS_CC:
            if (SPACECOP_VerifyCmdLength(SPACECOP_AppData.MsgPtr, sizeof(SPACECOP_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(SPACECOP_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, 
                                 "SPACECOP: RESET counters command received");
                SPACECOP_ResetCounters();
            }
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SPACECOP_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SPACECOP: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", 
                CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
} 

/**
 * @brief Process Telemetry Request - Triggered in response to a telemetry request
 *
 * Processes telemetry requests received via SPACECOP_REQ_HK_MID. The function
 * examines the command code to determine which telemetry packet to send.
 *
 * **Supported Command Codes:**
 * - SPACECOP_REQ_HK_TLM: Request housekeeping telemetry packet
 *
 * @return void
 *
 * @note Invalid command codes increment CommandErrorCount
 * @note Telemetry is timestamped before transmission
 *
 * @see SPACECOP_ReportHousekeeping()
 */
void SPACECOP_ProcessTelemetryRequest(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(SPACECOP_AppData.MsgPtr, &MsgId);

    /* Pull this command code from the message and then process */
    CFE_MSG_GetFcnCode(SPACECOP_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        /*
        ** Housekeeping telemetry request
        */
        case SPACECOP_REQ_HK_TLM:
            SPACECOP_ReportHousekeeping();
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SPACECOP_DEVICE_TLM_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SPACECOP: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", 
                CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}

/**
 * @brief Report Application Housekeeping
 *
 * Timestamps and transmits the housekeeping telemetry packet. The HK packet
 * contains application status information including:
 * - CommandCount: Number of valid commands received
 * - CommandErrorCount: Number of invalid commands received
 * - Additional app-specific telemetry points
 *
 * @return void
 *
 * @note Called in response to SPACECOP_REQ_HK_MID messages
 * @note Packet is timestamped with current spacecraft time
 * @note Uses reliable transmission (true parameter to TransmitMsg)
 *
 * @see SPACECOP_ProcessTelemetryRequest()
 */
void SPACECOP_ReportHousekeeping(void)
{
    /* Add current spacecraft time to telemetry packet */
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &SPACECOP_AppData.HkTelemetryPkt);
    
    /* Transmit housekeeping packet on Software Bus */
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &SPACECOP_AppData.HkTelemetryPkt, true);
    return;
}

/*=======================================================================================
** Utility Functions
**=======================================================================================*/

/**
 * @brief Reset all global counter variables
 *
 * Resets telemetry counters to zero. This function is called during:
 * - Application initialization
 * - Receipt of SPACECOP_RESET_COUNTERS_CC command
 *
 * **Counters Reset:**
 * - CommandErrorCount: Number of invalid commands received
 * - CommandCount: Number of valid commands received
 *
 * @return void
 *
 * @note Does not reset detection counters or rule state
 * @note Changes take effect on next housekeeping packet
 *
 * @see SPACECOP_ProcessGroundCommand()
 * @see SPACECOP_AppInit()
 */
void SPACECOP_ResetCounters(void)
{
    SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SPACECOP_AppData.HkTelemetryPkt.CommandCount = 0;
    return;
} 

/**
 * @brief Verify command packet length matches expected
 *
 * Validates that the received command packet length matches the expected
 * length for the command code. This prevents processing of malformed or
 * truncated commands.
 *
 * **On Success:**
 * - Increments CommandCount
 * - Returns OS_SUCCESS
 *
 * **On Failure:**
 * - Increments CommandErrorCount
 * - Generates error event with details
 * - Returns OS_ERROR
 *
 * @param[in] msg Pointer to command message
 * @param[in] expected_length Expected message length in bytes
 *
 * @return int32 OS_SUCCESS if length matches, OS_ERROR otherwise
 * @retval OS_SUCCESS Command length is correct
 * @retval OS_ERROR Command length mismatch
 *
 * @note Should be called for every ground command
 * @note Error event includes MID, command code, actual and expected lengths
 *
 * @see SPACECOP_ProcessGroundCommand()
 */
int32 SPACECOP_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length)
{     
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    /* Get actual message length */
    CFE_MSG_GetSize(msg, &actual_length);
    
    if (expected_length == actual_length)
    {
        /* Increment the command counter upon receipt of a valid command */
        SPACECOP_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        /* Get message details for error reporting */
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        /* Generate error event with diagnostic information */
        CFE_EVS_SendEvent(SPACECOP_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
           "Invalid msg length: ID = 0x%X,  CC = %d, Len = %d, Expected = %d",
              CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;

        /* Increment the command error counter upon receipt of an invalid command */
        SPACECOP_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
}