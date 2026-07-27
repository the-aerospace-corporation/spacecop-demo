/*******************************************************************************
** File: sysmon_app.c
**
** Purpose:
**   This file contains the source code for the SYSMON application.
**
*******************************************************************************/

/*
** Include Files
*/
#include <arpa/inet.h>
#include "sysmon_app.h"


/*
** Global Data
*/
SYSMON_AppData_t SYSMON_AppData;

/*
** Application entry point and main process loop
*/
void SYSMON_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /*
    ** Create the first Performance Log entry
    */
    CFE_ES_PerfLogEntry(SYSMON_PERF_ID);

    /* 
    ** Perform application initialization
    */
    status = SYSMON_AppInit();
    if (status != CFE_SUCCESS)
    {
        SYSMON_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /*
    ** Main loop
    */
    while (CFE_ES_RunLoop(&SYSMON_AppData.RunStatus) == true)
    {
        /*
        ** Performance log exit stamp
        */
        CFE_ES_PerfLogExit(SYSMON_PERF_ID);

        /* 
        ** Pend on the arrival of the next Software Bus message
        ** Note that this is the standard, but timeouts are available
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SYSMON_AppData.MsgPtr,  SYSMON_AppData.CmdPipe,  CFE_SB_PEND_FOREVER);
        
        /* 
        ** Begin performance metrics on anything after this line. This will help to determine
        ** where we are spending most of the time during this app execution.
        */
        CFE_ES_PerfLogEntry(SYSMON_PERF_ID);

        /*
        ** If the CFE_SB_ReceiveBuffer was successful, then continue to process the command packet
        ** If not, then exit the application in error.
        ** Note that a SB read error should not always result in an app quitting.
        */
        if (status == CFE_SUCCESS)
        {
            SYSMON_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SYSMON_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "SYSMON: SB Pipe Read Error = %d", (int) status);
            SYSMON_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Performance log exit stamp
    */
    CFE_ES_PerfLogExit(SYSMON_PERF_ID);

    /*
    ** Exit the application
    */
    CFE_ES_ExitApp(SYSMON_AppData.RunStatus);
} 


/* 
** Initialize application
*/
int32 SYSMON_AppInit(void)
{
    int32 status = OS_SUCCESS;
    
    SYSMON_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /*
    ** Register the events
    */ 
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);    /* as default, no filters are used */
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SYSMON: Error registering for event services: 0x%08X\n", (unsigned int) status);
       return status;
    }

    /*
    ** Create the Software Bus command pipe 
    */
    status = CFE_SB_CreatePipe(&SYSMON_AppData.CmdPipe, SYSMON_PIPE_DEPTH, "SYSMON_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SYSMON_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Creating SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }
    
    /*
    ** Subscribe to ground commands
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SYSMON_CMD_MID), SYSMON_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SYSMON_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Gnd Cmds, MID=0x%04X, RC=0x%08X",
            SYSMON_CMD_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to housekeeping (hk) message requests
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SYSMON_REQ_HK_MID), SYSMON_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SYSMON_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Request, MID=0x%04X, RC=0x%08X",
            SYSMON_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** TODO: Subscribe to any other messages here
    */


    /* 
    ** Initialize the published HK message - this HK message will contain the 
    ** telemetry that has been defined in the SYSMON_HkTelemetryPkt for this app.
    */
    CFE_MSG_Init(CFE_MSG_PTR(SYSMON_AppData.HkTelemetryPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(SYSMON_HK_TLM_MID),
                   SYSMON_HK_TLM_LNGTH);

    /*
    ** TODO: Initialize any other messages that this app will publish
    */


    /* 
    ** Always reset all counters during application initialization 
    */
    SYSMON_ResetCounters();

    /* 
     ** Send an information event that the app has initialized. 
     ** This is useful for debugging the loading of individual applications.
     */
    status = CFE_EVS_SendEvent(SYSMON_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
               "SYSMON App Initialized. Version %d.%d.%d.%d",
                SYSMON_MAJOR_VERSION,
                SYSMON_MINOR_VERSION, 
                SYSMON_REVISION, 
                SYSMON_MISSION_REV);	
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SYSMON: Error sending initialization event: 0x%08X\n", (unsigned int) status);
    }
    return status;
} 


/* 
** Process packets received on the SYSMON command pipe
*/
void SYSMON_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(SYSMON_AppData.MsgPtr, &MsgId);
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        /*
        ** Ground Commands with command codes fall under the SYSMON_CMD_MID (Message ID)
        */
        case SYSMON_CMD_MID:
            SYSMON_ProcessGroundCommand();
            break;

        /*
        ** All other messages, other than ground commands, add to this case statement.
        */
        case SYSMON_REQ_HK_MID:
            SYSMON_ProcessTelemetryRequest();
            break;

        /*
        ** All other invalid messages that this app doesn't recognize, 
        ** increment the command error counter and log as an error event.  
        */
        default:
            SYSMON_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SYSMON_PROCESS_CMD_ERR_EID,CFE_EVS_EventType_ERROR, "SYSMON: Invalid command packet, MID = 0x%x", CFE_SB_MsgIdToValue(MsgId));
            break;
    }
    return;
} 


/*
** Process ground commands
** TODO: Add additional commands required by the specific component
*/
void SYSMON_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /*
    ** MsgId is only needed if the command code is not recognized. See default case
    */
    CFE_MSG_GetMsgId(SYSMON_AppData.MsgPtr, &MsgId);

    /*
    ** Ground Commands, by definition, have a command code (_CC) associated with them
    ** Pull this command code from the message and then process
    */
    CFE_MSG_GetFcnCode(SYSMON_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        /*
        ** NOOP Command
        */
        case SYSMON_NOOP_CC:
            /*
            ** First, verify the command length immediately after CC identification 
            ** Note that VerifyCmdLength handles the command and command error counters
            */
            if (SYSMON_VerifyCmdLength(SYSMON_AppData.MsgPtr, sizeof(SYSMON_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                /* Second, send EVS event on successful receipt ground commands*/
                CFE_EVS_SendEvent(SYSMON_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "SYSMON: NOOP command received");
                /* Third, do the desired command action if applicable, in the case of NOOP it is no operation */
            }
            break;

        /*
        ** Reset Counters Command
        */
        case SYSMON_RESET_COUNTERS_CC:
            if (SYSMON_VerifyCmdLength(SYSMON_AppData.MsgPtr, sizeof(SYSMON_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(SYSMON_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, "SYSMON: RESET counters command received");
                SYSMON_ResetCounters();
            }
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SYSMON_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SYSMON_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SYSMON: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
} 


/*
** Process Telemetry Request - Triggered in response to a telemetery request
** TODO: Add additional telemetry required by the specific component
*/
void SYSMON_ProcessTelemetryRequest(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(SYSMON_AppData.MsgPtr, &MsgId);

    /* Pull this command code from the message and then process */
    CFE_MSG_GetFcnCode(SYSMON_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        case SYSMON_REQ_HK_TLM:
            SYSMON_ReportHousekeeping();
            break;
        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SYSMON_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SYSMON_DEVICE_TLM_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SYSMON: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}


/* 
** Report Application Housekeeping
*/
void SYSMON_ReportHousekeeping(void)
{
    SYSMON_ReadAll();
    /* Time stamp and publish housekeeping telemetry */
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &SYSMON_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &SYSMON_AppData.HkTelemetryPkt, true);
    return;
}

/*
** Reset all global counter variables
*/
void SYSMON_ResetCounters(void)
{
    SYSMON_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SYSMON_AppData.HkTelemetryPkt.CommandCount = 0;
    return;
} 

void SYSMON_ReadAll(void)
{

    float cpu_temp = 0;
    uint32 uptime = 0;
    uint32 total_mem = 0;
    uint32 free_mem = 0;
    uint32 disk_total = 0;
    uint32 disk_free = 0;
    float cpu_load = 0;

    if (SYSMON_ReadCpuTempC(&cpu_temp) != SYSMON_SUCCESS)
    {
        SYSMON_AppData.HkTelemetryPkt.CpuTempC = -1.0f;
    }
    else
    {
        SYSMON_AppData.HkTelemetryPkt.CpuTempC = cpu_temp;
    }

    if (SYSMON_ReadUptimeSeconds(&uptime) != SYSMON_SUCCESS)
    {
        SYSMON_AppData.HkTelemetryPkt.UptimeSeconds = 0;
    }
    else
    {
        SYSMON_AppData.HkTelemetryPkt.UptimeSeconds = uptime;
    }

    if (SYSMON_ReadMemoryKb(&total_mem, &free_mem) != SYSMON_SUCCESS)
    {
        SYSMON_AppData.HkTelemetryPkt.TotalMemoryKB = 0;
        SYSMON_AppData.HkTelemetryPkt.FreeMemoryKB = 0;
    }
    else
    {
        SYSMON_AppData.HkTelemetryPkt.TotalMemoryKB = total_mem;
        SYSMON_AppData.HkTelemetryPkt.FreeMemoryKB = free_mem;
    }

    if (SYSMON_ReadDiskMB("/", &disk_total, &disk_free) != SYSMON_SUCCESS)
    {
        SYSMON_AppData.HkTelemetryPkt.DiskTotalMB = 0;
        SYSMON_AppData.HkTelemetryPkt.DiskFreeMB = 0;
    }
    else
    {
        SYSMON_AppData.HkTelemetryPkt.DiskTotalMB = disk_total;
        SYSMON_AppData.HkTelemetryPkt.DiskFreeMB = disk_free;
    }

    if (SYSMON_ReadCpuLoadPercent(&cpu_load) != SYSMON_SUCCESS)
    {
        SYSMON_AppData.HkTelemetryPkt.CpuLoadPercent = -1.0f;
    }
    else
    {
        SYSMON_AppData.HkTelemetryPkt.CpuLoadPercent = cpu_load;
    }
}

/*
** Verify command packet length matches expected
*/
int32 SYSMON_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length)
{     
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length == actual_length)
    {
        /* Increment the command counter upon receipt of an invalid command */
        SYSMON_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(SYSMON_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
           "Invalid msg length: ID = 0x%X,  CC = %d, Len = %d, Expected = %d",
              CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;

        /* Increment the command error counter upon receipt of an invalid command */
        SYSMON_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
} 
