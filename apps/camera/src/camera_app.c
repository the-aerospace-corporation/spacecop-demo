/*******************************************************************************
** File: camera_app.c
**
** Purpose:
**   This file contains the source code for the CAMERA application.
**
*******************************************************************************/

/*
** Include Files
*/
#include <arpa/inet.h>
#include "camera_app.h"


/*
** Global Data
*/
CAMERA_AppData_t CAMERA_AppData;

/*
** Application entry point and main process loop
*/
void CAMERA_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /*
    ** Create the first Performance Log entry
    */
    CFE_ES_PerfLogEntry(CAMERA_PERF_ID);

    /* 
    ** Perform application initialization
    */
    status = CAMERA_AppInit();
    if (status != CFE_SUCCESS)
    {
        CAMERA_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /*
    ** Main loop
    */
    while (CFE_ES_RunLoop(&CAMERA_AppData.RunStatus) == true)
    {
        /*
        ** Performance log exit stamp
        */
        CFE_ES_PerfLogExit(CAMERA_PERF_ID);

        /* 
        ** Pend on the arrival of the next Software Bus message
        ** Note that this is the standard, but timeouts are available
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&CAMERA_AppData.MsgPtr,  CAMERA_AppData.CmdPipe,  CFE_SB_PEND_FOREVER);
        
        /* 
        ** Begin performance metrics on anything after this line. This will help to determine
        ** where we are spending most of the time during this app execution.
        */
        CFE_ES_PerfLogEntry(CAMERA_PERF_ID);

        /*
        ** If the CFE_SB_ReceiveBuffer was successful, then continue to process the command packet
        ** If not, then exit the application in error.
        ** Note that a SB read error should not always result in an app quitting.
        */
        if (status == CFE_SUCCESS)
        {
            CAMERA_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(CAMERA_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "CAMERA: SB Pipe Read Error = %d", (int) status);
            CAMERA_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Performance log exit stamp
    */
    CFE_ES_PerfLogExit(CAMERA_PERF_ID);

    /*
    ** Exit the application
    */
    CFE_ES_ExitApp(CAMERA_AppData.RunStatus);
} 


/* 
** Initialize application
*/
int32 CAMERA_AppInit(void)
{
    int32 status = OS_SUCCESS;
    
    CAMERA_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /*
    ** Register the events
    */ 
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);    /* as default, no filters are used */
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("CAMERA: Error registering for event services: 0x%08X\n", (unsigned int) status);
       return status;
    }

    /*
    ** Create the Software Bus command pipe 
    */
    status = CFE_SB_CreatePipe(&CAMERA_AppData.CmdPipe, CAMERA_PIPE_DEPTH, "CAMERA_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CAMERA_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Creating SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }
    
    /*
    ** Subscribe to ground commands
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CAMERA_CMD_MID), CAMERA_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CAMERA_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Gnd Cmds, MID=0x%04X, RC=0x%08X",
            CAMERA_CMD_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to housekeeping (hk) message requests
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CAMERA_REQ_HK_MID), CAMERA_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(CAMERA_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Request, MID=0x%04X, RC=0x%08X",
            CAMERA_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** TODO: Subscribe to any other messages here
    */


    /* 
    ** Initialize the published HK message - this HK message will contain the 
    ** telemetry that has been defined in the CAMERA_HkTelemetryPkt for this app.
    */
    CFE_MSG_Init(CFE_MSG_PTR(CAMERA_AppData.HkTelemetryPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(CAMERA_HK_TLM_MID),
                   CAMERA_HK_TLM_LNGTH);

    /*
    ** TODO: Initialize any other messages that this app will publish
    */
    CAMERA_AppData.HkTelemetryPkt.CameraAvailable = (CAMERA_CheckAvailable() == CAMERA_SUCCESS) ? 1 : 0;

    /* 
    ** Always reset all counters during application initialization 
    */
    CAMERA_ResetCounters();

    /* 
     ** Send an information event that the app has initialized. 
     ** This is useful for debugging the loading of individual applications.
     */
    status = CFE_EVS_SendEvent(CAMERA_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
               "CAMERA App Initialized. Version %d.%d.%d.%d",
                CAMERA_MAJOR_VERSION,
                CAMERA_MINOR_VERSION, 
                CAMERA_REVISION, 
                CAMERA_MISSION_REV);	
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("CAMERA: Error sending initialization event: 0x%08X\n", (unsigned int) status);
    }
    return status;
} 


/* 
** Process packets received on the CAMERA command pipe
*/
void CAMERA_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(CAMERA_AppData.MsgPtr, &MsgId);
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        /*
        ** Ground Commands with command codes fall under the CAMERA_CMD_MID (Message ID)
        */
        case CAMERA_CMD_MID:
            CAMERA_ProcessGroundCommand();
            break;

        /*
        ** All other messages, other than ground commands, add to this case statement.
        */
        case CAMERA_REQ_HK_MID:
            CAMERA_ProcessTelemetryRequest();
            break;

        /*
        ** All other invalid messages that this app doesn't recognize, 
        ** increment the command error counter and log as an error event.  
        */
        default:
            CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CAMERA_PROCESS_CMD_ERR_EID,CFE_EVS_EventType_ERROR, "CAMERA: Invalid command packet, MID = 0x%x", CFE_SB_MsgIdToValue(MsgId));
            break;
    }
    return;
} 


/*
** Process ground commands
** TODO: Add additional commands required by the specific component
*/
void CAMERA_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /*
    ** MsgId is only needed if the command code is not recognized. See default case
    */
    CFE_MSG_GetMsgId(CAMERA_AppData.MsgPtr, &MsgId);

    /*
    ** Ground Commands, by definition, have a command code (_CC) associated with them
    ** Pull this command code from the message and then process
    */
    CFE_MSG_GetFcnCode(CAMERA_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        /*
        ** NOOP Command
        */
        case CAMERA_NOOP_CC:
            /*
            ** First, verify the command length immediately after CC identification 
            ** Note that VerifyCmdLength handles the command and command error counters
            */
            if (CAMERA_VerifyCmdLength(CAMERA_AppData.MsgPtr, sizeof(CAMERA_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                /* Second, send EVS event on successful receipt ground commands*/
                CFE_EVS_SendEvent(CAMERA_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "CAMERA: NOOP command received");
                /* Third, do the desired command action if applicable, in the case of NOOP it is no operation */
            }
            break;

        /*
        ** Reset Counters Command
        */
        case CAMERA_RESET_COUNTERS_CC:
            if (CAMERA_VerifyCmdLength(CAMERA_AppData.MsgPtr, sizeof(CAMERA_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(CAMERA_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, "CAMERA: RESET counters command received");
                CAMERA_ResetCounters();
            }
            break;

        /*
        ** Enable Command
        */
        case CAMERA_TAKE_PIC_CC:
            if (CAMERA_VerifyCmdLength(CAMERA_AppData.MsgPtr, sizeof(CAMERA_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(CAMERA_CMD_ENABLE_INF_EID, CFE_EVS_EventType_INFORMATION, "CAMERA: Taking Picture");
                CAMERA_TakePic();
            }
            break;

        /*
        ** Disable Command
        */
        case CAMERA_DELETE_LAST_CC:
            if (CAMERA_VerifyCmdLength(CAMERA_AppData.MsgPtr, sizeof(CAMERA_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(CAMERA_CMD_DISABLE_INF_EID, CFE_EVS_EventType_INFORMATION, "CAMERA: Deleting Last Picture");
                CAMERA_DeleteLastPic();
            }
            break;
        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CAMERA_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "CAMERA: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
} 


/*
** Process Telemetry Request - Triggered in response to a telemetery request
** TODO: Add additional telemetry required by the specific component
*/
void CAMERA_ProcessTelemetryRequest(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(CAMERA_AppData.MsgPtr, &MsgId);

    /* Pull this command code from the message and then process */
    CFE_MSG_GetFcnCode(CAMERA_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        case CAMERA_REQ_HK_TLM:
            CAMERA_ReportHousekeeping();
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(CAMERA_DEVICE_TLM_ERR_EID, CFE_EVS_EventType_ERROR, 
                "CAMERA: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}


/* 
** Report Application Housekeeping
*/
void CAMERA_ReportHousekeeping(void)
{
    /* Time stamp and publish housekeeping telemetry */
    CAMERA_AppData.HkTelemetryPkt.CameraAvailable = (CAMERA_CheckAvailable() == CAMERA_SUCCESS) ? 1 : 0;
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &CAMERA_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &CAMERA_AppData.HkTelemetryPkt, true);
    return;
}

void CAMERA_TakePic(void)
{
    char path[CAMERA_PATH_LEN];
    uint32_t size_bytes = 0;
    uint32_t next_image;

    CAMERA_AppData.HkTelemetryPkt.CaptureInProgress = 1;
    CAMERA_AppData.HkTelemetryPkt.LastCaptureStatus = 0;

    if (CAMERA_EnsureDirectory(CAMERA_IMAGE_DIR) != CAMERA_SUCCESS)
    {
        CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
        CAMERA_AppData.HkTelemetryPkt.CaptureInProgress = 0;
        return;
    }

    next_image = CAMERA_AppData.HkTelemetryPkt.ImageCounter + 1;

    if (CAMERA_BuildImagePath(path, sizeof(path), CAMERA_IMAGE_DIR, next_image) != CAMERA_SUCCESS)
    {
        CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
        CAMERA_AppData.HkTelemetryPkt.CaptureInProgress = 0;
        return;
    }

    if (CAMERA_TakeImage(path, CAMERA_IMAGE_WIDTH, CAMERA_IMAGE_HEIGHT, CAMERA_TIMEOUT_MS) == CAMERA_SUCCESS)
    {
        CAMERA_AppData.HkTelemetryPkt.ImageCounter = next_image;
        CAMERA_AppData.HkTelemetryPkt.LastCaptureStatus = 1;
        CAMERA_AppData.HkTelemetryPkt.LastCaptureUnixTime = CAMERA_GetUnixTime();

        strncpy(CAMERA_AppData.HkTelemetryPkt.LastImagePath, path, sizeof(CAMERA_AppData.HkTelemetryPkt.LastImagePath) -1);

        CAMERA_AppData.HkTelemetryPkt.LastImagePath[sizeof(CAMERA_AppData.HkTelemetryPkt.LastImagePath) - 1] = '\0';

        if (CAMERA_GetFileSizeBytes(path, &size_bytes) == CAMERA_SUCCESS)
        {
            CAMERA_AppData.HkTelemetryPkt.LastImageSizeBytes = size_bytes;
        }
        else
        {
            CAMERA_AppData.HkTelemetryPkt.LastImageSizeBytes = 0;
        }

        CAMERA_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
        CAMERA_AppData.HkTelemetryPkt.LastCaptureStatus = 0;
    }

    CAMERA_AppData.HkTelemetryPkt.CaptureInProgress = 0;
}

void CAMERA_DeleteLastPic(void)
{
    if (CAMERA_DeleteImage(CAMERA_AppData.HkTelemetryPkt.LastImagePath) == CAMERA_SUCCESS)
    {
        CAMERA_AppData.HkTelemetryPkt.LastDeleteStatus = 1;
        CAMERA_AppData.HkTelemetryPkt.LastImageSizeBytes = 0;
        CAMERA_AppData.HkTelemetryPkt.LastImagePath[0] = '\0';
        CAMERA_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CAMERA_AppData.HkTelemetryPkt.LastDeleteStatus = 0;
        CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
}

/*
** Reset all global counter variables
*/
void CAMERA_ResetCounters(void)
{
    CAMERA_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    CAMERA_AppData.HkTelemetryPkt.CommandCount = 0;
    return;
} 

/*
** Verify command packet length matches expected
*/
int32 CAMERA_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length)
{     
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length == actual_length)
    {
        /* Increment the command counter upon receipt of an invalid command */
        CAMERA_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(CAMERA_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
           "Invalid msg length: ID = 0x%X,  CC = %d, Len = %d, Expected = %d",
              CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;

        /* Increment the command error counter upon receipt of an invalid command */
        CAMERA_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
} 
