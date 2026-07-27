/*******************************************************************************
** File: eps_app.c
**
** Purpose:
**   This file contains the source code for the EPS application.
**
*******************************************************************************/

/*
** Include Files
*/
#include <arpa/inet.h>
#include "eps_app.h"

static const char *EPS_I2cBus[EPS_MAX_CHANNELS] = 
{
    "/dev/i2c-1", //right
    "/dev/i2c-1", //back
    "/dev/i2c-1", //battery
    "/dev/i2c-1", //dead
    "/dev/i2c-3", //top
    "/dev/i2c-3", //left
    "/dev/i2c-3", //front
    "/dev/i2c-3"  //bottom
};

static const uint8_t EPS_I2cAddr[EPS_MAX_CHANNELS] = 
{
    0x40,
    0x41,
    0x44,
    0x45,
    0x40,
    0x41,
    0x44,
    0x45,
};
/*
** Global Data
*/
EPS_AppData_t EPS_AppData;

static void EPS_InitHardware(void)
{
    uint8_t sensor_count = 0;

    for (uint8_t i = 0; i < EPS_MAX_CHANNELS; i++)
    {
        if (INA219_Open(&EPS_AppData.Ina219[i], EPS_I2cBus[i], EPS_I2cAddr[i]) == 0)
        {
            EPS_AppData.HkTelemetryPkt.present[i] = 1;
            sensor_count ++;
        }
        else
        {
            EPS_AppData.HkTelemetryPkt.present[i] = 0;
        }
    }

    EPS_AppData.HkTelemetryPkt.sensor_count = sensor_count;

    CFE_EVS_SendEvent(I2C_SENSOR_EID, CFE_EVS_EventType_INFORMATION, "EPS: Detected %u INA219 sensors", sensor_count);
}

static void EPS_ReadSensors(void)
{
    float voltage = 0.0f;
    float currant_ma = 0.0f;

    for (uint8_t i = 0; i < EPS_MAX_CHANNELS; i++)
    {
        if (EPS_AppData.HkTelemetryPkt.present[i])
        {
            if (INA219_Read(&EPS_AppData.Ina219[i], &voltage, &currant_ma) == 0)
            {
                EPS_AppData.HkTelemetryPkt.voltage[i] = voltage;
                EPS_AppData.HkTelemetryPkt.currant_ma[i] = currant_ma;
            }
            else
            {
                EPS_AppData.HkTelemetryPkt.voltage[i] = -1.0f;
                EPS_AppData.HkTelemetryPkt.currant_ma[i] = -1.0f;
                EPS_AppData.HkTelemetryPkt.ErrorCount++;
            }
        }
        else
        {
            EPS_AppData.HkTelemetryPkt.voltage[i] = -1.0f;
            EPS_AppData.HkTelemetryPkt.currant_ma[i] = -1.0f;
        }

        //printf("EPS: Curr Num %d - voltage = %0.2f, currant_ma = %0.2f\n", i, EPS_AppData.HkTelemetryPkt.voltage[i], EPS_AppData.HkTelemetryPkt.currant_ma[i]);
    }
}

/*
** Application entry point and main process loop
*/
void EPS_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /*
    ** Create the first Performance Log entry
    */
    CFE_ES_PerfLogEntry(EPS_PERF_ID);

    /* 
    ** Perform application initialization
    */
    status = EPS_AppInit();
    if (status != CFE_SUCCESS)
    {
        EPS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /*
    ** Main loop
    */
    while (CFE_ES_RunLoop(&EPS_AppData.RunStatus) == true)
    {
        /*
        ** Performance log exit stamp
        */
        CFE_ES_PerfLogExit(EPS_PERF_ID);

        /* 
        ** Pend on the arrival of the next Software Bus message
        ** Note that this is the standard, but timeouts are available
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&EPS_AppData.MsgPtr,  EPS_AppData.CmdPipe,  CFE_SB_PEND_FOREVER);
        
        /* 
        ** Begin performance metrics on anything after this line. This will help to determine
        ** where we are spending most of the time during this app execution.
        */
        CFE_ES_PerfLogEntry(EPS_PERF_ID);

        /*
        ** If the CFE_SB_ReceiveBuffer was successful, then continue to process the command packet
        ** If not, then exit the application in error.
        ** Note that a SB read error should not always result in an app quitting.
        */
        if (status == CFE_SUCCESS)
        {
            EPS_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(EPS_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "EPS: SB Pipe Read Error = %d", (int) status);
            EPS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Performance log exit stamp
    */
    CFE_ES_PerfLogExit(EPS_PERF_ID);

    /*
    ** Exit the application
    */
    CFE_ES_ExitApp(EPS_AppData.RunStatus);
} 


/* 
** Initialize application
*/
int32 EPS_AppInit(void)
{
    int32 status = OS_SUCCESS;
    
    EPS_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /*
    ** Register the events
    */ 
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);    /* as default, no filters are used */
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("EPS: Error registering for event services: 0x%08X\n", (unsigned int) status);
       return status;
    }

    /*
    ** Create the Software Bus command pipe 
    */
    status = CFE_SB_CreatePipe(&EPS_AppData.CmdPipe, EPS_PIPE_DEPTH, "EPS_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(EPS_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Creating SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }
    
    /*
    ** Subscribe to ground commands
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(EPS_CMD_MID), EPS_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(EPS_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Gnd Cmds, MID=0x%04X, RC=0x%08X",
            EPS_CMD_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to housekeeping (hk) message requests
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(EPS_REQ_HK_MID), EPS_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(EPS_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Request, MID=0x%04X, RC=0x%08X",
            EPS_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** TODO: Subscribe to any other messages here
    */


    /* 
    ** Initialize the published HK message - this HK message will contain the 
    ** telemetry that has been defined in the EPS_HkTelemetryPkt for this app.
    */
    CFE_MSG_Init(CFE_MSG_PTR(EPS_AppData.HkTelemetryPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(EPS_HK_TLM_MID),
                   EPS_HK_TLM_LNGTH);

    EPS_InitHardware();
    /* 
    ** Always reset all counters during application initialization 
    */
    EPS_ResetCounters();

    /* 
     ** Send an information event that the app has initialized. 
     ** This is useful for debugging the loading of individual applications.
     */
    status = CFE_EVS_SendEvent(EPS_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
               "EPS App Initialized. Version %d.%d.%d.%d",
                EPS_MAJOR_VERSION,
                EPS_MINOR_VERSION, 
                EPS_REVISION, 
                EPS_MISSION_REV);	
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("EPS: Error sending initialization event: 0x%08X\n", (unsigned int) status);
    }
    return status;
} 


/* 
** Process packets received on the EPS command pipe
*/
void EPS_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(EPS_AppData.MsgPtr, &MsgId);
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        /*
        ** Ground Commands with command codes fall under the EPS_CMD_MID (Message ID)
        */
        case EPS_CMD_MID:
            EPS_ProcessGroundCommand();
            break;

        /*
        ** All other messages, other than ground commands, add to this case statement.
        */
        case EPS_REQ_HK_MID:
            //printf("EPS: Requesting HK\n");
            EPS_ProcessTelemetryRequest();
            break;

        /*
        ** All other invalid messages that this app doesn't recognize, 
        ** increment the command error counter and log as an error event.  
        */
        default:
            EPS_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(EPS_PROCESS_CMD_ERR_EID,CFE_EVS_EventType_ERROR, "EPS: Invalid command packet, MID = 0x%x", CFE_SB_MsgIdToValue(MsgId));
            break;
    }
    return;
} 


/*
** Process ground commands
** TODO: Add additional commands required by the specific component
*/
void EPS_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /*
    ** MsgId is only needed if the command code is not recognized. See default case
    */
    CFE_MSG_GetMsgId(EPS_AppData.MsgPtr, &MsgId);

    /*
    ** Ground Commands, by definition, have a command code (_CC) associated with them
    ** Pull this command code from the message and then process
    */
    CFE_MSG_GetFcnCode(EPS_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        /*
        ** NOOP Command
        */
        case EPS_NOOP_CC:
            /*
            ** First, verify the command length immediately after CC identification 
            ** Note that VerifyCmdLength handles the command and command error counters
            */
            if (EPS_VerifyCmdLength(EPS_AppData.MsgPtr, sizeof(EPS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                /* Second, send EVS event on successful receipt ground commands*/
                CFE_EVS_SendEvent(EPS_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "EPS: NOOP command received");
                /* Third, do the desired command action if applicable, in the case of NOOP it is no operation */
            }
            break;

        /*
        ** Reset Counters Command
        */
        case EPS_RESET_COUNTERS_CC:
            if (EPS_VerifyCmdLength(EPS_AppData.MsgPtr, sizeof(EPS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(EPS_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, "EPS: RESET counters command received");
                EPS_ResetCounters();
            }
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            EPS_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(EPS_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "EPS: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
} 


/*
** Process Telemetry Request - Triggered in response to a telemetery request
** TODO: Add additional telemetry required by the specific component
*/
void EPS_ProcessTelemetryRequest(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(EPS_AppData.MsgPtr, &MsgId);

    /* Pull this command code from the message and then process */
    CFE_MSG_GetFcnCode(EPS_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        case EPS_REQ_HK_TLM:
            EPS_ReportHousekeeping();
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            EPS_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(EPS_DEVICE_TLM_ERR_EID, CFE_EVS_EventType_ERROR, 
                "EPS: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}


/* 
** Report Application Housekeeping
*/
void EPS_ReportHousekeeping(void)
{
    EPS_ReadSensors();
    /* Time stamp and publish housekeeping telemetry */
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &EPS_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &EPS_AppData.HkTelemetryPkt, true);
    return;
}


/*
** Reset all global counter variables
*/
void EPS_ResetCounters(void)
{
    EPS_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    EPS_AppData.HkTelemetryPkt.CommandCount = 0;
    EPS_AppData.HkTelemetryPkt.ErrorCount = 0;
    return;
} 

/*
** Verify command packet length matches expected
*/
int32 EPS_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length)
{     
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length == actual_length)
    {
        /* Increment the command counter upon receipt of an invalid command */
        EPS_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(EPS_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
           "Invalid msg length: ID = 0x%X,  CC = %d, Len = %d, Expected = %d",
              CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;

        /* Increment the command error counter upon receipt of an invalid command */
        EPS_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
} 
