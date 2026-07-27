/*******************************************************************************
** File: stpyld_app.c
**
** Purpose:
**   This file contains the source code for the SP application.
**
*******************************************************************************/

/*
** Include Files
*/
#include <arpa/inet.h>
#include "stpyld_app.h"


/*
** Global Data
*/
SP_AppData_t SP_AppData;

/*
** Application entry point and main process loop
*/
void SP_AppMain(void)
{
    int32 status = OS_SUCCESS;

    /*
    ** Create the first Performance Log entry
    */
    CFE_ES_PerfLogEntry(SP_PERF_ID);

    /* 
    ** Perform application initialization
    */
    status = SP_AppInit();
    if (status != CFE_SUCCESS)
    {
        SP_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    /*
    ** Main loop
    */
    while (CFE_ES_RunLoop(&SP_AppData.RunStatus) == true)
    {
        /*
        ** Performance log exit stamp
        */
        CFE_ES_PerfLogExit(SP_PERF_ID);

        /* 
        ** Pend on the arrival of the next Software Bus message
        ** Note that this is the standard, but timeouts are available
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&SP_AppData.MsgPtr,  SP_AppData.CmdPipe,  CFE_SB_PEND_FOREVER);
        
        /* 
        ** Begin performance metrics on anything after this line. This will help to determine
        ** where we are spending most of the time during this app execution.
        */
        CFE_ES_PerfLogEntry(SP_PERF_ID);

        /*
        ** If the CFE_SB_ReceiveBuffer was successful, then continue to process the command packet
        ** If not, then exit the application in error.
        ** Note that a SB read error should not always result in an app quitting.
        */
        if (status == CFE_SUCCESS)
        {
            SP_ProcessCommandPacket();
        }
        else
        {
            CFE_EVS_SendEvent(SP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "SP: SB Pipe Read Error = %d", (int) status);
            SP_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    /*
    ** Performance log exit stamp
    */
    CFE_ES_PerfLogExit(SP_PERF_ID);

    /*
    ** Exit the application
    */
    CFE_ES_ExitApp(SP_AppData.RunStatus);
} 


/* 
** Initialize application
*/
int32 SP_AppInit(void)
{
    int32 status = OS_SUCCESS;
    
    SP_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    /*
    ** Register the events
    */ 
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);    /* as default, no filters are used */
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP: Error registering for event services: 0x%08X\n", (unsigned int) status);
       return status;
    }

    /*
    ** Create the Software Bus command pipe 
    */
    status = CFE_SB_CreatePipe(&SP_AppData.CmdPipe, SP_PIPE_DEPTH, "SP_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Creating SB Pipe,RC=0x%08X",(unsigned int) status);
       return status;
    }
    
    /*
    ** Subscribe to ground commands
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP_CMD_MID), SP_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Gnd Cmds, MID=0x%04X, RC=0x%08X",
            SP_CMD_MID, (unsigned int) status);
        return status;
    }

    /*
    ** Subscribe to housekeeping (hk) message requests
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SP_REQ_HK_MID), SP_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(SP_SUB_REQ_HK_ERR_EID, CFE_EVS_EventType_ERROR,
            "Error Subscribing to HK Request, MID=0x%04X, RC=0x%08X",
            SP_REQ_HK_MID, (unsigned int) status);
        return status;
    }

    /*
    ** TODO: Subscribe to any other messages here
    */


    /* 
    ** Initialize the published HK message - this HK message will contain the 
    ** telemetry that has been defined in the SP_HkTelemetryPkt for this app.
    */
    CFE_MSG_Init(CFE_MSG_PTR(SP_AppData.HkTelemetryPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(SP_HK_TLM_MID),
                   SP_HK_TLM_LNGTH);
    /*
    ** TODO: Initialize any other messages that this app will publish
    */

    SP_AppData.SerialFd = STEM_SERIAL_Open(SP_SERIAL_DEVICE, SP_SERIAL_BAUD);

    if (SP_AppData.SerialFd < 0)
    {
        CFE_EVS_SendEvent(SP_STARTUP_INF_EID, CFE_EVS_EventType_ERROR, "SP: Failed to open serial device %s", SP_SERIAL_DEVICE);
    }
    else
    {
        CFE_EVS_SendEvent(SP_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION, "SP: Opened serial device %s", SP_SERIAL_DEVICE);
    }


    /* 
    ** Always reset all counters during application initialization 
    */
    SP_ResetCounters();

    /* 
     ** Send an information event that the app has initialized. 
     ** This is useful for debugging the loading of individual applications.
     */
    status = CFE_EVS_SendEvent(SP_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
               "SP App Initialized. Version %d.%d.%d.%d",
                SP_MAJOR_VERSION,
                SP_MINOR_VERSION, 
                SP_REVISION, 
                SP_MISSION_REV);	
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("SP: Error sending initialization event: 0x%08X\n", (unsigned int) status);
    }
    return status;
} 


/* 
** Process packets received on the SP command pipe
*/
void SP_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(SP_AppData.MsgPtr, &MsgId);
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        /*
        ** Ground Commands with command codes fall under the SP_CMD_MID (Message ID)
        */
        case SP_CMD_MID:
            SP_ProcessGroundCommand();
            break;

        /*
        ** All other messages, other than ground commands, add to this case statement.
        */
        case SP_REQ_HK_MID:
            SP_ProcessTelemetryRequest();
            break;

        /*
        ** All other invalid messages that this app doesn't recognize, 
        ** increment the command error counter and log as an error event.  
        */
        default:
            SP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP_PROCESS_CMD_ERR_EID,CFE_EVS_EventType_ERROR, "SP: Invalid command packet, MID = 0x%x", CFE_SB_MsgIdToValue(MsgId));
            break;
    }
    return;
} 


/*
** Process ground commands
** TODO: Add additional commands required by the specific component
*/
void SP_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /*
    ** MsgId is only needed if the command code is not recognized. See default case
    */
    CFE_MSG_GetMsgId(SP_AppData.MsgPtr, &MsgId);

    /*
    ** Ground Commands, by definition, have a command code (_CC) associated with them
    ** Pull this command code from the message and then process
    */
    CFE_MSG_GetFcnCode(SP_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        /*
        ** NOOP Command
        */
        case SP_NOOP_CC:
            /*
            ** First, verify the command length immediately after CC identification 
            ** Note that VerifyCmdLength handles the command and command error counters
            */
            if (SP_VerifyCmdLength(SP_AppData.MsgPtr, sizeof(SP_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                /* Second, send EVS event on successful receipt ground commands*/
                CFE_EVS_SendEvent(SP_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "SP: NOOP command received");
                /* Third, do the desired command action if applicable, in the case of NOOP it is no operation */
            }
            break;

        /*
        ** Reset Counters Command
        */
        case SP_RESET_COUNTERS_CC:
            if (SP_VerifyCmdLength(SP_AppData.MsgPtr, sizeof(SP_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                CFE_EVS_SendEvent(SP_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, "SP: RESET counters command received");
                SP_ResetCounters();
            }
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SP: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
} 

/*
** Process Telemetry Request - Triggered in response to a telemetery request
** TODO: Add additional telemetry required by the specific component
*/
void SP_ProcessTelemetryRequest(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    /* MsgId is only needed if the command code is not recognized. See default case */
    CFE_MSG_GetMsgId(SP_AppData.MsgPtr, &MsgId);

    /* Pull this command code from the message and then process */
    CFE_MSG_GetFcnCode(SP_AppData.MsgPtr, &CommandCode);
    switch (CommandCode)
    {
        case SP_REQ_HK_TLM:
            SP_ReportHousekeeping();
            break;

        /*
        ** Invalid Command Codes
        */
        default:
            /* Increment the error counter upon receipt of an invalid command */
            SP_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(SP_DEVICE_TLM_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SP: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x", CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}


/* 
** Report Application Housekeeping
*/
void SP_ReportHousekeeping(void)
{
    SP_ReadSensorLine();
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &SP_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &SP_AppData.HkTelemetryPkt, true);
    return;
}

/*
** Reset all global counter variables
*/
void SP_ResetCounters(void)
{
    SP_AppData.HkTelemetryPkt.CommandErrorCount = 0;
    SP_AppData.HkTelemetryPkt.CommandCount = 0;
    return;
} 

/*
** Verify command packet length matches expected
*/
int32 SP_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length)
{     
    int32 status = OS_SUCCESS;
    CFE_SB_MsgId_t msg_id = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code = 0;
    size_t actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length == actual_length)
    {
        /* Increment the command counter upon receipt of an invalid command */
        SP_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(SP_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
           "Invalid msg length: ID = 0x%X,  CC = %d, Len = %d, Expected = %d",
              CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;

        /* Increment the command error counter upon receipt of an invalid command */
        SP_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
} 

void SP_ReadSensorLine(void)
{
    int len;

    SP_AppData.HkTelemetryPkt.PayloadValid = 0;
    SP_AppData.HkTelemetryPkt.BmeValid = 0;
    SP_AppData.HkTelemetryPkt.ImuValid = 0;
    SP_AppData.HkTelemetryPkt.GpsValid = 0;

    if (SP_AppData.SerialFd < 0)
    {
        SP_AppData.HkTelemetryPkt.CommandErrorCount++;
        return;
    }

    len = STEM_SERIAL_ReadLine(SP_AppData.SerialFd, SP_AppData.LineBuffer, sizeof(SP_AppData.LineBuffer));

    if (len <= 0)
    {
        SP_AppData.HkTelemetryPkt.CommandErrorCount++;
        return;
    }

    if (SP_ParseLine(SP_AppData.LineBuffer) != 0)
    {
        SP_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
}

int SP_ParseLine(const char *line)
{
    char ok[24];
    char bme[16];
    char mpu[16];
    char gps[16];
    char tmp[16];

    float temp;
    float pressure;
    float altitude;
    float humidity;

    float gx;
    float gy;
    float gz;

    float ax;
    float ay;
    float az;

    float gps1;
    float gps2;
    float gps3;

    float tmp_value;

    int fields;

    //_START_FLAG_OK BME280 31.78 979.79 282.41 30.49 MPU6050 -29.66 -7.36 6.53 -0.01 0.01 1.15 GPS 0.0000 0.0000 0.00 TMP 24.00_END_FLAG_

    fields = sscanf(line, "%23s %15s %f %f %f %f %15s %f %f %f %f %f %f %15s %f %f %f %15s %f", ok, bme, &temp, &pressure, &altitude, &humidity, mpu, &gx, &gy, &gz, &ax, &ay, &az, gps, &gps1, &gps2, &gps3, tmp, &tmp_value);

    if (fields != 19)
    {
        return -1;
    }

    if (strcmp(ok, "_START_FLAG_OK") != 0 || strcmp(bme, "BME280") != 0 || strcmp(mpu, "MPU6050") != 0 || strcmp(gps, "GPS") != 0 || strcmp(tmp, "TMP") != 0)
    {
        return -1;
    }

    SP_AppData.HkTelemetryPkt.PayloadValid = 1;

    SP_AppData.HkTelemetryPkt.Temperature_C = temp;
    SP_AppData.HkTelemetryPkt.Pressure_hPa = pressure;
    SP_AppData.HkTelemetryPkt.Altitude_m = altitude;
    SP_AppData.HkTelemetryPkt.Humidity_pct = humidity;
    SP_AppData.HkTelemetryPkt.GyroX_dps = gx;
    SP_AppData.HkTelemetryPkt.GyroY_dps = gy;
    SP_AppData.HkTelemetryPkt.GyroZ_dps = gz;
    SP_AppData.HkTelemetryPkt.AccelX_g = ax;
    SP_AppData.HkTelemetryPkt.AccelY_g = ay;
    SP_AppData.HkTelemetryPkt.AccelZ_g = az;
    SP_AppData.HkTelemetryPkt.GPSVal1 = gps1;
    SP_AppData.HkTelemetryPkt.GPSVal2 = gps2;
    SP_AppData.HkTelemetryPkt.GPSVal3 = gps3;

    if (!(temp == 0.0f && pressure == 0.0f && altitude == 0.0f && humidity == 0.0f))
    {
        SP_AppData.HkTelemetryPkt.BmeValid = 1;
    }

    if (!(gx == 0.0f && gy == 0.0f && gz == 0.0f && ax == 0.0f && ay == 0.0f && az == 0.0f))
    {
        SP_AppData.HkTelemetryPkt.ImuValid = 1;
    }

    if (!(gps1 == 0.0f && gps2 == 0.0f && gps3 == 0.0f))
    {
        SP_AppData.HkTelemetryPkt.GpsValid = 1;
    }

    return 0;
}


