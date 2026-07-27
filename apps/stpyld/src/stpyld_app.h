/*******************************************************************************
** File: stpyld_app.h
**
** Purpose:
**   This is the main header file for the SP application.
**
*******************************************************************************/
#ifndef _SP_APP_H_
#define _SP_APP_H_

/*
** Include Files
*/
#include "cfe.h"
#include "stpyld_events.h"
#include "stpyld_platform_cfg.h"
#include "stpyld_perfids.h"
#include "stpyld_msg.h"
#include "stpyld_msgids.h"
#include "stpyld_version.h"
#include "stpyld_serial.h"


/*
** Specified pipe depth - how many messages will be queued in the pipe
*/
#define SP_PIPE_DEPTH            32

#define SP_SERIAL_DEVICE        "/dev/serial0"
#define SP_SERIAL_BAUD          115200
#define SP_LINE_MAX             256


/*
** SP global data structure
** The cFE convention is to put all global app data in a single struct. 
** This struct is defined in the `stpyld_app.h` file with one global instance 
** in the `.c` file.
*/
typedef struct
{
    /*
    ** Housekeeping telemetry packet
    ** Each app defines its own packet which contains its OWN telemetry
    */
    SP_Hk_tlm_t   HkTelemetryPkt;   /* SP Housekeeping Telemetry Packet */
    
    /*
    ** Operational data  - not reported in housekeeping
    */
    CFE_MSG_Message_t * MsgPtr;             /* Pointer to msg received on software bus */
    CFE_SB_PipeId_t CmdPipe;            /* Pipe Id for HK command pipe */
    uint32 RunStatus;                   /* App run status for controlling the application state */
    int SerialFd;
    char LineBuffer[SP_LINE_MAX];
} SP_AppData_t;


/*
** Exported Data
** Extern the global struct in the header for the Unit Test Framework (UTF).
*/
extern SP_AppData_t SP_AppData; /* SP App Data */


/*
**
** Local function prototypes.
**
** Note: Except for the entry point (SP_AppMain), these
**       functions are not called from any other source module.
*/
void  SP_AppMain(void);
int32 SP_AppInit(void);
void  SP_ProcessCommandPacket(void);
void  SP_ProcessGroundCommand(void);
void  SP_ProcessTelemetryRequest(void);
void  SP_ReportHousekeeping(void);
void  SP_ResetCounters(void);
int32 SP_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length);
void SP_ReadSensorLine(void);
int SP_ParseLine(const char *line);

#endif /* _SP_APP_H_ */
