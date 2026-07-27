/*******************************************************************************
** File: sysmon_app.h
**
** Purpose:
**   This is the main header file for the SYSMON application.
**
*******************************************************************************/
#ifndef _SYSMON_APP_H_
#define _SYSMON_APP_H_

/*
** Include Files
*/
#include "cfe.h"
#include "sysmon_events.h"
#include "sysmon_platform_cfg.h"
#include "sysmon_perfids.h"
#include "sysmon_msg.h"
#include "sysmon_msgids.h"
#include "sysmon_version.h"
#include "sysmon_linux.h"


/*
** Specified pipe depth - how many messages will be queued in the pipe
*/
#define SYSMON_PIPE_DEPTH            32

/*
** SYSMON global data structure
** The cFE convention is to put all global app data in a single struct. 
** This struct is defined in the `sysmon_app.h` file with one global instance 
** in the `.c` file.
*/
typedef struct
{
    /*
    ** Housekeeping telemetry packet
    ** Each app defines its own packet which contains its OWN telemetry
    */
    SYSMON_Hk_tlm_t   HkTelemetryPkt;   /* SYSMON Housekeeping Telemetry Packet */
    
    /*
    ** Operational data  - not reported in housekeeping
    */
    CFE_MSG_Message_t * MsgPtr;             /* Pointer to msg received on software bus */
    CFE_SB_PipeId_t CmdPipe;            /* Pipe Id for HK command pipe */
    uint32 RunStatus;                   /* App run status for controlling the application state */

} SYSMON_AppData_t;


/*
** Exported Data
** Extern the global struct in the header for the Unit Test Framework (UTF).
*/
extern SYSMON_AppData_t SYSMON_AppData; /* SYSMON App Data */


/*
**
** Local function prototypes.
**
** Note: Except for the entry point (SYSMON_AppMain), these
**       functions are not called from any other source module.
*/
void  SYSMON_AppMain(void);
int32 SYSMON_AppInit(void);
void  SYSMON_ProcessCommandPacket(void);
void  SYSMON_ProcessGroundCommand(void);
void  SYSMON_ProcessTelemetryRequest(void);
void  SYSMON_ReportHousekeeping(void);
void  SYSMON_ResetCounters(void);
void SYSMON_ReadAll(void);
int32 SYSMON_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length);

#endif /* _SYSMON_APP_H_ */
