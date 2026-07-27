/*******************************************************************************
** File: camera_app.h
**
** Purpose:
**   This is the main header file for the CAMERA application.
**
*******************************************************************************/
#ifndef _CAMERA_APP_H_
#define _CAMERA_APP_H_

/*
** Include Files
*/
#include "cfe.h"
#include "camera_events.h"
#include "camera_platform_cfg.h"
#include "camera_perfids.h"
#include "camera_msg.h"
#include "camera_msgids.h"
#include "camera_version.h"
#include "camera_funcs.h"


/*
** Specified pipe depth - how many messages will be queued in the pipe
*/
#define CAMERA_PIPE_DEPTH            32

/* Deploy filesystem layout (physical host paths; must match the PSP FixedMap
 * targets in psp/fsw/pc-linux/src/cfe_psp_start.c). Camera shells out to
 * rpicam-still/raspistill, so these are RAW host paths, not OSAL virtual. */
#define CAMERA_IMAGE_DIR            "/var/pisat/data"
#define CAMERA_LOG_DIR             "/var/pisat/logs"
#define CAMERA_IMAGE_WIDTH          640
#define CAMERA_IMAGE_HEIGHT         480
#define CAMERA_TIMEOUT_MS           1000
/*
** CAMERA global data structure
** The cFE convention is to put all global app data in a single struct. 
** This struct is defined in the `camera_app.h` file with one global instance 
** in the `.c` file.
*/
typedef struct
{
    /*
    ** Housekeeping telemetry packet
    ** Each app defines its own packet which contains its OWN telemetry
    */
    CAMERA_Hk_tlm_t   HkTelemetryPkt;   /* CAMERA Housekeeping Telemetry Packet */
    
    /*
    ** Operational data  - not reported in housekeeping
    */
    CFE_MSG_Message_t * MsgPtr;             /* Pointer to msg received on software bus */
    CFE_SB_PipeId_t CmdPipe;            /* Pipe Id for HK command pipe */
    uint32 RunStatus;                   /* App run status for controlling the application state */
} CAMERA_AppData_t;


/*
** Exported Data
** Extern the global struct in the header for the Unit Test Framework (UTF).
*/
extern CAMERA_AppData_t CAMERA_AppData; /* CAMERA App Data */


/*
**
** Local function prototypes.
**
** Note: Except for the entry point (CAMERA_AppMain), these
**       functions are not called from any other source module.
*/
void  CAMERA_AppMain(void);
int32 CAMERA_AppInit(void);
void  CAMERA_ProcessCommandPacket(void);
void  CAMERA_ProcessGroundCommand(void);
void  CAMERA_ProcessTelemetryRequest(void);
void  CAMERA_ReportHousekeeping(void);
void  CAMERA_ResetCounters(void);
void CAMERA_DeleteLastPic(void);
void CAMERA_TakePic(void);
int32 CAMERA_VerifyCmdLength(CFE_MSG_Message_t * msg, uint16 expected_length);

#endif /* _CAMERA_APP_H_ */
