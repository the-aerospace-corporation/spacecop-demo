/*******************************************************************************
** File:
**   camera_msg.h
**
** Purpose:
**  Define CAMERA application commands and telemetry messages
**
*******************************************************************************/
#ifndef _CAMERA_MSG_H_
#define _CAMERA_MSG_H_

#include "cfe.h"

/*
** Ground Command Codes
** TODO: Add additional commands required by the specific component
*/
#define CAMERA_NOOP_CC                 0
#define CAMERA_RESET_COUNTERS_CC       1
#define CAMERA_TAKE_PIC_CC             2
#define CAMERA_DELETE_LAST_CC          3

#define CAMERA_PATH_LEN                128

/* 
** Telemetry Request Command Codes
** TODO: Add additional commands required by the specific component
*/
#define CAMERA_REQ_HK_TLM              0

/*
** Generic "no arguments" command type definition
*/
typedef struct
{
    /* Every command requires a header used to identify it */
    CFE_MSG_CommandHeader_t CmdHeader;

} CAMERA_NoArgs_cmd_t;


/*
** CAMERA housekeeping type definition
*/
typedef struct 
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   CommandErrorCount;
    uint8   CommandCount;
    uint16  ImageCounter;
    uint8   CameraAvailable;
    uint8   CaptureInProgress;
    uint8   LastCaptureStatus;
    char    LastImagePath[CAMERA_PATH_LEN];
    uint32  LastImageSizeBytes;
    uint32  LastCaptureUnixTime;
    uint8   LastDeleteStatus;
} __attribute__((packed)) CAMERA_Hk_tlm_t;
#define CAMERA_HK_TLM_LNGTH sizeof ( CAMERA_Hk_tlm_t )

#endif /* _CAMERA_MSG_H_ */
