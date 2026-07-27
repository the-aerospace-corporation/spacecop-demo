/************************************************************************
** File:
**   $Id: camera_msgids.h  $
**
** Purpose:
**  Define CAMERA Message IDs
**
*************************************************************************/
#ifndef _CAMERA_MSGIDS_H_
#define _CAMERA_MSGIDS_H_

/* 
** CCSDS V1 Command Message IDs (MID) must be 0x18xx
*/
#define CAMERA_CMD_MID              0x19DA /* TODO: Change this for your app */ 

/* 
** This MID is for commands telling the app to publish its telemetry message
*/
#define CAMERA_REQ_HK_MID           0x19DB /* TODO: Change this for your app */

/* 
** CCSDS V1 Telemetry Message IDs must be 0x08xx
*/
#define CAMERA_HK_TLM_MID           0x09DA /* TODO: Change this for your app */

#endif /* _CAMERA_MSGIDS_H_ */
