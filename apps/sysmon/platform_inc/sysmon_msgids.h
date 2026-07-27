/************************************************************************
** File:
**   $Id: sysmon_msgids.h  $
**
** Purpose:
**  Define SYSMON Message IDs
**
*************************************************************************/
#ifndef _SYSMON_MSGIDS_H_
#define _SYSMON_MSGIDS_H_

/* 
** CCSDS V1 Command Message IDs (MID) must be 0x18xx
*/
#define SYSMON_CMD_MID              0x19CA /* TODO: Change this for your app */ 

/* 
** This MID is for commands telling the app to publish its telemetry message
*/
#define SYSMON_REQ_HK_MID           0x19CB /* TODO: Change this for your app */

/* 
** CCSDS V1 Telemetry Message IDs must be 0x08xx
*/
#define SYSMON_HK_TLM_MID           0x09CA /* TODO: Change this for your app */

#endif /* _SYSMON_MSGIDS_H_ */
