/************************************************************************
** File:
**   $Id: eps_msgids.h  $
**
** Purpose:
**  Define EPS Message IDs
**
*************************************************************************/
#ifndef _EPS_MSGIDS_H_
#define _EPS_MSGIDS_H_

/* 
** CCSDS V1 Command Message IDs (MID) must be 0x18xx
*/
#define EPS_CMD_MID              0x19AA /* TODO: Change this for your app */ 

/* 
** This MID is for commands telling the app to publish its telemetry message
*/
#define EPS_REQ_HK_MID           0x19AB /* TODO: Change this for your app */

/* 
** CCSDS V1 Telemetry Message IDs must be 0x08xx
*/
#define EPS_HK_TLM_MID           0x09AA /* TODO: Change this for your app */

#endif /* _EPS_MSGIDS_H_ */
