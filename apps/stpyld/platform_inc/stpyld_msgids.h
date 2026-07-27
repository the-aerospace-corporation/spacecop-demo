/************************************************************************
** File:
**   $Id: stem_payload_msgids.h  $
**
** Purpose:
**  Define SP Message IDs
**
*************************************************************************/
#ifndef _SP_MSGIDS_H_
#define _SP_MSGIDS_H_

/* 
** CCSDS V1 Command Message IDs (MID) must be 0x18xx
*/
#define SP_CMD_MID              0x19BA /* TODO: Change this for your app */ 

/* 
** This MID is for commands telling the app to publish its telemetry message
*/
#define SP_REQ_HK_MID           0x19BB /* TODO: Change this for your app */

/* 
** CCSDS V1 Telemetry Message IDs must be 0x08xx
*/
#define SP_HK_TLM_MID           0x09BA /* TODO: Change this for your app */

#endif /* _SP_MSGIDS_H_ */
