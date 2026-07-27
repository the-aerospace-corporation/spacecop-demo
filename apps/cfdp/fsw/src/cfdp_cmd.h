/**
 * @file
 *
 * CF command processing function declarations
 */

#ifndef CFDP_CMD_H
#define CFDP_CMD_H

#include "cfe.h"
#include "cfdp_app.h"

CFE_Status_t CFDP_NoopCmd(void);

void CFDP_ResetCounters(void);

void CFDP_DownloadFromSatellite(const CFE_MSG_Message_t *MsgPtr);
void CFDP_UploadToSatellite(const CFE_MSG_Message_t *MsgPtr);
void CFDP_UploadToSatelliteConfirm(const CFE_MSG_Message_t *MsgPtr);
void CFDP_ResendChunk(const CFE_MSG_Message_t *MsgPtr);

#endif