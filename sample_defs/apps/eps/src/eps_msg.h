/*******************************************************************************
** File:
**   eps_msg.h
**
** Purpose:
**  Define EPS application commands and telemetry messages
**
*******************************************************************************/
#ifndef _EPS_MSG_H_
#define _EPS_MSG_H_

#include "cfe.h"

/*
** Ground Command Codes
** TODO: Add additional commands required by the specific component
*/
#define EPS_NOOP_CC                 0
#define EPS_RESET_COUNTERS_CC       1


/* 
** Telemetry Request Command Codes
** TODO: Add additional commands required by the specific component
*/
#define EPS_REQ_HK_TLM              0
#define EPS_REQ_DATA_TLM            1


/*
** Generic "no arguments" command type definition
*/
typedef struct
{
    /* Every command requires a header used to identify it */
    CFE_MSG_CommandHeader_t CmdHeader;

} EPS_NoArgs_cmd_t;


/*
** EPS housekeeping type definition
*/
typedef struct 
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   CommandErrorCount;
    uint8   CommandCount;

    uint8 ErrorCount;

    float voltage[8];
    float currant_ma[8];

    uint8_t present[8];
    uint8_t sensor_count;
    uint8_t spare[3];

} __attribute__((packed)) EPS_Hk_tlm_t;
#define EPS_HK_TLM_LNGTH sizeof ( EPS_Hk_tlm_t )

#endif /* _EPS_MSG_H_ */
