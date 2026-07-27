/*******************************************************************************
** File:
**   sysmon_msg.h
**
** Purpose:
**  Define SYSMON application commands and telemetry messages
**
*******************************************************************************/
#ifndef _SYSMON_MSG_H_
#define _SYSMON_MSG_H_

#include "cfe.h"


/*
** Ground Command Codes
** TODO: Add additional commands required by the specific component
*/
#define SYSMON_NOOP_CC                 0
#define SYSMON_RESET_COUNTERS_CC       1


/* 
** Telemetry Request Command Codes
** TODO: Add additional commands required by the specific component
*/
#define SYSMON_REQ_HK_TLM              0


/*
** Generic "no arguments" command type definition
*/
typedef struct
{
    /* Every command requires a header used to identify it */
    CFE_MSG_CommandHeader_t CmdHeader;

} SYSMON_NoArgs_cmd_t;


/*
** SYSMON housekeeping type definition
*/
typedef struct 
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   CommandErrorCount;
    uint8   CommandCount;
    uint32 UptimeSeconds;
    float CpuTempC;
    float CpuLoadPercent;
    uint32 TotalMemoryKB;
    uint32 FreeMemoryKB;
    uint32 DiskTotalMB;
    uint32 DiskFreeMB;
} __attribute__((packed)) SYSMON_Hk_tlm_t;
#define SYSMON_HK_TLM_LNGTH sizeof ( SYSMON_Hk_tlm_t )

#endif /* _SYSMON_MSG_H_ */
