/*******************************************************************************
** File:
**   stpyld_msg.h
**
** Purpose:
**  Define SP application commands and telemetry messages
**
*******************************************************************************/
#ifndef _SP_MSG_H_
#define _SP_MSG_H_

#include "cfe.h"

/*
** Ground Command Codes
** TODO: Add additional commands required by the specific component
*/
#define SP_NOOP_CC                 0
#define SP_RESET_COUNTERS_CC       1

/* 
** Telemetry Request Command Codes
** TODO: Add additional commands required by the specific component
*/
#define SP_REQ_HK_TLM              0


/*
** Generic "no arguments" command type definition
*/
typedef struct
{
    /* Every command requires a header used to identify it */
    CFE_MSG_CommandHeader_t CmdHeader;

} SP_NoArgs_cmd_t;


/*
** SP write configuration command
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} SP_Config_cmd_t;

/*
** SP housekeeping type definition
*/
typedef struct 
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   CommandErrorCount;
    uint8   CommandCount;

    uint8 PayloadValid;
    uint8 BmeValid;
    uint8 ImuValid;
    uint8 GpsValid;

    float Temperature_C;
    float Pressure_hPa;
    float Altitude_m;
    float Humidity_pct;

    float GyroX_dps;
    float GyroY_dps;
    float GyroZ_dps;

    float AccelX_g;
    float AccelY_g;
    float AccelZ_g;

    float GPSVal1;
    float GPSVal2;
    float GPSVal3;
} __attribute__((packed)) SP_Hk_tlm_t;
#define SP_HK_TLM_LNGTH sizeof ( SP_Hk_tlm_t )

#endif /* _SP_MSG_H_ */
