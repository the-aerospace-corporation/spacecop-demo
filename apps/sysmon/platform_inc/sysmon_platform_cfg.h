/************************************************************************
** File:
**   $Id: sysmon_platform_cfg.h  $
**
** Purpose:
**  Define sysmon Platform Configuration Parameters
**
** Notes:
**
*************************************************************************/
#ifndef _SYSMON_PLATFORM_CFG_H_
#define _SYSMON_PLATFORM_CFG_H_

/*
** Default SYSMON Configuration
*/
#ifndef SYSMON_CFG
    /* Notes: 
    **   NOS3 uart requires matching handle and bus number
    */
    #define SYSMON_CFG_STRING           "usart_16"
    #define SYSMON_CFG_HANDLE           16
    #define SYSMON_CFG_BAUDRATE_HZ      115200
    #define SYSMON_CFG_MS_TIMEOUT       50            /* Max 255 */
    /* Note: Debug flag disabled (commented out) by default */
    //#define SYSMON_CFG_DEBUG
#endif

#endif /* _SYSMON_PLATFORM_CFG_H_ */
