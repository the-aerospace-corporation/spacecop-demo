/************************************************************************
** File:
**   $Id: eps_platform_cfg.h  $
**
** Purpose:
**  Define eps Platform Configuration Parameters
**
** Notes:
**
*************************************************************************/
#ifndef _EPS_PLATFORM_CFG_H_
#define _EPS_PLATFORM_CFG_H_

/*
** Default EPS Configuration
*/
#ifndef EPS_CFG
    /* Notes: 
    **   NOS3 uart requires matching handle and bus number
    */
    #define EPS_CFG_STRING           "usart_16"
    #define EPS_CFG_HANDLE           16
    #define EPS_CFG_BAUDRATE_HZ      115200
    #define EPS_CFG_MS_TIMEOUT       50            /* Max 255 */
    /* Note: Debug flag disabled (commented out) by default */
    //#define EPS_CFG_DEBUG
#endif

#endif /* _EPS_PLATFORM_CFG_H_ */
