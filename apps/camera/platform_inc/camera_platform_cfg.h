/************************************************************************
** File:
**   $Id: camera_platform_cfg.h  $
**
** Purpose:
**  Define camera Platform Configuration Parameters
**
** Notes:
**
*************************************************************************/
#ifndef _CAMERA_PLATFORM_CFG_H_
#define _CAMERA_PLATFORM_CFG_H_

/*
** Default CAMERA Configuration
*/
#ifndef CAMERA_CFG
    /* Notes: 
    **   NOS3 uart requires matching handle and bus number
    */
    #define CAMERA_CFG_STRING           "usart_16"
    #define CAMERA_CFG_HANDLE           16
    #define CAMERA_CFG_BAUDRATE_HZ      115200
    #define CAMERA_CFG_MS_TIMEOUT       50            /* Max 255 */
    /* Note: Debug flag disabled (commented out) by default */
    //#define CAMERA_CFG_DEBUG
#endif

#endif /* _CAMERA_PLATFORM_CFG_H_ */
