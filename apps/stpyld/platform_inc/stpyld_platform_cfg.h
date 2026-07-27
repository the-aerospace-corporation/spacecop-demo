/************************************************************************
** File:
**   $Id: stem_payload_platform_cfg.h  $
**
** Purpose:
**  Define stem_payload Platform Configuration Parameters
**
** Notes:
**
*************************************************************************/
#ifndef _SP_PLATFORM_CFG_H_
#define _SP_PLATFORM_CFG_H_

/*
** Default SP Configuration
*/
#ifndef SP_CFG
    /* Notes: 
    **   NOS3 uart requires matching handle and bus number
    */
    #define SP_CFG_STRING           "usart_16"
    #define SP_CFG_HANDLE           16
    #define SP_CFG_BAUDRATE_HZ      115200
    #define SP_CFG_MS_TIMEOUT       50            /* Max 255 */
    /* Note: Debug flag disabled (commented out) by default */
    //#define SP_CFG_DEBUG
#endif

#endif /* _SP_PLATFORM_CFG_H_ */
