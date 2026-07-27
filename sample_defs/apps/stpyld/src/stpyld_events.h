/************************************************************************
** File:
**    stpyld_events.h
**
** Purpose:
**  Define SP application event IDs
**
*************************************************************************/

#ifndef _SP_EVENTS_H_
#define _SP_EVENTS_H_

/* Standard app event IDs */
#define SP_RESERVED_EID              0
#define SP_STARTUP_INF_EID           1
#define SP_LEN_ERR_EID               2
#define SP_PIPE_ERR_EID              3
#define SP_SUB_CMD_ERR_EID           4
#define SP_SUB_REQ_HK_ERR_EID        5
#define SP_PROCESS_CMD_ERR_EID       6

/* Standard command event IDs */
#define SP_CMD_ERR_EID               10
#define SP_CMD_NOOP_INF_EID          11
#define SP_CMD_RESET_INF_EID         12
#define SP_CMD_ENABLE_INF_EID        13
#define SP_ENABLE_INF_EID            14
#define SP_ENABLE_ERR_EID            15
#define SP_CMD_DISABLE_INF_EID       16
#define SP_DISABLE_INF_EID           17
#define SP_DISABLE_ERR_EID           18

/* Device specific command event IDs */
#define SP_CMD_CONFIG_INF_EID        20

/* Standard telemetry event IDs */
#define SP_DEVICE_TLM_ERR_EID        30
#define SP_REQ_HK_ERR_EID            31

/* Device specific telemetry event IDs */
#define SP_REQ_DATA_ERR_EID          32

/* Hardware protocol event IDs */
#define SP_UART_INIT_ERR_EID         40
#define SP_UART_CLOSE_ERR_EID        41

#endif /* _SP_EVENTS_H_ */
