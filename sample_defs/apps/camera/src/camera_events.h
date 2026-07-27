/************************************************************************
** File:
**    camera_events.h
**
** Purpose:
**  Define CAMERA application event IDs
**
*************************************************************************/

#ifndef _CAMERA_EVENTS_H_
#define _CAMERA_EVENTS_H_

/* Standard app event IDs */
#define CAMERA_RESERVED_EID              0
#define CAMERA_STARTUP_INF_EID           1
#define CAMERA_LEN_ERR_EID               2
#define CAMERA_PIPE_ERR_EID              3
#define CAMERA_SUB_CMD_ERR_EID           4
#define CAMERA_SUB_REQ_HK_ERR_EID        5
#define CAMERA_PROCESS_CMD_ERR_EID       6

/* Standard command event IDs */
#define CAMERA_CMD_ERR_EID               10
#define CAMERA_CMD_NOOP_INF_EID          11
#define CAMERA_CMD_RESET_INF_EID         12
#define CAMERA_CMD_ENABLE_INF_EID        13
#define CAMERA_ENABLE_INF_EID            14
#define CAMERA_ENABLE_ERR_EID            15
#define CAMERA_CMD_DISABLE_INF_EID       16
#define CAMERA_DISABLE_INF_EID           17
#define CAMERA_DISABLE_ERR_EID           18

/* Device specific command event IDs */
#define CAMERA_CMD_CONFIG_INF_EID        20

/* Standard telemetry event IDs */
#define CAMERA_DEVICE_TLM_ERR_EID        30
#define CAMERA_REQ_HK_ERR_EID            31

/* Device specific telemetry event IDs */
#define CAMERA_REQ_DATA_ERR_EID          32

/* Hardware protocol event IDs */
#define CAMERA_UART_INIT_ERR_EID         40
#define CAMERA_UART_CLOSE_ERR_EID        41

#endif /* _CAMERA_EVENTS_H_ */
