/************************************************************************
** File:
**    eps_events.h
**
** Purpose:
**  Define EPS application event IDs
**
*************************************************************************/

#ifndef _EPS_EVENTS_H_
#define _EPS_EVENTS_H_

/* Standard app event IDs */
#define EPS_RESERVED_EID              0
#define EPS_STARTUP_INF_EID           1
#define EPS_LEN_ERR_EID               2
#define EPS_PIPE_ERR_EID              3
#define EPS_SUB_CMD_ERR_EID           4
#define EPS_SUB_REQ_HK_ERR_EID        5
#define EPS_PROCESS_CMD_ERR_EID       6

#define I2C_SENSOR_EID				  7

/* Standard command event IDs */
#define EPS_CMD_ERR_EID               10
#define EPS_CMD_NOOP_INF_EID          11
#define EPS_CMD_RESET_INF_EID         12
#define EPS_CMD_ENABLE_INF_EID        13
#define EPS_ENABLE_INF_EID            14
#define EPS_ENABLE_ERR_EID            15
#define EPS_CMD_DISABLE_INF_EID       16
#define EPS_DISABLE_INF_EID           17
#define EPS_DISABLE_ERR_EID           18

/* Device specific command event IDs */
#define EPS_CMD_CONFIG_INF_EID        20

/* Standard telemetry event IDs */
#define EPS_DEVICE_TLM_ERR_EID        30
#define EPS_REQ_HK_ERR_EID            31

/* Device specific telemetry event IDs */
#define EPS_REQ_DATA_ERR_EID          32

/* Hardware protocol event IDs */
#define EPS_UART_INIT_ERR_EID         40
#define EPS_UART_CLOSE_ERR_EID        41

#endif /* _EPS_EVENTS_H_ */
