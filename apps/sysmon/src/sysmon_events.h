/************************************************************************
** File:
**    sysmon_events.h
**
** Purpose:
**  Define SYSMON application event IDs
**
*************************************************************************/

#ifndef _SYSMON_EVENTS_H_
#define _SYSMON_EVENTS_H_

/* Standard app event IDs */
#define SYSMON_RESERVED_EID              0
#define SYSMON_STARTUP_INF_EID           1
#define SYSMON_LEN_ERR_EID               2
#define SYSMON_PIPE_ERR_EID              3
#define SYSMON_SUB_CMD_ERR_EID           4
#define SYSMON_SUB_REQ_HK_ERR_EID        5
#define SYSMON_PROCESS_CMD_ERR_EID       6

/* Standard command event IDs */
#define SYSMON_CMD_ERR_EID               10
#define SYSMON_CMD_NOOP_INF_EID          11
#define SYSMON_CMD_RESET_INF_EID         12
#define SYSMON_CMD_ENABLE_INF_EID        13
#define SYSMON_ENABLE_INF_EID            14
#define SYSMON_ENABLE_ERR_EID            15
#define SYSMON_CMD_DISABLE_INF_EID       16
#define SYSMON_DISABLE_INF_EID           17
#define SYSMON_DISABLE_ERR_EID           18

/* Device specific command event IDs */
#define SYSMON_CMD_CONFIG_INF_EID        20

/* Standard telemetry event IDs */
#define SYSMON_DEVICE_TLM_ERR_EID        30
#define SYSMON_REQ_HK_ERR_EID            31

/* Device specific telemetry event IDs */
#define SYSMON_REQ_DATA_ERR_EID          32

/* Hardware protocol event IDs */
#define SYSMON_UART_INIT_ERR_EID         40
#define SYSMON_UART_CLOSE_ERR_EID        41

#endif /* _SYSMON_EVENTS_H_ */
