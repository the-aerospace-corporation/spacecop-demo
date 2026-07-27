// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
// All rights reserved.
//
//This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
//limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
//for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
//any warranty that the software will be error free.
//
//In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
//arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
//contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
//documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

/**
 * @file spacecop_ids_helper.h
 * @brief Header file for SpaceCop Intrusion Detection System (IDS) telemetry helper functions
 *
 * This header defines the data structures, constants, and function prototypes
 * for the SpaceCop IDS telemetry reporting subsystem. It provides a thread-safe
 * interface for initializing, managing, and transmitting IDS alert messages
 * through the cFE Software Bus.
 */

#ifndef _SPACECOP_IDS_HELPER_H_
#define _SPACECOP_IDS_HELPER_H_

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include "cfe.h"
#include "spacecop_msgids.h"
#include "sparta_stix.h"
#include <pthread.h>

/*=======================================================================================
** Macro Definitions
**=======================================================================================*/

/** @brief Maximum length of IDS report message string in bytes */
#define IDS_REPORT_MESSAGE_LEN           1024

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief IDS telemetry packet structure
 *
 * Defines the telemetry packet format for transmitting IDS alert and status
 * messages via the cFE Software Bus. The structure includes a standard cFE
 * telemetry header followed by a variable-length message string.
 *
 * @note The packed attribute ensures no padding is added between structure members,
 *       which is critical for consistent serialization across different platforms
 */
typedef struct 
{
    /** @brief Standard cFE telemetry message header */
    CFE_MSG_TelemetryHeader_t TlmHeader;

    /** @brief IDS message content (null-terminated string, max IDS_REPORT_MESSAGE_LEN bytes) */
    char msg[IDS_REPORT_MESSAGE_LEN];

} __attribute__((packed)) SPACECOP_IDS_tlm_t;

/** @brief Total length of the IDS telemetry packet structure in bytes */
#define SPACECOP_IDS_TLM_LNGTH sizeof ( SPACECOP_IDS_tlm_t )

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Initialize the IDS telemetry packet
 *
 * Initializes the IDS telemetry packet structure with default values and
 * registers it with the cFE Software Bus. Must be called before any IDS
 * messages can be transmitted.
 *
 * @return void
 */
void SPACECOP_IDS_InitPkt(void);

/**
 * @brief Report an IDS message via telemetry
 *
 * Thread-safe function to transmit IDS alert or status messages via the
 * cFE Software Bus. The message is timestamped and published to all subscribers.
 *
 * @param[in] message Null-terminated string containing the IDS message to report.
 *                    Message will be truncated if longer than IDS_REPORT_MESSAGE_LEN.
 *
 * @return void
 *
 * @note This function is thread-safe and uses mutex locking internally
 */
void SPACECOP_ReportIDSMsg(const char* message);

/**
 * @brief Initialize the mutex lock for IDS report thread safety
 *
 * Creates and initializes the pthread mutex lock that protects shared resources
 * during IDS report operations. Must be called during application initialization
 * before any threads attempt to report IDS messages.
 *
 * @return int Returns 1 on success, -1 on failure
 */
int SPACECOP_InitReportLock(void);

/**
 * @brief Destroy the IDS report mutex lock
 *
 * Cleans up and destroys the pthread mutex lock used for IDS reporting.
 * Should be called during application shutdown to free system resources.
 *
 * @return void
 */
void SPACECOP_DestroyReportLock(void);

#endif /* _SPACECOP_IDS_HELPER_H_ */