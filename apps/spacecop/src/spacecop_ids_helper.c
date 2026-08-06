// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop - CE
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
 * @file spacecop_ids_helper.c
 * @brief Helper functions for SpaceCop Intrusion Detection System (IDS) telemetry reporting
 *
 * This file implements thread-safe telemetry packet management and reporting
 * functionality for the SpaceCop IDS component. It provides initialization,
 * locking mechanisms, and message transmission capabilities for IDS alerts
 * and status messages via the cFE Software Bus.
 */

#include "spacecop_ids_helper.h"

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/** @brief IDS telemetry packet structure for reporting messages */
SPACECOP_IDS_tlm_t IDSPkt;

/** 
 * @brief Mutex lock for thread-safe access to IDS reporting functions
 * 
 * Used to control access to the ids_report_function and other shared
 * AppData resources to prevent race conditions in multi-threaded environments.
 */
pthread_mutex_t ids_report_lock;

/*=======================================================================================
** Function Definitions
**=======================================================================================*/

/**
 * @brief Initialize the IDS telemetry packet
 *
 * Initializes the IDS telemetry packet structure with default values and
 * registers it with the cFE Software Bus. Sets up the message header with
 * the appropriate message ID and length.
 *
 * @return void
 *
 * @note Prints initialization status to stdout for debugging purposes
 */
void SPACECOP_IDS_InitPkt()
{
    printf("[SPACECOP] Initialized report packet\n");
    
    /* Initialize message header with telemetry message ID and length */
    CFE_MSG_Init(CFE_MSG_PTR(IDSPkt.TlmHeader),
                   CFE_SB_ValueToMsgId(SPACECOP_REPORT_TLM_MID),
                   SPACECOP_IDS_TLM_LNGTH);
    
    /* Set initial message content */
    sprintf(IDSPkt.msg, "Init");
}

/**
 * @brief Initialize the mutex lock for IDS report thread safety
 *
 * Creates and initializes a pthread mutex lock that protects shared resources
 * during IDS report generation and transmission. This ensures thread-safe
 * access to the IDS packet and related data structures.
 *
 * @return int Returns 1 on success, -1 on failure
 *
 * @note Sends an error event message via CFE_EVS if initialization fails
 */
int SPACECOP_InitReportLock()
{
    /* Initialize mutex lock for threads to use */
    if (pthread_mutex_init(&ids_report_lock, NULL) != 0)
    {
        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "Error Initializing Lock\n");
        return -1;
    }
    return 1;
}

/**
 * @brief Destroy the IDS report mutex lock
 *
 * Cleans up and destroys the pthread mutex lock used for IDS reporting.
 * Should be called during application shutdown or cleanup to free system
 * resources associated with the mutex.
 *
 * @return void
 */
void SPACECOP_DestroyReportLock()
{
    pthread_mutex_destroy(&ids_report_lock);
}

/**
 * @brief Report an IDS message via telemetry
 *
 * Thread-safe function to transmit IDS alert or status messages via the
 * cFE Software Bus. The function locks the mutex, copies the message into
 * the telemetry packet, timestamps it, and publishes it to subscribers.
 *
 * @param[in] message Null-terminated string containing the IDS message to report.
 *                    Message will be truncated if longer than IDS_REPORT_MESSAGE_LEN.
 *
 * @return void
 *
 * @note This function is thread-safe due to mutex protection
 * @note The message buffer is cleared before and after transmission for security
 * @note No error is reported if the device is disabled (intentional design choice)
 *
 * @warning Ensure message parameter is a valid null-terminated string
 */
void SPACECOP_ReportIDSMsg(const char* message)
{
    /* Acquire lock to ensure thread-safe access to shared telemetry packet */
    pthread_mutex_lock(&ids_report_lock);
    
    /* Clear any existing message data from the packet */
    memset(IDSPkt.msg, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
    
    /* Copy the new message into the telemetry packet (with length limit) */
    strncpy(IDSPkt.msg, message, IDS_REPORT_MESSAGE_LEN);

    /* Intentionally do not report errors if device is disabled */

    /* Time stamp the message with current spacecraft time */
    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &IDSPkt);
    
    /* Transmit the message on the Software Bus (true = increment sequence counter) */
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &IDSPkt, true);

    /* Clear the message buffer for security after transmission */
    memset(IDSPkt.msg, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
    
    /* Release the lock to allow other threads to access reporting functions */
    pthread_mutex_unlock(&ids_report_lock);
    
    return;
}