// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_msg.h
 * @brief Command and telemetry message definitions for SpaceCop IDS application
 *
 * This header defines all command codes and message structure definitions for
 * the SpaceCop application's Software Bus interface. It includes:
 * - Ground command codes for commanding SpaceCop
 * - Telemetry request command codes
 * - Command message structure definitions
 * - Telemetry message structure definitions
 *
 * **Message Categories:**
 * - Ground Commands: Sent from ground systems to control SpaceCop
 * - Telemetry Requests: Trigger transmission of telemetry packets
 * - Housekeeping Telemetry: Status and counter information
 * - IDS Telemetry: Intrusion detection alerts and reports
 *
 * **Software Bus Integration:**
 * These message structures are transmitted via the cFE Software Bus using
 * message IDs defined in spacecop_msgids.h. Each message includes a cFE
 * message header for routing and identification.
 *
 * **Command Processing:**
 * Commands are received on SPACECOP_CMD_MID and processed by
 * SPACECOP_ProcessGroundCommand(). The command code field determines which
 * operation to perform.
 *
 * **Telemetry Generation:**
 * Telemetry requests are received on SPACECOP_REQ_HK_MID and processed by
 * SPACECOP_ProcessTelemetryRequest(). The command code field determines which
 * telemetry packet to transmit.
 *
 * @note All multi-byte fields use network byte order (big-endian)
 * @note Structures use packed attribute to prevent padding
 * @note Message lengths include header size
 *
 * @see spacecop_msgids.h for message ID definitions
 * @see SPACECOP_ProcessGroundCommand() for command processing
 * @see SPACECOP_ProcessTelemetryRequest() for telemetry processing
 */

#ifndef _SPACECOP_MSG_H_
#define _SPACECOP_MSG_H_

/*=======================================================================================
** Include Files
**=======================================================================================*/

#include "cfe.h"

/*=======================================================================================
** Ground Command Codes
** 
** Command codes for ground commands sent via SPACECOP_CMD_MID.
** Each command code identifies a specific operation to perform.
**=======================================================================================*/

/**
 * @brief No Operation (NOOP) command code
 *
 * Command code for NOOP command. Used to verify command interface is
 * operational without performing any action. Useful for:
 * - Testing command path connectivity
 * - Verifying command processing is active
 * - Incrementing command counter for verification
 *
 * **Response:**
 * - Increments CommandCount
 * - Sends SPACECOP_CMD_NOOP_INF_EID event
 *
 * @see SPACECOP_ProcessGroundCommand()
 */
#define SPACECOP_NOOP_CC                 0

/**
 * @brief Reset Counters command code
 *
 * Command code for resetting telemetry counters. Resets:
 * - CommandCount: Number of valid commands received
 * - CommandErrorCount: Number of invalid commands received
 *
 * Used to clear counters after troubleshooting or testing.
 *
 * **Response:**
 * - Resets CommandCount to 0
 * - Resets CommandErrorCount to 0
 * - Sends SPACECOP_CMD_RESET_INF_EID event
 *
 * @note Does not reset detection counters or rule state
 *
 * @see SPACECOP_ResetCounters()
 * @see SPACECOP_ProcessGroundCommand()
 */
#define SPACECOP_RESET_COUNTERS_CC       1

/*=======================================================================================
** Telemetry Request Command Codes
** 
** Command codes for telemetry requests sent via SPACECOP_REQ_HK_MID.
** Each command code triggers transmission of a specific telemetry packet.
**=======================================================================================*/

/**
 * @brief Housekeeping telemetry request
 *
 * Command code for requesting housekeeping telemetry packet. Triggers
 * transmission of SPACECOP_Hk_tlm_t containing:
 * - CommandCount: Number of valid commands received
 * - CommandErrorCount: Number of invalid commands received
 *
 * Typically sent periodically by the scheduler application.
 *
 * **Response:**
 * - Timestamps and transmits housekeeping packet on SPACECOP_HK_TLM_MID
 *
 * @see SPACECOP_ReportHousekeeping()
 * @see SPACECOP_Hk_tlm_t
 */
#define SPACECOP_REQ_HK_TLM              0

/**
 * @brief Data telemetry request
 *
 * Command code for requesting device-specific data telemetry. Reserved for
 * future use or mission-specific telemetry requirements.
 *
 * **Response:**
 * - Mission-specific data telemetry packet
 *
 * @note Currently reserved for future implementation
 */
#define SPACECOP_REQ_DATA_TLM            1

/**
 * @brief IDS telemetry request
 *
 * Command code for requesting IDS-specific telemetry. May include:
 * - Detection statistics
 * - Rule execution status
 * - ML integration status
 * - Recent alerts summary
 *
 * **Response:**
 * - IDS status telemetry packet
 *
 * @note Currently reserved for future implementation
 */
#define SPACECOP_REQ_IDS_TLM             2

/*=======================================================================================
** Command Message Structure Definitions
**=======================================================================================*/

/**
 * @brief Generic "no arguments" command structure
 *
 * Generic command structure for commands that require no additional parameters
 * beyond the command header. Used by:
 * - NOOP command
 * - Reset Counters command
 * - Other simple commands without parameters
 *
 * **Structure:**
 * - CmdHeader: Standard cFE command header containing:
 *   - Message ID (identifies the command destination)
 *   - Command Code (identifies the specific command)
 *   - Sequence counter
 *   - Length
 *
 * **Usage Example:**
 * @code
 * SPACECOP_NoArgs_cmd_t cmd;
 * CFE_MSG_Init(&cmd.CmdHeader, SPACECOP_CMD_MID, sizeof(cmd));
 * CFE_MSG_SetFcnCode(&cmd.CmdHeader, SPACECOP_NOOP_CC);
 * CFE_SB_TransmitMsg(&cmd, true);
 * @endcode
 *
 * @note This structure can be reused for any command without parameters
 * @note Command validation checks message length matches sizeof(SPACECOP_NoArgs_cmd_t)
 *
 * @see SPACECOP_VerifyCmdLength()
 */
typedef struct
{
    /** 
     * @brief Standard cFE command header
     * 
     * Every command requires a header used to identify and route it through
     * the Software Bus. Contains message ID, command code, and metadata.
     */
    CFE_MSG_CommandHeader_t CmdHeader;

} SPACECOP_NoArgs_cmd_t;

/*=======================================================================================
** Telemetry Message Structure Definitions
**=======================================================================================*/

/**
 * @brief SPACECOP housekeeping telemetry structure
 *
 * Housekeeping telemetry packet containing application status and command
 * processing statistics. Transmitted in response to SPACECOP_REQ_HK_TLM
 * requests on message ID SPACECOP_HK_TLM_MID.
 *
 * **Packet Contents:**
 * - TlmHeader: Standard cFE telemetry header with timestamp
 * - CommandErrorCount: Number of invalid commands received
 * - CommandCount: Number of valid commands received
 *
 * **Transmission:**
 * - Sent periodically (typically 1 Hz) by scheduler
 * - Timestamped with spacecraft time before transmission
 * - Includes sequence counter for packet loss detection
 *
 * **Ground System Usage:**
 * - Monitor application health
 * - Verify command reception
 * - Detect command errors
 * - Track application activity
 *
 * **Counter Behavior:**
 * - CommandCount increments on valid command reception
 * - CommandErrorCount increments on invalid command or length mismatch
 * - Both counters reset to 0 on SPACECOP_RESET_COUNTERS_CC command
 * - Counters are 8-bit (wrap at 255)
 *
 * @note Structure is packed to prevent compiler padding
 * @note Use SPACECOP_HK_TLM_LNGTH macro for message length
 *
 * Example usage:
 * @code
 * SPACECOP_Hk_tlm_t hk_pkt;
 * CFE_MSG_Init(&hk_pkt.TlmHeader, SPACECOP_HK_TLM_MID, 
 *              SPACECOP_HK_TLM_LNGTH);
 * hk_pkt.CommandCount = 42;
 * hk_pkt.CommandErrorCount = 0;
 * CFE_SB_TimeStampMsg(&hk_pkt);
 * CFE_SB_TransmitMsg(&hk_pkt, true);
 * @endcode
 *
 * @see SPACECOP_ReportHousekeeping()
 * @see SPACECOP_ResetCounters()
 */
typedef struct 
{
    /**
     * @brief Standard cFE telemetry header
     * 
     * Contains message ID, timestamp, sequence counter, and length.
     * Automatically populated by cFE message services.
     */
    CFE_MSG_TelemetryHeader_t TlmHeader;
    
    /**
     * @brief Command error counter
     * 
     * Number of invalid commands received since last counter reset.
     * Incremented when:
     * - Unrecognized command code received
     * - Command length mismatch detected
     * - Command validation fails
     * 
     * Reset by SPACECOP_RESET_COUNTERS_CC command.
     */
    uint8   CommandErrorCount;
    
    /**
     * @brief Valid command counter
     * 
     * Number of valid commands successfully received and processed since
     * last counter reset. Incremented when:
     * - Command code is recognized
     * - Command length is correct
     * - Command validation passes
     * 
     * Reset by SPACECOP_RESET_COUNTERS_CC command.
     */
    uint8   CommandCount;

} __attribute__((packed)) SPACECOP_Hk_tlm_t;

/**
 * @brief Housekeeping telemetry packet length
 *
 * Defines the total length of the housekeeping telemetry packet in bytes,
 * including the telemetry header. Used for:
 * - Message initialization
 * - Buffer allocation
 * - Ground system packet definitions
 *
 * @note Automatically calculated from structure size
 * @note Includes header size
 */
#define SPACECOP_HK_TLM_LNGTH sizeof ( SPACECOP_Hk_tlm_t )

#endif /* _SPACECOP_MSG_H_ */