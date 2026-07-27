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
 * @file spacecop_mission_specific.c
 * @brief Mission-specific utility functions for SpaceCop IDS
 *
 * This file implements mission-specific helper functions that adapt SpaceCop
 * to the particular cFS environment and mission configuration. These functions
 * provide:
 * - Time conversion between cFS and generic time formats
 * - Message-to-IOB mapping for command monitoring
 * - Telemetry message identification and classification
 *
 * **Key Functions:**
 * - Time abstraction for portability across missions
 * - Command message matching against monitoring table
 * - Telemetry message matching against monitoring table
 * - Support for activation/deactivation trigger detection
 *
 * **Mission Adaptation:**
 * This file may need modification when porting SpaceCop to different missions
 * or cFS configurations. The command monitoring table structure and message
 * ID assignments are mission-specific.
 *
 * @note This file contains mission-specific code that may require updates
 * @see spacecop_table_defs.h for CommandMonitorEntry structure definition
 */

#include "spacecop_mission_specific.h"
#include "spacecop_app.h"

/*=======================================================================================
** Time Conversion Functions
**=======================================================================================*/

/**
 * @brief Get current spacecraft time in generic format
 *
 * Retrieves the current spacecraft time from cFE Time Services and converts
 * it to a mission-independent generic time format. This abstraction allows
 * SpaceCop to work across different cFS missions with varying time
 * representations.
 *
 * **Time Conversion:**
 * - Seconds: Copied directly from CFE_TIME_SysTime_t
 * - Microseconds: Subseconds converted via CFE_TIME_Sub2MicroSecs()
 *
 * **Use Cases:**
 * - Timestamping IDS alerts
 * - Rule evaluation timing
 * - Event correlation across time windows
 * - STIX report generation
 *
 * @param[out] generic_time Pointer to TimeElement_t structure to populate
 *
 * @return void
 *
 * @note Returns immediately if generic_time is NULL (safe guard)
 * @note Time is in spacecraft time (not UTC or GPS)
 * @note Subseconds are converted to microseconds for portability
 *
 * Example usage:
 * @code
 * TimeElement_t current_time;
 * SPACECOP_GetTime(&current_time);
 * printf("Time: %u.%06u\n", current_time.Seconds, current_time.Microseconds);
 * @endcode
 */
void SPACECOP_GetTime(TimeElement_t* generic_time)
{
	/* Validate input pointer */
	if(generic_time == NULL){
		return;
	}
	
	/* Get current spacecraft time from cFE Time Services */
	CFE_TIME_SysTime_t mission_time = CFE_TIME_GetTime();
	
	/* Convert to generic time format */
	generic_time->Seconds = mission_time.Seconds;
	generic_time->Microseconds = CFE_TIME_Sub2MicroSecs(mission_time.Subseconds);
}

/*=======================================================================================
** Command Message Mapping Functions
**=======================================================================================*/

/**
 * @brief Convert command message to STIX IOB identifier
 *
 * Searches the command monitoring table for an entry matching the received
 * command message. Returns the matching entry and indicates whether the
 * message triggers activation or deactivation of monitoring.
 *
 * **Matching Logic:**
 * For each command entry in the table:
 * 1. Check if Message ID matches ActionOnMid AND CommandCode matches ActionOnCommandCode
 *    - If match: Return entry with ACTIVATE result
 * 2. Check if Message ID matches DeactivateOnMid AND CommandCode matches DeactivateOnCommandCode
 *    - If match: Return entry with DEACTIVATE result
 *
 * **Activation vs Deactivation:**
 * - ACTIVATE: Command triggers monitoring rule (potential violation)
 * - DEACTIVATE: Command disables monitoring rule (valid state change)
 *
 * **Offset Parameter:**
 * Allows iterating through multiple matches in the table. Set to 0 for first
 * search, then use returned offset value for subsequent searches.
 *
 * @param[in] tbl Pointer to command monitoring table
 * @param[in] MonitorMsgPtr Pointer to received Software Bus message
 * @param[out] ResultType Result of search (ACTIVATE, DEACTIVATE, or ERROR)
 * @param[in,out] offset Starting index for search; updated to next index on match
 *
 * @return CommandMonitorEntry_t* Pointer to matching table entry, or NULL if no match
 *
 * @note Only processes entries where Command flag is true (command messages)
 * @note Sets ResultType to ERROR if no match found
 * @note Offset is incremented past matched entry for continued searching
 * @note Commented-out debug printf statements available for troubleshooting
 *
 * Example usage:
 * @code
 * Result_t result;
 * uint8_t offset = 0;
 * CommandMonitorEntry_t* entry = SPACECOP_ConvertCommandToStixId(
 *     table, msg, &result, &offset);
 * if (entry != NULL && result == ACTIVATE) {
 *     // Process activation trigger
 *     printf("IOB: %s\n", entry->IOB);
 * }
 * @endcode
 */
CommandMonitorEntry_t* SPACECOP_ConvertCommandToStixId(CommandMonitorEntryTable_t* tbl, 
                                                        CFE_MSG_Message_t* MonitorMsgPtr, 
                                                        Result_t* ResultType, 
                                                        uint8_t* offset)
{
	CFE_SB_MsgId_t MsgId;
	CFE_MSG_FcnCode_t CommandCode;
	*ResultType = ERROR;
	CommandMonitorEntry_t* current;

	/* Extract message ID and command code from received message */
	CFE_MSG_GetMsgId(MonitorMsgPtr, &MsgId);
	CFE_MSG_GetFcnCode(MonitorMsgPtr, &CommandCode);

	/* Search table starting from offset */
	for(uint8_t i = *offset; i < tbl->CommandMonitorEntryCount; i++)
	{
		current = tbl->CommandMonitorEntries + i;
		
		/* Debug output (commented out for production) */
		//printf("My ActionOnMid [0x%04X] and received MsgId [0x%04X]\n", 
		//       CFE_SB_MsgIdToValue(current->ActionOnMid), CFE_SB_MsgIdToValue(MsgId));
		//printf("My ActionOnCommandeCode [%d] and received CommandCode [%d]\n", 
		//       current->ActionOnCommandCode, CommandCode);
		//printf("My DeactivateOnMid [0x%04X] and received MsgId [0x%04X]\n", 
		//       CFE_SB_MsgIdToValue(current->DeactivateOnMid), CFE_SB_MsgIdToValue(MsgId));
		//printf("My DeactivateOnCommandeCode [%d] and received CommandCode [%d]\n", 
		//       current->DeactivateOnCommandCode, CommandCode);
		
		/* Only process command entries (not telemetry) */
		if (current->Command) 
		{
			/* Check for activation trigger match */
			if (CFE_SB_MsgId_Equal(MsgId, current->ActionOnMid) && 
			    CommandCode == current->ActionOnCommandCode)
			{
				*offset = i + 1;  /* Update offset for next search */
				*ResultType = ACTIVATE;
				return current;
			}
			/* Check for deactivation trigger match */
			else if (CFE_SB_MsgId_Equal(MsgId, current->DeactivateOnMid) && 
			         CommandCode == current->DeactivateOnCommandCode)
			{
				*offset = i + 1;  /* Update offset for next search */
				*ResultType = DEACTIVATE;
				return current;
			}
		}
	}
	
	/* No match found */
	*ResultType = ERROR;
	return NULL;
}

/*=======================================================================================
** Telemetry Message Mapping Functions
**=======================================================================================*/

/**
 * @brief Convert telemetry message to STIX IOB identifier
 *
 * Searches the command monitoring table for an entry matching the received
 * telemetry message. Returns the matching entry and indicates activation
 * (telemetry does not support deactivation triggers).
 *
 * **Matching Logic:**
 * For each telemetry entry in the table:
 * 1. Check if Message ID matches ActionOnMid
 *    - If match: Return entry with ACTIVATE result
 *
 * **Telemetry vs Command:**
 * Unlike command messages, telemetry messages:
 * - Do not have command codes (function codes)
 * - Only match on Message ID
 * - Do not support deactivation triggers
 * - Are typically used for anomaly detection rules
 *
 * **Offset Parameter:**
 * Allows iterating through multiple matches in the table. Set to 0 for first
 * search, then use returned offset value for subsequent searches.
 *
 * @param[in] tbl Pointer to command monitoring table
 * @param[in] MonitorMsgPtr Pointer to received Software Bus message
 * @param[out] ResultType Result of search (ACTIVATE or ERROR)
 * @param[in,out] offset Starting index for search; updated to next index on match
 *
 * @return CommandMonitorEntry_t* Pointer to matching table entry, or NULL if no match
 *
 * @note Only processes entries where Command flag is false (telemetry messages)
 * @note Sets ResultType to ERROR if no match found
 * @note Offset is incremented past matched entry for continued searching
 * @note Commented-out debug printf statements available for troubleshooting
 * @note Telemetry entries never return DEACTIVATE result
 *
 * Example usage:
 * @code
 * Result_t result;
 * uint8_t offset = 0;
 * CommandMonitorEntry_t* entry = SPACECOP_ConvertTelemetryToStixId(
 *     table, msg, &result, &offset);
 * if (entry != NULL && result == ACTIVATE) {
 *     // Process telemetry-based rule
 *     printf("IOB: %s\n", entry->IOB);
 * }
 * @endcode
 */
CommandMonitorEntry_t* SPACECOP_ConvertTelemetryToStixId(CommandMonitorEntryTable_t* tbl, 
                                                          CFE_MSG_Message_t* MonitorMsgPtr, 
                                                          Result_t* ResultType, 
                                                          uint8_t* offset)
{
	CFE_SB_MsgId_t MsgId;
	*ResultType = ERROR;
	CommandMonitorEntry_t* current;

	/* Extract message ID from received message */
	CFE_MSG_GetMsgId(MonitorMsgPtr, &MsgId);

	/* Search table starting from offset */
	for(uint8_t i = *offset; i < tbl->CommandMonitorEntryCount; i++)
	{
		current = tbl->CommandMonitorEntries + i;
		
		/* Debug output (commented out for production) */
		//printf("My ActionOnMid [0x%04X] and received MsgId [0x%04X]\n", 
		//       CFE_SB_MsgIdToValue(current->ActionOnMid), CFE_SB_MsgIdToValue(MsgId));
		//printf("My ActionOnCommandeCode [%d] and received CommandCode [%d]\n", 
		//       current->ActionOnCommandCode, CommandCode);
		//printf("My DeactivateOnMid [0x%04X] and received MsgId [0x%04X]\n", 
		//       CFE_SB_MsgIdToValue(current->DeactivateOnMid), CFE_SB_MsgIdToValue(MsgId));
		//printf("My DeactivateOnCommandeCode [%d] and received CommandCode [%d]\n", 
		//       current->DeactivateOnCommandCode, CommandCode);
		
		/* Only process telemetry entries (not commands) */
		if (!current->Command) 
		{
			/* Check for activation trigger match (MID only, no command code) */
			if (CFE_SB_MsgId_Equal(MsgId, current->ActionOnMid))
			{
				*offset = i + 1;  /* Update offset for next search */
				*ResultType = ACTIVATE;
				return current;
			}
		}
	}
	
	/* No match found */
	*ResultType = ERROR;
	return NULL;
}