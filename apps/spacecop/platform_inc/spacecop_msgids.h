// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
// All rights reserved.
//
// This software is provided "as is" without any warranty of any kind either express, implied, or statutory, including, but not
// limited to, any warranty that the software will conform to specifications any implied warranties of merchantability, fitness
// for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
// any warranty that the software will be error free.
//
// In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
// arising out of, resulting from, or in any way connected with the software or its documentation. Whether or not based upon warranty,
// contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
// documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

/**
 * @file spacecop_msgids.h
 * @brief SpaceCop software bus message identifier definitions
 *
 * This header defines the CCSDS message identifiers (MIDs) used by SpaceCop
 * for software bus communication. Message IDs enable routing of commands and
 * telemetry between applications in the cFS architecture.
 *
 * **cFS Software Bus Overview:**
 * The cFS Software Bus (SB) is a publish-subscribe message passing system
 * that enables decoupled communication between applications. Message IDs
 * uniquely identify message types and determine routing.
 *
 * **CCSDS V1 Message ID Format:**
 * SpaceCop uses CCSDS Version 1 message IDs with the following structure:
 * @code
 * Bits:  15  14  13  12  11  10   9   8   7   6   5   4   3   2   1   0
 *       ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
 *       │Ver│Typ│SHF│ APID (Application ID)                             │
 *       └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
 * 
 * Ver: Version (0 for CCSDS V1)
 * Typ: Type (0 = Telemetry, 1 = Command)
 * SHF: Secondary Header Flag
 * APID: Application Process ID (0-2047)
 * @endcode
 *
 * **Message ID Ranges:**
 * - **0x08xx - 0x0Fxx:** Telemetry messages (Type bit = 0)
 * - **0x18xx - 0x1Fxx:** Command messages (Type bit = 1)
 *
 * **SpaceCop Message Categories:**
 * 
 * 1. **Command Messages (0x18xx):**
 *    - SPACECOP_CMD_MID: Application commands
 *    - SPACECOP_REQ_HK_MID: Housekeeping requests
 * 
 * 2. **Telemetry Messages (0x08xx - 0x09xx):**
 *    - SPACECOP_HK_TLM_MID: Housekeeping telemetry
 *    - SPACECOP_REPORT_TLM_MID: Detection reports
 *    - SPACECOP_DEVICE_TLM_MID: Device status
 *    - SPACECOP_CTI_SHARE_MID: Threat intelligence sharing
 * 
 * 3. **Heartbeat Messages (0x19xx):**
 *    - SPACECOP_HB_MID: Operational status
 *
 * **Message Routing:**
 * Applications subscribe to message IDs to receive messages:
 * @code
 * // Subscribe to SpaceCop commands
 * CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SPACECOP_CMD_MID), 
 *                  SPACECOP_CommandPipe);
 * 
 * // Publish housekeeping telemetry
 * CFE_MSG_Init(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_HK_TLM_MID),
 *              sizeof(SPACECOP_HkTelemetryPkt));
 * CFE_SB_TransmitMsg(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg, true);
 * @endcode
 *
 * **Ground System Integration:**
 * Ground systems use these MIDs to:
 * - Send commands to SpaceCop
 * - Receive telemetry and alerts
 * - Monitor operational status
 * - Retrieve threat intelligence
 *
 * **Message ID Assignment:**
 * MIDs are assigned to avoid conflicts with other cFS applications.
 * The 0xFx range is typically reserved for mission-specific applications.
 *
 * **Multi-Spacecraft Configuration:**
 * In constellations, each spacecraft may:
 * - Use same MIDs (different spacecraft IDs in routing)
 * - Use offset MIDs (e.g., SC1: 0x08FE, SC2: 0x09FE)
 * - Route via crosslink or ground relay
 *
 * **Usage Example:**
 * @code
 * // Initialize SpaceCop application
 * void SPACECOP_Init(void) {
 *     // Create command pipe
 *     CFE_SB_CreatePipe(&SPACECOP_CommandPipe, 
 *                       SPACECOP_PIPE_DEPTH, 
 *                       "SPACECOP_CMD_PIPE");
 *     
 *     // Subscribe to commands
 *     CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SPACECOP_CMD_MID),
 *                      SPACECOP_CommandPipe);
 *     CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SPACECOP_REQ_HK_MID),
 *                      SPACECOP_CommandPipe);
 *     
 *     // Subscribe to peer alerts
 *     CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID),
 *                      SPACECOP_CTIPipe);
 * }
 * 
 * // Send detection report
 * void SPACECOP_SendReport(void) {
 *     CFE_MSG_Init(&ReportMsg.TlmHeader.Msg,
 *                  CFE_SB_ValueToMsgId(SPACECOP_REPORT_TLM_MID),
 *                  sizeof(ReportMsg));
 *     CFE_SB_TransmitMsg(&ReportMsg.TlmHeader.Msg, true);
 * }
 * @endcode
 *
 * **Debugging:**
 * Use cFS TO (Telemetry Output) application to route messages to ground:
 * @code
 * # Enable SpaceCop telemetry
 * TO_ENABLE_OUTPUT_CC MID=0x08FE
 * TO_ENABLE_OUTPUT_CC MID=0x08FD
 * TO_ENABLE_OUTPUT_CC MID=0x09FC
 * @endcode
 *
 * @note MID values must be unique across all cFS applications
 * @note Changes require coordination with ground system
 * @note CCSDS V2 uses different MID format (not used here)
 *
 * @see cFE Software Bus documentation for routing details
 * @see spacecop_msg.h for message structure definitions
 * @see CCSDS Blue Book for message format specification
 */

/************************************************************************
** File:
**   $Id: spacecop_msgids.h  $
**
** Purpose:
**  Define SPACECOP Message IDs
**
*************************************************************************/
#ifndef _SPACECOP_MSGIDS_H_
#define _SPACECOP_MSGIDS_H_

/*=======================================================================================
** Message ID Definitions
**=======================================================================================*/

/**
 * @brief SpaceCop heartbeat message ID
 * 
 * Message identifier for SpaceCop operational heartbeat messages. Used to
 * indicate the application is running and operational. Heartbeats enable:
 * - Health monitoring by ground systems
 * - Peer-to-peer operational awareness
 * - Failover detection and coordination
 * - Distributed detection health tracking
 *
 * **Message Type:** Command (0x1xxx range, but used as status indicator)
 * **Typical Rate:** 0.033 Hz (every 30 seconds)
 * **Subscribers:** Ground system, peer SpaceCop instances
 *
 * **Usage:**
 * @code
 * // Send heartbeat
 * SPACECOP_Heartbeat_t hb_msg;
 * CFE_MSG_Init(&hb_msg.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_HB_MID),
 *              sizeof(SPACECOP_Heartbeat_t));
 * hb_msg.timestamp = OS_TimeGetTotalSeconds(...);
 * CFE_SB_TransmitMsg(&hb_msg.TlmHeader.Msg, true);
 * 
 * // Ground system monitors for missed heartbeats
 * if (time_since_last_heartbeat > HEARTBEAT_TIMEOUT) {
 *     alert("SpaceCop heartbeat timeout on SC1");
 * }
 * @endcode
 *
 * @note Value: 0x19FC
 * @note Periodic transmission recommended
 * @note Ground systems should monitor for gaps
 *
 * @see SPACECOP_SendHeartbeat for transmission function
 */
#define SPACECOP_HB_MID               0x19FC

/**
 * @brief SpaceCop command message ID
 * 
 * Message identifier for SpaceCop application commands. Ground operators
 * and automated systems send commands to this MID to control SpaceCop
 * operation.
 *
 * **Message Type:** Command (0x18xx range per CCSDS V1)
 * **Direction:** Ground → Spacecraft
 * **Subscribers:** SpaceCop application command pipe
 *
 * **Supported Commands:**
 * - SPACECOP_NOOP_CC: No-operation (connectivity test)
 * - SPACECOP_RESET_COUNTERS_CC: Reset housekeeping counters
 * - SPACECOP_ENABLE_RULE_CC: Enable detection rule
 * - SPACECOP_DISABLE_RULE_CC: Disable detection rule
 * - SPACECOP_UPDATE_CONFIG_CC: Update configuration
 * - SPACECOP_DUMP_STIX_CC: Dump STIX log to file
 *
 * **Usage:**
 * @code
 * // Ground system sends command
 * SPACECOP_NoopCmd_t noop_cmd;
 * CFE_MSG_Init(&noop_cmd.CmdHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_CMD_MID),
 *              sizeof(SPACECOP_NoopCmd_t));
 * CFE_MSG_SetFcnCode(&noop_cmd.CmdHeader.Msg, SPACECOP_NOOP_CC);
 * CFE_SB_TransmitMsg(&noop_cmd.CmdHeader.Msg, true);
 * 
 * // SpaceCop receives and processes
 * void SPACECOP_ProcessCommandPacket(CFE_SB_Buffer_t *SBBufPtr) {
 *     CFE_SB_MsgId_t MsgId = CFE_SB_GetMsgId(&SBBufPtr->Msg);
 *     
 *     if (MsgId == CFE_SB_ValueToMsgId(SPACECOP_CMD_MID)) {
 *         SPACECOP_ProcessGroundCommand(SBBufPtr);
 *     }
 * }
 * @endcode
 *
 * **Command Validation:**
 * All commands are validated for:
 * - Message length
 * - Function code validity
 * - Parameter ranges
 * - Authorization (if applicable)
 *
 * @note Value: 0x18FE
 * @note All SpaceCop commands use this MID
 * @note Function code determines specific command
 *
 * @see spacecop_msg.h for command structure definitions
 * @see SPACECOP_ProcessGroundCommand for command handler
 */
#define SPACECOP_CMD_MID              0x18FE 

/**
 * @brief SpaceCop housekeeping request message ID
 * 
 * Message identifier for requesting SpaceCop to publish its housekeeping
 * telemetry. Typically sent by the Scheduler (SCH) application at regular
 * intervals (e.g., 1 Hz).
 *
 * **Message Type:** Command (0x18xx range)
 * **Direction:** SCH → SpaceCop
 * **Response:** SPACECOP_HK_TLM_MID telemetry packet
 *
 * **Typical Configuration:**
 * @code
 * # In scheduler table (SCH_LAB_table.c)
 * {
 *     .MessageBuffer = SPACECOP_REQ_HK_MID,
 *     .Period = 1000,  // 1 Hz (every 1000ms)
 *     .Offset = 100,   // 100ms offset
 * }
 * @endcode
 *
 * **Processing Flow:**
 * @code
 * 1. SCH sends SPACECOP_REQ_HK_MID (1 Hz)
 * 2. SpaceCop receives request
 * 3. SpaceCop updates housekeeping data
 * 4. SpaceCop publishes SPACECOP_HK_TLM_MID
 * 5. Ground system receives telemetry
 * @endcode
 *
 * **Usage:**
 * @code
 * // SpaceCop processes request
 * void SPACECOP_ProcessCommandPacket(CFE_SB_Buffer_t *SBBufPtr) {
 *     CFE_SB_MsgId_t MsgId = CFE_SB_GetMsgId(&SBBufPtr->Msg);
 *     
 *     if (MsgId == CFE_SB_ValueToMsgId(SPACECOP_REQ_HK_MID)) {
 *         SPACECOP_ReportHousekeeping();
 *     }
 * }
 * 
 * // Report housekeeping
 * void SPACECOP_ReportHousekeeping(void) {
 *     // Update counters
 *     SPACECOP_HkTelemetryPkt.DetectionCount = detection_count;
 *     SPACECOP_HkTelemetryPkt.AlertCount = alert_count;
 *     
 *     // Send telemetry
 *     CFE_SB_TimeStampMsg(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg);
 *     CFE_SB_TransmitMsg(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg, true);
 * }
 * @endcode
 *
 * @note Value: 0x18FF
 * @note Typically sent by SCH application
 * @note Triggers housekeeping telemetry publication
 *
 * @see SPACECOP_HK_TLM_MID for response message
 * @see SPACECOP_ReportHousekeeping for handler function
 */
#define SPACECOP_REQ_HK_MID           0x18FF 

/**
 * @brief SpaceCop CTI sharing message ID
 * 
 * Message identifier for Cyber Threat Intelligence (CTI) sharing between
 * SpaceCop instances. Used to distribute STIX bundles and heartbeats across
 * spacecraft constellation and to ground systems.
 *
 * **Message Type:** Telemetry (0x09xx range - extended telemetry)
 * **Direction:** Spacecraft ↔ Spacecraft, Spacecraft → Ground
 * **Subscribers:** Peer SpaceCop instances, ground SIEM/SOC
 *
 * **Message Subtypes:**
 * - SPACECOP_ALERT_STIX: STIX 2.1 threat intelligence bundle
 * - SPACECOP_HEARTBEAT: Operational status heartbeat
 *
 * **Distributed Detection:**
 * @code
 * ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
 * │ SpaceCop A  │────────▶│  CTI Share  │────────▶│ SpaceCop B  │
 * │ (Detector)  │  0x09FC │   Message   │  0x09FC │ (Receiver)  │
 * └─────────────┘         └─────────────┘         └─────────────┘
 * @endcode
 *
 * **Usage:**
 * @code
 * // Send STIX alert to peers
 * SPACECOP_Alert_t alert;
 * CFE_MSG_Init(&alert.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID),
 *              sizeof(SPACECOP_Alert_t));
 * alert.AlertType = SPACECOP_ALERT_STIX;
 * alert.BundleSize = strlen(stix_bundle);
 * memcpy(alert.StixBundle, stix_bundle, alert.BundleSize);
 * CFE_SB_TransmitMsg(&alert.TlmHeader.Msg, true);
 * 
 * // Peer receives and processes
 * void SPACECOP_ProcessMessages(void) {
 *     CFE_SB_Buffer_t *buf;
 *     while (CFE_SB_ReceiveBuffer(&buf, cti_pipe, timeout) == CFE_SUCCESS) {
 *         if (CFE_SB_GetMsgId(&buf->Msg) == 
 *             CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID)) {
 *             SPACECOP_ProcessPeerAlert(&buf->Msg);
 *         }
 *     }
 * }
 * @endcode
 *
 * **Constellation Configuration:**
 * Each spacecraft subscribes to CTI_SHARE_MID to receive alerts from peers:
 * @code
 * CFE_SB_Subscribe(CFE_SB_ValueToMsgId(SPACECOP_CTI_SHARE_MID),
 *                  SPACECOP_CTIPipe);
 * @endcode
 *
 * **Benefits:**
 * - Real-time threat intelligence sharing
 * - Coordinated constellation defense
 * - Early warning for peer spacecraft
 * - Attack campaign correlation
 *
 * @note Value: 0x09FC
 * @note Used for both STIX bundles and heartbeats
 * @note Enables distributed intrusion detection
 *
 * @see SPACECOP_Alert_t for message structure
 * @see SPACECOP_SendStixAlert for sending function
 * @see SPACECOP_ProcessPeerAlert for receiving function
 */
#define SPACECOP_CTI_SHARE_MID        0x09FC

/**
 * @brief SpaceCop detection report telemetry message ID
 * 
 * Message identifier for detailed detection reports. Published when SpaceCop
 * detects a potential intrusion or suspicious behavior. Contains detailed
 * information about the detection for ground analysis.
 *
 * **Message Type:** Telemetry (0x08xx range)
 * **Direction:** Spacecraft → Ground
 * **Typical Rate:** Event-driven (on detection)
 * **Subscribers:** Ground system, telemetry archival
 *
 * **Report Contents:**
 * - IOB identifier (e.g., "UACE-1")
 * - Detection timestamp
 * - Artifact information (file, command, network, etc.)
 * - Confidence level
 * - Severity assessment
 * - Recommended actions
 *
 * **Usage:**
 * @code
 * // Generate detection report
 * SPACECOP_Report_t report;
 * CFE_MSG_Init(&report.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_REPORT_TLM_MID),
 *              sizeof(SPACECOP_Report_t));
 * 
 * strncpy(report.IobId, "UACE-1", sizeof(report.IobId));
 * strncpy(report.Description, 
 *         "Hardware Command Executed Outside Authorized Schedule",
 *         sizeof(report.Description));
 * report.Timestamp = OS_TimeGetTotalSeconds(...);
 * report.Severity = SPACECOP_SEVERITY_HIGH;
 * report.Confidence = 95;
 * 
 * CFE_SB_TimeStampMsg(&report.TlmHeader.Msg);
 * CFE_SB_TransmitMsg(&report.TlmHeader.Msg, true);
 * 
 * // Ground system processes report
 * if (report.Severity >= SPACECOP_SEVERITY_HIGH) {
 *     alert_operator(report);
 *     initiate_response_protocol(report);
 * }
 * @endcode
 *
 * **Ground System Integration:**
 * Reports are typically:
 * - Logged to telemetry database
 * - Displayed in real-time monitoring
 * - Analyzed by SIEM/SOC
 * - Correlated with other spacecraft data
 * - Used for incident response
 *
 * @note Value: 0x08FD
 * @note Published on each detection event
 * @note Critical for ground situational awareness
 *
 * @see SPACECOP_Report_t for message structure
 * @see SPACECOP_ReportDetection for generation function
 */
#define SPACECOP_REPORT_TLM_MID       0x08FD 

/**
 * @brief SpaceCop housekeeping telemetry message ID
 * 
 * Message identifier for SpaceCop housekeeping telemetry. Contains status
 * information, performance metrics, and operational counters. Published
 * periodically in response to SPACECOP_REQ_HK_MID.
 *
 * **Message Type:** Telemetry (0x08xx range)
 * **Direction:** Spacecraft → Ground
 * **Typical Rate:** 1 Hz (in response to housekeeping request)
 * **Subscribers:** Ground system, telemetry archival
 *
 * **Housekeeping Contents:**
 * - Command counters (valid/invalid)
 * - Detection statistics (total, by category)
 * - Alert counters
 * - Rule status (enabled/disabled count)
 * - Performance metrics (CPU, memory)
 * - Error counters
 * - Application version
 *
 * **Usage:**
 * @code
 * // Publish housekeeping telemetry
 * void SPACECOP_ReportHousekeeping(void) {
 *     // Update housekeeping packet
 *     SPACECOP_HkTelemetryPkt.CmdCounter = cmd_counter;
 *     SPACECOP_HkTelemetryPkt.ErrCounter = err_counter;
 *     SPACECOP_HkTelemetryPkt.DetectionCount = detection_count;
 *     SPACECOP_HkTelemetryPkt.AlertCount = alert_count;
 *     SPACECOP_HkTelemetryPkt.EnabledRules = enabled_rule_count;
 *     
 *     // Timestamp and transmit
 *     CFE_SB_TimeStampMsg(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg);
 *     CFE_SB_TransmitMsg(&SPACECOP_HkTelemetryPkt.TlmHeader.Msg, true);
 * }
 * 
 * // Ground system monitors health
 * if (hk.ErrCounter > ERROR_THRESHOLD) {
 *     alert_operator("SpaceCop error count high");
 * }
 * if (hk.DetectionCount > DETECTION_THRESHOLD) {
 *     alert_operator("High detection rate - possible attack");
 * }
 * @endcode
 *
 * **Ground Display:**
 * Housekeeping telemetry typically displayed in:
 * - Real-time telemetry pages
 * - Application status dashboards
 * - Trending plots (detection rate over time)
 * - Health and status summaries
 *
 * @note Value: 0x08FE
 * @note Published at 1 Hz (typical)
 * @note Essential for health monitoring
 *
 * @see SPACECOP_HkTelemetryPkt for packet structure
 * @see SPACECOP_REQ_HK_MID for request message
 * @see SPACECOP_ReportHousekeeping for handler
 */
#define SPACECOP_HK_TLM_MID           0x08FE 

/**
 * @brief SpaceCop device telemetry message ID
 * 
 * Message identifier for device-specific telemetry from monitored subsystems.
 * Contains detailed information about hardware devices, buses, and interfaces
 * being monitored by SpaceCop.
 *
 * **Message Type:** Telemetry (0x08xx range)
 * **Direction:** Spacecraft → Ground
 * **Typical Rate:** Variable (0.1 - 1 Hz depending on device)
 * **Subscribers:** Ground system, device monitoring tools
 *
 * **Device Categories:**
 * - CAN bus controllers and nodes
 * - SpaceWire routers and endpoints
 * - MIL-STD-1553 bus controllers/remote terminals
 * - Cryptographic modules
 * - Memory controllers
 * - GNSS receivers
 *
 * **Telemetry Contents:**
 * - Device identifier
 * - Device type
 * - Operational status
 * - Error counters
 * - Bus statistics (message rate, errors, arbitration)
 * - Security metrics
 * - Performance data
 *
 * **Usage:**
 * @code
 * // Publish device telemetry
 * SPACECOP_DeviceTlm_t device_tlm;
 * CFE_MSG_Init(&device_tlm.TlmHeader.Msg,
 *              CFE_SB_ValueToMsgId(SPACECOP_DEVICE_TLM_MID),
 *              sizeof(SPACECOP_DeviceTlm_t));
 * 
 * device_tlm.DeviceId = CAN_BUS_1;
 * device_tlm.DeviceType = DEVICE_TYPE_CAN;
 * device_tlm.MessageRate = can_message_count / elapsed_time;
 * device_tlm.ErrorRate = can_error_count / elapsed_time;
 * device_tlm.ArbitrationLosses = can_arb_loss_count;
 * 
 * CFE_SB_TimeStampMsg(&device_tlm.TlmHeader.Msg);
 * CFE_SB_TransmitMsg(&device_tlm.TlmHeader.Msg, true);
 * 
 * // Ground system monitors device health
 * if (device_tlm.ErrorRate > DEVICE_ERROR_THRESHOLD) {
 *     alert_operator("High error rate on CAN bus 1");
 * }
 * @endcode
 *
 * **Ground Analysis:**
 * Device telemetry used for:
 * - Hardware health monitoring
 * - Bus performance analysis
 * - Attack correlation (e.g., CAN bus flooding)
 * - Anomaly detection baseline establishment
 * - Forensic investigation
 *
 * @note Value: 0x08FF
 * @note Rate varies by device type
 * @note Supports multiple device types
 *
 * @see SPACECOP_DeviceTlm_t for packet structure
 * @see AT_DEVICE artifact type in SPARTA IOBs
 */
#define SPACECOP_DEVICE_TLM_MID       0x08FF

#endif /* _SPACECOP_MSGIDS_H_ */