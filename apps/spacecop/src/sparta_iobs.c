// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file sparta_iobs.c
 * @brief SPARTA Indicator of Behavior (IOB) database implementation
 *
 * This file implements the comprehensive IOB database for the SpaceCop
 * Intrusion Detection System, based on the SPARTA (Space Attack Research
 * and Tactic Analysis) framework. It provides:
 * - Complete catalog of space system attack indicators
 * - STIX-based detection patterns
 * - Attack artifact type classifications
 * - IOB lookup and retrieval functions
 *
 * **SPARTA Framework:**
 * SPARTA is a knowledge base of adversary tactics and techniques targeting
 * space systems, analogous to MITRE ATT&CK for enterprise systems. Each
 * IOB represents a specific observable indicator of malicious activity.
 *
 * **IOB Categories:**
 * The database is organized into seven primary attack categories:
 *
 * 1. **UACE - Unauthorized Command Execution (26 IOBs)**
 *    - Hardware command manipulation
 *    - Parameter tampering
 *    - Command flooding
 *    - Safe-mode exploitation
 *    - Propulsion system attacks
 *
 * 2. **UCEB - Unauthorized Cryptographic and Encryption Bypass (11 IOBs)**
 *    - Key manipulation
 *    - Encryption bypass
 *    - Authentication circumvention
 *    - Protocol exploitation
 *
 * 3. **CSNE - Communication and Satellite Network Exploitation (45 IOBs)**
 *    - Ground station spoofing
 *    - Network protocol attacks
 *    - Bus system exploitation (CAN, SpaceWire, 1553)
 *    - Crosslink manipulation
 *    - Downlink attacks
 *
 * 4. **ARFS - Authentication and RF Signal Manipulation (12 IOBs)**
 *    - Authentication tampering
 *    - Signal jamming
 *    - RF interference
 *    - SLE protocol attacks
 *
 * 5. **GNTM - GNSS and Navigation Time Manipulation (12 IOBs)**
 *    - GPS spoofing
 *    - Time manipulation
 *    - Position falsification
 *    - Clock attacks
 *
 * 6. **MIRE - Memory Integrity and Resource Exhaustion (18 IOBs)**
 *    - Memory corruption
 *    - Boot sequence attacks
 *    - Flash/EEPROM tampering
 *    - Resource exhaustion
 *
 * 7. **WTRE - Watchdog Timer and Register Exploitation (7 IOBs)**
 *    - Watchdog manipulation
 *    - Register tampering
 *    - Timing attacks
 *
 * 8. **SIUU - Software Integrity and Unauthorized Updates (26 IOBs)**
 *    - Malicious code injection
 *    - Unauthorized updates
 *    - Process manipulation
 *    - Firmware attacks
 *
 * 9. **SMSR - Sensor Manipulation and System Resource Attacks (19 IOBs)**
 *    - Sensor spoofing
 *    - CPU/memory exhaustion
 *    - ADCS manipulation
 *    - System resource attacks
 *
 * 10. **DISE - Data Integrity and Storage Exploitation (17 IOBs)**
 *     - File integrity violations
 *     - Storage exhaustion
 *     - Data tampering
 *     - Log manipulation
 *
 * **STIX Pattern Language:**
 * Each IOB includes a STIX (Structured Threat Information eXpression)
 * pattern that defines the observable conditions for detection:
 *
 * @code
 * // Example STIX pattern
 * "[x-opencti-command-log:command = 'hw_cmd_execute' AND 
 *   x-opencti-command-log:execution_time != 'authorized_time']"
 *
 * // Pattern components:
 * - Observable type: x-opencti-command-log
 * - Property: command, execution_time
 * - Comparison: =, !=, >, <, IN
 * - Value: 'hw_cmd_execute', 'authorized_time'
 * - Logic: AND, OR
 * @endcode
 *
 * **Artifact Types:**
 * Each IOB is classified by the primary artifact type used for detection:
 * - AT_COMMAND: Command logs and execution traces
 * - AT_NETWORK: Network traffic and communication
 * - AT_KEY: Cryptographic keys and certificates
 * - AT_CONFIG: Configuration files and settings
 * - AT_PROGRAM: Process and program execution
 * - AT_MEMORY: Memory contents and access patterns
 * - AT_DEVICE: Hardware devices and buses
 * - AT_FILE: File system and storage
 * - AT_NONE: Multiple sources or telemetry-based
 *
 * **Usage Example:**
 * @code
 * // Look up IOB by identifier
 * const IOBCTI *iob = FindIoB("UACE-1");
 * if (iob != NULL) {
 *     printf("IOB: %s\n", iob->iob);
 *     printf("Name: %s\n", iob->name);
 *     printf("Pattern: %s\n", iob->pattern);
 *     printf("Artifact Type: %d\n", iob->arttype);
 *     
 *     // Use in detection rule
 *     if (evaluate_stix_pattern(iob->pattern, system_state)) {
 *         generate_alert(iob->iob, iob->name);
 *     }
 * }
 * @endcode
 *
 * **Integration with SpaceCop:**
 * IOBs are referenced throughout SpaceCop:
 * - Rule tables specify IOB identifiers for alerts
 * - Detection engine evaluates STIX patterns
 * - Alert messages include IOB names and IDs
 * - Ground systems use IOBs for threat intelligence
 * - Forensic analysis correlates IOBs to attacks
 *
 * **Extending the Database:**
 * To add new IOBs:
 * 1. Choose appropriate category (UACE, UCEB, etc.)
 * 2. Assign sequential number within category
 * 3. Create descriptive name
 * 4. Define STIX pattern for detection
 * 5. Classify artifact type
 * 6. Add entry to iobs[] array
 * 7. Update IOB_ARRAY_SIZE in sparta_iobs.h
 * 8. Document in mission-specific guide
 *
 * **STIX Pattern Development:**
 * When creating STIX patterns:
 * - Use specific observable types (x-opencti-*)
 * - Define clear comparison criteria
 * - Avoid overly broad patterns (false positives)
 * - Test against known attack scenarios
 * - Consider performance impact
 * - Document expected values and thresholds
 *
 * **Performance Considerations:**
 * - Array is const (stored in read-only memory)
 * - Linear search is acceptable for ~200 IOBs
 * - Consider hash table for >1000 IOBs
 * - Cache frequently used IOBs
 * - Pattern evaluation is the performance bottleneck
 *
 * @note IOB identifiers must be unique across all categories
 * @note STIX patterns use mission-specific threshold values
 * @note Some patterns require baseline establishment
 * @note Patterns marked 'expected_*' require configuration
 *
 * @see sparta_iobs.h for structure definitions and constants
 * @see spacecop_table_runtime.c for pattern evaluation
 * @see SPARTA framework documentation for detailed attack descriptions
 *
 * @warning Modifying IOB identifiers breaks compatibility with existing rules
 * @warning STIX patterns must be validated before deployment
 */

#include "sparta_iobs.h"

/*=======================================================================================
** IOB Database
**=======================================================================================*/

/**
 * @brief Global IOB database array
 * 
 * Complete database of Indicators of Behavior for space system intrusion
 * detection. Each entry defines:
 * - Unique IOB identifier (e.g., "UACE-1")
 * - Human-readable name
 * - STIX detection pattern
 * - Primary artifact type for detection
 *
 * **Database Organization:**
 * IOBs are grouped by attack category with sequential numbering:
 * - UACE-1 through UACE-26: Command execution attacks
 * - UCEB-1 through UCEB-11: Encryption/crypto attacks
 * - CSNE-1 through CSNE-45: Network/communication attacks
 * - ARFS-1 through ARFS-12: Authentication/RF attacks
 * - GNTM-1 through GNTM-12: GNSS/time attacks
 * - MIRE-1 through MIRE-18: Memory/resource attacks
 * - WTRE-1 through WTRE-7: Watchdog/register attacks
 * - SIUU-1 through SIUU-26: Software integrity attacks
 * - SMSR-1 through SMSR-19: Sensor/resource attacks
 * - DISE-1 through DISE-17: Data integrity attacks
 *
 * **Total:** 193 IOBs covering comprehensive space system threat landscape
 *
 * @note Array is const - cannot be modified at runtime
 * @note Size must match IOB_ARRAY_SIZE in sparta_iobs.h
 */
const IOBCTI iobs[IOB_ARRAY_SIZE] = {
	
	/*=======================================================================================
	** UACE - Unauthorized Command Execution
	** 
	** Detects unauthorized or malicious command execution including:
	** - Commands sent outside authorized schedules
	** - Parameter tampering
	** - Command flooding
	** - Safe-mode exploitation
	** - Propulsion system manipulation
	**=======================================================================================*/
	
	{ .iob = "UACE-1", .name = "Hardware Command Executed Outside Authorized Schedule", 
        .pattern = "[x-opencti-command-log:command = 'hw_cmd_execute' AND x-opencti-command-log:execution_time != 'authorized_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-2", .name = "Unauthorized Hardware Command-Induced Configuration Change", 
        .pattern = "[x-opencti-command-log:command = 'hw_cmd_configure' AND x-opencti-system:configuration != 'baseline_configuration']", .arttype = AT_COMMAND },
	{ .iob = "UACE-3", .name = "Legitimate Command with Malicious Parameters Targeting Subsystems", 
        .pattern = "[x-opencti-command-log:command_type = 'legitimate_command' AND x-opencti-command-log:target_subsystem != 'expected_subsystem' AND x-opencti-command-log:parameter_value > 'safe_threshold']", .arttype = AT_COMMAND },
	{ .iob = "UACE-4", .name = "Unexpected Legitimate Command Sent", 
        .pattern = "[x-opencti-command-log:command_type = 'legitimate_command' AND x-opencti-command-log:timestamp != 'expected_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-5", .name = "Unexpected counter increment (valid or invalid count)", 
        .pattern = "[x-opencti-command-counter:value = 'unexpected']", .arttype = AT_NONE },
	{ .iob = "UACE-6", .name = "Unauthorized Commands Issued from Unrecognized Ground Station", 
        .pattern = "[x-opencti-command-log:command_origin != 'authorized_ground_station' AND x-opencti-command-log:command_type = 'control']", .arttype = AT_NETWORK },
	{ .iob = "UACE-7", .name = "Duplicate Command Packet Executions", 
        .pattern = "[x-opencti-command-log:command_id = 'duplicate' AND x-opencti-command-log:timestamp = 'unexpected_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-8", .name = "Anomalous Command Packet Signatures", 
        .pattern = "[x-opencti-command-log:signature != 'expected_signature']", .arttype = AT_COMMAND },
	{ .iob = "UACE-9", .name = "Valid Command Flooding", 
        .pattern = "[x-opencti-command-data:command_type = 'satellite_vehicle_command' AND x-opencti-command-data:command_frequency > 'expected_rate' AND x-opencti-command-data:source = 'external' AND x-opencti-command-data:command_validity = 'valid']", .arttype = AT_COMMAND },
	{ .iob = "UACE-10", .name = " Logs of Processed Commands Flooding", 
        .pattern = "[x-opencti-log-entry:log_type = 'command' AND x-opencti-log-entry:entry_count > 'expected_threshold' AND x-opencti-log-entry:entry_rate > 'normal_rate']", .arttype = AT_NONE },
	{ .iob = "UACE-11", .name = "Unauthorized Command Execution via Flight Software", 
        .pattern = "[x-opencti-command-log:command_origin != 'trusted_source' AND x-opencti-command-log:execution_status = 'unauthorized']", .arttype = AT_COMMAND },
	{ .iob = "UACE-12", .name = "Anomalous Command or Sequence in Safe-Mode", 
        .pattern = "[x-opencti-command-log:command != 'expected' AND x-opencti-spacecraft-status:mode = 'safe-mode']", .arttype = AT_COMMAND },
	{ .iob = "UACE-13", .name = "Unexpected Command Execution During Safe-Mode", 
        .pattern = "[x-opencti-command-log:command = 'critical_cmd' AND x-opencti-spacecraft-status:mode = 'safe-mode']", .arttype = AT_COMMAND },
	{ .iob = "UACE-14", .name = "Safe-Mode Exit Command Executed at Unexpected Time", 
        .pattern = "[x-opencti-command-log:command = 'exit_safe_mode' AND x-opencti-command-log:execution_time != 'authorized_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-15", .name = "Command from Untrusted Ground Station or Location in Safe-Mode", 
        .pattern = "[x-opencti-command-log:command_origin.location != 'authorized_geolocation' AND x-opencti-spacecraft-status:mode = 'safe-mode']", .arttype = AT_NETWORK },
	{ .iob = "UACE-16", .name = "Irregular Orbit Maneuver Commands Detected on Attitude Control", 
        .pattern = "[x-opencti-command:observable_type = 'adcs-command' AND x-opencti-command:value != 'expected_orbit_maneuver_commands']", .arttype = AT_COMMAND },
	{ .iob = "UACE-17", .name = "Abnormal Burn Duration Detected in Propulsion Subsystem", 
        .pattern = "[x-opencti-propulsion-system:burn_duration > 'expected_max_duration' OR x-opencti-propulsion-system:burn_duration < 'expected_min_duration']", .arttype = AT_NONE },
	{ .iob = "UACE-18", .name = "Suspicious Burn Sequence Executed Outside Planned Timeline", 
        .pattern = "[x-opencti-propulsion-system:burn_command_time != 'expected_burn_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-19", .name = "Unexpected Thrust Direction Detected in Propulsion Subsystem", 
        .pattern = "[x-opencti-propulsion-system:thrust_direction != 'expected_direction' AND x-opencti-propulsion-system:burn_command_issued = 'true']", .arttype = AT_COMMAND },
	{ .iob = "UACE-20", .name = "Repeated Downlink Commands with Identical Timestamps", 
        .pattern = "[x-opencti-command-log:command = 'downlink_data' AND x-opencti-command-log:timestamp = 'duplicate_timestamp']", .arttype = AT_COMMAND },
	{ .iob = "UACE-21", .name = "Repeated Downlink Commands Sent Outside Authorized Time", 
        .pattern = "[x-opencti-command-log:command = 'downlink_payload_data' AND x-opencti-command-log:timestamp != 'expected_time']", .arttype = AT_COMMAND },
	{ .iob = "UACE-22", .name = "Multiple Consecutive Burn Commands Exceeding Duration Limits", 
        .pattern = "[x-opencti-propulsion-system:burn_duration > 'expected_duration' AND x-opencti-propulsion-system:consecutive_burn_commands > 'threshold_value']", .arttype = AT_COMMAND },
	{ .iob = "UACE-23", .name = "Unusual Commands from Subsystem Acting as Bus Controller (1553)", 
        .pattern = "[x-opencti-bus-master:role = 'subsystem' AND x-opencti-bus-master:commands != 'expected_commands']", .arttype = AT_DEVICE },
	{ .iob = "UACE-24", .name = "Unauthorized CLTU-START, STOP, or UNBIND Initiation from Unauthorized User or Rogue IP", 
        .pattern = "[(x-opencti-command-log:command = 'CLTU-START' OR x-opencti-command-log:command = 'CLTU-STOP' OR x-opencti-command-log:command = 'CLTU-UNBIND') AND (x-opencti-command-log:user != 'authorized_user' OR network-traffic:src_ref.value != 'authorized_ip')]", .arttype = AT_NETWORK },
	{ .iob = "UACE-25", .name = "Telecommand Format Tampering in CLTU-TRANSFER_DATA", 
        .pattern = "[network-traffic:protocols = 'x_ccsds_tc' AND network-traffic:x_content_format != 'expected_ccsds_tc_format' AND network-traffic:x_content = 'cltu-transfer_data']", .arttype = AT_NONE },
	{ .iob = "UACE-26", .name = "Unauthorized Crosslink Command at Unexpected Time", 
        .pattern = "[x-opencti-command-log:command = 'crosslink_command' AND x-opencti-command-log:timestamp != 'expected_time']", .arttype = AT_COMMAND },

	/*=======================================================================================
	** UCEB - Unauthorized Cryptographic and Encryption Bypass
	** 
	** Detects cryptographic attacks and encryption bypass attempts including:
	** - Key manipulation and misuse
	** - Encryption configuration tampering
	** - Authentication bypass
	** - Protocol-level crypto attacks
	**=======================================================================================*/
	
	{ .iob = "UCEB-1", .name = "Repeated Use of Cryptographic Keys from Unusual Locations", 
        .pattern = "[x-opencti-cryptographic-key:usage_location != 'authorized_locations' AND x-opencti-cryptographic-key:use_count > 'threshold']", .arttype = AT_KEY },
	{ .iob = "UCEB-2", .name = "Use of Old or Rotated Cryptographic Keys for Authentication", 
        .pattern = "[x-opencti-cryptographic-key:status = 'rotated or expired']", .arttype = AT_KEY },
	{ .iob = "UCEB-3", .name = "Unexpected Access to Cryptographic Keys", 
        .pattern = "[x-opencti-cryptographic-key:access_time != 'authorized_access_time' AND x-opencti-cryptographic-key:usage = 'decryption']", .arttype = AT_KEY },
	{ .iob = "UCEB-4", .name = "Unexpected Changes to Encryption Configuration Settings", 
        .pattern = "[x-opencti-encryption-config:status = 'disabled' AND x-opencti-encryption-config:change_time != 'authorized_change_time']", .arttype = AT_CONFIG },
	{ .iob = "UCEB-5", .name = "Unexpected SPI Value Triggering Segmentation Fault", 
        .pattern = "[network-traffic:spi != 'valid_range' AND network-traffic:protocols[*]= 'SDLS']", .arttype = AT_NONE },
	{ .iob = "UCEB-6", .name = "Abnormal Security Association (SA) Pointer Retrieval", 
        .pattern = "[process:x_sa_pointer_retrieval != 'valid_range' AND process:image_ref.name = 'CryptoLib']", .arttype = AT_PROGRAM },
	{ .iob = "UCEB-7", .name = "Modification of Encryption Algorithms", 
        .pattern = "[x-opencti-encryption-algorithm:algorithm != 'expected_algorithm' AND x-opencti-encryption-algorithm:modification_time != 'authorized_time']", .arttype = AT_CONFIG },
	{ .iob = "UCEB-8", .name = "Payload Channel Operating Without Encryption", 
        .pattern = "[network-traffic:src_ref.value = 'payload_channel' AND network-traffic:encryption_status != 'encrypted']", .arttype = AT_NONE },
	{ .iob = "UCEB-9", .name = "Failed Credential Encryption in SLE Protocol", 
        .pattern = "[network-traffic:dst_ref.value = 'SLE_Provider' AND network-traffic:encryption_status != 'encrypted']", .arttype = AT_NETWORK },
	{ .iob = "UCEB-10", .name = "Crosslink Channel Operating Without Encryption", 
        .pattern = "[network-traffic:src_ref.value = 'crosslink' AND network-traffic:encryption_status != 'encrypted']", .arttype = AT_NONE },
	{ .iob = "UCEB-11", .name = "Use of Account or Cryptographic Keys at Unexpected Times", 
        .pattern = "[user-account:last_login_time != 'expected_operational_hours' OR x-opencti-cryptographic-key:usage_time != 'expected_usage_time']", .arttype = AT_KEY },

	/*=======================================================================================
	** CSNE - Communication and Satellite Network Exploitation
	** 
	** Detects network and communication attacks including:
	** - Ground station spoofing
	** - Protocol manipulation
	** - Bus system attacks (CAN, SpaceWire, MIL-STD-1553)
	** - Crosslink exploitation
	** - Data exfiltration
	**=======================================================================================*/
	
	{ .iob = "CSNE-1", .name = "Unexpected Ground Station IP Address in Communication", 
        .pattern = "[network-traffic:src_ref.value != 'authorized_ground_station_ip' AND network-traffic:protocols[*] = 'satellite_communication']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-2", .name = "ARP Spoofing Attack (Rogue IP)", 
        .pattern = "[network-traffic:src_ref.role = 'ground_station' AND network-traffic:dst_ref.role = 'mission_control_system' AND network-traffic:src_ref.value != 'authorized_ip']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-3", .name = "Backup Channel Activity Outside Scheduled Time Windows", 
        .pattern = "[network-traffic:src_ref.value = 'backup_channel' AND network-traffic:timestamp != 'scheduled_window']", .arttype = AT_NONE },
	{ .iob = "CSNE-4", .name = "Unexpected Data Transfer Over Backup Channel While Primary Active", 
        .pattern = "[network-traffic:src_ref.value = 'backup_channel' AND network-traffic:traffic_volume > 'baseline_threshold' AND network-traffic:primary_channel_status = 'active']", .arttype = AT_NONE },
	{ .iob = "CSNE-5", .name = "Traffic Volume Spike on Backup Channel", 
        .pattern = "[network-traffic:src_ref.value = 'backup_channel' AND network-traffic:traffic_volume > 'baseline_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-6", .name = "Unexpected Communication Protocols in Uplink", 
        .pattern = "[network-traffic:protocols[*] != 'expected_protocol' AND network-traffic:direction = 'uplink']", .arttype = AT_NONE },
	{ .iob = "CSNE-7", .name = "Use of Unexpected Protocol on Backup Channel", 
        .pattern = "[network-traffic:protocols != 'expected_protocol' AND network-traffic:src_ref.channel = 'backup_channel']", .arttype = AT_NONE },
	{ .iob = "CSNE-8", .name = "Denial of Service Due to Saturated Bandwidth Detected", 
        .pattern = "[network-traffic:x_bandwidth_usage > 'maximum_capacity' AND network-traffic:protocols[*] = 'satellite_communication']", .arttype = AT_NONE },
	{ .iob = "CSNE-9", .name = "Unexpected Downlink Traffic Dropped or Disrupted", 
        .pattern = "[network-traffic:direction = 'downlink' AND network-traffic:status = 'dropped' OR network-traffic:error_rate > 'acceptable_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-10", .name = "Transmission to Unauthorized Ground Station Detected", 
        .pattern = "[network-traffic:dst_ref.value != 'authorized_ground_station']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-11", .name = "Data Exfiltration Detected During Scheduled Communication Windows", 
        .pattern = "[network-traffic:direction = 'downlink' AND network-traffic:data_size > 'expected_size']", .arttype = AT_NONE },
	{ .iob = "CSNE-12", .name = "Generic Flooding Attack", 
        .pattern = "[network-traffic:protocols[*] = 'satellite_vehicle' AND network-traffic:src_port IN ('uplink_port','crosslink_port') AND network-traffic:packet_size > 'expected_max_size' AND network-traffic:packet_count > 'normal_packet_rate']", .arttype = AT_NONE },
	{ .iob = "CSNE-13", .name = "Erroneous Input Flooding", 
        .pattern = "[network-traffic:protocols[*] = 'satellite_vehicle' AND network-traffic:data_size < 'minimum_valid_size' AND network-traffic:data_content = 'non-system-relevant' AND network-traffic:packet_count > 'expected_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-14", .name = "Unusual Data Transmission Between SpaceWire Routing Switches", 
        .pattern = "[x-opencti-bus-traffic:src_ref.role = 'routing_switch' AND x-opencti-bus-traffic:dst_ref.role = 'critical_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-15", .name = "Unexpected Communication Between Subsystems", 
        .pattern = "[x-opencti-bus-traffic:src_ref.subsystem != 'expected_subsystem' AND x-opencti-bus-traffic:dst_ref.subsystem != 'authorized_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-16", .name = "Suspicious Network Traffic Without Expected Encryption", 
        .pattern = "[network-traffic:encryption_status != 'encrypted' AND network-traffic:protocols[*] = 'satellite_communication' AND network-traffic:dst_ref.role = 'ground_station']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-17", .name = "Creation of FIFO for Data Exfiltration or Command Injection", 
        .pattern = "[process:image_ref.name = 'mkfifo' AND process:x_execution_time = 'unexpected_time']", .arttype = AT_PROGRAM },
	{ .iob = "CSNE-18", .name = "Process Execution Tied to Specific Geographic Coordinates", 
        .pattern = "[process:status = 'executing' AND process:start_time != 'expected_time' AND x-opencti-pnt-data:geolocation IN ('restricted_geofence')]", .arttype = AT_PROGRAM },
	{ .iob = "CSNE-19", .name = "Unexpected High-Priority Messages on the CAN Bus", 
        .pattern = "[x-opencti-bus-traffic:can_message_id < 'expected_lowest_priority' AND x-opencti-bus-traffic:src_ref.subsystem != 'authorized_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-20", .name = "Unauthorized Downlink Communication at Unexpected Time", 
        .pattern = "[network-traffic:direction = 'downlink' AND network-traffic:timestamp != 'expected_time']", .arttype = AT_NONE },
	{ .iob = "CSNE-21", .name = "Unauthorized Data Transmission from Ground System to External IP", 
        .pattern = "[network-traffic:src_ref.role = 'ground_system' AND network-traffic:dst_ref.value != 'authorized_external_ip']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-22", .name = "Traffic Volume Spike on Out-of-Band Link", 
        .pattern = "[network-traffic:src_ref.value = 'out_of_band_channel' AND network-traffic:traffic_volume > 'baseline_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-23", .name = "Sudden Increase in Bandwidth Usage from Ground System", 
        .pattern = "[network-traffic:bandwidth_usage > 'expected_threshold' AND network-traffic:src_ref.role = 'ground_system']", .arttype = AT_NONE },
	{ .iob = "CSNE-24", .name = "ARP Spoofing via MAC Address Mismatch", 
        .pattern = "[network-traffic:src_ref.value != 'authorized_mac_address' AND network-traffic:src_ref.role = 'ground_station']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-25", .name = "CAN Bus Error Frames Detected Across Multiple Nodes", 
        .pattern = "[x-opencti-can-error-frame:error_count > 'threshold' AND bus-traffic:src_ref.subsystem != 'authorized_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-26", .name = "Frequent CAN Arbitration Loss by Critical Subsystems", 
        .pattern = "[x-opencti-can-arbitration:loss_count > 'threshold' AND x-opencti-can-arbitration:losing_node = 'critical_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-27", .name = "Unexpected Communication Between SpaceWire Nodes", 
        .pattern = "[x-opencti-bus-traffic:src_ref.spacewire_node != 'expected_node' AND x-opencti-bus-traffic:dst_ref.spacewire_node != 'authorized_node']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-28", .name = "Detection of CANBus Replay Attack with Duplicate Message ID and Timing Anomalies", 
        .pattern = "[x-opencti-bus-traffic:can_message_id = 'legitimate_id' AND x-opencti-bus-traffic:message_payload = 'expected_payload' AND (x-opencti-bus-traffic:transmission_time != 'expected_transmission_time' OR x-opencti-bus-traffic:duplicate_message_count > 1)]", .arttype = AT_NONE },
	{ .iob = "CSNE-29", .name = "Replay of Legitimate CANBus Message with Known Message ID", 
        .pattern = "[x-opencti-bus-traffic:can_message_id = 'legitimate_id' AND x-opencti-bus-traffic:transmission_time != 'expected_transmission_time']", .arttype = AT_NONE },
	{ .iob = "CSNE-30", .name = "Unauthorized Device Acting as Bus Controller (1553)", 
        .pattern = "[x-opencti-bus-controller:role = 'bus_controller' AND x-opencti-bus-controller:device != 'authorized_bus_controller']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-31", .name = "Specially Crafted CAN Messages Sent to Critical Subsystems", 
        .pattern = "[x-opencti-bus-traffic:can_message_id = 'unexpected_value' AND x-opencti-bus-traffic:dst_ref.role = 'critical_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-32", .name = "Repeated CAN Message Spoofing Detected Between Subsystems", 
        .pattern = "[x-opencti-bus-traffic:x_can_message_id = 'legitimate_id' AND x-opencti-bus-traffic:src_ref.subsystem != 'authorized_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-33", .name = "Unusual Communication Between Payload and Critical Subsystems", 
        .pattern = "[x-opencti-bus-traffic:src_ref.role = 'payload' AND x-opencti-bus-traffic:dst_ref.role = 'critical_subsystem']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-34", .name = "Unusual Data Transmission from Remote Terminal to Subsystem. (1553)", 
        .pattern = "[x-opencti-bus-traffic:src_ref.role = 'remote_terminal' AND x-opencti-bus-traffic:dst_ref.role = 'critical_subsystem' AND x-opencti-bus-traffic:protocols[*]!= 'expected_protocol']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-35", .name = "Traffic Volume Spike on Payload Channel", 
        .pattern = "[network-traffic:src_ref.value = 'payload_channel' AND network-traffic:traffic_volume > 'baseline_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-36", .name = "Payload Channel Activity Outside Scheduled Time Windows", 
        .pattern = "[network-traffic:src_ref.value = 'payload_channel' AND network-traffic:timestamp != 'scheduled_window']", .arttype = AT_NONE },
	{ .iob = "CSNE-37", .name = "Out-of-Band Activity Outside Scheduled Time Windows", 
        .pattern = "[network-traffic:src_ref.value = 'out_of_band_channel' AND network-traffic:timestamp != 'scheduled_window']", .arttype = AT_NONE },
	{ .iob = "CSNE-38", .name = "Use of Unexpected Protocol on Out-of-Band Link", 
        .pattern = "[network-traffic:protocols != 'expected_protocol' AND network-traffic:src_ref.channel = 'out_of_band']", .arttype = AT_NONE },
	{ .iob = "CSNE-39", .name = "Unauthorized Frequency Usage on Out-of-Band Link", 
        .pattern = "[x-opencti-rf-sensor:frequency_band = 'out_of_band_channel' AND x-opencti-rf-sensor:usage != 'baseline_usage']", .arttype = AT_NONE },
	{ .iob = "CSNE-40", .name = "Unplanned Deactivation of Downlink Transmitter", 
        .pattern = "[x-opencti-telemetry:component = 'downlink_transmitter' AND x-opencti-telemetry:status = 'inactive' AND x-opencti-telemetry:deactivation_reason != 'planned']", .arttype = AT_DEVICE },
	{ .iob = "CSNE-41", .name = "High Latency Detected in Downlink Communication", 
        .pattern = "[network-traffic:latency > 'acceptable_latency_threshold' AND network-traffic:direction = 'downlink']", .arttype = AT_COMMAND },
	{ .iob = "CSNE-42", .name = "Multiple Failed Downlink Attempts from Spacecraft", 
        .pattern = "[x-opencti-telemetry-log:direction = 'downlink' AND x-opencti-telemetry-log:transmission_attempts > 'threshold' AND x-opencti-telemetry-log:status = 'failed']", .arttype = AT_NONE },
	{ .iob = "CSNE-43", .name = "Anomalous Increase in Crosslink Traffic Volume", 
        .pattern = "[network-traffic:src_ref.value = 'crosslink' AND network-traffic:traffic_volume > 'baseline_threshold']", .arttype = AT_NONE },
	{ .iob = "CSNE-44", .name = "Communication to Unauthorized Neighboring Spacecraft", 
        .pattern = "[network-traffic:src_ref.value = 'crosslink' AND network-traffic:dst_ref.value != 'authorized_spacecraft']", .arttype = AT_NETWORK },
	{ .iob = "CSNE-45", .name = "Unauthorized Signal Transmission to Secondary Receiver", 
        .pattern = "[network-traffic:dst_ref.channel = 'secondary_receiver' AND network-traffic:src_ref.value != 'authorized_ground_station']", .arttype = AT_NETWORK },

	/*=======================================================================================
	** ARFS - Authentication and RF Signal Manipulation
	** 
	** Detects authentication bypass and RF-based attacks including:
	** - Authentication tampering
	** - Signal jamming and interference
	** - RF parameter manipulation
	** - SLE protocol attacks
	**=======================================================================================*/
	
	{ .iob = "ARFS-1", .name = "Authentication Process Tampering", 
        .pattern = "[x-opencti-system-log:authentication_process_modification = 'TRUE']", .arttype = AT_NONE },
	{ .iob = "ARFS-2", .name = "Anomalous Authentication Attempts", 
        .pattern = "[x-opencti-authentication-log:attempts > 'threshold' AND x-opencti-authentication-log:result = 'failure']", .arttype = AT_NONE },
	{ .iob = "ARFS-3", .name = "Invalid RF Command Lock", 
        .pattern = "[x-opencti-signal_char:value = 'invalid']", .arttype = AT_NONE },
	{ .iob = "ARFS-4", .name = "Unexpected Latency in Command Packet Processing", 
        .pattern = "[x-opencti-telemetry:command_delay > 'threshold']", .arttype = AT_NONE },
	{ .iob = "ARFS-5", .name = "Failed Authentication Attempts Due to RF/EMI Interference", 
        .pattern = "[x-opencti-radio-communication:signal_strength = 'unexpected_variation' AND x-opencti-authentication-log:status = 'failed' AND x-opencti-authentication-log:source_location NOT IN ('list_of_known_ground_stations')]", .arttype = AT_NETWORK },
	{ .iob = "ARFS-6", .name = "Abnormal Signal Strength", 
        .pattern = "[network-traffic:signal_strength > 'expected_threshold' AND network-traffic:protocols[*] = 'satellite_communication']", .arttype = AT_NONE },
	{ .iob = "ARFS-7", .name = "Noise Injection Detected in Communication Channels", 
        .pattern = "[network-traffic:x_signal_noise_ratio < 'expected_noise_threshold' AND network-traffic:protocols[*] = 'satellite_communication']", .arttype = AT_NONE },
	{ .iob = "ARFS-8", .name = "Unauthorized Frequency Usage on Backup Channel", 
        .pattern = "[x-opencti-rf-sensor:frequency_band = 'backup_channel' AND x-opencti-rf-sensor:usage != 'baseline_usage']", .arttype = AT_NONE },
	{ .iob = "ARFS-9", .name = "Safe-Mode Activation Due to Signal Jamming", 
        .pattern = "[x-opencti-rf-sensor:frequency_band IN ('gnss_band','uplink_band') AND x-opencti-rf-sensor:noise_level > 'maximum_threshold' AND x-opencti-spacecraft-status:mode = 'safe-mode']", .arttype = AT_NONE },
	{ .iob = "ARFS-10", .name = "CLTU BIND Authentication Failure", 
        .pattern = "[x-opencti-command-log:command = 'CLTU-BIND' AND x-opencti-command-log:authentication_result = 'failure']", .arttype = AT_COMMAND },
	{ .iob = "ARFS-11", .name = "Authorized SLE Session Establishment by Attacker (Rogue IP)", 
        .pattern = "[x-opencti-command-log:command = 'CLTU-BIND' AND x-opencti-command-log:user = 'authorized_user' AND network-traffic:src_ref.value != 'authorized_ip']", .arttype = AT_NETWORK },
	{ .iob = "ARFS-12", .name = "Rejection of CLTU BIND Due to Tampered/Invalid Credentials", 
        .pattern = "[x-opencti-command-log:command = 'CLTU-BIND' AND x-opencti-command-log:status = 'rejected' AND x-opencti-command-log:reason = 'invalid_credentials']", .arttype = AT_COMMAND },

	/*=======================================================================================
	** GNTM - GNSS and Navigation Time Manipulation
	** 
	** Detects GNSS spoofing and time manipulation attacks including:
	** - GPS signal manipulation
	** - Time synchronization attacks
	** - Position falsification
	** - Clock tampering
	**=======================================================================================*/
	
	{ .iob = "GNTM-1", .name = "Unexpected GNSS Signal Delay", 
        .pattern = "[x-opencti-gnss-log:signal_delay > 'acceptable_latency']", .arttype = AT_NONE },
	{ .iob = "GNTM-2", .name = "Signal-to-Noise Ratio Drop in GNSS Receiver", 
        .pattern = "[x-opencti-gnss-log:signal_to_noise_ratio < 'minimum_threshold']", .arttype = AT_NONE },
	{ .iob = "GNTM-3", .name = "GNSS Signal Outage Detected",
        .pattern = "[x-opencti-gnss-log:signal_status = 'lost' AND x-opencti-gnss-log:duration > 'outage_threshold']", .arttype = AT_NONE },
	{ .iob = "GNTM-4", .name = "GNSS Receiver Power Fluctuations", 
        .pattern = "[x-opencti-gnss-log:power_fluctuation > 'threshold']", .arttype = AT_NONE },
	{ .iob = "GNTM-5", .name = "Time Discrepancy Detected in GPS/External Signal Input", 
        .pattern = "[x-opencti-sensor-data:sensor_type = 'gps_time' AND x-opencti-sensor-data:timestamp != 'expected_timestamp' AND x-opencti-time:delta_value != 'expected_delta_value']", .arttype = AT_NONE },
	{ .iob = "GNTM-6", .name = "Unexpected Time Delta Detected", 
        .pattern = "[x-opencti-system:component = 'time_controller' AND x-opencti-time:delta_value != 'expected_delta_value']", .arttype = AT_NONE },
	{ .iob = "GNTM-7", .name = "Time Adjustment Commands Detected", 
        .pattern = "[x-opencti-system:component = 'time_controller' AND x-opencti-command:command = 'adjust_time' AND x-opencti-command:execution_count > 'threshold']", .arttype = AT_COMMAND },
	{ .iob = "GNTM-8", .name = "Anomalous Hardware Clock Behavior", 
        .pattern = "[x-opencti-hardware-log:clock_speed != 'expected_speed']", .arttype = AT_NONE },
	{ .iob = "GNTM-9", .name = "Anomalous GNSS Timing Behavior (Time Rewind Detected)", 
        .pattern = "[x-opencti-gnss:delta_time < 0]", .arttype = AT_NONE },
	{ .iob = "GNTM-10", .name = "Anomalous Sensor Data (Time Rewind Detected)", 
        .pattern = "[x-opencti-sensor-data:sensor_type = 'gps_time' AND x-opencti-sensor-data:rewind_detected = true]", .arttype = AT_NONE },
	{ .iob = "GNTM-11", .name = "Unexpected Position Delta Detected via Anomalous GNSS Position Data", 
        .pattern = "[x-opencti-gnss:delta_position > 'expected_delta_value']", .arttype = AT_NONE },
	{ .iob = "GNTM-12", .name = "ICD Field Non-Compliance Detected", 
        .pattern = "[x-opencti-gnss:icd_field_value < 'MIN_LIMIT'] OR [x-opencti-gnss:icd_field_value > 'MAX_LIMIT']", .arttype = AT_NONE },

	/*=======================================================================================
	** MIRE - Memory Integrity and Resource Exhaustion
	** 
	** Detects memory corruption and resource exhaustion attacks including:
	** - Flash/EEPROM tampering
	** - Boot memory attacks
	** - Memory corruption
	** - Resource exhaustion
	**=======================================================================================*/
	
	{ .iob = "MIRE-1", .name = "Anomalous Flash Write Operations Detected in Short Timeframe", 
        .pattern = "[x-opencti-memory:block = 'flash_memory' AND x-opencti-memory:write_operation_count > 'threshold' AND x-opencti-memory:write_duration < 'threshold']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-2", .name = "Anomalous Flash/EEPROM Memory Checksums Detected", 
        .pattern = "[x-opencti-memory:table_ref.name = 'flash_memory' OR x-opencti-memory:table_ref.name = 'eeprom_memory' AND x-opencti-memory:checksum != 'expected_checksum']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-3", .name = "Unusual Access Frequency to Critical Memory Regions", 
        .pattern = "[x-opencti-memory:access_frequency > 'expected_rate' AND x-opencti-memory:memory_region != 'expected']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-4", .name = "Skipped Boot Integrity Check", 
        .pattern = "[x-opencti-memory:block = 'boot' AND x-opencti-memory:integrity_check = 'skipped']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-5", .name = "Memory Corruption Detected in Flight Software", 
        .pattern = "[x-opencti-memory:status = 'corrupted' AND x-opencti-software:component = 'flight_software']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-6", .name = "Unexpected Modification of Memory Location Associated with Telemetry Data", 
        .pattern = "[x-opencti-memory:block = 'telemetry_memory_block' AND x-opencti-memory:write_operation = 'unexpected' AND x-opencti-memory:modification_time != 'authorized_time']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-7", .name = "Unexpected Memory Value Write or Modification", 
        .pattern = "[x-opencti-memory:write_operation = 'unexpected_write' AND x-opencti-memory:value != 'expected']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-8", .name = "Resource Exhaustion Due to Handling Invalid Inputs", 
        .pattern = "[x-opencti-system-log:memory_usage > 'threshold' AND x-opencti-system-log:cpu_usage > 'threshold' AND x-opencti-error-log:error_type = 'invalid_input_handling' AND x-opencti-system-log:event_count > 'threshold']", .arttype = AT_NONE },
	{ .iob = "MIRE-9", .name = "Failed Boot Memory Validation", 
        .pattern = "[x-opencti-system:boot_memory_validation = 'failed']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-10", .name = "Anomalous Boot Sequence Execution", 
        .pattern = "[x-opencti-system:boot_sequence = 'unexpected']", .arttype = AT_NONE },
	{ .iob = "MIRE-11", .name = "Detection of Malicious Code in Boot Memory (Integrity Failure)", 
        .pattern = "[x-opencti-memory:block = 'boot' AND x-opencti-memory:integrity_check = 'failed']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-12", .name = "Unexpected Modification to Encryption Memory/Table", 
        .pattern = "[x-opencti-memory:table_ref.name = 'encryption_table' AND x-opencti-memory:checksum != 'expected_checksum' AND x-opencti-memory:range = 'Value1 - Value999']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-13", .name = "Unexpected Modification to Stored Commands Area", 
        .pattern = "[x-opencti-memory:table_ref.name = 'stored_command_area' AND x-opencti-memory:write_operation = 'unexpected_write' AND x-opencti-memory:timestamp != 'expected_update_time']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-14", .name = "Abnormal Memory Consumption by Malicious Process", 
        .pattern = "[process:x_memory_usage > 'threshold' AND process:image_ref.name != 'authorized_process']", .arttype = AT_PROGRAM },
	{ .iob = "MIRE-15", .name = "Unexpected Modification of Memory Location Associated with Payload Data", 
        .pattern = "[x-opencti-memory:block = 'payload_memory_block' AND x-opencti-memory:write_operation = 'unexpected']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-16", .name = "Unexpected Boot Memory Modifications", 
        .pattern = "[x-opencti-memory:block = 'boot' AND x-opencti-memory-log:block = 'boot' AND x-opencti-memory-log:status != 'expected']", .arttype = AT_MEMORY },
	{ .iob = "MIRE-17", .name = "Unauthorized System Call to Open Flash Memory Blocks (/dev/mtd)", 
        .pattern = "[process:image_ref.name = 'open' AND file:path LIKE '/dev/mtd%' AND file:access_time != 'authorized_access_time']", .arttype = AT_FILE },
	{ .iob = "MIRE-18", .name = "Bit Flip in Critical Memory Region Detected via Error Detection", 
        .pattern = "[x-opencti-memory-log:error_detection_status = 'failed' AND x-opencti-memory-log:memory_region IN ('critical_region_1','critical_region_2')]", .arttype = AT_MEMORY },

	/*=======================================================================================
	** WTRE - Watchdog Timer and Register Exploitation
	** 
	** Detects watchdog and register manipulation attacks including:
	** - Watchdog timer tampering
	** - Register access violations
	** - Timing manipulation
	**=======================================================================================*/
	
	{ .iob = "WTRE-1", .name = "Reduced Watchdog Timer Reset Frequency", 
        .pattern = "[x-opencti-watchdog:reset_frequency < 'minimum_threshold']", .arttype = AT_NONE },
	{ .iob = "WTRE-2", .name = "Abnormal Frequency of Watchdog Timer Resets", 
        .pattern = "[x-opencti-watchdog:reset_frequency > 'expected_threshold']", .arttype = AT_NONE },
	{ .iob = "WTRE-3", .name = "Watchdog Timer Status Disabled", 
        .pattern = "[x-opencti-watchdog:status = 'disabled']", .arttype = AT_NONE },
	{ .iob = "WTRE-4", .name = "Watchdog Timer Timeout Modified to Unexpected Value", 
        .pattern = "[x-opencti-watchdog:timeout != 'baseline_value']", .arttype = AT_NONE },
	{ .iob = "WTRE-5", .name = "Unauthorized Access Attempt to Critical Registers", 
        .pattern = "[x-opencti-register:access_origin != 'trusted_source' AND x-opencti-register:region = 'critical_subsystem']", .arttype = AT_NONE },
	{ .iob = "WTRE-6", .name = "Unexpected Register Reset Activity", 
        .pattern = "[x-opencti-register:reset_status = 'unexpected']", .arttype = AT_NONE },
	{ .iob = "WTRE-7", .name = "Anomalous Register Value Modification", 
        .pattern = "[x-opencti-register:value != 'expected_value' AND x-opencti-register:region = 'critical_subsystem']", .arttype = AT_NONE },

	/*=======================================================================================
	** SIUU - Software Integrity and Unauthorized Updates
	** 
	** Detects software integrity violations and unauthorized updates including:
	** - Malicious code injection
	** - Unauthorized software updates
	** - Process manipulation
	** - Firmware tampering
	**=======================================================================================*/
	
	{ .iob = "SIUU-1", .name = "Unexpected Hardware Interrupt Trigger", 
        .pattern = "[x-opencti-hardware-interrupt:triggered = true AND x-opencti-hardware-interrupt:source != 'authorized_source']", .arttype = AT_NONE },
	{ .iob = "SIUU-2", .name = "Unexpected System Integrity Failures in Software", 
        .pattern = "[x-opencti-software:integrity_check = 'failed' AND x-opencti-software:name = 'spacecraft_software']", .arttype = AT_FILE },
	{ .iob = "SIUU-3", .name = "Security Feature Bypass Detected in Hardware Design", 
        .pattern = "[x-opencti-hardware:security_feature_status != 'enabled']", .arttype = AT_NONE },
	{ .iob = "SIUU-4", .name = "Abnormal Software Update Activity Detected", 
        .pattern = "[x-opencti-update-log:source != 'trusted_source' AND x-opencti-update-log:software_component = 'critical_subsystem']", .arttype = AT_FILE },
	{ .iob = "SIUU-5", .name = "Unscheduled Software Updates Detected", 
        .pattern = "[x-opencti-software-update:scheduled = 'false' AND x-opencti-software:name = 'spacecraft_software']", .arttype = AT_FILE },
	{ .iob = "SIUU-6", .name = "Compromised Software Certificates or Digital Signatures", 
        .pattern = "[x-opencti-software:certificate_validity = 'failed' OR x-opencti-software:signature != 'expected_signature']", .arttype = AT_FILE },
	{ .iob = "SIUU-7", .name = "Invalid Digital Signature in On-Orbit Update Package", 
        .pattern = "[x-opencti-software:signature_validity = 'invalid' AND x-opencti-software:name = 'on_orbit_update_package']", .arttype = AT_FILE },
	{ .iob = "SIUU-8", .name = "Malicious Code via New Process", 
        .pattern = "[x-opencti-logs:event_type = 'code_execution' AND x-opencti-processor-usage:activity_type = 'unexpected' AND x-opencti-processor-usage:process_name NOT IN ('list_of_known_processes')]", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-9", .name = "Unexpected Software Crash Detected in Flight Software", 
        .pattern = "[x-opencti-software:status = 'crashed' AND x-opencti-software:component != 'expected_crash_behavior']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-10", .name = "Process Executing Priority Modification", 
        .pattern = "[process:image_ref.name = 'renice' OR process:image_ref.name = 'setpriority' AND process:x_execution_time != 'authorized_period']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-11", .name = "Suspicious Binary or Script Execution", 
        .pattern = "[process:image_ref.name != 'expected_binary_or_script']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-12", .name = "Loading of Malicious Kernel Modules", 
        .pattern = "[process:image_ref.name = 'insmod' OR syscall:name = 'INIT_MODULE']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-13", .name = "Repeated File Access to /null and Other Dummy Files", 
        .pattern = "[file:path = '/dev/null' OR file:path = '/null' AND file:access_time != 'expected_time']", .arttype = AT_NONE },
	{ .iob = "SIUU-14", .name = "Abnormal System Calls Indicative of a Software Backdoor/Malicious Code", 
        .pattern = "[process:image_ref.name = 'unexpected_process' AND process:system_call = 'unexpected_system_call']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-15", .name = "Repeated File Access to /zero or /null Devices", 
        .pattern = "[file:path = '/dev/null' OR file:path = '/dev/zero' AND file:access_time != 'expected_time']", .arttype = AT_NONE },
	{ .iob = "SIUU-16", .name = "Execution of System Commands", 
        .pattern = "[process:image_ref.name = 'grep' OR process:image_ref.name = 'ps' OR process:image_ref.name = 'awk' OR process:image_ref.name = 'chmod' OR process:image_ref.name = 'dd' OR process:image_ref.name = 'cat' OR process:image_ref.name = 'sh' AND process:x_execution_time != 'authorized_time']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-17", .name = "Detection of Anomalous API Calls in Flight Software", 
        .pattern = "[x-opencti-api-log:api_call != 'expected_behavior']", .arttype = AT_NONE },
	{ .iob = "SIUU-18", .name = "Suspicious Activity in Software Compilation or Build Process", 
        .pattern = "[x-opencti-build-log:process = 'compilation' AND x-opencti-build-log:result != 'expected']", .arttype = AT_NONE },
	{ .iob = "SIUU-19", .name = "Unauthorized Modification of Source Code in Software Repository", 
        .pattern = "[x-opencti-code-repository:commit_author != 'trusted_contributor' AND x-opencti-code-repository:code_change != 'expected']", .arttype = AT_FILE },
	{ .iob = "SIUU-20", .name = "Suspicious Access to Vulnerable Software Process", 
        .pattern = "[process:binary_ref.type = 'software' AND process:parent_ref.name NOT IN ('authorized_parents') AND process:binary_ref.version = 'known_vulnerable_version']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-21", .name = "Detection of Anomalous Process Behavior Due to Code Exploitation", 
        .pattern = "[x-opencti-process:behavior != 'expected_behavior' AND x-opencti-process:software_component != 'trusted_component']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-22", .name = "Abnormal Subsystem Behavior Following Malicious Code Execution", 
        .pattern = "[x-opencti-subsystem-log:status != 'expected' AND process:image_ref.name = 'malicious_process']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-23", .name = "Detection of Unauthorized Hardware Debugging", 
        .pattern = "[x-opencti-hardware-log:debug_mode = true AND x-opencti-hardware-log:activation_time != 'expected_time']", .arttype = AT_NONE },
	{ .iob = "SIUU-24", .name = "Suspicious Firmware Version Rollback", 
        .pattern = "[x-opencti-firmware-log:version != 'latest_version' AND x-opencti-firmware-log:rollback_attempt = true]", .arttype = AT_FILE },
	{ .iob = "SIUU-25", .name = "Unauthorized Function Hooking in Telemetry Process", 
        .pattern = "[process:image_ref.name = 'telemetry_process' AND process:hooked_function = 'packet_write_function']", .arttype = AT_PROGRAM },
	{ .iob = "SIUU-26", .name = "Unauthorized Modification of Downlink Configuration", 
        .pattern = "[x-opencti-radio-configuration:downlink_frequency != 'authorized_value' AND x-opencti-radio-configuration:modification_time != 'scheduled_window']", .arttype = AT_CONFIG },

	/*=======================================================================================
	** SMSR - Sensor Manipulation and System Resource Attacks
	** 
	** Detects sensor spoofing and resource exhaustion attacks including:
	** - Sensor data manipulation
	** - CPU/memory exhaustion
	** - ADCS tampering
	** - System resource attacks
	**=======================================================================================*/
	
	{ .iob = "SMSR-1", .name = "Sensor Data Exceeds Operational Ranges", 
        .pattern = "[x-opencti-sensor-data:value NOT  IN ('expected_min','expected_max')]", .arttype = AT_NONE },
	{ .iob = "SMSR-2", .name = "High CPU Utilization Due to Anomalous/Malicious Activity", 
        .pattern = "[x-opencti-processor-usage:cpu_load > 'threshold' AND x-opencti-processor-usage:activity_type = 'unexpected' AND x-opencti-processor-usage:process_name NOT IN ('list_of_known_processes')]", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-3", .name = "Unauthorized State Changes in Critical Sensors", 
        .pattern = "[x-opencti-sensor:state = 'off' AND x-opencti-sensor:state_change_time != 'authorized_time']", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-4", .name = "ADCS Onboard Values Manipulation", 
        .pattern = "[x-opencti-telemetry-data:telemetry_type = 'attitude-control' AND x-opencti-telemetry-data:parameter_name IN ('quaternion','gyro_reading','magnetometer_value') AND x-opencti-telemetry-data:value_change > 'threshold_value' AND x-opencti-telemetry-data:change_rate > 'expected_rate']", .arttype = AT_NONE },
	{ .iob = "SMSR-5", .name = "Unexpected Spacecraft Telemetry or Movement Detected on Attitude", 
        .pattern = "[x-opencti-telemetry:movement_type = 'orbit-deviation' AND x-opencti-telemetry:deviation_value > 'threshold_value']", .arttype = AT_NONE },
	{ .iob = "SMSR-6", .name = "Unauthorized Fault Management Configuration Change Detected Outside Expected Time", 
        .pattern = "[x-opencti-fault-management:configuration != 'baseline_configuration' AND x-opencti-fault-management:modification_time != 'authorized_time_window']", .arttype = AT_CONFIG },
	{ .iob = "SMSR-7", .name = "Unauthorized Star Map Changes in Star Trackers", 
        .pattern = "[x-opencti-onboard-data:component = 'star_tracker' AND x-opencti-onboard-data:data_type = 'star_map' AND x-opencti-onboard-data:hashes != 'expected_star_map_hash']", .arttype = AT_FILE },
	{ .iob = "SMSR-8", .name = "Sudden Orbit Correction Detected Outside of Planned Windows", 
        .pattern = "[x-opencti-orbit-adjustment:status = 'active' AND x-opencti-orbit-adjustment:scheduled != 'TRUE']", .arttype = AT_NONE },
	{ .iob = "SMSR-9", .name = "Security Feature Disabled in Safe-Mode", 
        .pattern = "[x-opencti-spacecraft-status:mode = 'safe-mode' AND x-opencti-security-feature:status = 'disabled']", .arttype = AT_NONE },
	{ .iob = "SMSR-10", .name = "Ransomware Holding CPU Cycles Hostage", 
        .pattern = "[process:x_cpu_usage > 'high_threshold' AND process:image_ref.name = 'ransomware_process' AND process:x_status = 'running' AND process:x_memory_usage > 'threshold' AND process:x_termination_attempt = 'failed']", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-11", .name = "High CPU Usage Detected for Unauthorized Process", 
        .pattern = "[process:x_cpu_usage > 'threshold' AND process:image_ref.name != 'authorized_process']", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-12", .name = "Microwave Emissions Targeting Sensitive Nodes", 
        .pattern = "[x-opencti-rf-sensor:frequency_band = 'microwave_band' AND x-opencti-rf-sensor:signal_power > 'safe_threshold']", .arttype = AT_NONE },
	{ .iob = "SMSR-13", .name = "High Energy Particle Strike on Sensitive Node", 
        .pattern = "[x-opencti-radiation-sensor:energy_level > 'threshold' AND x-opencti-radiation-sensor:node_location = 'critical_component']", .arttype = AT_NONE },
	{ .iob = "SMSR-14", .name = "Multiple Failed System Reinitializations Due to Exploit", 
        .pattern = "[x-opencti-system:status = 'reinitialization' AND x-opencti-system:failure_count > 'threshold']", .arttype = AT_NONE },
	{ .iob = "SMSR-15", .name = "Unexpected Changes to Software-Defined Radio (SDR) Configuration", 
        .pattern = "[x-opencti-sdr-configuration:value != 'expected_value' AND x-opencti-sdr-configuration:name = 'radio_settings']", .arttype = AT_CONFIG },
	{ .iob = "SMSR-16", .name = "Unexpected Fault Management Process Termination", 
        .pattern = "[process:name = 'fault_management_service' AND process:status != 'running']", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-17", .name = "Telemetry Packet Drops Due to CPU or Memory Overload", 
        .pattern = "[x-opencti-telemetry:packet_drop_rate > 'threshold' AND x-opencti-system:cpu_usage > 'threshold']", .arttype = AT_NONE },
	{ .iob = "SMSR-18", .name = "Abnormal Process Forking Leading to Resource Exhaustion", 
        .pattern = "[process:image_ref.name != 'authorized_process' AND process:x_fork_count > 'threshold' AND process:x_cpu_usage > 'threshold' AND process:x_memory_usage > 'threshold']", .arttype = AT_PROGRAM },
	{ .iob = "SMSR-19", .name = "System Freeze or Crash Detected After High Resource Consumption (CPU, Memory, Storage)", 
        .pattern = "[x-opencti-system:status = 'unresponsive' AND x-opencti-system:memory_usage > 'threshold' AND x-opencti-system:cpu_usage > 'threshold' AND x-opencti-file-system:available_space < 'threshold']", .arttype = AT_NONE },

	/*=======================================================================================
	** DISE - Data Integrity and Storage Exploitation
	** 
	** Detects data integrity violations and storage attacks including:
	** - File tampering
	** - Storage exhaustion
	** - Sensor data manipulation
	** - Log tampering
	**=======================================================================================*/
	
	{ .iob = "DISE-1", .name = "File or Data Integrity Check Failure", 
        .pattern = "[file:hashes != 'expected_hash_value' AND file:name = 'data_file']", .arttype = AT_FILE },
	{ .iob = "DISE-2", .name = "Unauthorized Modification of On-Orbit Update Binary", 
        .pattern = "[file:hashes != 'expected_hash_value' AND file:name = 'on_orbit_update_binary']", .arttype = AT_FILE },
	{ .iob = "DISE-3", .name = "Multiple Failed Attempts to Access Encrypted Data", 
        .pattern = "[file:status = 'unreadable' AND file:access_attempts > 'threshold']", .arttype = AT_FILE },
	{ .iob = "DISE-4", .name = "Storage Exhaustion (Disk Full)", 
        .pattern = "[x-opencti-file-system:available_space < 'threshold']", .arttype = AT_NONE },
	{ .iob = "DISE-5", .name = "Unusual File Encryption Activity Detected", 
        .pattern = "[file:x_encryption_algorithm != 'none' AND file:modified_time = 'recent']", .arttype = AT_FILE },
	{ .iob = "DISE-6", .name = "Suspicious Activity Leading to Storage Exhaustion", 
        .pattern = "[x-opencti-file-system:available_space < 'threshold' AND process:x_execution_time != 'authorized_time']", .arttype = AT_PROGRAM },
	{ .iob = "DISE-7", .name = "Attitude Sensor Data and Actuator Behavior", 
        .pattern = "[x-opencti-sensor-data:sensor_type = 'inertial-measurement-unit' AND x-opencti-sensor-data:anomaly_value > 'threshold_value']AND[x-opencti-actuator:actuator_type IN ('thruster','reaction-wheel') AND x-opencti-actuator:operation_status = 'unexpected']", .arttype = AT_NONE },
	{ .iob = "DISE-8", .name = "Anomalous Frequency of Sensor Data Updates", 
        .pattern = "[x-opencti-sensor-data:update_frequency != 'baseline_frequency']", .arttype = AT_NONE },
	{ .iob = "DISE-9", .name = "Unexpected Change in Gyroscope Sensor Data", 
        .pattern = "[x-opencti-sensor-data:sensor_type = 'gyroscope' AND x-opencti-sensor-data:reading_delta > 'threshold']", .arttype = AT_NONE },
	{ .iob = "DISE-10", .name = "Abnormal Data Flow in Attitude Control Telemetry", 
        .pattern = "[x-opencti-telemetry:telemetry_type = 'attitude_control' AND x-opencti-telemetry:data_rate > 'expected_rate']", .arttype = AT_NONE },
	{ .iob = "DISE-11", .name = "Sensor Data Spike Detected", 
        .pattern = "[x-opencti-sensor-data:reading_delta > 'acceptable_threshold']", .arttype = AT_NONE },
	{ .iob = "DISE-12", .name = "Discrepancy Between Redundant Sensor Systems", 
        .pattern = "[x-opencti-sensor-data:value != 'redundant_value']", .arttype = AT_NONE },
	{ .iob = "DISE-13", .name = "Flight Software Configuration Anomalies", 
        .pattern = "[x-opencti-system:configuration = 'unexpected' AND x-opencti-system:subsystem = 'flight_software']", .arttype = AT_CONFIG },
	{ .iob = "DISE-14", .name = "Unexpected Audit Log Rotation", 
        .pattern = "[x-opencti-audit-log:rotation_event = 'triggered' AND x-opencti-audit-log:timestamp != 'expected_time']", .arttype = AT_FILE },
	{ .iob = "DISE-15", .name = "High Volume of Audit Log Entries Detected", 
        .pattern = "[x-opencti-audit-log:event_count > 'threshold' AND x-opencti-audit-log:timestamp = 'recent_period']", .arttype = AT_NONE },
	{ .iob = "DISE-16", .name = "Audit Log Capacity Limit Reached", 
        .pattern = "[x-opencti-audit-log:capacity_used >= 'max_capacity']", .arttype = AT_FILE },
	{ .iob = "DISE-17", .name = "Unauthorized Modification of Critical Onboard Values", 
        .pattern = "[x-opencti-data-element:modification_detected = true AND x-opencti-data-element:modification_source != 'trusted_source']", .arttype = AT_NONE }
};

/*=======================================================================================
** Function Implementations
**=======================================================================================*/

/**
 * @brief Find IOB entry by identifier string
 * 
 * Searches the IOB database for an entry matching the specified IOB identifier.
 * Performs linear search through the iobs[] array.
 * 
 * **Search Algorithm:**
 * - Linear search through iobs[] array
 * - String comparison using strncmp()
 * - Returns pointer to first match
 * - Returns NULL if not found
 * 
 * **Performance:**
 * - O(n) time complexity where n = IOB_ARRAY_SIZE
 * - Average case: ~97 comparisons (193 IOBs / 2)
 * - Worst case: 193 comparisons
 * - Typical execution: <10 microseconds on space-grade CPU
 * 
 * **Usage Examples:**
 * @code
 * // Look up specific IOB
 * const IOBCTI *iob = FindIoB("UACE-1");
 * if (iob != NULL) {
 *     printf("Found: %s\n", iob->name);
 *     evaluate_pattern(iob->pattern);
 * } else {
 *     printf("IOB not found\n");
 * }
 * 
 * // Use in rule evaluation
 * void evaluate_rule(Rule *rule) {
 *     const IOBCTI *iob = FindIoB(rule->iob_id);
 *     if (iob != NULL) {
 *         if (matches_pattern(iob->pattern, system_state)) {
 *             generate_alert(iob);
 *         }
 *     }
 * }
 * 
 * // Validate IOB reference
 * bool validate_rule_table(RuleTable *table) {
 *     for (int i = 0; i < table->num_rules; i++) {
 *         if (FindIoB(table->rules[i].iob_id) == NULL) {
 *             CFE_EVS_SendEvent(ERR_EID, CFE_EVS_ERROR,
 *                              "Invalid IOB reference: %s",
 *                              table->rules[i].iob_id);
 *             return false;
 *         }
 *     }
 *     return true;
 * }
 * @endcode
 * 
 * **Optimization Opportunities:**
 * For improved performance with large IOB databases:
 * - Hash table: O(1) average lookup
 * - Binary search: O(log n) if array sorted
 * - Caching: Store frequently used IOBs
 * - Indexing: Separate arrays per category
 * 
 * @param[in] iob_id IOB identifier string to search for (e.g., "UACE-1")
 * 
 * @return Pointer to matching IOBCTI structure if found
 * @return NULL if IOB identifier not found in database
 * 
 * @pre iob_id must be null-terminated string
 * @pre iob_id length must be <= IOB_ID_SZ
 * @post Return value is const (cannot modify IOB data)
 * 
 * @note Comparison is case-sensitive
 * @note Only compares first IOB_ID_SZ characters
 * @note Returned pointer is const - IOB data cannot be modified
 * @note Thread-safe (read-only operation on const data)
 * 
 * @warning Do not free returned pointer (points to static data)
 * @warning Null pointer must be checked before dereferencing
 * 
 * @see IOBCTI for IOB structure definition
 * @see IOB_ARRAY_SIZE for database size
 * @see IOB_ID_SZ for maximum identifier length
 */
const IOBCTI *FindIoB(char *iob_id)
{
	for (uint32_t i = 0; i < IOB_ARRAY_SIZE; i++)
	{
		if (strncmp(iobs[i].iob, iob_id, IOB_ID_SZ) == 0)
			return &iobs[i];
	}
	return NULL;
}