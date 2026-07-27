# Auto-generated CCSDS/COSMOS Packet Analyzer for Zeek
# Generated from COSMOS command and telemetry definitions
# UDP Port 5012: Commands
# UDP Port 5013: Telemetry

@load base/protocols/conn

module CCSDS;

export {
    redef enum Log::ID += { COMMAND_LOG, TELEMETRY_LOG };
    
    # Command packet record
    type CommandInfo: record {
        ts: time &log;
        uid: string &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        
        # CCSDS Header
        stream_id: count &log &optional;
        stream_id_hex: string &log &optional;
        apid: count &log &optional;
        sequence_flags: count &log &optional;
        packet_sequence: count &log &optional;
        data_length: count &log &optional;
        
        # Command-specific
        function_code: count &log &optional;
        checksum: count &log &optional;
        
        # Decoded info
        target: string &log &optional;
        command_name: string &log &optional;
        command_desc: string &log &optional;
        
        # Raw data
        raw_hex: string &log &optional;
        packet_length: count &log;
        
        # Validation
        valid: bool &log &default=F;
        error: string &log &optional;
    };
    
    # Telemetry packet record
    type TelemetryInfo: record {
        ts: time &log;
        uid: string &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        
        # CCSDS Header
        stream_id: count &log &optional;
        stream_id_hex: string &log &optional;
        apid: count &log &optional;
        sequence_flags: count &log &optional;
        packet_sequence: count &log &optional;
        data_length: count &log &optional;
        
        # Decoded info
        target: string &log &optional;
        packet_name: string &log &optional;
        packet_desc: string &log &optional;
        
        # Raw data
        raw_hex: string &log &optional;
        packet_length: count &log;
        
        # Validation
        valid: bool &log &default=F;
        error: string &log &optional;
    };
    
    # Port definitions - UDP only
    const COMMAND_PORT = 5012/udp &redef;
    const TELEMETRY_PORT = 5013/udp &redef;
}

event zeek_init()
    {
    Log::create_stream(COMMAND_LOG, [$columns=CommandInfo, $path="ccsds_commands"]);
    Log::create_stream(TELEMETRY_LOG, [$columns=TelemetryInfo, $path="ccsds_telemetry"]);
    }

# Command lookup table: "stream_id_function_code" -> [target, name, description]
const command_table: table[string] of vector of string = {
    ["6145_0"] = ["CFE", "CFE_EVS_NO_OPERATION", "This command performs no other function than to increment the command execution counter. The command may be used to verify general aliveness of the Event Services task."],
    ["6145_1"] = ["CFE", "CFE_EVS_RESET_COUNTERS", "This command resets the following counters within the Event Services housekeeping telemetry:  Command Execution Counter ($sc_$cpu_EVS_CMDPC)Command Error Counter ($sc_$cpu_EVS_CMDEC) "],
    ["6145_2"] = ["CFE", "CFE_EVS_ENABLE_EVENT_TYPE", "This command enables the command specified Event Type allowing event messages of this type to be sent through Event Service. An Event Type is defined to be a classification of an Event Message such as debug, informational, error and critical. This command is a global enable of a particular event type, it applies to all applications."],
    ["6145_3"] = ["CFE", "CFE_EVS_DISABLE_EVENT_TYPE", "This command disables the command specified Event Type preventing event messages of this type to be sent through Event Service. An Event Type is defined to be a classification of an Event Message such as debug, informational, error and critical. This command is a global disable of a particular event type, it applies to all applications."],
    ["6145_4"] = ["CFE", "CFE_EVS_SET_EVENT_FORMAT_MODE", "This command sets the event format mode to the command specified value. The event format mode may be either short or long. A short event format detaches the Event Data from the event message and only includes the following information in the event packet: Processor ID, Application ID, Event ID, and Event Type. Refer to section 5.3.3.4 for a description of the Event Service event packet contents. Event Data is defined to be data describing an Event that is supplied to the cFE Event Service. ASCII text strings are used as the primary format for Event Data because heritage ground systems use string compares as the basis for their automated alert systems. Two systems, ANSR and SERS were looked at for interface definitions. The short event format is used to accommodate experiences with limited telemetry bandwidth. The long event format includes all event information included within the short format along with the Event Data."],
    ["6145_5"] = ["CFE", "CFE_EVS_ENABLE_APP_EVENT_TYPE", "This command enables the command specified event type for the command specified application, allowing the application to send event messages of the command specified event type through Event Service. An Event Type is defined to be a classification of an Event Message such as debug, informational, critical, and error. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_6"] = ["CFE", "CFE_EVS_DISABLE_APP_EVENT_TYPE", "This command disables the command specified event type for the command specified application, preventing the application from sending event messages of the command specified event type through Event Service. An Event Type is defined to be a classification of an Event Message such as debug, informational, critical, and error. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_7"] = ["CFE", "CFE_EVS_ENABLE_APP_EVENTS", "This command enables the command specified application to send events through the Event Service. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_8"] = ["CFE", "CFE_EVS_DISABLE_APP_EVENTS", "This command disables the command specified application from sending events through Event Service. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_9"] = ["CFE", "CFE_EVS_RESET_APP_COUNTER", "This command sets the command specified application's event counter to zero. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_10"] = ["CFE", "CFE_EVS_SET_FILTER", "This command sets the command specified application's event filter mask to the command specified value for the command specified event. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_11"] = ["CFE", "CFE_EVS_ENABLE_PORTS", "This command enables the command specified port to output event messages"],
    ["6145_12"] = ["CFE", "CFE_EVS_DISABLE_PORTS", "This command disables the specified port from outputting event messages."],
    ["6145_13"] = ["CFE", "CFE_EVS_RESET_FILTER", "This command resets the command specified application's event filter for the command specified event ID. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_14"] = ["CFE", "CFE_EVS_RESET_ALL_FILTERS", "This command resets all of the command specified applications event filters. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_15"] = ["CFE", "CFE_EVS_ADD_EVENT_FILTER", "This command adds the given filter for the given application identifier and event identifier. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_16"] = ["CFE", "CFE_EVS_DELETE_EVENT_FILTER", "This command removes the given filter for the given application identifier and event identifier. Note: In order for this command to take effect, applications must be registered for Event Service."],
    ["6145_17"] = ["CFE", "CFE_EVS_FILE_WRITE_APP_DATA", "This command writes all application data to a file for all applications that have registered with the EVS. The application data includes the Application ID, Active Flag, Event Count, Event Types Active Flag, and Filter Data."],
    ["6145_18"] = ["CFE", "CFE_EVS_FILE_WRITE_LOG_DATA", "This command requests the Event Service to generate a file containing the contents of the local event log."],
    ["6145_19"] = ["CFE", "CFE_EVS_SET_LOG_MODE", "This command sets the logging mode to the command specified value."],
    ["6145_20"] = ["CFE", "CFE_EVS_CLEAR_LOG", "This command clears the contents of the local event log."],
    ["6147_0"] = ["CFE", "CFE_SB_NOOP", "This command performs no other function than to increment the command execution counter. The command may be used to verify general aliveness of the Software Bus task."],
    ["6147_1"] = ["CFE", "CFE_SB_RESET_CTRS", "This command resets the following counters within the Software Bus housekeeping telemetry: Command Execution Counter ($sc_$cpu_SB_CMDPC)Command Error Counter ($sc_$cpu_SB_CMDEC)"],
    ["6147_2"] = ["CFE", "CFE_SB_SEND_SB_STATS", "This command will cause the SB task to send a statistics packet containing current utilization figures and high water marks which may be useful for checking the margin of the SB platform configuration settings."],
    ["6147_3"] = ["CFE", "CFE_SB_SEND_ROUTING_INFO", "This command will create a file containing the software bus routing information. The routing information contains information about every subscription that has been received through the SB subscription APIs. An abosulte path and filename may be specified in the command. If this command field contains an empty string (NULL terminator as the first character) the default file path and name is used. The default file path and name is defined in the platform configuration file as CFE_SB_DEFAULT_ROUTING_FILENAME."],
    ["6147_4"] = ["CFE", "CFE_SB_ENABLE_ROUTE", "This command will enable a particular destination. The destination is specified in terms of MsgID and PipeID. The MsgId and PipeID are parmaters in the command. All destinations are enabled by default. This command is needed only after a CFE_SB_DISABLE_ROUTE_CC command is used."],
    ["6147_5"] = ["CFE", "CFE_SB_DISABLE_ROUTE", "This command will disable a particular destination. The destination is specified in terms of MsgID and PipeID. The MsgId and PipeID are parmaters in the command. All destinations are enabled by default."],
    ["6147_7"] = ["CFE", "CFE_SB_SEND_PIPE_INFO", "This command will create a file containing the software bus pipe information. The pipe information contains information about every pipe that has been created through the CFE_SB_CreatePipe API. An abosulte path and filename may be specified in the command. If this command field contains an empty string (NULL terminator as the first character) the default file path and name is used. The default file path and name is defined in the platform configuration file as CFE_SB_DEFAULT_PIPE_FILENAME."],
    ["6147_8"] = ["CFE", "CFE_SB_SEND_MAP_INFO", "map information. The message map is a lookup table (an array of uint16s)that allows fast access to the correct routing table element during a softeware bus send operation. This is diasgnostic information that may be needed due to the dynamic nature of the cFE software bus. An abosulte path and filename may be specified in the command. If this command field contains an empty string (NULL terminator as the first character) the default file path and name is used. The default file path and name is defined in the platform configuration file as CFE_SB_DEFAULT_MAP_FILENAME."],
    ["6147_9"] = ["CFE", "CFE_SB_ENABLE_SUB_REPORTING", "be used only by the CFS SBN (Software Bus Networking) Application. It is not intended to be sent from the ground or used by operations. When subscription reporting is enabled, SB will generate and send a software bus packet for each subscription received. The software bus packet that is sent contains the information received in the subscription API. This subscription report is neeeded by SBN if offboard routing is required."],
    ["6147_10"] = ["CFE", "CFE_SB_DISABLE_SUB_REPORTING", "be used only by the CFS SBN (Software Bus Networking) Application. It is not intended to be sent from the ground or used by operations. When subscription reporting is enabled, SB will generate and send a software bus packet for each subscription received. The software bus packet that is sent contains the information received in the subscription API. This subscription report is neeeded by SBN if offboard routing is required."],
    ["6147_11"] = ["CFE", "CFE_SB_SEND_PREV_SUBS", "regarding all subscriptions previously received by SB. This command is intended to be used only by the CFS SBN(Software Bus Networking) Application. It is not intended to be sent from the ground or used by operations. When this command is received the software bus will generate and send a series of packets containing information about all subscription previously received."],
    ["6148_0"] = ["CFE", "CFE_TBL_NOOP", "This command performs no other function than to increment the command execution counter. The command may be used to verify general aliveness of the Table Services task."],
    ["6148_1"] = ["CFE", "CFE_TBL_RESET", "This command resets the following counters within the Table Services housekeeping telemetry: Command Execution Counter ($sc_$cpu_TBL_CMDPC)Command Error Counter ($sc_$cpu_TBL_CMDEC)Successful Table Validations Counter ($sc_$cpu_TBL_ValSuccessCtr)Failed Table Validations Counter ($sc_$cpu_TBL_ValFailedCtr)Number of Table Validations Requested ($sc_$cpu_TBL_ValReqCtr)"],
    ["6148_2"] = ["CFE", "CFE_TBL_LOAD", "This command loads the contents of the specified file into an inactive buffer for the table specified within the file."],
    ["6148_3"] = ["CFE", "CFE_TBL_DUMP", "This command will cause the Table Services to put the contents of the specified table buffer into the command specified file."],
    ["6148_4"] = ["CFE", "CFE_TBL_VALIDATE", "This command will cause Table Services to calculate the Data Integrity Value for the specified table and to notify the owning application that the table's validation function should be executed. The results of both the Data Integrity Value computation and the validation function are reported in Table Services Housekeeping Telemetry."],
    ["6148_5"] = ["CFE", "CFE_TBL_ACTIVATE", "This command will cause Table Services to notify a table's owner that an update is pending. The owning application will then update the contents of the active table buffer with the contents of the associated inactive table buffer at a time of their convenience."],
    ["6148_6"] = ["CFE", "CFE_TBL_DUMP_REG", "This command will cause Table Services to write some of the contents of the Table Registry to the command specified file. This allows the operator to see the current state and configuration of all tables that have been registered with the cFE."],
    ["6148_7"] = ["CFE", "CFE_TBL_TLM_REG", "This command will cause Table Services to telemeter the contents of the Table Registry for the command specified table."],
    ["6148_8"] = ["CFE", "CFE_TBL_DELETE_CDS", "This command will delete the Critical Data Store (CDS) associated with the specified Critical Table. Note that any table still present in the Table Registry is unable to be deleted from the Critical Data Store. All Applications that are accessing the critical table must release and unregister their access before the CDS can be deleted."],
    ["6148_9"] = ["CFE", "CFE_TBL_ABORT_LOAD", "This command will cause Table Services to discard the contents of a table buffer that was previously loaded with the data in a file as specified by a Table Load command. For single buffered tables, the allocated shared working buffer is freed and becomes available for other Table Load commands."],
    ["6149_0"] = ["CFE", "CFE_TIME_NOOP", "This command performs no other function than to increment the command execution counter. The command may be used to verify general aliveness of the Time Services task."],
    ["6149_1"] = ["CFE", "CFE_TIME_RESET", "This command resets the following counters within the Time Services Housekeeping Telemetry :  Command Execution Counter ($sc_$cpu_TIME_CMDPC)Command Error Counter ($sc_$cpu_TIME_CMDEC) This command also resets the following counters within the Time Services Diagnostic Telemetry :Tone Signal Detected Software Bus Message Counter ($sc_$cpu_TIME_DTSDetCNT)Time at the Tone Data Software Bus Message Counter ($sc_$cpu_TIME_DTatTCNT)Tone Signal/Data Verify Counter ($sc_$cpu_TIME_DVerifyCNT)Tone Signal/Data Error Counter ($sc_$cpu_TIME_DVerifyER)Tone Signal Interrupt Counter ($sc_$cpu_TIME_DTsISRCNT)Tone Signal Interrupt Error Counter ($sc_$cpu_TIME_DTsISRERR)Tone Signal Task Counter ($sc_$cpu_TIME_DTsTaskCNT)Local 1 Hz Interrupt Counter ($sc_$cpu_TIME_D1HzISRCNT)Local 1 Hz Task Counter ($sc_$cpu_TIME_D1HzTaskCNT)Reference Time Version Counter ($sc_$cpu_TIME_DVersionCNT) "],
    ["6149_2"] = ["CFE", "CFE_TIME_DIAG_TLM", "This command requests that the Time Service generate a message containing various data values not included in the normal Time Service housekeeping message. The command requests only a single copy of the diagnostic message. Refer to CFE_TIME_DiagPacket_t for a description of the Time Service diagnostic message contents."],
    ["6149_3"] = ["CFE", "CFE_TIME_SET_SOURCE", "This command selects the Time Service clock source. Although the list of potential clock sources is mission specific and defined via configuration parameters, this command provides a common method for switching between the local processor clock and an external source for time data. When commanded to accept external time data (GPS, MET, spacecraft time, etc.), the Time Server will enable input via an API function specific to the configuration definitions for the particular source. When commanded to use internal time data, the Time Server will ignore the external data. However, the Time Server will continue to use the API function as the trigger to generate a 'time at the tone' command packet regardless of the internal/external command selection. Notes: Operating in FLYWHEEL mode is not considered a choice related to clock source, but rather an element of the clock state. See below for a description of the CFE_TIME_SET_STATE_CC command.This command is only valid when the CFE_TIME_CFG_SOURCE configuration parameter in the cfe_platform_cfg.h file has been set to TRUE."],
    ["6149_4"] = ["CFE", "CFE_TIME_SET_STATE", "This command indirectly affects the Time Service on-board determination of clock state. Clock state is a combination of factors, most significantly whether the spacecraft time has been accurately set, and whether Time Service is operating in FLYWHEEL mode. This command may be used to notify the Time Server that spacecraft time is now correct, or that time is no longer correct. This information will be distributed to Time Clients, and in turn, to any interested sub-systems.  Also, this command may be used to force a Time Server or Time Client into FLYWHEEL mode. Use of FLYWHEEL mode is mainly for debug purposes although in extreme circumstances, it may be of value to force Time Service not to rely on normal time updates. Note that when commanded into FLYWHEEL mode, the Time Service will remain so until receipt of another 'set state' command setting the state into a mode other than FLYWHEEL. Note also that setting the clock state to VALID or INVALID on a Time Client that is currently getting time updates from the Time Server will have very limited effect. As soon as the Time Client receives the next time update, the VALID/INVALID selection will be set to that of the Time Server. However, setting a Time Client to FLYWHEEL cannot be overridden by the Time Server since the Time Client will ignore time updates from the Time Server while in FLYWHEEL mode."],
    ["6149_5"] = ["CFE", "CFE_TIME_ADD_DELAY", "This command is used to factor out a known, predictable latency between the Time Server and a particular Time Client. The correction is applied (added) to the current time calculation for Time Clients, so this command has no meaning for Time Servers. Each Time Client can have a unique latency setting. The latency value is a positive number of seconds and microseconds that represent the deviation from the time maintained by the Time Server."],
    ["6149_6"] = ["CFE", "CFE_TIME_SUB_DELAY", "This command is used to factor out a known, predictable latency between the Time Server and a particular Time Client. The correction is applied (subtracted) to the current time calculation for Time Clients, so this command has no meaning for Time Servers. Each Time Client can have a unique latency setting. The latency value is a positive number of seconds and microseconds that represent the deviation from the time maintained by the Time Server. Note that it is unimaginable that the seconds value will ever be anything but zero."],
    ["6149_7"] = ["CFE", "CFE_TIME_SET_TIME", "This command sets the spacecraft clock to a new value, regardless of the current setting (time jam). The new time value represents the desired offset from the mission-defined time epoch and takes effect immediately upon execution of this command. Time Service will calculate a new STCF value based on the current MET and the desired new time using one of the following: If Time Service is configured to compute current time as TAI. STCF = (new time) - (current MET)  (current time) = (current MET) + STCF. If Time Service is configured to compute current time as UTC STCF = ((new time) - (current MET)) + (Leap Seconds)  (current time) = ((curent MET) + STCF) - (Leap Seconds)."],
    ["6149_8"] = ["CFE", "CFE_TIME_SET_MET", "This command sets the Mission Elapsed Timer (MET) to the specified value. Note that the MET (as implemented for cFE Time Service) is a logical representation and not a physical timer. Thus, setting the MET is not dependent on whether the hardware supports a MET register that can be written to. Note also that Time Service 'assumes' that during normal operation, the MET is synchronized to the tone signal. Therefore, unless operating in FLYWHEEL mode, the sub-seconds portion of the MET will be set to zero at the next tone signal interrupt. The new MET takes effect immediately upon execution of this command."],
    ["6149_9"] = ["CFE", "CFE_TIME_SET_STCF", "This command sets the Spacecraft Time Correlation Factor (STCF) to the specified value. This command differs from the previously described SET CLOCK in the nature of the command argument. This command sets the STCF value directly, rather than extracting the STCF from a value representing the total of MET, STCF and optionally, Leap Seconds. The new STCF takes effect immediately upon execution of this command."],
    ["6149_10"] = ["CFE", "CFE_TIME_SET_LEAP_SECONDS", "This command sets the spacecraft Leap Seconds to the specified value. Leap Seconds may be positive or negative, and there is no limit to the value except, of course, the limit imposed by the 16 bit signed integer data type. The new Leap Seconds value takes effect immediately upon execution of this command."],
    ["6149_11"] = ["CFE", "CFE_TIME_ADD_ADJUST", "This command adjusts the Spacecraft Time Correlation Factor (STCF) by adding the specified value. The new STCF takes effect immediately upon execution of this command."],
    ["6149_12"] = ["CFE", "CFE_TIME_SUB_ADJUST", "This command adjusts the Spacecraft Time Correlation Factor (STCF) by subtracting the specified value. The new STCF takes effect immediately upon execution of this command."],
    ["6149_13"] = ["CFE", "CFE_TIME_ADD_1HZADJ", "This command has been updated to take actual sub-seconds (1/2^32 seconds) rather than micro-seconds as an input argument. This change occurred after the determination was made that one micro-second is too large an increment for a constant 1Hz adjustment. This command continuously adjusts the Spacecraft Time Correlation Factor (STCF) every second, by adding the specified value. The adjustment to the STCF is applied in the Time Service local 1Hz interrupt handler. As the local 1Hz interrupt is not synchronized to the tone signal, one cannot say when the adjustment will occur, other than once a second, at about the same time relative to the tone. There was some debate about whether the maximum 1Hz clock drift correction factor would ever need to exceed some small fraction of a second. But, the decision was made to provide the capability to make 1Hz adjustments greater than one second and leave it to the ground system to provide mission specific limits."],
    ["6149_14"] = ["CFE", "CFE_TIME_SUB_1HZADJ", "This command has been updated to take actual sub-seconds (1/2^32 seconds) rather than micro-seconds as an input argument. This change occurred after the determination was made that one micro-second is too large an increment for a constant 1Hz adjustment. This command continuously adjusts the Spacecraft Time Correlation Factor (STCF) every second, by subtracting the specified value. The adjustment to the STCF is applied in the Time Service local 1Hz interrupt handler. As the local 1Hz interrupt is not synchronized to the tone signal, one cannot say when the adjustment will occur, other than once a second, at about the same time relative to the tone.There was some debate about whether the maximum 1Hz clock drift correction factor would ever need to exceed some small fraction of a second. But, the decision was made to provide the capability to make 1Hz adjustments greater than one second and leave it to the ground system to provide mission specific limits."],
    ["6149_15"] = ["CFE", "CFE_TIME_SET_SIGNAL", "This command selects the Time Service tone signal source. Although the list of potential tone signal sources is mission specific, a common choice is the selection of primary or redundant tone signal. The selection may be available to both the Time Server and Time Clients, depending on hardware configuration. Notes: This command is only valid when the CFE_TIME_CFG_SIGNAL configuration parameter in the cfe_platform_cfg.h file has been set to TRUE. "],
    ["6157_0"] = ["CFE", "CFE_TIME_SEND_HK", "Request cFS TIME HK Packet"],
    ["6234_0"] = ["CFDP", "NOOP", "Generate an info event message with app version"],
    ["6234_1"] = ["CFDP", "RESET_CTRS", "Resets HK TLM parent and child task counters"],
    ["6234_29"] = ["CFDP", "DOWNLOAD_FROM_SATELLITE_CC", "Download file from Satellite"],
    ["6234_30"] = ["CFDP", "UPLOAD_TO_SATELLITE_CC", "Upload file to Satellite"],
    ["6234_31"] = ["CFDP", "UPLOAD_TO_SATELLITE_DATA", "Upload data to Satellite"],
    ["6280_0"] = ["MM", "MM_NOOP", "Implements the Noop command that insures the MM task is alive"],
    ["6280_1"] = ["MM", "MM_RESET", "Resets the MM housekeeping counters"],
    ["6280_2"] = ["MM", "MM_PEEK", "Reads 8,16, or 32 bits of data from any given input address"],
    ["6280_3"] = ["MM", "MM_POKE", "Writes 8, 16, or 32 bits of data to any memory address"],
    ["6280_4"] = ["MM", "MM_LOAD_MEM_WID", "Reprogram processor memory with input data. Loads up to MM_MAX_UNINTERRUPTABLE_DATA data bytes into RAM with interrupts disabled"],
    ["6280_5"] = ["MM", "MM_LOAD_MEM_FROM_FILE", "Reprograms processor memory with the data contained within the given input file"],
    ["6280_6"] = ["MM", "MM_DUMP_MEM_TO_FILE", "Dumps the input number of bytes from processor memory to a file"],
    ["6280_7"] = ["MM", "MM_DUMP_IN_EVENT", "Dumps up to MM_MAX_DUMP_INEVENT_BYTES of memory in an event message"],
    ["6280_8"] = ["MM", "MM_FILL_MEM", "Reprograms processor memory with the fill pattern contained within the command message"],
    ["6280_9"] = ["MM", "MM_LOOKUP_SYM", "Queries the system symbol table and reports the resolved address in telemetry and an informational event message"],
    ["6280_10"] = ["MM", "MM_SYMTBL_TO_FILE", "Saves the system symbol table to a file that can be transfered to the ground"],
    ["6280_11"] = ["MM", "MM_ENABLE_EEPROM_WRITE", "Enables writing to a specified EEPROM bank"],
    ["6280_12"] = ["MM", "MM_DISABLE_EEPROM_WRITE", "Disables writing to a specified EEPROM bank"],
    ["6284_0"] = ["FM", "FM_NOOP", "This command performs no operation other than to generate an informational event that also contains software version data. The command is most often used as a general aliveness test by demonstrating that the application can receive commands and generate telemetry."],
    ["6284_1"] = ["FM", "FM_RESET", "This command resets the following housekeeping telemetry: Command success counter /FM_CMDPCCommand error counter /FM_CMDECCommand warning counter /FM_WarnCtrChild cmd success counter /FM_ChildCMDPCChild cmd error counter /FM_ChildCMDECChild cmd warning counter /FM_ChildWarnCtr "],
    ["6284_2"] = ["FM", "FM_COPY", "This command copies the source file to the target file. The source must be an existing file and the target must not be a directory name. If the Overwrite command argument is TRUE, then the target may be an existing file, provided that the file is closed. If the Overwrite command argument is FALSE, then the target must not exist. The source and target may be on different file systems. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but copying the file will be performed by a lower priority child task. As such, the command result for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_3"] = ["FM", "FM_MOVE", "This command moves the source file to the target file. The source must be an existing file and the target must not be a directory name. If the Overwrite command argument is TRUE, then the target may be an existing file, provided that the file is closed. If the Overwrite command argument is FALSE, then the target must not exist. Source and target must both be on the same file system. The move command does not actually move any file data. The command modifies the file system directory structure to create a different file entry for the same file data. If the user wishes to move a file across file systems, he must first copy the file and then delete the original."],
    ["6284_4"] = ["FM", "FM_RENAME", "This command renames the source file to the target file. Source must be an existing file and target must not exist. Source and target must both be on the same file system. The rename command does not actually move any file data. The command modifies the file system directory structure to create a different file entry for the same file data. If the user wishes to rename a file across file systems, he must first copy the file and then delete the original."],
    ["6284_5"] = ["FM", "FM_DELETE", "This command deletes the source file. Source must be an existing file that is not open."],
    ["6284_7"] = ["FM", "FM_DELETE_ALL", "This command deletes all files in the source directory. Source must be an existing directory. Open files and sub-directories are not deleted. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but reading the directory and deleting each file will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_8"] = ["FM", "FM_DECOMPRESS", "This command invokes a CFE function to decompress the source file into the target file. Source must be an existing file and target must not exist. Source and target may be on different file systems. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but decompressing the source file into the target file will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_9"] = ["FM", "FM_CONCAT", "This command concatenates two source files into the target file. Sources must both be existing files and target must not exist. Sources and target may be on different file systems. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but copying the first source file to the target file and then appending the second source file to the target file will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_10"] = ["FM", "FM_GET_FILE_INFO", "This command creates an FM file information telemetry packet for the source file. The file information packet includes status that indicates whether source is a file that is open or closed, a directory, or does not exist. The file information data also includes a CRC, file size, last modify time and the source name. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but collecting the status data and calculating the CRC will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_11"] = ["FM", "FM_GET_OPEN_FILES", "This command creates an FM open files telemetry packet. The open files packet includes the number of open files and for each open file, the name of the file and the name of the application that has the file opened."],
    ["6284_12"] = ["FM", "FM_CREATE_DIR", "This command creates the source directory. Source must be a valid directory name that does not exist."],
    ["6284_13"] = ["FM", "FM_DELETE_DIR", "This command deletes the source directory, it does not delete the contents of the directory. Source must be a valid directory name that exists."],
    ["6284_14"] = ["FM", "FM_GET_DIR_FILE", "This command writes a listing of the contents of the source directory to the target file. If the target filename buffer is empty, then the default target filename FM_DIR_LIST_FILE_DEFNAME is used. The command will overwrite a previous copy of the target file, if one exists. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but reading the directory will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_15"] = ["FM", "FM_GET_DIR_PKT", "This command creates a telemetry packet FM_DirListPkt_t that contains a listing of the entries in the specified directory. Since the packet will likely hold fewer entries than will be possible in a directory, the command also provides an index argument to define which entry in the directory is the first entry reported in the telemetry packet. After reading the directory list and skipping entries until reaching the index of the first entry reported, the remaining entries in the packet are filled sequentially until either the packet is full or until there are no more entries in the directory. The first entry index is zero based - thus, when the first entry index is zero the first directory entry will be the first packet entry. The number of entries per packet FM_DIR_LIST_PKT_ENTRIES is a platform configuration definition. Because of the possibility that this command might take a very long time to complete, command argument validation will be done immediately but reading the directory will be performed by a lower priority child task. As such, the return value for this function only refers to the result of command argument verification and being able to place the command on the child task interface queue."],
    ["6284_16"] = ["FM", "FM_GET_FREE_SPACE", "This command queries the amount of free space for each of the enabled entries in the file system free space table. The data is then placed in a telemetry packet and sent to ground."],
    ["6284_17"] = ["FM", "FM_SET_FILE_PERM", "Set Permissions of a file."],
    ["6284_18"] = ["FM", "FM_DELETE_INT", "This is a special version of the FM_DELETE_CC command for use when the command is sent by another application, rather than from the ground. This version of the command will not generate a success event, nor will the command increment the command success counter. The intent is to avoid confusion resulting from telemetry representing the results of delete commands sent by other applications and those sent from the ground. Refer to FM_DELETE_CC command for use details."],
    ["6285_0"] = ["FM", "FM_SEND_HK", "Request FM HK"],
    ["6288_0"] = ["CFS", "MD_NOOP", "This command increments the MD application's valid command execution counter."],
    ["6288_1"] = ["CFS", "MD_RESET_CNTRS", "This command resets the following counters within the Memory Dwell housekeeping telemetry: Command Execution Counter ($sc_$cpu_MD_CMDPC)Command Error Counter ($sc_$cpu_MD_CMDEC) "],
    ["6288_2"] = ["CFS", "MD_START_DWELL", "This command sets the Enabled flag(s) associated with the Dwell Table(s) that have been designated by the command's TableMask argument."],
    ["6288_3"] = ["CFS", "MD_STOP_DWELL", "This command clears the Enabled flag(s) associated with the Dwell Table(s) that have been designated by the command's TableMask argument."],
    ["6288_4"] = ["CFS", "MD_JAM_DWELL", "This command inserts the specified dwell parameters (dwell address, dwell field length, and delay count) into the specified table, at the specified index."],
    ["6288_5"] = ["CFS", "MD_SET_SIGNATURE", "Associates a signature with the specified Dwell Table."],
    ["6293_0"] = ["SCH", "SCH_NOOP", "This command performs no other function than to increment the command execution counter. The command may be used to verify general aliveness of the Scheduler Application."],
    ["6293_1"] = ["SCH", "SCH_RESET", "This command resets the following counters within the Scheduler housekeeping telemetry: Command Execution Counter ($sc_$cpu_SCH_CMDPC)Command Error Counter ($sc_$cpu_SCH_CMDEC)Schedule Activities Success Counter ($sc_$cpu_SCH_ActSuccessCtr)Schedule Activities Failure Counter ($sc_$cpu_SCH_ActFailCtr)Schedule Slots Processed Counter ($sc_$cpu_SCH_SlotProcCtr)Schedule Skipping Slots Counter ($sc_$cpu_SCH_SlotSkipCtr)Multiple Schedule Slots Processed Counter ($sc_$cpu_SCH_MultSlotCtr)Awoke in Same Slot Counter ($sc_$cpu_SCH_SameSlotCtr)Corrupted Table Data Counter ($sc_$cpu_SCH_BadTblDataCtr)Table Loads Successfully Verified Counter ($sc_$cpu_SCH_TblPassVerifyCtr)Table Loads Unsuccessfully Verified Counter ($sc_$cpu_SCH_TblFailVerifyCtr)Valid Major Frames Received Counter ($sc_$cpu_SCH_ValidMajorFrameCtr)Missed Major Frames Received Counter ($sc_$cpu_SCH_MissedMajorFrameCtr)Unexpected Major Frames Received Counter ($sc_$cpu_SCH_UnexpectedMajorFrameCtr)"],
    ["6293_2"] = ["SCH", "SCH_ENABLE", "This command enables a single activity in the Schedule Definition Table."],
    ["6293_3"] = ["SCH", "SCH_DISABLE", "This command disables a single activity in the Schedule Definition Table."],
    ["6293_4"] = ["SCH", "SCH_ENABLE_GROUP", "This command enables a single group and/or a collection of Multi-Group Activities in the Schedule Definition Table."],
    ["6293_5"] = ["SCH", "SCH_DISABLE_GROUP", "This command disables a single group and/or a collection of Multi-Group Activities in the Schedule Definition Table."],
    ["6293_6"] = ["SCH", "SCH_ENABLE_SYNC", "This command allows the operator to enable processing and synchronization of the Major Frame Signal to the processing of the Schedule Definition Table."],
    ["6293_7"] = ["SCH", "SCH_SEND_DIAG_TLM", "This command generates and sends the Scheduler Application's Diagnostic Telemetry packet."],
    ["6298_0"] = ["CFS", "HK_NOOP", "This command will increment the command execution counter and send an event containing the version number of the application"],
    ["6298_1"] = ["CFS", "HK_RESET", "This command resets the following counters within the HK housekeeping telemetry: Command Execution Counter ($sc_$cpu_HK_CMDPC)Command Error Counter ($sc_$cpu_HK_CMDEC)Combined Packets Sent Counter ($sc_$cpu_HK_CmbPktSent)Missing Data Counter ($sc_$cpu_HK_MissDataCtr) "],
    ["6303_0"] = ["CS", "CS_NOOP", "Implements the Noop command that insures the CS task is alive"],
    ["6303_1"] = ["CS", "CS_RESET", "Resets the CS housekeeping counters"],
    ["6303_2"] = ["CS", "CS_ONESHOT", "Computes a checksum on the given address and size of memory specified in the command. This command spawns a child task to complete the checksum."],
    ["6303_3"] = ["CS", "CS_CANCEL_ONESHOT", "Cancels a one shot calculation that is already in progress."],
    ["6303_4"] = ["CS", "CS_ENABLE_ALL_CS", "Allows CS to continue background checking"],
    ["6303_5"] = ["CS", "CS_DISABLE_ALL_CS", "Disables all background checking"],
    ["6303_6"] = ["CS", "CS_ENABLE_CFECORE", "Enables background checking on the cFE core code segment"],
    ["6303_7"] = ["CS", "CS_DISABLE_CFECORE", "Disables background checking on the cFE core code segment"],
    ["6303_8"] = ["CS", "CS_REPORT_BASELINE_CFECORE", "Reports the baseline checksum of the cFE core that has already been calculated."],
    ["6303_9"] = ["CS", "CS_RECOMPUTE_BASELINE_CFECORE", "Recomputesthe baseline checksum of the cFE core and use the new value as the baseline."],
    ["6303_10"] = ["CS", "CS_ENABLE_OS", "Enables background checking on the OS code segment"],
    ["6303_11"] = ["CS", "CS_DISABLE_OS", "Disables background checking on the OS code segment code segment"],
    ["6303_12"] = ["CS", "CS_REPORT_BASELINE_OS", "Reports the baseline checksum of the OS code segment that has already been calculated."],
    ["6303_13"] = ["CS", "CS_RECOMPUTE_BASELINE_OS", "Recomputesthe baseline checksum of the OS code segment and use the new value as the baseline."],
    ["6303_14"] = ["CS", "CS_ENABLE_EEPROM", "Allow the Eeprom table to checksummed in the background"],
    ["6303_15"] = ["CS", "CS_DISABLE_EEPROM", "Disable the Eeprom table background checksumming"],
    ["6303_16"] = ["CS", "CS_REPORT_BASELINE_EEPROM", "Reports the baseline checksum of the Eeprom table entry that has already been calculated."],
    ["6303_17"] = ["CS", "CS_RECOMPUTE_BASELINE_EEPROM", "Recompute the baseline checksum of the Eeprom table entry and use that value as the new baseline. This command spawns a child task to do the recompute."],
    ["6303_18"] = ["CS", "CS_ENABLE_ENTRY_EEPROM", "Allow the Eeprom entry to checksummed in the background"],
    ["6303_19"] = ["CS", "CS_DISABLE_ENTRY_EEPROM", "Disable the Eeprom entry background checksumming"],
    ["6303_20"] = ["CS", "CS_GET_ENTRY_ID_EEPROM", "Gets the Entry ID of an Eeprom address to use in subsequent commands."],
    ["6303_21"] = ["CS", "CS_ENABLE_MEMORY", "Allow the Memory table to checksummed in the background"],
    ["6303_22"] = ["CS", "CS_DISABLE_MEMORY", "Disable the Memory table background checksumming"],
    ["6303_23"] = ["CS", "CS_REPORT_BASELINE_MEMORY", "Reports the baseline checksum of the Memory table entry that has already been calculated."],
    ["6303_24"] = ["CS", "CS_RECOMPUTE_BASELINE_MEMORY", "Recompute the baseline checksum of the Memory table entry and use that value as the new baseline. This command spawns a child task to do the recompute."],
    ["6303_25"] = ["CS", "CS_ENABLE_ENTRY_MEMORY", "Allow the Memory entry to checksummed in the background"],
    ["6303_26"] = ["CS", "CS_DISABLE_ENTRY_MEMORY", "Disable the Memory entry background checksumming"],
    ["6303_27"] = ["CS", "CS_GET_ENTRY_ID_MEMORY", "Gets the Entry ID of a Memory address to use in subsequent commands."],
    ["6303_28"] = ["CS", "CS_ENABLE_TABLES", "Allow the Tables table to checksummed in the background"],
    ["6303_29"] = ["CS", "CS_DISABLE_TABLES", "Disable the Tables table background checksumming"],
    ["6303_30"] = ["CS", "CS_REPORT_BASELINE_TABLE", "Reports the baseline checksum of the table that has already been calculated."],
    ["6303_31"] = ["CS", "CS_RECOMPUTE_BASELINE_TABLE", "Recompute the baseline checksum of the table and use that value as the new baseline. This command spawns a child task to do the recompute."],
    ["6303_32"] = ["CS", "CS_ENABLE_NAME_TABLE", "Allow the table to checksummed in the background"],
    ["6303_33"] = ["CS", "CS_DISABLE_NAME_TABLE", "Disable background checking of the table"],
    ["6303_34"] = ["CS", "CS_ENABLE_APPS", "Allow the App table to checksummed in the background"],
    ["6303_35"] = ["CS", "CS_DISABLE_APPS", "Disable the App table background checksumming"],
    ["6303_36"] = ["CS", "CS_REPORT_BASELINE_APP", "Reports the baseline checksum of the app that has already been calculated."],
    ["6303_37"] = ["CS", "CS_RECOMPUTE_BASELINE_APP", "Recompute the baseline checksum of the app and use that value as the new baseline. This command spawns a child task to do the recompute."],
    ["6303_38"] = ["CS", "CS_ENABLE_NAME_APP", "Allow the app to checksummed in the background"],
    ["6303_39"] = ["CS", "CS_DISABLE_NAME_APP", "Disable background checking of the app"],
    ["6308_0"] = ["CFS", "LC_NOOP", "Implements the Noop command that insures the LC task is alive"],
    ["6308_1"] = ["CFS", "LC_RESET", "Resets the LC housekeeping counters"],
    ["6308_2"] = ["CFS", "LC_SET_LC_STATE", "Sets the operational state of the LC application"],
    ["6308_3"] = ["CFS", "LC_SET_AP_STATE", "Set actionpoint state"],
    ["6308_4"] = ["CFS", "LC_SET_AP_PERMOFF", "Set the specified actionpoint's state to LC_APSTATE_PERMOFF"],
    ["6308_5"] = ["CFS", "LC_RESET_AP_STATS", "Resets actionpoint statistics"],
    ["6308_6"] = ["CFS", "LC_RESET_WP_STATS", "Resets watchpoint statistics"],
    ["6313_0"] = ["CFS", "SC_NOOP", "Implements the Noop command that insures the SC app is alive"],
    ["6313_1"] = ["CFS", "SC_RESET_COUNTERS", "Resets the SC housekeeping counters"],
    ["6313_2"] = ["CFS", "SC_START_ATS", "Starts the specified ATS"],
    ["6313_3"] = ["CFS", "SC_STOP_ATS", "Stops the specified ATS"],
    ["6313_4"] = ["CFS", "SC_START_RTS", "Starts the specified RTS"],
    ["6313_5"] = ["CFS", "SC_STOP_RTS", "Stops the specified RTS"],
    ["6313_6"] = ["CFS", "SC_DISABLE_RTS", "Disables the specified RTS"],
    ["6313_7"] = ["CFS", "SC_ENABLE_RTS", "Enables the specified RTS"],
    ["6313_8"] = ["CFS", "SC_SWITCH_ATS", "Switches the running ATS and the ATS no running"],
    ["6313_9"] = ["CFS", "SC_JUMP_ATS", "Moves the 'current time' pointer in the ATS to another time"],
    ["6313_10"] = ["CFS", "SC_CONTINUE_ATS_ON_FAILURE", "Sets the flag which specifies whether or not to continue processing an ATS if one of the commands in the ATS fails checksum validation before being sent out."],
    ["6313_11"] = ["CFS", "SC_APPEND_ATS", "Adds contents of the Append table to the specified ATS table"],
    ["6313_12"] = ["CFS", "SC_MANAGE_TABLE", "This command signals a need for the host application (SC) to allow cFE Table Services to manage the specified table. For loadable tables, this command indicates that a table update is available. For dump only tables, this command indicates that cFE Table Services wants to dump the table data. In either case, the host application must call the table manage API function so that the pending function can be executed within the context of the host."],
    ["6313_13"] = ["CFS", "SC_START_RTSGRP", "The load state for an RTS may be LOADED or NOT LOADED. The enable state for an RTS may be ENABLED or DISABLED. The run state for an RTS may be STARTED or STOPPED. This command STARTS each RTS in the specified group that is currently LOADED, ENABLED and STOPPED."],
    ["6313_14"] = ["CFS", "SC_STOP_RTSGRP", "The load state for an RTS may be LOADED or NOT LOADED. The enable state for an RTS may be ENABLED or DISABLED. The run state for an RTS may be STARTED or STOPPED. This command STOPS each RTS in the specified group that is currently STARTED."],
    ["6313_15"] = ["CFS", "SC_DISABLE_RTSGRP", "The enable state for an RTS may be ENABLED or DISABLED. This command sets the enable state for the specified group of RTS to DISABLED."],
    ["6313_16"] = ["CFS", "SC_ENABLE_RTSGRP", "The enable state for an RTS may be ENABLED or DISABLED. This command sets the enable state for the specified group of RTS to ENABLED."],
    ["6314_0"] = ["CFS", "SC_SEND_HK", "Request SC Housekeeping"],
    ["6318_0"] = ["CFS", "HS_NOOP", "Implements the Noop command that insures the HS task is alive"],
    ["6318_1"] = ["CFS", "HS_RESET", "Resets the HS housekeeping counters"],
    ["6318_2"] = ["CFS", "HS_ENABLE_APPMON", "Enables the Critical Applications Monitor"],
    ["6318_3"] = ["CFS", "HS_DISABLE_APPMON", "Disables the Critical Applications Monitor"],
    ["6318_4"] = ["CFS", "HS_ENABLE_EVENTMON", "Enables the Critical Events Monitor"],
    ["6318_5"] = ["CFS", "HS_DISABLE_EVENTMON", "Disables the Critical Events Monitor"],
    ["6318_6"] = ["CFS", "HS_ENABLE_ALIVENESS", "Enables the Aliveness Indicator UART output"],
    ["6318_7"] = ["CFS", "HS_DISABLE_ALIVENESS", "Disables the Aliveness Indicator UART output"],
    ["6318_8"] = ["CFS", "HS_RESET_RESETS_PERFORMED", "Resets the count of HS performed resets maintained by HS"],
    ["6318_9"] = ["CFS", "HS_SET_MAX_RESETS", "Sets the max allowable count of processor resets to the provided value"],
    ["6318_10"] = ["CFS", "HS_ENABLE_CPUHOG", "Enables the CPU Hogging Indicator Event Message"],
    ["6318_11"] = ["CFS", "HS_DISABLE_CPUHOG", "Disables the CPU Hogging Indicator Event Message"],
    ["6331_0"] = ["CFS", "DS_NOOP", "This command will increment the command execution counter and send an event containing the version number of the application. The command is often used as a general test for application 'aliveness'."],
    ["6331_1"] = ["CFS", "DS_RESET", "This command will set the following housekeeping counters to zero: Command Execution Counter ($sc_$cpu_DS_CMDPC)Command Error Counter ($sc_$cpu_DS_CMDEC)Ignored Packet Counter ($sc_$cpu_DS_IgnoredPktCnt)Filtered Packet Counter ($sc_$cpu_DS_FilteredPktCnt)Passed Packet Counter ($sc_$cpu_DS_PassedPktCnt)File Access Counter ($sc_$cpu_DS_FileWriteCnt)File Access Error Counter ($sc_$cpu_DS_FileWriteErrCnt)Destination Table Load Counter ($sc_$cpu_DS_DestLoadCnt)Filter Table Load Counter ($sc_$cpu_DS_FilterLoadCnt)Destination Table Ptr Error Counter ($sc_$cpu_DS_DestPtrErrCnt)Filter Table Ptr Error Counter ($sc_$cpu_DS_FilterPtrErrCnt) "],
    ["6331_2"] = ["CFS", "DS_SET_APP_STATE", "This command will modify the Ena/Dis State selection for the DS application. No packets are stored while DS is disabled."],
    ["6331_3"] = ["CFS", "DS_SET_FILTER_FILE", "This command will modify the Destination File selection for the indicated entry in the Packet Filter Table."],
    ["6331_4"] = ["CFS", "DS_SET_FILTER_TYPE", "This command will modify the Filter Type selection for the indicated entry in the Packet Filter Table."],
    ["6331_5"] = ["CFS", "DS_SET_FILTER_PARMS", "This command will modify the Algorithm Parameters for the indicated entry in the Packet Filter Table."],
    ["6331_6"] = ["CFS", "DS_SET_DEST_TYPE", "This command will modify the Filename Type selection for the indicated entry in the Destination File Table."],
    ["6331_7"] = ["CFS", "DS_SET_DEST_STATE", "This command will modify the Ena/Dis State selection for the indicated entry in the Destination File Table."],
    ["6331_8"] = ["CFS", "DS_SET_DEST_PATH", "This command will modify the Pathname portion of the filename for the indicated entry in the Destination File Table."],
    ["6331_9"] = ["CFS", "DS_SET_DEST_BASE", "This command will modify the Basename portion of the filename for the indicated entry in the Destination File Table."],
    ["6331_10"] = ["CFS", "DS_SET_DEST_EXT", "This command will modify the Extension portion of the filename for the indicated entry in the Destination File Table."],
    ["6331_11"] = ["CFS", "DS_SET_DEST_SIZE", "This command will modify the max file size selection for the indicated entry in the Destination File Table."],
    ["6331_12"] = ["CFS", "DS_SET_DEST_AGE", "This command will modify the max file age selection for the indicated entry in the Destination File Table."],
    ["6331_13"] = ["CFS", "DS_SET_DEST_COUNT", "This command will modify the sequence count value for the indicated entry in the Destination File Table."],
    ["6331_14"] = ["CFS", "DS_CLOSE_FILE", "This command will close the indicated Destination File."],
    ["6331_15"] = ["CFS", "DS_GET_FILE_INFO", "This command will send the DS File Info Packet."],
    ["6331_16"] = ["CFS", "DS_ADD_MID", "This command will change the Message ID selection for an unused Packet Filter Table entry to the indicated value."],
    ["6331_17"] = ["CFS", "DS_CLOSE_ALL", "This command will close all open Destination Files. NOTE: Using this command may incur a performance hit based upon the number and size of the files being closed. "],
    ["6368_0"] = ["CFS", "CI_DEBUG_NOOP_CC", "NOOP Command"],
    ["6368_2"] = ["CFS", "CI_DEBUG_RESET_COUNTERS_CC", "Reset Counters"],
    ["6376_0"] = ["CFS", "TO_DEBUG_NOOP_CC", "NOOP Command"],
    ["6376_2"] = ["CFS", "TO_DEBUG_ENABLE_OUTPUT_CC", "Enable Output Command"],
    ["6376_5"] = ["CFS", "TO_DEBUG_REMOVE_ALL_PKT_CC", "Remove all packets"],
    ["6398_0"] = ["SPACECOP", "SPACECOP_NOOP_CC", "SPACECOP NOOP Command"],
    ["6398_1"] = ["SPACECOP", "SPACECOP_RESET_COUNTERS_CC", "SPACECOP Reset Counters Command"],
    ["6399_0"] = ["SPACECOP", "SPACECOP_REQUEST_HK_CC", "SPACECOP HK Request"],
    ["6399_2"] = ["SPACECOP", "SPACECOP_REQUEST_IDS_CC", "SPACECOP IDS Request"],
    ["6570_0"] = ["EPS", "NOOP", "Generate an info event message with app version"],
    ["6570_1"] = ["EPS", "RESET_CTRS", "Resets HK TLM parent and child task counters"],
    ["6571_0"] = ["EPS", "EPS_REQUEST_HK_CC", "EPS HK Request"],
    ["6586_0"] = ["STPYLD", "NOOP", "Generate an info event message with app version"],
    ["6586_1"] = ["STPYLD", "RESET_CTRS", "Resets HK TLM parent and child task counters"],
    ["6587_0"] = ["STPYLD", "STPYLD_REQUEST_HK_CC", "STPYLD HK Request"],
    ["6602_0"] = ["SYSMON", "NOOP", "Generate an info event message with app version"],
    ["6602_1"] = ["SYSMON", "RESET_CTRS", "Resets HK TLM parent and child task counters"],
    ["6603_0"] = ["SYSMON", "SYSMON_REQUEST_HK_CC", "SYSMON HK Request"],
    ["6618_0"] = ["CAMERA", "NOOP", "Generate an info event message with app version"],
    ["6618_2"] = ["CAMERA", "TAKE_PIC", "Takes a picture"],
    ["6618_3"] = ["CAMERA", "DELETE_LAST", "Deletes last picture taken"],
    ["7610_1"] = ["CAMERA", "RESET_CTRS", "Resets HK TLM parent and child task counters"],
} &redef;

# Telemetry lookup table: stream_id -> [target, name, description]
const telemetry_table: table[count] of vector of string = {
} &redef;

# Utility functions for parsing

function extract_uint16_be(data: string, offset: count): count
    {
    if (|data| < offset + 2)
        return 0;
    
    local byte_vec = raw_bytes_to_v4_addr(data);
    local b1: count = 0;
    local b2: count = 0;
    
    # Safe byte extraction
    local len = |data|;
    if (offset < len)
        b1 = bytestring_to_count(data[offset]);
    if (offset + 1 < len)
        b2 = bytestring_to_count(data[offset + 1]);
    
    return (b1 * 256) + b2;
    }

function extract_uint8(data: string, offset: count): count
    {
    if (|data| <= offset)
        return 0;
    
    return bytestring_to_count(data[offset]);
    }

function to_hex_string(data: string): string
    {
    local hex = "";
    local len = |data|;
    local i = 0;
    
    while (i < len)
        {
        if (hex != "")
            hex = fmt("%s ", hex);
        hex = fmt("%s%02X", hex, bytestring_to_count(data[i]));
        i = i + 1;
        }
    
    return hex;
    }

function parse_command_packet(payload: string): CommandInfo
    {
    local info: CommandInfo;
    info$packet_length = |payload|;
    info$raw_hex = to_hex_string(payload);
    
    if (|payload| < 6)
        {
        info$error = fmt("Packet too short: %d bytes", |payload|);
        return info;
        }
    
    # Parse CCSDS Primary Header (6 bytes)
    local stream_id = extract_uint16_be(payload, 0);
    local sequence = extract_uint16_be(payload, 2);
    local data_length = extract_uint16_be(payload, 4);
    
    info$stream_id = stream_id;
    info$stream_id_hex = fmt("0x%04X", stream_id);
    info$sequence_flags = (sequence / 16384) % 4;  # Right shift 14 bits
    info$packet_sequence = sequence % 16384;        # Lower 14 bits
    info$data_length = data_length;
    info$apid = stream_id % 2048;                   # Lower 11 bits
    
    # Parse Secondary Header (Command-specific)
    if (|payload| >= 7)
        {
        local fc = extract_uint8(payload, 6);
        info$function_code = fc;
        
        if (|payload| >= 8)
            {
            info$checksum = extract_uint8(payload, 7);
            }
        
        # Look up command using string key
        local lookup_key = fmt("%d_%d", stream_id, fc);
        if (lookup_key in command_table)
            {
            local cmd = command_table[lookup_key];
            info$target = cmd[0];
            info$command_name = cmd[1];
            info$command_desc = cmd[2];
            info$valid = T;
            }
        else
            {
            info$error = fmt("Unknown command: StreamID=0x%04X, FC=%d", stream_id, fc);
            }
        }
    else
        {
        info$error = "No secondary header";
        }
    
    return info;
    }

function parse_telemetry_packet(payload: string): TelemetryInfo
    {
    local info: TelemetryInfo;
    info$packet_length = |payload|;
    info$raw_hex = to_hex_string(payload);
    
    if (|payload| < 6)
        {
        info$error = fmt("Packet too short: %d bytes", |payload|);
        return info;
        }
    
    # Parse CCSDS Primary Header (6 bytes)
    local stream_id = extract_uint16_be(payload, 0);
    local sequence = extract_uint16_be(payload, 2);
    local data_length = extract_uint16_be(payload, 4);
    
    info$stream_id = stream_id;
    info$stream_id_hex = fmt("0x%04X", stream_id);
    info$sequence_flags = (sequence / 16384) % 4;
    info$packet_sequence = sequence % 16384;
    info$data_length = data_length;
    info$apid = stream_id % 2048;
    
    # Look up telemetry
    if (stream_id in telemetry_table)
        {
        local tlm = telemetry_table[stream_id];
        info$target = tlm[0];
        info$packet_name = tlm[1];
        info$packet_desc = tlm[2];
        info$valid = T;
        }
    else
        {
        info$error = fmt("Unknown telemetry: StreamID=0x%04X", stream_id);
        info$target = "UNKNOWN";
        info$packet_name = "UNKNOWN";
        }
    
    return info;
    }

# UDP event handler - Port-based packet type detection

event udp_contents(c: connection, is_orig: bool, payload: string)
    {
    local src_port = c$id$orig_p;
    local dst_port = c$id$resp_p;
    
    # Skip if not our ports
    if (src_port != COMMAND_PORT && dst_port != COMMAND_PORT &&
        src_port != TELEMETRY_PORT && dst_port != TELEMETRY_PORT)
        return;
    
    # Skip empty payloads
    if (|payload| < 6)
        return;
    
    # Determine packet type based on port
    if (src_port == COMMAND_PORT || dst_port == COMMAND_PORT)
        {
        # This is a command packet (port 5012)
        local cmd_info = parse_command_packet(payload);
        cmd_info$ts = network_time();
        cmd_info$uid = c$uid;
        cmd_info$src_ip = c$id$orig_h;
        cmd_info$src_port = src_port;
        cmd_info$dst_ip = c$id$resp_h;
        cmd_info$dst_port = dst_port;
        
        Log::write(COMMAND_LOG, cmd_info);
        }
    else if (src_port == TELEMETRY_PORT || dst_port == TELEMETRY_PORT)
        {
        # This is a telemetry packet (port 5013)
        local tlm_info = parse_telemetry_packet(payload);
        tlm_info$ts = network_time();
        tlm_info$uid = c$uid;
        tlm_info$src_ip = c$id$orig_h;
        tlm_info$src_port = src_port;
        tlm_info$dst_ip = c$id$resp_h;
        tlm_info$dst_port = dst_port;
        
        Log::write(TELEMETRY_LOG, tlm_info);
        }
    }
