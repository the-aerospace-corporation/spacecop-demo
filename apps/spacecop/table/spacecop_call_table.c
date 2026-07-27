
#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "spacecop_table_defs.h"

/*
 * SpaceCop Rule Table - PISAT PORT
 * --------------------------------
 * Ported from the NOS3 proof-of-concept. Most rules are unchanged because they
 * monitor the Linux host (cpu/proc/file/syscall/memory/disk scans) or core cFE
 * (time delta, time-adjust count, app-control state change) - all identical on
 * the Raspberry Pi build.
 *
 * Changed for the pisat port:
 *   - UACE-17 (propulsion burn duration) is DISABLED: there is no propulsion
 *     app on this build, and nothing feeds propulsion_burn_duration_id.
 *   - The RULE_ML entries (call_index 13) arm the single ML monitor task; the
 *     per-SYSTEM routing now lives in spacecop_command_monitor_table.c, which
 *     feeds every pisat app's CMD + HK stream to the ML detector. The same ML
 *     IOB family is reused across systems (the alert's "system" field
 *     distinguishes them).
 */
RuleTable SPACECOP_RuleTable =
{
    .num_rules = 22,
    .rules = 
    {
       /*
       *      Rule 1: GNTM-6 Unexpected Time Delta
       *      STIX Pattern: [x-opencti-system:component = 'time_controller' AND x-opencti-time:delta_value != 'expected_delta_value']
       *      Tolerance is in seconds
       */
       {
              .enabled = 1,
              .iob_id = "GNTM-6",
              .mode = RULE_PERIODIC, //Run every tick
              .period_ticks = 3, //Limit one run every 3 seconds
              .call_index = 0, //look in spacecop_registry.c for index
              .lhs = { .kind = SRC_CALL_NEW, .type = VT_U32 },
              .op = OP_ABS_DIFF_GT,
              .rhs = { .kind = SRC_CALL_OLD, .type = VT_U32 },
              .tol = { .type = VT_U32, .v = { .u32 = 5 }},
       },
       /*
       *      Rule 2: SMSR-2 High CPU Utilization Due to Anomalous/Malicious Activity 
       *      STIX Pattern: [x-opencti-processor-usage:cpu_load > 'threshold' AND x-opencti-processor-usage:activity_type = 'unexpected' AND x-opencti-processor-usage:process_name NOT IN ('list_of_known_processes')]
       *      Tolerance is in percent
       */
       {
              .enabled = 1,
              .iob_id = "SMSR-2", 
              .mode = RULE_TRIGGER,
              .period_ticks = 10,
              .call_index = 1, //look in spacecop_registry.c for index
              .tol = { .type = VT_F32, .v = { .f32 = 40.0f }},
       },
       /*
       *      Rule 3: SIUU-11 Suspicious Binary or Script Execution
       *      STIX Pattern: [process:image_ref.name != 'expected_binary_or_script']
       */
       {
              .enabled = 1,
              .iob_id = "SIUU-11", 
              .mode = RULE_TRIGGER,
              .period_ticks = 5,
              .call_index = 2, //look in spacecop_registry.c for index
       },
       /*
       *      Rule 4: DISE-1: File or Data Integrity Check Failure
       *      STIX Pattern: [file:hashes != 'expected_hash_value' AND file:name = 'data_file']
       */
       {
              .enabled = 1,
              .iob_id = "DISE-1", 
              .mode = RULE_TRIGGER,
              .period_ticks = 5,
              .call_index = 3, //look in spacecop_registry.c for index
       },
       /*
       *      Rule 5: CSNE-0017: Creation of FIFO for Data Exfiltration or Command Injection
       *      STIX Pattern: [process:image_ref.name = 'mkfifo' AND process:x_execution_time = 'unexpected_time']
       */
       {
              .enabled = 1,
              .iob_id = "CSNE-17", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,
       },
       /*
       *      Rule 6: SIUU-0015: Repeated File Access to /zero or /null Devices
       *      STIX Pattern: [file:path = '/dev/null' OR file:path = '/dev/zero' AND file:access_time != 'expected_time']
       *      Tolerance: 10 times before reporting
       */
       {
              .enabled = 1,
              .iob_id = "SIUU-15", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,     
              .tol = { .type = VT_I32, .v = { .i32 = 100 }}
       },
       /*
       *      Rule 7: SIUU-0012: Loading of Malicious Kernel Modules
       *      STIX Pattern: [process:image_ref.name = 'insmod' OR ONEANDDONE:name = 'INIT_MODULE']
       */
       {
              .enabled = 1,
              .iob_id = "SIUU-12", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,     
       },
       /*
       *      Rule 8: SIUU-0010: Process Executing Priority Modification
       *      STIX Pattern: [process:image_ref.name = 'renice' OR process:image_ref.name = 'setpriority' AND process:x_execution_time != 'authorized_period']
       */
       {
              .enabled = 1,
              .iob_id = "SIUU-10", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,     
       },
       /*
       *      Rule 9: SIUU-0016: Execution of System Commands
       *      STIX Pattern: [process:image_ref.name = 'grep' OR process:image_ref.name = 'ps' OR process:image_ref.name = 'awk' OR process:image_ref.name = 'chmod' OR process:image_ref.name = 'dd' OR process:image_ref.name = 'cat' OR process:image_ref.name = 'sh' AND process:x_execution_time != 'authorized_time']
       */
       {
              .enabled = 1,
              .iob_id = "SIUU-16", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,     
       },
       /*
       *      Rule 10: MIRE-0017: Unauthorized System Call to Open Flash Memory Blocks (/dev/mtd)
       *      STIX Pattern: [process:image_ref.name = 'open' AND file:path LIKE '/dev/mtd%' AND file:access_time != 'authorized_access_time']
       */
       {
              .enabled = 1,
              .iob_id = "MIRE-17", 
              .mode = RULE_ONEANDDONE,
              .call_index = 4,     
       },
       /*
       *      Rule 11: MIRE-14: Abnormal Memory Consumption by Malicious Process
       *      STIX Pattern: [process:x_memory_usage > 'threshold' AND process:image_ref.name != 'authorized_process']
       *      Threshold is in kilobytes
       */
       {
              .enabled = 1,
              .iob_id = "MIRE-14", 
              .mode = RULE_TRIGGER,
              .period_ticks = 10,
              .call_index = 5, //look in spacecop_registry.c for index
              .tol = { .type = VT_U32, .v = { .u32 = 1000000 }},
       },
       /*
       *        Rule 12: UACE-0017: Abnormal Burn Duration Detected in Propulsion Subsystem
       *        STIX Pattern: [x-opencti-propulsion-system:burn_duration > 'expected_max_duration' OR x-opencti-propulsion-system:burn_duration < 'expected_min_duration']
       *        Threshold is in seconds
       *
       *        PISAT PORT: DISABLED (.enabled = 0). There is no propulsion/thruster
       *        app on this build, so no command-monitor entry populates
       *        propulsion_burn_duration_id and this rule can never fire. Re-enable
       *        and add a COUNT_DURATION command-monitor entry if a propulsion app
       *        is introduced.
       */
       {
                .enabled = 0,
                .iob_id = "UACE-17",
                .mode = RULE_PERIODIC,
                .period_ticks = 3,
                .call_index = 6,
                .lhs = { .kind = SRC_CALL_NEW, .type = VT_U32 },
                .rhs = { .kind = SRC_TOL, .type = VT_U32 },
                .tol = { .type = VT_U32, .v = { .u32 = 3  }},
                .op = OP_GT,
       },
       /*
       *      Rule 13: DISE-0004: Storage Exhaustion (Disk Full)
       *      STIX Pattern: [x-opencti-file-system:available_space < 'threshold']
       *      Threshold is in percent
       */
       {
              .enabled = 1,
              .iob_id = "DISE-4", 
              .mode = RULE_TRIGGER,
              .period_ticks = 10,
              .call_index = 7, //look in spacecop_registry.c for index
              .tol = { .type = VT_F32, .v = { .f32 = 20.0f }},
       },
       /*
       *      Rule 14: GNTM-0007: Time Adjustment Commands Detected
       *      STIX Pattern: [x-opencti-system:component = 'time_controller' AND x-opencti-command:command = 'adjust_time' AND x-opencti-command:execution_count > 'threshold']
       *      Threshold is in seconds
       */
       {
              .enabled = 1,
              .iob_id = "GNTM-7",
              .mode = RULE_PERIODIC,
              .period_ticks = 3,
              .call_index = 8,
              .lhs = { .kind = SRC_CALL_NEW, .type = VT_U32 },
              .rhs = { .kind = SRC_TOL, .type = VT_U32 },
              .tol = { .type = VT_U32, .v = { .u32 = 3  }},
              .op = OP_GT,
       },
       /*
       *      Rule 15: MIRE-15: Unexpected Modification of Memory Location Associated with Payload Data
       *      STIX Pattern: [x-opencti-memory:block = 'payload_memory_block' AND x-opencti-memory:write_operation = 'unexpected']
       *      Check Interval: Every 10 ticks during normal ops
       */
       {
              .enabled = 1,
              .iob_id = "MIRE-15", 
              .mode = RULE_TRIGGER,
              .period_ticks = 10,
              .call_index = 9, //look in spacecop_registry.c for index
       },
        /*
       *      Rule 16: MIRE-16: Unexpected Access and Changes in Boot Memory Region
       *      STIX Pattern: [x-opencti-memory:block = 'boot' AND x-opencti-memory-log:block = 'boot' AND x-opencti-memory-log:status != 'expected']
       *      Check Interval: Every 5 ticks (5 seconds) during steady state - boot memory should be static
       */
       {
              .enabled = 1,
              .iob_id = "MIRE-16", 
              .mode = RULE_TRIGGER,
              .period_ticks = 5,     /* Check every 5 ticks (5 seconds) - boot memory rarely changes */
              .call_index = 10,        /* memory-monitor-boot */
       },
       /*
       *      Rule 17: MIRE-18: Error Detection Status Failed in Critical Memory Regions
       *      STIX Pattern: [x-opencti-memory-log:error_detection_status = 'failed' AND x-opencti-memory-log:memory_region IN ('critical_region_1','critical_region_2')]
       *      Check Interval: Every 5 ticks 
       */
       {
              .enabled = 1,
              .iob_id = "MIRE-18", 
              .mode = RULE_TRIGGER,
              .period_ticks = 5,      /* Check every 55 ticks for radiation-induced errors */
              .call_index = 11,        /* memory-monitor-critical */
       },
       /*
       *      Rule 18: CSNE-41: High Latency Detected in Downlink Communication
       *      STIX Pattern: [network-traffic:latency > 'acceptable_latency_threshold' AND network-traffic:direction = 'downlink']
       *      Acceptable latency 5s
       */
       {
              .enabled = 1,
              .iob_id = "CSNE-41",
              .mode = RULE_PERIODIC,
              .period_ticks = 3,
              .call_index = 12,
              .lhs = { .kind = SRC_CALL_NEW, .type = VT_U32 },
              .rhs = { .kind = SRC_TOL, .type = VT_U32 },
              .tol = { .type = VT_U32, .v = { .u32 = 5  }},
              .op = OP_GT,
       },
       /*
       *      Rule 19: UACE-16: Irregular Orbit Maneuver Commands Detected on Attitude Control
       *      STIX Pattern: [x-opencti-command:observable_type = 'adcs-command' AND x-opencti-command:value != 'expected_orbit_maneuver_commands']
       */
       {
              .enabled = 1,
              .iob_id = "UACE-16",
              .mode = RULE_ML,
              .call_index = 13,
       },
      /*
       *      Rule 20: UACE-9: Valid Command Flooding
       *      STIX Pattern: [x-opencti-command-data:command_type = 'satellite_vehicle_command' AND x-opencti-command-data:command_frequency > 'expected_rate' AND x-opencti-command-data:source = 'external' AND x-opencti-command-data:command_validity = 'valid']
       */
       {
              .enabled = 1,
              .iob_id = "UACE-9",
              .mode = RULE_ML,
              .call_index = 13,
       },
       /*
       *      Rule 21: UACE-7: Duplicate Command Packet Executions
       *      STIX Pattern: [x-opencti-command-log:command_id = 'duplicate' AND x-opencti-command-log:timestamp = 'unexpected_time']
       */
       {
              .enabled = 1,
              .iob_id = "UACE-7",
              .mode = RULE_ML,
              .call_index = 13,
       },
       /*
       *      Rule 22: SMSR-3: Unauthorized State Changes in Critical Sensors
       *      STIX Pattern: [x-opencti-command-log:command_id = 'duplicate' AND x-opencti-command-log:timestamp = 'unexpected_time']
       */
       {
              .enabled = 1,
              .iob_id = "SMSR-3",
              .mode = RULE_ONEANDDONE,
              .call_index = 14,
       },
    }
};


/* Macro for table structure */
CFE_TBL_FILEDEF(SPACECOP_RuleTable, SPACECOP.SC_RuleTbl, SPACECOP Rule Table, spacecop_rule.tbl)
