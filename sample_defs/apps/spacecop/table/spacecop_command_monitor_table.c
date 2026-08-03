#include "cfe.h"
#include "spacecop_stix_components.h"
#include "spacecop_mission_specific.h"
#include "spacecop_external_imports.h"
#include "cfe_tbl_filedef.h"

CommandMonitorEntryTable_t SPACECOP_CommandMonitorTable = {
	.CommandMonitorEntryCount=54,
	.CommandMonitorEntries={
		/* ================================================================
		 * High-impact commands. Previously blind: SpaceCop only watched
		 * each MID at CommandCode 0 (NOOP), so the actual dangerous command
		 * codes (arbitrary memory write, table load, checksum disable) went
		 * undetected. The matcher is exact (MID, CommandCode), so each
		 * dangerous code needs its own entry. All fire an immediate alert.
		 * ================================================================ */
		{ /* MM arbitrary memory write (the "I win" primitive) */
			.Command=1, .ActionOnMid={MM_CMD_MID}, .ActionOnCommandCode=MM_POKE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* MM bulk memory write (interrupts disabled) */
			.Command=1, .ActionOnMid={MM_CMD_MID}, .ActionOnCommandCode=MM_LOAD_MEM_WID_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* MM load memory image from file */
			.Command=1, .ActionOnMid={MM_CMD_MID}, .ActionOnCommandCode=MM_LOAD_MEM_FROM_FILE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* MM dump memory to file (exfil) */
			.Command=1, .ActionOnMid={MM_CMD_MID}, .ActionOnCommandCode=MM_DUMP_MEM_TO_FILE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* MM memory read / recon */
			.Command=1, .ActionOnMid={MM_CMD_MID}, .ActionOnCommandCode=MM_PEEK_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* Table load from file (e.g. a neutered SpaceCop cmd-monitor table) */
			.Command=1, .ActionOnMid={CFE_TBL_CMD_MID}, .ActionOnCommandCode=CFE_TBL_LOAD_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* Table activate (commit a loaded table) */
			.Command=1, .ActionOnMid={CFE_TBL_CMD_MID}, .ActionOnCommandCode=CFE_TBL_ACTIVATE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* Disable ALL checksum integrity monitoring */
			.Command=1, .ActionOnMid={CS_CMD_MID}, .ActionOnCommandCode=CS_DISABLE_ALL_CS_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		/* --- Second tier: memory read/exfil, file tampering, stored sequences --- */
		{ /* MD set memory-dwell address (arbitrary memory read setup) */
			.Command=1, .ActionOnMid={MD_CMD_MID}, .ActionOnCommandCode=MD_JAM_DWELL_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* MD start dwell (telemeter memory -> exfil) */
			.Command=1, .ActionOnMid={MD_CMD_MID}, .ActionOnCommandCode=MD_START_DWELL_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* FM delete file */
			.Command=1, .ActionOnMid={FM_CMD_MID}, .ActionOnCommandCode=FM_DELETE_FILE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* FM move file (replace a trusted file) */
			.Command=1, .ActionOnMid={FM_CMD_MID}, .ActionOnCommandCode=FM_MOVE_FILE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* FM rename file (replace a trusted file) */
			.Command=1, .ActionOnMid={FM_CMD_MID}, .ActionOnCommandCode=FM_RENAME_FILE_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* SC start ATS (run a stored absolute-time command sequence) */
			.Command=1, .ActionOnMid={SC_CMD_MID}, .ActionOnCommandCode=SC_START_ATS_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		{ /* SC start RTS (run a stored relative-time command sequence) */
			.Command=1, .ActionOnMid={SC_CMD_MID}, .ActionOnCommandCode=SC_START_RTS_CC,
			.HaveDeactivate=0, .StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id}, .enableML=0
		},
		/*
		 * Time-adjust command counting (GNTM-7). Core cFE - unchanged from PoC.
		 * Each CFE_TIME_SET_TIME_CC increments adjust_time_id; the periodic rule
		 * on call_index 8 alerts when the count exceeds threshold.
		 */
		{
			.Command=1,
			.ActionOnMid={CFE_TIME_CMD_MID},
			.ActionOnCommandCode=CFE_TIME_SET_TIME_CC,
			.HaveDeactivate=0,
			.StixInfo={.Action=COUNT_TOTAL, .StixId=adjust_time_id},
			.enableML=0
		},
		/*
		 * Telemetry downlink latency (CSNE-41). to_lab exists on pisat, so this
		 * is kept as-is: store TO_LAB HK packets and measure inter-packet latency
		 * (read by the periodic rule on call_index 12).
		 */
		{
			.Command=0,
			.ActionOnMid={TO_LAB_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=STORE_PACKET, .StixId=tlm_downlink_id},
			.enableML=0
		},
		/* App lifecycle command -> immediate alert (state:change / SMSR-3). Core cFE. */
		{
			.Command=1,
			.ActionOnMid={CFE_ES_CMD_MID},
			.ActionOnCommandCode=CFE_ES_STOP_APP_CC,
			.HaveDeactivate=0,
			.StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id},
			.enableML=0
		},
		/* App lifecycle command -> immediate alert (state:change / SMSR-3). Core cFE. */
		{
			.Command=1,
			.ActionOnMid={CFE_ES_CMD_MID},
			.ActionOnCommandCode=CFE_ES_START_APP_CC,
			.HaveDeactivate=0,
			.StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id},
			.enableML=0
		},
		/* App lifecycle command -> immediate alert (state:change / SMSR-3). Core cFE. */
		{
			.Command=1,
			.ActionOnMid={CFE_ES_CMD_MID},
			.ActionOnCommandCode=CFE_ES_RESTART_APP_CC,
			.HaveDeactivate=0,
			.StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id},
			.enableML=0
		},
		/* App lifecycle command -> immediate alert (state:change / SMSR-3). Core cFE. */
		{
			.Command=1,
			.ActionOnMid={CFE_ES_CMD_MID},
			.ActionOnCommandCode=CFE_ES_RELOAD_APP_CC,
			.HaveDeactivate=0,
			.StixInfo={.Action=ALERT_IMMEDIATELY, .StixId=state_change_id},
			.enableML=0
		},
		/* camera: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={CAMERA_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* camera: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={CAMERA_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* eps: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={EPS_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* eps: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={EPS_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* fm: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={FM_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* fm: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={FM_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* hk: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={HK_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* hk: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={HK_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* hs: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={HS_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* hs: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={HS_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* lc: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={LC_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* lc: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={LC_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* md: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={MD_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* md: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={MD_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* mm: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={MM_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* mm: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={MM_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sc: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={SC_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sc: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={SC_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sch: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={SCH_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sch: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={SCH_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* ds: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={DS_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* ds: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={DS_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* cs: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={CS_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* cs: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={CS_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* stpyld: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={SP_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* stpyld: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={SP_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sysmon: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={SYSMON_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* sysmon: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={SYSMON_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* ci_lab: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={CI_LAB_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* ci_lab: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={CI_LAB_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* cfdp: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={CFDP_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* cfdp: HK telemetry -> ML anomaly detection */
		{
			.Command=0,
			.ActionOnMid={CFDP_HK_TLM_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		},
		/* to_lab: command stream -> ML anomaly detection */
		{
			.Command=1,
			.ActionOnMid={TO_LAB_CMD_MID},
			.ActionOnCommandCode=0,
			.HaveDeactivate=0,
			.StixInfo={.Action=0, .StixId=0},
			.enableML=1
		}
	}
};

// Table macro
CFE_TBL_FILEDEF(SPACECOP_CommandMonitorTable, SPACECOP.SC_CmdMonTbl, SP Cmd Mon Tbl, spacecop_cmdmon.tbl)
