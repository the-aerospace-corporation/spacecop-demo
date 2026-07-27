/************************************************************************
**
**      GSC-18128-1, "Core Flight Executive Version 6.7"
**
**      Copyright (c) 2006-2002 United States Government as represented by
**      the Administrator of the National Aeronautics and Space Administration.
**      All Rights Reserved.
**
**      Licensed under the Apache License, Version 2.0 (the "License");
**      you may not use this file except in compliance with the License.
**      You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**      Unless required by applicable law or agreed to in writing, software
**      distributed under the License is distributed on an "AS IS" BASIS,
**      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**      See the License for the specific language governing permissions and
**      limitations under the License.
**
** File: to_lab_sub_table.c
**
** Purpose:
**  Define TO Lab CPU specific subscription table
**
** Notes:
**
*************************************************************************/

/*
** Include Files
*/
#include "cfe_tbl_filedef.h" /* Required to obtain the CFE_TBL_FILEDEF macro definition */
#include "cfe_sb_api_typedefs.h"
#include "to_lab_sub_table.h"
#include "cfe_msgids.h"

/*
** Add the proper include file for the message IDs below
*/
#include "to_lab_msgids.h"
#include "ci_lab_msgids.h"

#include "cfdp_msgids.h"
#include "cs_msgids.h"
#include "ds_msgids.h"
#include "eps_msgids.h"
#include "fm_msgids.h"
#include "hk_msgids.h"
#include "hs_msgids.h"
#include "lc_msgids.h"
#include "md_msgids.h"
#include "mm_msgids.h"
#include "sc_msgids.h"
#include "sch_msgids.h"
#include "spacecop_msgids.h"
#include "stpyld_msgids.h"
#include "sysmon_msgids.h"
#include "camera_msgids.h"

/*
** Local Structure Declarations
*/
#define CF_CONFIG_TLM_MID 0x08B2
#define CF_PDU_TLM_MID    0x0FFD

TO_LAB_Subs_t TO_LAB_Subs =
{
    .Subs =
    {
        /* CFS App Subscriptions */
        {CFE_SB_MSGID_WRAP_VALUE(TO_LAB_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(TO_LAB_DATA_TYPES_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CI_LAB_HK_TLM_MID), {0, 0}, 4},

        {CFE_SB_MSGID_WRAP_VALUE(CS_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFDP_FILEDOWNLOAD_TLM_MID),   {0,0},  32},
        {CFE_SB_MSGID_WRAP_VALUE(DS_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(EPS_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(FM_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(FM_DIR_LIST_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(FM_FILE_INFO_TLM_MID), {0, 0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(FM_OPEN_FILES_TLM_MID), {0, 0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(FM_MONITOR_TLM_MID), {0, 0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(HK_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(HK_COMBINED_PKT1_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(HK_COMBINED_PKT2_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(HK_COMBINED_PKT3_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(HK_COMBINED_PKT4_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(HS_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(LC_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(MD_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(MD_DWELL_PKT_MID_BASE), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(MM_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(SC_HK_TLM_MID), {0,0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(SPACECOP_REPORT_TLM_MID), {0,0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(SPACECOP_HK_TLM_MID), {0,0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(SP_HK_TLM_MID), {0,0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(SYSMON_HK_TLM_MID), {0,0}, 32},
        {CFE_SB_MSGID_WRAP_VALUE(CAMERA_HK_TLM_MID), {0,0}, 32},
        
        /* cFE Core subscriptions */
        {CFE_SB_MSGID_WRAP_VALUE(CFE_ES_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_EVS_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_SB_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_TBL_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_TIME_HK_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_TIME_DIAG_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_SB_STATS_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_TBL_REG_TLM_MID), {0, 0}, 4},
        {CFE_SB_MSGID_WRAP_VALUE(CFE_EVS_LONG_EVENT_MSG_MID), {0, 0}, 32},
    }
};

CFE_TBL_FILEDEF(TO_LAB_Subs, TO_LAB_APP.TO_LAB_Subs, TO Lab Sub Tbl, to_lab_sub.tbl)
