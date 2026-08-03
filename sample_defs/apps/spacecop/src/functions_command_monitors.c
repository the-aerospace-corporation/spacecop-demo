// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file functions_command_monitors.c
 * @brief Implementation of command and telemetry monitoring functions for SpaceCop IDS
 *
 * This file implements comprehensive monitoring capabilities including:
 * - Event duration tracking with start/stop timestamps
 * - Event counting with automatic timeout handling
 * - Telemetry packet latency analysis
 * - IOB (Indicator of Behavior) detection and reporting
 * - Automatic cleanup of expired tracking entries
 *
 * All tracking structures use linked lists for dynamic memory management
 * and are designed to handle multiple concurrent tracking operations.
 */

#include "functions_command_monitors.h"

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/** @brief Head of the count/duration tracking linked list */
static CountDurationEntry_t* head = NULL;

/** @brief Tail of the count/duration tracking linked list */
static CountDurationEntry_t* tail = NULL;

/** @brief Head of the telemetry tracker linked list */
static TlmTracker_t *tlm_head = NULL;

/** @brief Tail of the telemetry tracker linked list */
static TlmTracker_t *tlm_tail = NULL;

/** @brief IOB reporter configuration array */
static ReportInfo reporter[] =
{
    { .enabled = 0, .iob = "SMSR-3" },
};

/*=======================================================================================
** Telemetry Latency Tracking Functions
**=======================================================================================*/

/**
 * @brief Store a telemetry packet for latency tracking
 *
 * Stores packet metadata including generation time and receipt time for subsequent
 * latency analysis. Automatically creates a new tracker if one doesn't exist for
 * the given reference/MsgId combination. Maintains a maximum of 2 packets per
 * tracker, removing the oldest when a third arrives.
 *
 * @param[in] reference STIX component reference ID
 * @param[in] msgid cFE Software Bus Message ID
 * @param[in] packet Pointer to pointer to packet buffer
 *
 * @return void
 *
 * @note Packets are stored in most-recent-first order
 * @note Only the seconds portion of generation time is stored to save memory
 */
void SPACECOP_StorePacket(StixComponentId_t reference, CFE_SB_MsgId_t msgid, CFE_SB_Buffer_t **packet) {
    
    if (!packet) {
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: StorePacket - NULL packet\n");
        #endif
        return;
    }
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: StorePacket for ref=%d, MsgId=0x%04X\n", 
           reference, CFE_SB_MsgIdToValue(msgid));
    #endif
    
    /* Find or create tracker for this MsgId */
    TlmTracker_t *tracker = tlm_head;
    
    while (tracker != NULL) {
        if (tracker->ReferenceId == reference && 
            CFE_SB_MsgIdToValue(tracker->MsgId) == CFE_SB_MsgIdToValue(msgid)) {
            break;
        }
        tracker = tracker->Next;
    }
    
    /* Create new tracker if not found */
    if (tracker == NULL) {
        tracker = (TlmTracker_t *)malloc(sizeof(TlmTracker_t));
        if (tracker == NULL) {
            #ifdef SPACECOP_MONITOR_DEBUG
            printf("SPACECOP: Failed to allocate tracker\n");
            #endif
            return;
        }
        
        memset(tracker, 0, sizeof(TlmTracker_t));
        tracker->MsgId = msgid;
        tracker->ReferenceId = reference;
        tracker->PacketListHead = NULL;
        tracker->PacketCount = 0;
        tracker->Next = NULL;
        
        /* Add to tracker list */
        if (tlm_head == NULL) {
            tlm_head = tracker;
            tlm_tail = tracker;
        } else {
            tlm_tail->Next = tracker;
            tlm_tail = tracker;
        }
        
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Created new tracker\n");
        #endif
    }
    
    /* Create new packet entry */
    PacketEntry_t *new_packet = (PacketEntry_t *)malloc(sizeof(PacketEntry_t));
    if (new_packet == NULL) {
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Failed to allocate packet entry\n");
        #endif
        return;
    }
    
    memset(new_packet, 0, sizeof(PacketEntry_t));
    
    /* Extract packet information */
    CFE_TIME_SysTime_t pktTime;
    CFE_MSG_GetMsgTime(&(*packet)->Msg, &pktTime);

    /* Store only seconds to save memory */
    new_packet->PacketGenTime_sec = pktTime.Seconds;
    new_packet->ReceiptTime = CFE_TIME_GetTime();
    new_packet->MsgId = msgid;
    new_packet->Next = NULL;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: New packet - GenTime=%u sec\n", new_packet->PacketGenTime_sec);
    #endif
    
    /* Add to front of packet list (most recent first) */
    new_packet->Next = tracker->PacketListHead;
    tracker->PacketListHead = new_packet;
    tracker->PacketCount++;
    
    /* Enforce max 2 packets - remove oldest if we have 3 */
    if (tracker->PacketCount > 2) {
        PacketEntry_t *current = tracker->PacketListHead;
        PacketEntry_t *prev = NULL;
        
        /* Navigate to the 2nd packet (keep head and 2nd, remove 3rd) */
        while (current != NULL && current->Next != NULL) {
            prev = current;
            current = current->Next;
        }
        
        /* Remove the oldest (3rd) packet */
        if (prev != NULL && current != NULL) {
            prev->Next = NULL;
            free(current);
            tracker->PacketCount = 2;
        }
    }
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Tracker now has %u packets\n", tracker->PacketCount);
    #endif
}

/**
 * @brief Calculate latency delta between two most recent packets
 *
 * Computes the absolute difference in latency between the two most recent
 * packets for the specified reference. Latency is defined as the time between
 * packet generation and receipt. After calculation, the older packet is
 * automatically removed from the tracker.
 *
 * @param[in] reference STIX component reference ID
 *
 * @return uint32_t Latency delta in seconds, or 0 if insufficient data
 *
 * @note Requires at least 2 packets to calculate delta
 * @note The older (second) packet is freed after calculation
 */
uint32_t SPACECOP_EvaluateLatency(StixComponentId_t reference) { 
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: EvaluateLatency for ref=%d\n", reference);
    #endif
    
    /* Find the tracker */
    TlmTracker_t *tracker = tlm_head;
    
    while (tracker != NULL) {
        if (tracker->ReferenceId == reference) {
            break;
        }
        tracker = tracker->Next;
    }
    
    if (tracker == NULL) {
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Tracker not found for ref=%d\n", reference);
        #endif
        return 0;
    }
    
    /* Check if we have at least 2 packets */
    if (tracker->PacketCount < 2) {
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Not enough packets (%u) to evaluate\n", tracker->PacketCount);
        #endif
        return 0;
    }
    
    /* Get the two most recent packets */
    PacketEntry_t *newest = tracker->PacketListHead;
    PacketEntry_t *second = newest->Next;
    
    if (!newest || !second) {
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Packet list corrupted\n");
        #endif
        return 0;
    }
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Newest packet - GenTime=%u sec\n", newest->PacketGenTime_sec);
    printf("SPACECOP: Second packet - GenTime=%u sec\n", second->PacketGenTime_sec);
    #endif
    
    /* Calculate latency for each packet (in seconds) */
    /* Latency = ReceiptTime.Seconds - PacketGenTime_sec */
    uint32_t newest_latency_sec = newest->ReceiptTime.Seconds - newest->PacketGenTime_sec;
    uint32_t second_latency_sec = second->ReceiptTime.Seconds - second->PacketGenTime_sec;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Newest latency = %u sec\n", newest_latency_sec);
    printf("SPACECOP: Second latency = %u sec\n", second_latency_sec);
    #endif
    
    /* Calculate delta (absolute difference) */
    uint32_t latency_delta;
    if (newest_latency_sec > second_latency_sec) {
        latency_delta = newest_latency_sec - second_latency_sec;
    } else {
        latency_delta = second_latency_sec - newest_latency_sec;
    }
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Latency delta = %u sec\n", latency_delta);
    #endif
    
    /* Remove the oldest packet (second) */
    newest->Next = second->Next;  /* Unlink the second packet */
    free(second);
    tracker->PacketCount--;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Tracker now has %u packets\n", tracker->PacketCount);
    #endif
    
    return latency_delta;
}

/**
 * @brief Remove stale telemetry trackers
 *
 * Scans all telemetry trackers and removes those whose most recent packet
 * is older than the cleanup timeout (120 seconds). Frees all associated
 * packet entries and the tracker itself.
 *
 * @return void
 *
 * @note Cleanup timeout is 120 seconds
 * @note Should be called periodically to prevent memory leaks
 */
void SPACECOP_CleanupTrackers(void) {
    
    #define CLEANUP_TIMEOUT_SEC 120
    
    TlmTracker_t *current = tlm_head;
    TlmTracker_t *prev = NULL;
    CFE_TIME_SysTime_t now = CFE_TIME_GetTime();
    int cleaned = 0;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Running tlm tracker cleanup\n");
    #endif
    
    while (current != NULL) {
        
        /* Check if this tracker has any packets */
        if (current->PacketListHead != NULL) {
            /* Check age of most recent packet (compare seconds only) */
            int64_t elapsed_sec = (int64_t)(now.Seconds - current->PacketListHead->ReceiptTime.Seconds);
            
            if (elapsed_sec > CLEANUP_TIMEOUT_SEC) {
                /* Remove this tracker and all its packets */
                
                #ifdef SPACECOP_MONITOR_DEBUG
                printf("SPACECOP: Removing stale tracker (ref=%d, elapsed=%ld sec)\n",
                       current->ReferenceId, elapsed_sec);
                #endif
                
                /* Free all packets in this tracker */
                PacketEntry_t *pkt = current->PacketListHead;
                while (pkt != NULL) {
                    PacketEntry_t *next_pkt = pkt->Next;
                    free(pkt);
                    pkt = next_pkt;
                }
                
                /* Remove tracker from list */
                TlmTracker_t *to_free = current;
                
                if (current == tlm_head) {
                    tlm_head = current->Next;
                    if (tlm_head == NULL) tlm_tail = NULL;
                    current = tlm_head;
                } else if (current == tlm_tail) {
                    prev->Next = NULL;
                    tlm_tail = prev;
                    current = NULL;
                } else {
                    prev->Next = current->Next;
                    current = current->Next;
                }
                
                free(to_free);
                cleaned++;
                continue;
            }
        }
        
        prev = current;
        current = current->Next;
    }
    
    #ifdef SPACECOP_MONITOR_DEBUG
    if (cleaned > 0) {
        printf("SPACECOP: Cleaned up %d stale trackers\n", cleaned);
    }
    #endif
}

/*=======================================================================================
** Count/Duration Tracking Functions
**=======================================================================================*/

/**
 * @brief Start duration tracking for a STIX component
 *
 * Creates a new tracking entry and records the start time. Prevents duplicate
 * active entries for the same reference ID. The entry remains in the list
 * until explicitly removed or set inactive.
 *
 * @param[in] reference STIX component ID to track
 *
 * @return void
 *
 * @note Does not create duplicate active entries
 */
void SPACECOP_StartCountDuration(StixComponentId_t reference){
    CountDurationEntry_t *current = head;
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Starting a new count for %d\n", reference);
    #endif

    /* Check if already exists and is active */
    while(current != NULL){
        if(current -> ReferenceId == reference && current -> Status == ACTIVE){
            #ifdef SPACECOP_MONITOR_DEBUG
            printf("SPACECOP: Entry already exists and is ACTIVE\n");
            #endif
            return;
        }
        current = current -> Next;
    }
    
    /* Allocate new entry */
    current = (CountDurationEntry_t*)malloc(sizeof(CountDurationEntry_t));
    if(current == NULL){
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Could not allocate memory for a count tracker\n");
        #endif
        return;
    }
    
    /* Initialize the new entry */
    memset(current, 0, sizeof(CountDurationEntry_t));
    current -> Next = NULL;
    current -> ReferenceId = reference;
    current -> Status = ACTIVE;
    SPACECOP_GetTime(&(current -> CountStartTime));

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Created new ACTIVE entry, start time=%u\n", current->CountStartTime.Seconds);
    #endif

    /* Add to linked list */
    if (head == NULL){
        head = current;
        tail = current;
    }
    else{
        tail -> Next = current;
        tail = current;
    }
}

/**
 * @brief Increment total event count for a STIX component
 *
 * Increments the event counter and updates the last trigger time. Creates
 * a new entry if one doesn't exist. Reactivates INACTIVE entries.
 *
 * @param[in] reference STIX component ID to increment
 *
 * @return void
 *
 * @see SPACECOP_GetCountTotal()
 */
void SPACECOP_StartCountTotal(StixComponentId_t reference)
{
    CountDurationEntry_t *current = head;
    TimeElement_t current_time;
    
    SPACECOP_GetTime(&current_time);
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: StartCountTotal for %d\n", reference);
    #endif

    /* Look for existing entry */
    while(current != NULL){
        if(current -> ReferenceId == reference){
            current -> CountTotal += 1;
            current -> LastTriggerTime = current_time;
            current -> Status = ACTIVE;
            
            #ifdef SPACECOP_MONITOR_DEBUG
            printf("SPACECOP: Incremented existing count to %d\n", current->CountTotal);
            #endif
            return;
        }
        current = current -> Next;
    }
    
    /* Create new entry if not found */
    current = (CountDurationEntry_t*)malloc(sizeof(CountDurationEntry_t));
    if(current == NULL){
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Could not allocate memory for a count tracker\n");
        #endif
        return;
    }

    /* Initialize new entry */
    memset(current, 0, sizeof(CountDurationEntry_t));
    current -> Next = NULL;
    current -> ReferenceId = reference;
    current -> CountTotal = 1;
    current -> LastTriggerTime = current_time;
    current -> Status = ACTIVE;

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Created new entry with count=1\n");
    #endif

    /* Add to linked list */
    if (head == NULL){
        head = current;
        tail = current;
    }
    else{
        tail -> Next = current;
        tail = current;
    }
}

/**
 * @brief Get total event count for a STIX component
 *
 * Returns the current event count. If more than 60 seconds have elapsed
 * since the last trigger, the count is automatically reset to 0.
 *
 * @param[in] reference STIX component ID to query
 *
 * @return int32_t Current event count, or 0 if not found or timed out
 *
 * @note Timeout period is 60 seconds
 */
int32_t SPACECOP_GetCountTotal(StixComponentId_t reference)
{
    CountDurationEntry_t *current = head;
    TimeElement_t current_time;
    int64_t elapsed_seconds;
    
    #define TIMEOUT_SECONDS 60

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: GetCountTotal for reference %d\n", reference);
    #endif

    while(current != NULL){
        if(current -> ReferenceId == reference){
            SPACECOP_GetTime(&current_time);
            
            elapsed_seconds = (int64_t)(current_time.Seconds - current->LastTriggerTime.Seconds);
            
            #ifdef SPACECOP_MONITOR_DEBUG
            printf("SPACECOP: Found reference %d, count=%d, elapsed=%ld sec\n", 
                   reference, current->CountTotal, elapsed_seconds);
            #endif
            
            /* Check if timeout expired */
            if (elapsed_seconds > TIMEOUT_SECONDS){
                #ifdef SPACECOP_MONITOR_DEBUG
                printf("SPACECOP: Timeout expired (%ld > %d), resetting count\n", 
                       elapsed_seconds, TIMEOUT_SECONDS);
                #endif
                current->CountTotal = 0;
                return 0;
            }
            
            return current->CountTotal;
        }
        current = current -> Next;
    }

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Reference %d not found, returning 0\n", reference);
    #endif
    return 0;
}

/**
 * @brief Remove expired counter entries
 *
 * Scans all counter entries and removes those that have not been triggered
 * for more than 120 seconds. Prevents memory leaks from abandoned counters.
 *
 * @return void
 *
 * @note Cleanup timeout is 120 seconds
 */
void SPACECOP_CleanupExpiredCounters(void)
{
    CountDurationEntry_t *current = head, *prev = NULL, *temp;
    TimeElement_t current_time;
    int64_t elapsed_seconds;
    int cleaned = 0;
    
    #define CLEANUP_TIMEOUT_SECONDS 120 
    
    SPACECOP_GetTime(&current_time);

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Running cleanup, current time=%u\n", current_time.Seconds);
    #endif

    while(current != NULL){
        elapsed_seconds = (int64_t)(current_time.Seconds - current->LastTriggerTime.Seconds);
        
        if (elapsed_seconds > CLEANUP_TIMEOUT_SECONDS){
            #ifdef SPACECOP_MONITOR_DEBUG
            printf("SPACECOP: Removing expired entry for reference %d (elapsed=%ld sec)\n", 
                   current->ReferenceId, elapsed_seconds);
            #endif
            
            temp = current;
            cleaned++;
            
            /* Remove from list */
            if (current == head){
                head = current -> Next;
                if (head == NULL) tail = NULL;
                current = head;
            }
            else if (current == tail){
                prev -> Next = NULL;
                tail = prev;
                current = NULL;
            }
            else{
                prev -> Next = current -> Next;
                current = current -> Next;
            }
            
            free(temp);
        }
        else{
            prev = current;
            current = current -> Next;
        }
    }

    #ifdef SPACECOP_MONITOR_DEBUG
    if(cleaned > 0) {
        printf("SPACECOP: Cleaned up %d expired entries\n", cleaned);
    }
    #endif
}

/**
 * @brief Calculate duration and remove inactive tracking entry
 *
 * Calculates the time delta between start and end times. For INACTIVE entries,
 * uses the recorded end time and removes the entry from the list. For ACTIVE
 * entries, uses current time but does not remove the entry.
 *
 * @param[in] reference STIX component ID to process
 *
 * @return TimeElement_t Duration delta with Seconds and Microseconds fields
 *
 * @note Only INACTIVE entries are removed from the list
 * @note Handles microsecond underflow correctly
 */
TimeElement_t SPACECOP_RemoveCountDurationIfInactive(StixComponentId_t reference){
    CountDurationEntry_t *current = head, *prev = NULL;
    TimeElement_t compare_time, start_time;
    TimeElement_t delta = {
        .Seconds=0,
        .Microseconds=0
    };
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: RemoveCountDurationIfInactive called for ref %d\n", reference);
    #endif
    
    /* Find the entry */
    while(current != NULL && current -> ReferenceId != reference){
        prev = current;
        current = current -> Next;  
    }

    if (current == NULL){
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Reference %d not found in list\n", reference);
        #endif
        return delta;
    }

    start_time = current -> CountStartTime;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Found entry, Status=%s, start_time=%u\n", 
           current->Status == ACTIVE ? "ACTIVE" : "INACTIVE",
           start_time.Seconds);
    #endif

    if (current -> Status == INACTIVE){
        /* Use the recorded end time */
        compare_time = current -> CountEndTime;
        
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Entry is INACTIVE, end_time=%u\n", compare_time.Seconds);
        #endif
        
        /* Remove from list */
        if (current == head){
            head = current -> Next;
            if (head == NULL) tail = NULL;
        }
        else if (current == tail){
            prev -> Next = NULL;
            tail = prev;
        }
        else{
            prev -> Next = current -> Next;
        }

        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Removed INACTIVE entry from list\n");
        #endif
        
        free(current);
    }
    else{
        /* Entry is still ACTIVE - use current time */
        SPACECOP_GetTime(&compare_time);
        
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Entry is ACTIVE, using current_time=%u\n", compare_time.Seconds);
        #endif
    }
    
    /* Calculate duration */
    delta.Seconds = compare_time.Seconds - start_time.Seconds;
    delta.Microseconds = compare_time.Microseconds - start_time.Microseconds;
    
    /* Handle microsecond underflow */
    if (delta.Microseconds < 0) {
        delta.Seconds -= 1;
        delta.Microseconds += 1000000;
    }

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Calculated delta: %u.%06u seconds\n", 
           delta.Seconds, delta.Microseconds);
    #endif

    return delta;
}

/**
 * @brief Check current duration without removing entry
 *
 * Calculates the current duration for a tracking entry. Uses CountEndTime
 * for INACTIVE entries, or current time for ACTIVE entries. Does not modify
 * or remove the entry.
 *
 * @param[in] reference STIX component ID to query
 *
 * @return TimeElement_t Current duration, or zero if not found
 */
TimeElement_t SPACECOP_CheckCountDuration(StixComponentId_t reference){
    CountDurationEntry_t *current = head;
    TimeElement_t current_time;
    TimeElement_t delta = {
        .Seconds=0,
        .Microseconds=0
    };
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: CheckCountDuration for ref %d\n", reference);
    #endif
    
    /* Find the entry */
    while(current != NULL && current -> ReferenceId != reference){
        current = current -> Next;  
    }

    if (current == NULL){
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Reference %d not found\n", reference);
        #endif
        return delta;
    }
    
    /* Get appropriate end time */
    if (current -> Status == INACTIVE){
        current_time = current -> CountEndTime;
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Entry is INACTIVE, using end_time=%u\n", current_time.Seconds);
        #endif
    }
    else{
        SPACECOP_GetTime(&current_time);
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Entry is ACTIVE, using current_time=%u\n", current_time.Seconds);
        #endif
    }

    /* Calculate duration */
    delta.Seconds = current_time.Seconds - current -> CountStartTime.Seconds;
    delta.Microseconds = current_time.Microseconds - current -> CountStartTime.Microseconds;
    
    /* Handle microsecond underflow */
    if (delta.Microseconds < 0) {
        delta.Seconds -= 1;
        delta.Microseconds += 1000000;
    }

    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: Duration: %u.%06u seconds\n", delta.Seconds, delta.Microseconds);
    #endif

    return delta;
}

/**
 * @brief Mark a tracking entry as inactive
 *
 * Sets the status to INACTIVE and records the current time as the end time.
 * This prepares the entry for removal by SPACECOP_RemoveCountDurationIfInactive().
 *
 * @param[in] reference STIX component ID to mark inactive
 *
 * @return void
 */
void SPACECOP_SetEntryInactive(StixComponentId_t reference){
    CountDurationEntry_t *current = head;
    TimeElement_t current_time;
    
    #ifdef SPACECOP_MONITOR_DEBUG
    printf("SPACECOP: SetEntryInactive for ref %d\n", reference);
    #endif
    
    /* Find the entry */
    while(current != NULL && current -> ReferenceId != reference){
        current = current -> Next;
    }
    
    if (current != NULL){
        current -> Status = INACTIVE;
        SPACECOP_GetTime(&current_time);
        current -> CountEndTime = current_time;
        
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Set entry INACTIVE, end_time=%u\n", current_time.Seconds);
        #endif
    }
    else{
        #ifdef SPACECOP_MONITOR_DEBUG
        printf("SPACECOP: Reference %d not found, cannot set INACTIVE\n", reference);
        #endif
    }
}

/*=======================================================================================
** IOB Reporting Functions
**=======================================================================================*/

/**
 * @brief Toggle IOB reporter enable/disable state
 *
 * Searches the reporter array for the specified IOB identifier and toggles
 * its enabled flag. When disabled, no alerts will be generated for that IOB.
 *
 * @param[in] iob IOB identifier string (e.g., "SMSR-3")
 *
 * @return void
 */
void Toggle_Reporter(const char *iob)
{   
    for (uint32_t i = 0; i < (sizeof(reporter) / sizeof(reporter[0])); i++)
    {
        if (strcmp(reporter[i].iob, iob) == 0)
        {
            printf("Toggling %s\n", iob);
            reporter[i].enabled = !reporter[i].enabled;
        }
    }
}

/**
 * @brief Check if an IOB reporter is enabled
 *
 * Internal helper function to determine if alerts should be generated
 * for a specific IOB type.
 *
 * @param[in] iob IOB identifier string
 *
 * @return int8_t 1 if enabled, 0 if disabled or not found
 */
static int8_t IsReporterEnabled(const char* iob)
{
    for (uint32_t i = 0; i < (sizeof(reporter) / sizeof(reporter[0])); i++)
    {
        if (strcmp(reporter[i].iob, iob) == 0)
            return reporter[i].enabled;
    }
    return 0;
}

/**
 * @brief Process and report command messages immediately
 *
 * Monitors cFE Executive Services commands for application lifecycle events
 * (start, stop, restart, reload). When an enabled IOB is detected, generates
 * an IDS alert message, writes a STIX report, and sends a cFE event message.
 *
 * Currently monitors:
 * - CFE_ES_STOP_APP_CC: Application stopped
 * - CFE_ES_START_APP_CC: Application started
 * - CFE_ES_RESTART_APP_CC: Application restarted
 * - CFE_ES_RELOAD_APP_CC: Application reloaded
 *
 * All events are reported under SPARTA ID SMSR-3 if that reporter is enabled.
 *
 * @param[in] MonitorMsgPtr Pointer to cFE message to analyze
 *
 * @return void
 *
 * @note Sends error event if message ID is not recognized
 */
void SPACECOP_ReportImmediately(CFE_MSG_Message_t* MonitorMsgPtr)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(MonitorMsgPtr, &MsgId);
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(MonitorMsgPtr, &CommandCode);

    char message[IDS_REPORT_MESSAGE_LEN];
    
    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case CFE_ES_CMD_MID:
            switch (CommandCode)
            {
                case CFE_ES_STOP_APP_CC:
                    if (IsReporterEnabled("SMSR-3")) {
                        const CFE_ES_StopAppCmd_t *CmdPtr = (const CFE_ES_StopAppCmd_t *)MonitorMsgPtr;
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Stopped: %s)", CmdPtr->Payload.Application);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(CmdPtr->Payload.Application, NULL, "SMSR-3");
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Stopped: %s)", CmdPtr->Payload.Application);
                    }
                    break;
                    
                case CFE_ES_START_APP_CC:
                    if (IsReporterEnabled("SMSR-3")) {
                        const CFE_ES_StartAppCmd_t *CmdPtr = (const CFE_ES_StartAppCmd_t *)MonitorMsgPtr;
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Started: %s)", CmdPtr->Payload.Application);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(CmdPtr->Payload.Application, NULL, "SMSR-3");
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Started: %s)", CmdPtr->Payload.Application);
                    }
                    break;
                    
                case CFE_ES_RESTART_APP_CC:
                    if (IsReporterEnabled("SMSR-3")) {
                        const CFE_ES_StopAppCmd_t *CmdPtr = (const CFE_ES_StopAppCmd_t *)MonitorMsgPtr;
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Restarted: %s)", CmdPtr->Payload.Application);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(CmdPtr->Payload.Application, NULL, "SMSR-3");
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Restarted: %s)", CmdPtr->Payload.Application);
                    }
                    break;
                    
                case CFE_ES_RELOAD_APP_CC:
                    if (IsReporterEnabled("SMSR-3")) {
                        const CFE_ES_ReloadAppCmd_t *CmdPtr = (const CFE_ES_ReloadAppCmd_t *)MonitorMsgPtr;
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Reloaded: %s)", CmdPtr->Payload.Application);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(CmdPtr->Payload.Application, NULL, "SMSR-3");
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, "[SPACECOP] IOB Detected: SPARTA ID=SMSR-3 (App Reloaded: %s)", CmdPtr->Payload.Application);
                    }
                    break;
                    
                default:
                    break;
            }
            break;
            
        default:
            CFE_EVS_SendEvent(SPACECOP_PROCESS_CMD_ERR_EID, CFE_EVS_EventType_ERROR, 
                "SPACECOP: Invalid command packet in runtime, MID = 0x%x", 
                CFE_SB_MsgIdToValue(MsgId));
            break;
    }
}