// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file ml_interface.c
 * @brief Implementation of Machine Learning bridge for SpaceCop IDS
 *
 * This file implements a bidirectional communication bridge between SpaceCop
 * and an external Machine Learning anomaly detection system. The system operates
 * in two modes:
 *
 * **Telemetry Streaming (SpaceCop → ML Server):**
 * - Converts binary telemetry to hexadecimal format
 * - Sends via TCP socket to ML server (port 9111)
 * - Automatic reconnection on connection loss
 * - Retry logic with fixed reconnection intervals (see Error Handling below)
 *
 * **Alert Reception (ML Server → SpaceCop):**
 * - Listens for JSON-formatted alerts on TCP port 9112
 * - Blocking accept() and recv() for reliable message delivery
 * - Parses JSON alerts into structured data
 * - Generates multi-channel IDS alerts
 *
 * **Supported Alert Types:**
 * 1. ML_ANOMALY (UACE-16): Statistical deviations detected by ML models
 *    - Includes MSE (Mean Squared Error) and responsible feature
 *    - Used for telemetry anomaly detection
 *
 * 2. COMMAND_FLOODING (UACE-9): Excessive command rates
 *    - Tracks commands per minute against threshold
 *    - Detects DoS attempts via command flooding
 *
 * 3. REPLAY_ATTACK (UACE-7): Duplicate command patterns
 *    - Detects repeated identical commands
 *    - Prevents replay-based attacks
 *
 * **Architecture:**
 * - TCP sockets (not UDP) for reliable delivery
 * - Separate send and receive sockets
 * - Blocking I/O on receive socket (runs in dedicated thread/task)
 * - Blocking send with automatic reconnection
 * - JSON parsing using simple string extraction
 * - IOB mapping via configuration table
 *
 * **Error Handling:**
 * - Automatic reconnection on send failures (30 retries, 10s intervals)
 * - Graceful handling of client disconnections
 * - Connection state monitoring via getsockopt()
 * - Partial send detection and logging
 */

#include "ml_interface.h"
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <dirent.h>

/* Minimum seconds between ML-sender reconnect attempts on the telemetry drain
** path. Bounds reconnect cost so a down/slow ML server can never stall the
** drain (which would overflow MonitorMLPipe and starve higher-priority work). */
#define ML_RECONNECT_MIN_SEC 5

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/** @brief Global ML Bridge application data */
/* Sockets start at -1 (not the zero-initialized 0, which is a live fd = stdin).
** A 0 here makes the "recv_sockfd < 0" guard below pass and accept() run on
** stdin -> "Socket operation on non-socket" (ENOTSOCK). */
MLBridge_AppData_t MLBridge_AppData = { .send_sockfd = -1, .recv_sockfd = -1 };

/**
 * @brief ML monitor configuration table
 *
 * Maps IOB identifiers to message IDs and tracks enable state for each
 * ML-based detection capability.
 */
static MLMonitorInfo mlmonitor[] =
{
    { .enabled = 0, .iob = "UACE-16", .mid = "GENERIC_THRUSTER_HK_TLM_MID" },
    { .enabled = 0, .iob = "UACE-7", .mid = "REPLAY_ATTACK" },
    { .enabled = 0, .iob = "UACE-9", .mid = "COMMAND_FLOODING" },
};

/** @brief Number of entries in ML monitor table */
#define MLMONITOR_COUNT (sizeof(mlmonitor) / sizeof(mlmonitor[0]))

/*=======================================================================================
** Monitor Control Functions
**=======================================================================================*/

/**
 * @brief Toggle ML monitoring on/off for a specific IOB
 *
 * Enables or disables ML-based monitoring for the specified IOB. When disabled,
 * telemetry is not sent to the ML server for that IOB and alerts are not generated.
 *
 * @param[in] iob IOB identifier string
 *
 * @return void
 */
void Toggle_MLMonitor(const char *iob)
{
    for (uint32_t i = 0; i < (sizeof(mlmonitor) / sizeof(mlmonitor[0])); i++)
    {
        if (strcmp(mlmonitor[i].iob, iob) == 0)
            mlmonitor[i].enabled = !mlmonitor[i].enabled;
    }
}

/*=======================================================================================
** JSON Parsing Helper Functions
**=======================================================================================*/

/**
 * @brief Extract a string field value from JSON
 *
 * Performs simple JSON parsing to extract a string value for the specified
 * field name. Searches for pattern "field_name":"value" and extracts the value.
 *
 * @param[in] json JSON string to parse
 * @param[in] field_name Name of the field to extract
 *
 * @return const char* Pointer to static buffer containing the value, or NULL if not found
 *
 * @note Returns pointer to static buffer - not thread-safe
 * @note Does not handle escaped quotes in values
 * @note Maximum value length is 511 characters
 */
static const char* extract_json_string(const char* json, const char* field_name)
{
    static char value_buffer[512];
    char search_pattern[128];
    
    /* Build search pattern: "field_name":" */
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":\"", field_name);
    
    /* Find the field */
    const char* start = strstr(json, search_pattern);
    if (start == NULL) {
        return NULL;
    }
    
    /* Move past the search pattern */
    start += strlen(search_pattern);
    
    /* Find the closing quote */
    const char* end = strchr(start, '"');
    if (end == NULL) {
        return NULL;
    }
    
    /* Extract the value */
    size_t len = end - start;
    if (len >= sizeof(value_buffer)) {
        len = sizeof(value_buffer) - 1;
    }
    
    strncpy(value_buffer, start, len);
    value_buffer[len] = '\0';
    
    return value_buffer;
}

/**
 * @brief Extract an integer field value from JSON
 *
 * Performs simple JSON parsing to extract an integer value for the specified
 * field name. Searches for pattern "field_name":value and parses the integer.
 *
 * @param[in] json JSON string to parse
 * @param[in] field_name Name of the field to extract
 *
 * @return int The integer value, or -1 if not found or parse error
 *
 * @note Does not distinguish between "not found" and actual value of -1
 */
static int extract_json_int(const char* json, const char* field_name)
{
    char search_pattern[128];
    
    /* Build search pattern: "field_name": */
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);
    
    /* Find the field */
    const char* start = strstr(json, search_pattern);
    if (start == NULL) {
        return -1;
    }
    
    /* Move past the search pattern */
    start += strlen(search_pattern);
    
    /* Skip whitespace */
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    
    /* Parse the integer */
    int value = 0;
    if (sscanf(start, "%d", &value) == 1) {
        return value;
    }
    
    return -1;
}

/**
 * @brief Extract a floating-point field value from JSON
 *
 * Performs simple JSON parsing to extract a double value for the specified
 * field name. Searches for pattern "field_name":value and parses the float.
 *
 * @param[in] json JSON string to parse
 * @param[in] field_name Name of the field to extract
 *
 * @return double The floating-point value, or -1.0 if not found or parse error
 *
 * @note Does not distinguish between "not found" and actual value of -1.0
 */
static double extract_json_float(const char* json, const char* field_name)
{
    char search_pattern[128];
    
    /* Build search pattern: "field_name": */
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);
    
    /* Find the field */
    const char* start = strstr(json, search_pattern);
    if (start == NULL) {
        return -1.0;
    }
    
    /* Move past the search pattern */
    start += strlen(search_pattern);
    
    /* Skip whitespace */
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    
    /* Parse the float */
    double value = 0.0;
    if (sscanf(start, "%lf", &value) == 1) {
        return value;
    }
    
    return -1.0;
}

/*=======================================================================================
** IOB Mapping Functions
**=======================================================================================*/

/**
 * @brief Map alert type to IOB identifier
 *
 * Converts an AlertType_t enumeration to the corresponding IOB identifier
 * by looking up the alert type in the ML monitor configuration table.
 *
 * @param[in] alert_type Alert type enumeration value
 *
 * @return const char* IOB identifier string, or NULL if not found or disabled
 *
 * @note Returns NULL if the corresponding monitor is disabled
 * @note Checks enabled flag before returning IOB
 */
const char* MLBridge_GetIOBFromAlertType(AlertType_t alert_type)
{
    const char* mid_name = NULL;
    
    /* Map alert type to MID name */
    switch (alert_type) {
        case ALERT_TYPE_REPLAY_ATTACK:
            mid_name = "REPLAY_ATTACK";
            break;
        case ALERT_TYPE_COMMAND_FLOODING:
            mid_name = "COMMAND_FLOODING";
            break;
        case ALERT_TYPE_ML_ANOMALY:
            mid_name = "ML_ANOMALY";
            break;
        default:
            return NULL;
    }
    
    /* Search table for matching MID */
    for (int i = 0; i < MLMONITOR_COUNT; i++) {
        if (strcmp(mid_name, mlmonitor[i].mid) == 0) {
            if (mlmonitor[i].enabled) {
                return mlmonitor[i].iob;
            }
            else {
                printf("[SPACECOP] IOB not enabled\n");
                return NULL;
            }
        }
    }
    
    fflush(stdout);
    return NULL;
}

/**
 * @brief Extract IOB identifier from JSON response
 *
 * Parses a JSON response to extract the telemetry name, converts it to MID
 * format, and looks up the corresponding IOB in the configuration table.
 *
 * Expected JSON format: {"name":"GENERIC_THRUSTER_HK_TLM", ...}
 * Converted to MID: "GENERIC_THRUSTER_HK_TLM_MID"
 *
 * @param[in] json_buffer JSON string to parse
 *
 * @return const char* IOB identifier string, or NULL if not found
 *
 * @note Uses static buffers - not thread-safe
 * @note Appends "_MID" to telemetry name for lookup
 */
const char* MLBridge_GetIOBFromResponse(const char* json_buffer)
{
    /* Extract the "name" field from JSON */
    const char *name_start = strstr(json_buffer, "\"name\":\"");
    if (name_start == NULL) {
        return NULL;
    }
    
    /* Move past "name":" */
    name_start += 8;  /* strlen("\"name\":\"") */
    
    /* Find the closing quote */
    const char *name_end = strchr(name_start, '"');
    if (name_end == NULL) {
        return NULL;
    }
    
    /* Extract the telemetry name */
    static char tlm_name[60];
    size_t name_len = name_end - name_start;
    if (name_len >= sizeof(tlm_name)) {
        name_len = sizeof(tlm_name) - 1;
    }
    strncpy(tlm_name, name_start, name_len);
    tlm_name[name_len] = '\0';
    
    /* Convert TLM name to MID format by appending "_MID" */
    static char mid_name[64];
    snprintf(mid_name, sizeof(mid_name), "%s_MID", tlm_name);
    
    /* Search table for matching MID */
    for (int i = 0; i < MLMONITOR_COUNT; i++) {
        if (strcmp(mid_name, mlmonitor[i].mid) == 0) {
            return mlmonitor[i].iob;
        }
    }
    
    fflush(stdout);
    return NULL;
}

/*=======================================================================================
** Socket Connection Management Functions
**=======================================================================================*/

/**
 * @brief Attempt to reconnect the sender socket
 *
 * Closes the existing sender socket and attempts to reconnect to the ML server
 * on port 9111. Retries up to 30 times with 10-second intervals between attempts.
 *
 * @return int32_t CFE_SUCCESS on successful reconnection, error code on failure
 *
 * @note Blocks for up to 5 minutes (30 retries × 10 seconds)
 * @note Prints status messages to stdout
 * @note Sends cFE event on successful reconnection
 */
static int32_t MLBridge_ReconnectSender(void)
{
    struct sockaddr_in server_addr;
    int retry_count = 0;
    /* Single fast attempt: connect() to localhost fails immediately when the ML
    ** server is down (ECONNREFUSED), so we never block here. Callers on the drain
    ** path rate-limit how often they invoke this (ML_RECONNECT_MIN_SEC). */
    const int MAX_RETRIES = 1;
    
    /* Close existing socket if open */
    if (MLBridge_AppData.send_sockfd >= 0) {
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
    }
    
    /* Retry loop */
    while (retry_count < MAX_RETRIES) {
        /* Create new socket */
        MLBridge_AppData.send_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (MLBridge_AppData.send_sockfd < 0) {
            printf("[SPACECOP] Failed to create sender socket: %s\n", strerror(errno));
            fflush(stdout);
            retry_count++;
            continue;
        }
        
        /* Configure server address */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(ML_SEND_PORT);
        inet_pton(AF_INET, ML_SERVER_IP, &server_addr.sin_addr);
        
        /* Attempt connection */
        if (connect(MLBridge_AppData.send_sockfd, 
                    (struct sockaddr*)&server_addr, 
                    sizeof(server_addr)) == 0) {
            printf("[SPACECOP] Successfully reconnected to port 9111\n");
            fflush(stdout);
            return CFE_SUCCESS;
        }
        
        /* Connection failed - close socket and retry */
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
        
        retry_count++;
        printf("[SPACECOP] Reconnection attempt %d/%d failed: %s\n", 
               retry_count, MAX_RETRIES, strerror(errno));
        printf("[SPACECOP] Retrying in 10 seconds...\n");
        fflush(stdout);
        
        if (retry_count < MAX_RETRIES) {
            sleep(10);
        }
    }
    
    printf("[SPACECOP] Failed to reconnect after %d attempts\n", MAX_RETRIES);
    fflush(stdout);
    return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
}

/*=======================================================================================
** Public Socket Communication Functions
**=======================================================================================*/

/*
 * Reclaim ML_RECV_PORT if a previous instance of this app leaked the listening
 * socket within the SAME process. cFS runs all apps in one process, so after an
 * app reload force-deletes our tasks (before MLBridge_Cleanup could run), the
 * orphaned listener fd survives in /proc/self/fd -- but its number is lost, so a
 * plain close() can't reach it and bind() keeps failing "Address already in use"
 * (SO_REUSEADDR does NOT override a live listener). Walk our fd table, find any
 * AF_INET *listening* socket bound to `port`, and close it. Returns count closed.
 * A holder in a DIFFERENT process cannot be reclaimed here -- that needs the
 * stale process to be killed.
 */
static int MLBridge_ReclaimLeakedPort(uint16_t port)
{
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return 0;
    }

    int closed = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        int fd = atoi(ent->d_name);
        if (fd <= 2) {
            continue;   /* skip stdio, and "."/".." (atoi -> 0) */
        }

        struct sockaddr_in sa;
        socklen_t salen = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &salen) != 0) {
            continue;   /* not a socket, or not bound */
        }
        if (sa.sin_family != AF_INET || ntohs(sa.sin_port) != port) {
            continue;
        }

        /* Only close a *listening* socket -- not an accepted connection that
        ** merely shares the local port 9112. */
        int is_listener = 0;
        socklen_t optlen = sizeof(is_listener);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &is_listener, &optlen) == 0
            && is_listener) {
            close(fd);
            closed++;
        }
    }

    closedir(d);
    return closed;
}

/**
 * @brief Initialize TCP sockets for ML communication
 *
 * Creates and configures two TCP sockets:
 * 1. Send socket: Connects to ML server on port 9111 (with retry logic)
 * 2. Receive socket: Listens for ML server connections on port 9112
 *
 * The receive socket is configured with SO_REUSEADDR to allow quick restart
 * and is placed in listening mode with a backlog of 1.
 *
 * @return int32_t CFE_SUCCESS on success, error code on failure
 *
 * @note Sender connection failure is not fatal (will retry on first send)
 * @note Receiver socket must bind and listen successfully
 * @note Sends cFE events for connection status
 */
int32_t MLBridge_InitSockets(void)
{
    struct sockaddr_in server_addr;
    int opt = 1;
    int retry_count = 0;
    const int MAX_RETRIES = 5;
    bool send_connected = false;
    
    /*=======================================================================================
    ** Initialize Receiver Socket (Port 9112)
    **=======================================================================================*/
    
    /* Idempotent: close any sockets left over from a previous init BEFORE
    ** creating new ones. Without this, re-entering InitSockets (after an app
    ** reload, or when the recv path re-initializes) overwrites recv_sockfd with
    ** a fresh socket while the old one still holds ML_RECV_PORT -- so bind()
    ** fails "Address already in use" and the old listener is leaked with its fd
    ** lost, wedging port 9112 until the process exits. Close-then-recreate lets
    ** us reclaim the port cleanly. */
    if (MLBridge_AppData.recv_sockfd >= 0) {
        close(MLBridge_AppData.recv_sockfd);
        MLBridge_AppData.recv_sockfd = -1;
    }
    if (MLBridge_AppData.send_sockfd >= 0) {
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
    }

    /* Reclaim a listener leaked by a previous instance whose fd we no longer
    ** track (e.g. an app reload that force-deleted our tasks). Without this,
    ** bind() below fails "Address already in use" and SO_REUSEADDR can't help. */
    {
        int reclaimed = MLBridge_ReclaimLeakedPort(ML_RECV_PORT);
        if (reclaimed > 0) {
            printf("[SPACECOP] Reclaimed %d leaked listener(s) on port %d\n",
                   reclaimed, ML_RECV_PORT);
            fflush(stdout);
        }
    }

    /* Create receiver socket */
    MLBridge_AppData.recv_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (MLBridge_AppData.recv_sockfd < 0) {
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_ERROR, 
                         "Failed to create receiver socket: %s", strerror(errno));
        if (MLBridge_AppData.send_sockfd >= 0) {
            close(MLBridge_AppData.send_sockfd);
        }
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Set SO_REUSEADDR to allow quick restart */
    if (setsockopt(MLBridge_AppData.recv_sockfd, SOL_SOCKET, SO_REUSEADDR, 
                   &opt, sizeof(opt)) < 0) {
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_ERROR, 
                         "Failed to set socket options: %s", strerror(errno));
        if (MLBridge_AppData.send_sockfd >= 0) {
            close(MLBridge_AppData.send_sockfd);
        }
        close(MLBridge_AppData.recv_sockfd);
        MLBridge_AppData.recv_sockfd = -1;
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Bind to port 9112 on all interfaces */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(ML_RECV_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(MLBridge_AppData.recv_sockfd, 
             (struct sockaddr*)&server_addr, 
             sizeof(server_addr)) < 0) {
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_ERROR, 
                         "Failed to bind to port %d: %s", ML_RECV_PORT, strerror(errno));
        if (MLBridge_AppData.send_sockfd >= 0) {
            close(MLBridge_AppData.send_sockfd);
        }
        close(MLBridge_AppData.recv_sockfd);
        MLBridge_AppData.recv_sockfd = -1;
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Start listening with backlog of 1 */
    if (listen(MLBridge_AppData.recv_sockfd, 5) < 0) {
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_ERROR, 
                         "Failed to listen on port %d: %s", ML_RECV_PORT, strerror(errno));
        if (MLBridge_AppData.send_sockfd >= 0) {
            close(MLBridge_AppData.send_sockfd);
        }
        close(MLBridge_AppData.recv_sockfd);
        MLBridge_AppData.recv_sockfd = -1;
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    printf("[SPACECOP] Successfully listening on port %d\n", ML_RECV_PORT);
    fflush(stdout);

    /*=======================================================================================
    ** Initialize Sender Socket (Port 9111) with Retry Logic
    **=======================================================================================*/
    
    /* Try to connect sender socket with limited retries */
    while (retry_count < MAX_RETRIES) {
        MLBridge_AppData.send_sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (MLBridge_AppData.send_sockfd < 0) {
            printf("[SPACECOP] Failed to create sender socket: %s\n", strerror(errno));
            fflush(stdout);
            retry_count++;
            sleep(2);
            continue;
        }
        
        /* Configure ML server address */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(ML_SEND_PORT);
        inet_pton(AF_INET, ML_SERVER_IP, &server_addr.sin_addr);
        
        /* Attempt connection */
        if (connect(MLBridge_AppData.send_sockfd, 
                    (struct sockaddr*)&server_addr, 
                    sizeof(server_addr)) == 0) {
            printf("[SPACECOP] Successfully connected to port 9111\n");
            fflush(stdout);
            send_connected = true;
            break;
        }
        
        /* Connection failed */
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
        
        retry_count++;
        printf("[SPACECOP] Failed to connect to port 9111 (attempt %d/%d): %s\n", 
               retry_count, MAX_RETRIES, strerror(errno));
        fflush(stdout);
        
        if (retry_count < MAX_RETRIES) {
            sleep(2);
        }
    }
    
    /* Handle sender connection failure (non-fatal) */
    if (!send_connected) {
        printf("[SPACECOP] Could not connect to port 9111 initially - will retry on first send\n");
        fflush(stdout);
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_INFORMATION, 
                         "Could not connect to port 9111 - will retry later");
        MLBridge_AppData.send_sockfd = -1;
    } else {
        CFE_EVS_SendEvent(0, CFE_EVS_EventType_INFORMATION, 
                         "Connected to ML server on port 9111");
    }
    
    CFE_EVS_SendEvent(0, CFE_EVS_EventType_INFORMATION, 
                     "ML Bridge initialized (send:%s, listening on %d)", 
                     send_connected ? "connected to 9111" : "will retry 9111", 
                     ML_RECV_PORT);
    
    return CFE_SUCCESS;
}

/**
 * @brief Send raw telemetry data to ML server as hexadecimal
 *
 * Converts binary telemetry data to hexadecimal string format and transmits
 * it to the ML server via TCP socket. Handles connection failures with
 * automatic reconnection and retry logic.
 *
 * Process:
 * 1. Validate socket connection state
 * 2. Convert binary data to hex string
 * 3. Append newline delimiter
 * 4. Send via TCP socket
 * 5. Retry on connection failure
 *
 * @param[in] data Pointer to binary telemetry data
 * @param[in] length Length of data in bytes
 * @param[in] msg_id cFE Software Bus Message ID
 *
 * @return int32_t CFE_SUCCESS on success, error code on failure
 *
 * @note Maximum data length is 4095 bytes (8190 hex chars + newline + null)
 * @note Automatically reconnects on EPIPE, ECONNRESET, ENOTCONN, EBADF
 * @note Prints warnings for partial sends
 * @note Uses static buffer - not thread-safe
 */
int32_t MLBridge_SendRawHex(const uint8_t *data, size_t length, CFE_SB_MsgId_t msg_id)
{
    static char hex_buffer[8192];
    static time_t last_reconnect_attempt = 0;
    size_t hex_offset = 0;
    int bytes_sent;

    /* Best-effort forward on the ML drain task -- it must NEVER stall. A stall
    ** backs up MonitorMLPipe ("Pipe Overflow") and, because this task outranks
    ** the main task, also starves command/HK processing. If the send socket is
    ** down, attempt to reconnect at most once every ML_RECONNECT_MIN_SEC and
    ** otherwise drop this sample. */
    if (MLBridge_AppData.send_sockfd < 0) {
        time_t now = time(NULL);
        if ((now - last_reconnect_attempt) < ML_RECONNECT_MIN_SEC) {
            return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;   /* not connected -- drop, don't stall */
        }
        last_reconnect_attempt = now;
        if (MLBridge_ReconnectSender() != CFE_SUCCESS) {
            return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
        }
    }

    /* Validate data pointer */
    if (data == NULL) {
        printf("[SPACECOP] ERROR: data is NULL\n");
        fflush(stdout);
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Limit length to prevent buffer overflow */
    size_t max_len = (sizeof(hex_buffer) - 2) / 2;
    if (length > max_len) {
        length = max_len;
    }
    
    /* Convert binary data to hexadecimal string */
    for (size_t i = 0; i < length; i++) {
        hex_offset += snprintf(hex_buffer + hex_offset, 
                              sizeof(hex_buffer) - hex_offset, 
                              "%02X", 
                              data[i]);
    }
    
    /* Add newline delimiter */
    hex_buffer[hex_offset] = '\n';
    hex_offset++;
    hex_buffer[hex_offset] = '\0';
    
    /* Non-blocking send: a slow/backed-up ML consumer must not block this task. */
    bytes_sent = send(MLBridge_AppData.send_sockfd, hex_buffer, hex_offset, MSG_DONTWAIT);

    /* Handle send errors */
    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket buffer full -- ML consumer is behind. Drop this sample
            ** rather than blocking; the next sample will try again. */
            return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
        }
        /* Connection-level error: tear the socket down so the rate-limited
        ** reconnect at the top re-establishes it on a later call. */
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
        return CFE_STATUS_EXTERNAL_RESOURCE_FAIL;
    }
    
    /* Warn on partial send */
    if (bytes_sent != (int)hex_offset) {
        printf("[SPACECOP] WARNING: Partial send! Sent %d of %zu bytes\n", 
               bytes_sent, hex_offset);
        fflush(stdout);
    }
    
    fflush(stdout);
    
    return CFE_SUCCESS;
}

/*=======================================================================================
** Alert Parsing and Handling Functions
**=======================================================================================*/

/**
 * @brief Parse JSON alert message into structured data
 *
 * Extracts fields from a JSON alert message and populates a ParsedAlert_t
 * structure. Handles three alert types with different field requirements:
 *
 * - REPLAY_ATTACK: Extracts hex pattern
 * - COMMAND_FLOODING: Extracts system, data_type, current_rate, threshold
 * - ML_ANOMALY: Extracts system, data_type, MSE, threshold, responsible_feature
 *
 * @param[in] json_buffer JSON string to parse
 * @param[out] alert Pointer to ParsedAlert_t structure to populate
 *
 * @return AlertType_t Type of alert parsed, or ALERT_TYPE_UNKNOWN on error
 *
 * @note Initializes all fields to safe defaults before parsing
 * @note Handles missing fields gracefully
 * @note Uses simple string-based JSON parsing (not a full JSON parser)
 */
AlertType_t MLBridge_ParseAlert(const char* json_buffer, ParsedAlert_t* alert)
{
    if (json_buffer == NULL || alert == NULL) {
        return ALERT_TYPE_UNKNOWN;
    }
    
    /* Initialize alert structure with safe defaults */
    memset(alert, 0, sizeof(ParsedAlert_t));
    alert->current_rate = -1;
    alert->threshold = -1;
    alert->mse = -1.0;
    
    fflush(stdout);
    
    /* Extract alert_type field */
    const char* alert_type_str = extract_json_string(json_buffer, "alert_type");
    if (alert_type_str == NULL) {
        fflush(stdout);
        return ALERT_TYPE_UNKNOWN;
    }
    
    fflush(stdout);
    
    /* Determine alert type from string */
    if (strcmp(alert_type_str, "ML_ANOMALY") == 0) {
        alert->alert_type = ALERT_TYPE_ML_ANOMALY;
    }
    else if (strcmp(alert_type_str, "COMMAND_FLOODING") == 0) {
        alert->alert_type = ALERT_TYPE_COMMAND_FLOODING;
    }
    else if (strcmp(alert_type_str, "REPLAY_ATTACK") == 0) {
        alert->alert_type = ALERT_TYPE_REPLAY_ATTACK;
    }
    else {
        fflush(stdout);
        alert->alert_type = ALERT_TYPE_UNKNOWN;
    }
    
    /* Extract common fields */
    const char* severity = extract_json_string(json_buffer, "severity");
    if (severity != NULL) {
        strncpy(alert->severity, severity, sizeof(alert->severity) - 1);
    }
    
    const char* stix_pattern = extract_json_string(json_buffer, "stix_pattern");
    if (stix_pattern != NULL) {
        strncpy(alert->stix_pattern, stix_pattern, sizeof(alert->stix_pattern) - 1);
    }
    
    const char* description = extract_json_string(json_buffer, "description");
    if (description != NULL) {
        strncpy(alert->description, description, sizeof(alert->description) - 1);
    }
    
    /* Extract type-specific fields */
    switch (alert->alert_type) {
        case ALERT_TYPE_REPLAY_ATTACK:
            {
                const char* hex = extract_json_string(json_buffer, "hex");
                if (hex != NULL) {
                    strncpy(alert->hex, hex, sizeof(alert->hex) - 1);
                }
            }
            break;
            
        case ALERT_TYPE_COMMAND_FLOODING:
            {
                const char* system = extract_json_string(json_buffer, "system");
                if (system != NULL) {
                    strncpy(alert->system, system, sizeof(alert->system) - 1);
                }
                
                const char* data_type = extract_json_string(json_buffer, "data_type");
                if (data_type != NULL) {
                    strncpy(alert->data_type, data_type, sizeof(alert->data_type) - 1);
                }
                
                const char* app_id = extract_json_string(json_buffer, "app_id");
                if (app_id != NULL) {
                    strncpy(alert->system, app_id, sizeof(alert->system) - 1);
                }
                
                alert->current_rate = extract_json_int(json_buffer, "current_rate");
                alert->threshold = extract_json_int(json_buffer, "threshold");
            }
            break;
            
        case ALERT_TYPE_ML_ANOMALY:
            {
                /* Extract system from nested data object */
                const char* data_start = strstr(json_buffer, "\"data\":");
                if (data_start != NULL) {
                    const char* system = extract_json_string(data_start, "system");
                    if (system != NULL) {
                        strncpy(alert->system, system, sizeof(alert->system) - 1);
                    }
                    
                    const char* data_type = extract_json_string(data_start, "data_type");
                    if (data_type != NULL) {
                        strncpy(alert->data_type, data_type, sizeof(alert->data_type) - 1);
                    }
                }
                
                /* Extract anomaly detection details */
                const char* anomaly_start = strstr(json_buffer, "\"anomaly_detection\":");
                if (anomaly_start != NULL) {
                    alert->mse = extract_json_float(anomaly_start, "mse");
                    double threshold_float = extract_json_float(anomaly_start, "threshold");
                    alert->threshold = (int)(threshold_float * 1000000); /* Store as micro-units */
                    
                    const char* feature = extract_json_string(anomaly_start, "responsible_feature");
                    if (feature != NULL) {
                        strncpy(alert->responsible_feature, feature, 
                               sizeof(alert->responsible_feature) - 1);
                    }
                }
            }
            break;
            
        default:
            break;
    }
    
    return alert->alert_type;
}

/**
 * @brief Handle parsed alert and generate IDS alerts
 *
 * Processes a parsed alert structure and generates appropriate multi-channel
 * alerts including:
 * - IDS telemetry messages (SPACECOP_ReportIDSMsg)
 * - STIX reports (write_to_stix)
 * - System log entries (CFE_ES_WriteToSysLog)
 *
 * Alert content is customized based on alert type and includes relevant
 * details such as MSE values, rate information, and responsible features.
 *
 * @param[in] alert Pointer to parsed alert structure
 *
 * @return void
 *
 * @note Looks up IOB identifier from alert type
 * @note Skips STIX logging if IOB is not found or disabled
 * @note Prints detailed alert information to stdout
 */
void MLBridge_HandleAlert(const ParsedAlert_t* alert)
{
    if (alert == NULL) {
        return;
    }
    
    char artifact_desc[1024];
    char ids_message[IDS_REPORT_MESSAGE_LEN];
    const char* iob_name = NULL;
    
    fflush(stdout);
    
    /* Process alert based on type */
    switch (alert->alert_type) {
        case ALERT_TYPE_REPLAY_ATTACK:
            fflush(stdout);
            
            /* Create artifact description for STIX */
            snprintf(artifact_desc, sizeof(artifact_desc), 
                    "REPLAY_ATTACK:HEX=%s", alert->hex);
            
            /* Create IDS message */
            snprintf(ids_message, sizeof(ids_message), 
                    "[SPACECOP] Replay Attack Detected: Duplicate packet %s", alert->hex);
            
            iob_name = MLBridge_GetIOBFromAlertType(ALERT_TYPE_REPLAY_ATTACK);
            break;
            
        case ALERT_TYPE_COMMAND_FLOODING:
            fflush(stdout);
            
            /* Create artifact description for STIX */
            snprintf(artifact_desc, sizeof(artifact_desc), 
                    "COMMAND_FLOODING:SYSTEM=%s:RATE=%d:THRESHOLD=%d", 
                    alert->system, alert->current_rate, alert->threshold);
            
            /* Create IDS message */
            snprintf(ids_message, sizeof(ids_message), 
                    "[SPACECOP] Command Flooding Detected: %s at %d cmd/min (threshold: %d)", 
                    alert->system, alert->current_rate, alert->threshold);
            
            iob_name = MLBridge_GetIOBFromAlertType(ALERT_TYPE_COMMAND_FLOODING);
            break;
            
        case ALERT_TYPE_ML_ANOMALY:
            fflush(stdout);
            
            /* Create artifact description for STIX */
            snprintf(artifact_desc, sizeof(artifact_desc), 
                    "ML_ANOMALY:SYSTEM=%s:TYPE=%s:FEATURE=%s:MSE=%.6f:SEVERITY=%s", 
                    alert->system, alert->data_type, alert->responsible_feature, 
                    alert->mse, alert->severity);
            
            /* Create IDS message */
            snprintf(ids_message, sizeof(ids_message), 
                    "[SPACECOP] ML Anomaly Detected: %s %s - Feature: %s", 
                    alert->system, alert->data_type, alert->responsible_feature);
            
            /* For ML anomalies, try to get IOB from response first */
            iob_name = MLBridge_GetIOBFromResponse(artifact_desc);
            if (iob_name == NULL) {
                /* Fall back to generic ML_ANOMALY IOB */
                iob_name = MLBridge_GetIOBFromAlertType(ALERT_TYPE_ML_ANOMALY);
            }
            break;
            
        default:
            printf("UNKNOWN\n");
            fflush(stdout);
            return;
    }
    
    fflush(stdout);
    
    /* Report to IDS */
    SPACECOP_ReportIDSMsg(ids_message);
    
    /* Write to STIX if IOB is available */
    if (iob_name != NULL) {
        int stix_result = write_to_stix(artifact_desc, NULL, iob_name);
        
        if (stix_result == 0) {
            fflush(stdout);
            CFE_ES_WriteToSysLog("[SPACECOP] Alert logged: %s\n", artifact_desc);
        }
        else {
            printf("[SPACECOP] ERROR: Failed to log to STIX (code: %d)\n", stix_result);
            fflush(stdout);
        }
    }
    else {
        printf("[SPACECOP] WARNING: No IOB found for alert, skipping STIX logging\n");
        fflush(stdout);
    }
}

/**
 * @brief Check for and process alerts from ML server
 *
 * Main alert reception loop that:
 * 1. Waits for ML client to connect (blocking accept)
 * 2. Receives JSON alert messages (blocking recv)
 * 3. Parses and handles each alert
 * 4. Handles client disconnections gracefully
 * 5. Waits for new client connections
 *
 * This function runs in an infinite loop and should be called from a
 * dedicated thread or task. It blocks on accept() and recv() calls.
 *
 * @return void
 *
 * @note Runs in infinite loop - does not return under normal operation
 * @note Blocking I/O operations (accept and recv)
 * @note Automatically handles client reconnections
 * @note Prints detailed connection and message status
 * @note Sends cFE events for connection state changes
 */
void MLBridge_CheckForResponse(void)
{
    static char buffer[BUFFER_SIZE];
    int bytes_received;
    int client_sockfd = -1;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    fflush(stdout);
    
    /* Do NOT (re)initialize the socket here. MLBridge_InitSockets() is called
    ** exactly ONCE, at app init. Re-initializing from this accept path races
    ** with app init and re-binds ML_RECV_PORT ("initializing 9112 multiple
    ** times"). If the listener isn't up yet, just wait -- RunMLResp calls us
    ** again; accept() below only runs on a valid fd thanks to the loop guard. */
    if (MLBridge_AppData.recv_sockfd < 0) {
        sleep(1);
        return;
    }

    /* Main loop to handle reconnections */
    while (1) {
        /* Defensive: never accept() on a torn-down/invalid socket. */
        if (MLBridge_AppData.recv_sockfd < 0) {
            sleep(1);
            return;
        }
        /* Wait for ML client to connect (blocking) */
        client_sockfd = accept(MLBridge_AppData.recv_sockfd,
                              (struct sockaddr*)&client_addr, 
                              &client_len);
        
        if (client_sockfd < 0) {
            printf("[SPACECOP] ERROR: Failed to accept connection: %s\n", strerror(errno));
            fflush(stdout);
            sleep(10);
            continue;
        }
        
        fflush(stdout);
        
        int message_count = 0;
        
        /* Handle messages from this client */
        while (1) {
            /* Clear buffer before receiving */
            memset(buffer, 0, BUFFER_SIZE);
            
            /* Blocking recv - wait for ML server to send alerts */
            bytes_received = recv(client_sockfd, 
                                 buffer, 
                                 BUFFER_SIZE - 1, 
                                 0);
            
            if (bytes_received > 0) {
                message_count++;
                buffer[bytes_received] = '\0';
                
                fflush(stdout);
                
                /* Parse the alert */
                ParsedAlert_t alert;
                AlertType_t alert_type = MLBridge_ParseAlert(buffer, &alert);
                
                if (alert_type != ALERT_TYPE_UNKNOWN) {
                    /* Handle the parsed alert */
                    MLBridge_HandleAlert(&alert);
                }
                else {
                    fflush(stdout);
                }
            }
            else if (bytes_received == 0) {
                /* Client disconnected gracefully */
                fflush(stdout);
                break;
            }
            else {
                /* Connection error */
                fflush(stdout);
                break;
            }
        }
        
        /* Close client socket, then go straight back to accept() so the ML
        ** server's next connection is picked up immediately. A sleep here left
        ** us deaf to reconnects for a full second, so the client saw refused/
        ** backlogged connects to 9112 and kept retrying. */
        close(client_sockfd);
        client_sockfd = -1;
        fflush(stdout);
    }
}

/*=======================================================================================
** Cleanup Functions
**=======================================================================================*/

/**
 * @brief Clean up ML bridge resources
 *
 * Closes both send and receive sockets and sends termination event.
 * Should be called during application shutdown.
 *
 * @return void
 *
 * @note Safe to call even if sockets are already closed
 */
void MLBridge_Cleanup(void)
{
    if (MLBridge_AppData.send_sockfd >= 0) {
        close(MLBridge_AppData.send_sockfd);
        MLBridge_AppData.send_sockfd = -1;
    }

    if (MLBridge_AppData.recv_sockfd >= 0) {
        close(MLBridge_AppData.recv_sockfd);
        MLBridge_AppData.recv_sockfd = -1;
    }

    CFE_EVS_SendEvent(0, CFE_EVS_EventType_INFORMATION, "MLBridge App Terminated");
}