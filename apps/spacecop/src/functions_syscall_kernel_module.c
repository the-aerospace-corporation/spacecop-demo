// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop - CE
// All rights reserved.
//
// This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including,
// but not limited to, any warranty that the software will conform to specifications, any implied warranties of merchantability,
// fitness for a particular purpose, freedom from infringement, or that the documentation will conform to the program,
// or be error free.
//
// In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct,
// indirect, special, or consequential damages, arising out of, resulting from, or in any way connected with the software
// or its documentation. Whether based upon warranty, contract, tort, or otherwise, and whether or not loss was sustained from,
// or arose out of the results of, or use of, the software, documentation or services provided hereunder.
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)
// Brandon Bailey (brandon.bailey@aero.org)

/**
 * @file functions_syscall_kernel_module.c
 * @brief System call monitoring via Linux kernel module for SpaceCop IDS
 *
 * This file implements comprehensive system call monitoring using a custom
 * Linux kernel module that intercepts system calls and reports them to
 * userspace via Netlink sockets.
 *
 * **Architecture:**
 * - Kernel module (aerospace.ko) intercepts system calls
 * - Netlink socket provides kernel-to-userspace communication
 * - Userspace component parses events and applies detection rules
 * - Configurable thresholds and enable/disable per IOB
 *
 * **Monitored System Calls and IOBs:**
 * - CSNE-17: mkfifo (named pipe creation)
 * - SIUU-15: Repeated access to dummy files (/dev/null, /dev/zero)
 * - SIUU-12: Kernel module loading (insmod, INIT_MODULE)
 * - SIUU-10: Process priority modification (renice, setpriority)
 * - SIUU-16: System command execution (grep, ps, awk, chmod, dd, cat, sh)
 * - MIRE-17: Flash memory block access (/dev/mtd*)
 *
 * **Detection Methods:**
 * - execve: Detects program execution (command analysis)
 * - openat: Detects file access (dummy files, flash memory)
 * - INIT_MODULE: Detects direct kernel module loading
 *
 * **Key Features:**
 * - Automatic kernel module loading
 * - Event parsing and structured data extraction
 * - Noise filtering (excludes shell processes)
 * - Threshold-based alerting
 * - Multi-channel reporting (IDS, STIX, cFE events)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <errno.h>

#include "functions_syscall_kernel_module.h"
#include "spacecop_platform_cfg.h"  /* SPACECOP_CF_DIR */

/*=======================================================================================
** Constants and Macros
**=======================================================================================*/

/** @brief Maximum payload size for Netlink messages */
#define MAX_PAYLOAD 1024

/*=======================================================================================
** Type Definitions
**=======================================================================================*/

/**
 * @brief Parsed system call event structure
 *
 * Contains structured information extracted from kernel module messages
 * for easier processing and detection logic.
 */
typedef struct {
    char process[16];      /**< Process name that made the system call */
    int pid;               /**< Process ID */
    int tgid;              /**< Thread group ID (main thread PID) */
    int uid;               /**< User ID that owns the process */
    char filename[256];    /**< File path for file-related system calls */
    char program[256];     /**< Program path for execve calls */
    char syscall[64];      /**< System call name */
} SyscallEvent;

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/**
 * @brief System call monitoring configuration array
 *
 * Defines all monitored system call categories with their IOB identifiers,
 * enable states, and tolerance thresholds.
 */
static SyscallInfo syscalls[] =
{
    { .enabled = 0, .name = "fifo", .iob = "CSNE-17" },
    { .enabled = 0, .name = "repeated_null", .curr_count = 0, .tolerance = 10, .iob = "SIUU-15" },
    { .enabled = 0, .name = "kernel_mod", .iob = "SIUU-12" },
    { .enabled = 0, .name = "priority", .iob = "SIUU-10" },
    { .enabled = 0, .name = "execve", .iob = "SIUU-16" },
    { .enabled = 0, .name = "memory", .iob = "MIRE-17" }
};

/*=======================================================================================
** Noise Filtering Functions
**=======================================================================================*/

/**
 * @brief Check if a process is considered "noisy" and should be filtered
 *
 * Filters out common interactive shell and editor processes that generate
 * high volumes of benign system calls. Reduces false positive rate.
 *
 * @param[in] process_name Name of the process to check
 *
 * @return int Returns 1 if process is noisy, 0 otherwise
 *
 * @note Noisy processes: zsh, bash, sh, tmux, screen, vim, nano, less, more
 */
static int is_noisy_process(const char *process_name)
{
    const char *noisy_processes[] = {
        "zsh",
        "bash",
        "sh",
        "tmux",
        "screen",
        "vim",
        "nano",
        "less",
        "more"
    };
    
    for (size_t i = 0; i < sizeof(noisy_processes) / sizeof(noisy_processes[0]); i++) {
        if (strcmp(process_name, noisy_processes[i]) == 0) {
            return 1;  /* Is noisy */
        }
    }
    return 0;  /* Not noisy */
}

/*=======================================================================================
** Kernel Module Management Functions
**=======================================================================================*/

/**
 * @brief Check if a kernel module is loaded
 *
 * Queries /proc/modules to determine if a kernel module with the specified
 * name is currently loaded in the kernel.
 *
 * @param[in] name Name of the kernel module (without .ko extension)
 *
 * @return int Returns 1 if module is loaded, 0 otherwise
 *
 * @note Parses /proc/modules line by line
 * @note Module name must match at start of line followed by space or tab
 */
static int module_loaded_proc(const char *name)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) 
        return 0;

    char line[512];
    int found = 0;
    size_t nlen = strlen(name);

    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, name, nlen) == 0 && (line[nlen] == ' ' || line[nlen] == '\t'))
        {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

/**
 * @brief Load a kernel module using insmod
 *
 * Executes the insmod command to load the specified kernel module file.
 * Exits the program if loading fails.
 *
 * @param[in] path Path to the kernel module file (.ko)
 *
 * @return void
 *
 * @note Requires root privileges
 * @note Exits program on failure
 * @note Prints success message to stdout
 *
 * @warning This function calls system() and exits on failure
 */
static void load_kernel_module(const char *path)
{
    char command[256];
    snprintf(command, sizeof(command), "insmod %s", path);

    if(system(command) != 0)
    {
        perror("Failed to load kernel module");
        exit(EXIT_FAILURE);
    }
    printf("[SPACECOP] - Kernel module loaded successfully.\n");
}

/*=======================================================================================
** Counter Management Functions
**=======================================================================================*/

/**
 * @brief Increment the current count for a system call monitor
 *
 * Used for threshold-based detection where multiple occurrences must
 * be observed before alerting.
 *
 * @param[in] name Name of the system call monitor
 *
 * @return void
 */
static void IncreaseCount(const char *name)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].name, name) == 0)
            syscalls[i].curr_count++;
    } 
}

/**
 * @brief Reset the current count for a system call monitor
 *
 * Called after an alert is generated to start a new counting period.
 *
 * @param[in] name Name of the system call monitor
 *
 * @return void
 */
static void ResetCount(const char *name)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].name, name) == 0)
            syscalls[i].curr_count = 0;
    } 
}

/*=======================================================================================
** Configuration Functions
**=======================================================================================*/

/**
 * @brief Toggle monitoring on/off for a specific IOB
 *
 * Enables or disables system call monitoring for the specified IOB.
 * Toggles between current state.
 *
 * @param[in] iob IOB identifier string
 *
 * @return void
 */
void Toggle_Monitor(const char *iob)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].iob, iob) == 0)
            syscalls[i].enabled = !syscalls[i].enabled;
    }
}

/**
 * @brief Set the tolerance threshold for a specific IOB
 *
 * Configures how many system calls can occur before generating an alert.
 *
 * @param[in] iob IOB identifier string
 * @param[in] tolerance Maximum allowed count before alert
 *
 * @return void
 */
void Set_Tolerance(const char *iob, int16_t tolerance)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].iob, iob) == 0)
            syscalls[i].tolerance = tolerance;
    }
}

/**
 * @brief Check if a system call monitor is enabled
 *
 * @param[in] name Name of the system call monitor
 *
 * @return int8_t Returns 1 if enabled, 0 if disabled
 */
static int8_t IsSyscallEnabled(const char* name)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].name, name) == 0)
            return syscalls[i].enabled;
    }
    return 0;
}

/**
 * @brief Find a system call monitor configuration by name
 *
 * @param[in] name Name of the system call monitor
 *
 * @return const SyscallInfo* Pointer to configuration, or NULL if not found
 */
const SyscallInfo* FindSyscall(const char *name)
{
    for (uint32_t i = 0; i < (sizeof(syscalls) / sizeof(syscalls[0])); i++)
    {
        if (strcmp(syscalls[i].name, name) == 0)
            return &syscalls[i];
    }
    return NULL;
}

/*=======================================================================================
** Event Parsing Functions
**=======================================================================================*/

/**
 * @brief Parse kernel module message into structured event
 *
 * Extracts structured information from raw kernel messages for easier
 * processing. Handles multiple message formats:
 * - "Syscall X called by process=Y,pid=Z,tgid=A,uid=B with filename: C"
 * - "openat called by process=Y,pid=Z,tgid=A,uid=B with filename: C"
 * - "INIT_MODULE called by process=Y,pid=Z,tgid=A,uid=B (module addr: ...)"
 *
 * @param[in] msg Raw kernel message string
 * @param[out] event Pointer to SyscallEvent structure to populate
 *
 * @return void
 *
 * @note Handles multiple message formats from kernel module
 * @note Extracts: syscall name, process info, filename, program path
 * @note Removes trailing newlines from extracted strings
 */
static void parse_kernel_message(const char *msg, SyscallEvent *event)
{
    memset(event, 0, sizeof(SyscallEvent));
    
    /* Extract syscall name */
    if (strncmp(msg, "Syscall ", 8) == 0) {
        sscanf(msg, "Syscall %s called", event->syscall);
    } else if (strncmp(msg, "openat ", 7) == 0) {
        strcpy(event->syscall, "openat");
    } else if (strncmp(msg, "INIT_MODULE ", 12) == 0) {
        strcpy(event->syscall, "INIT_MODULE");
    }
    
    /* Extract process information */
    char *proc_start = strstr(msg, "process=");
    if (proc_start) {
        sscanf(proc_start, "process=%[^,],pid=%d,tgid=%d,uid=%d",
               event->process, &event->pid, &event->tgid, &event->uid);
    }
    
    /* Extract filename if present */
    char *filename_ptr = strstr(msg, "with filename: ");
    if (filename_ptr) {
        strncpy(event->filename, filename_ptr + 15, sizeof(event->filename) - 1);
        event->filename[strcspn(event->filename, "\n")] = 0;  /* Remove newline */
    }
    
    /* Extract program path if present */
    char *program_ptr = strstr(msg, "with program: ");
    if (program_ptr) {
        strncpy(event->program, program_ptr + 14, sizeof(event->program) - 1);
        event->program[strcspn(event->program, "\n")] = 0;  /* Remove newline */
    }
}

/*=======================================================================================
** Public API Functions
**=======================================================================================*/

/**
 * @brief Initialize the system call monitoring subsystem
 *
 * Checks if the kernel module is loaded and loads it if necessary.
 * Must be called before starting monitoring.
 *
 * @return void
 *
 * @note Loads module from "cf/aerospace.ko"
 * @note Requires root privileges
 */
void Init_Syscall(void)
{
    if (!module_loaded_proc("aerospace"))
    {
        load_kernel_module(SPACECOP_CF_DIR "/aerospace.ko");
    }
}

/**
 * @brief Main system call monitoring loop
 *
 * Establishes Netlink socket connection to kernel module, receives system
 * call events, parses them, and applies detection rules. Generates alerts
 * when suspicious patterns are detected.
 *
 * Detection rules:
 * - SIUU-16: System command execution (grep, ps, awk, chmod, dd, cat, sh)
 * - CSNE-17: Named pipe creation (mkfifo)
 * - SIUU-12: Kernel module loading (insmod, INIT_MODULE)
 * - SIUU-10: Process priority modification (renice, setpriority)
 * - SIUU-15: Repeated dummy file access (/dev/null, /dev/zero)
 * - MIRE-17: Flash memory access (/dev/mtd*)
 *
 * @return void
 *
 * @note Runs in infinite loop until socket error occurs
 * @note Requires Init_Syscall() to be called first
 * @note Blocks waiting for kernel messages
 * @note Filters out noisy processes (shells, editors)
 *
 * @warning This function does not return under normal operation
 */
void SYSCALL_Monitor(void) 
{
    printf("[SPACECOP] - Starting syscall monitor\n");

    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;

    /* Ensure kernel module is loaded */
    Init_Syscall();

    /* Create Netlink socket */
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(sock_fd < 0)
    {
        printf("Socket creation failed: %s\n", strerror(errno));
        return;
    }

    /* Configure source address (userspace) */
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    /* Bind socket */
    if(bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0)
    {
        printf("Bind failed: %s\n", strerror(errno));
        close(sock_fd);
        return;
    }

    /* Configure destination address (kernel) */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;      /* Kernel */
    dest_addr.nl_groups = 0;   /* Unicast */

    /* Allocate Netlink message header */
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh)
    {
        printf("Memory allocation failed\n");
        close(sock_fd);
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    /* Send registration message to kernel */
    strcpy(NLMSG_DATA(nlh), "Registering user-space server!");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if(sendmsg(sock_fd, &msg, 0) < 0)
    {
        printf("Error sending message to kernel: %s\n", strerror(errno));
        close(sock_fd);
        free(nlh);
        return;
    }

    printf("[SPACECOP] Listening for messages from the kernel...\n");

    char kernel_msg[1024];
    char message[IDS_REPORT_MESSAGE_LEN];
    SyscallEvent event;

    /* Main monitoring loop */
    while (1)
    {
        /* Receive message from kernel */
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        if (recvmsg(sock_fd, &msg, 0) < 0)
        {
            printf("Error receiving message: %s\n", strerror(errno));
            break;
        }

        /* Extract kernel message */
        strcpy(kernel_msg, (char *)NLMSG_DATA(nlh));
        
        /* Parse the kernel message into structured event */
        parse_kernel_message(kernel_msg, &event);

        /*=======================================================================================
        ** EXECVE-BASED DETECTIONS
        **=======================================================================================*/
        
        if (strstr(kernel_msg, "execve") != NULL)
        {
            /* SIUU-16: System command execution detection */
            if (IsSyscallEnabled("execve"))
            {
                const SyscallInfo *info = FindSyscall("execve");

                /* Match on the executable's BASENAME, compared EXACTLY. The
                 * original strstr() substring test produced false positives:
                 * "sh" matched bash/ssh/flush, "ps" matched gpsd, "cat" matched
                 * concatenate/locate, "dd" matched add/address, etc.
                 *
                 * NOTE: on a general-purpose Linux (this Pi) these tools run
                 * legitimately all the time. "sh" in particular is spawned
                 * constantly - including by SpaceCop's own system("insmod ...")
                 * call - so it is intentionally omitted. Tune this list to
                 * whatever is genuinely anomalous for THIS mission (or
                 * whitelist expected parent processes). */
                static const char *watched_cmds[] = {
                    "grep", "ps", "awk", "chmod", "dd", "cat"
                    /* , "sh"  <- omitted: ubiquitous / self-triggered on Linux */
                };

                const char *base = strrchr(event.program, '/');
                base = base ? base + 1 : event.program;

                for (uint32_t c = 0; c < sizeof(watched_cmds) / sizeof(watched_cmds[0]); c++)
                {
                    if (strcmp(base, watched_cmds[c]) == 0)
                    {
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN,
                                 "[SPACECOP] IOB Detected: SPARTA ID=%s (System Command %s executed by process %s, PID=%d)",
                                 info->iob, event.program, event.process, event.pid);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(event.process, NULL, info->iob);
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR,
                                         "[SPACECOP] IOB Detected: SPARTA ID=%s (System Command %s executed by process %s, PID=%d)",
                                         info->iob, event.program, event.process, event.pid);
                        break;
                    }
                }
            }
            
            /* CSNE-17: mkfifo (named pipe) detection */
            if (IsSyscallEnabled("fifo"))
            {
                const SyscallInfo *info = FindSyscall("fifo");
                if (strstr(event.program, "mkfifo") != NULL)
                {
                    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                    snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (mkfifo executed by process %s, PID=%d)", 
                             info->iob, event.process, event.pid);
                    SPACECOP_ReportIDSMsg(message);
                    write_to_stix(event.process, NULL, info->iob);
                    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                     "[SPACECOP] IOB Detected: SPARTA ID=%s (mkfifo executed by process %s, PID=%d)", 
                                     info->iob, event.process, event.pid);
                }
            }
            
            /* SIUU-12: insmod (kernel module loading) detection */
            if (IsSyscallEnabled("kernel_mod"))
            {
                const SyscallInfo *info = FindSyscall("kernel_mod");
                if (strstr(event.program, "insmod") != NULL)
                {
                    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                    snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (insmod executed by process %s, PID=%d)", 
                             info->iob, event.process, event.pid);
                    SPACECOP_ReportIDSMsg(message);
                    write_to_stix(event.process, NULL, info->iob);
                    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                     "[SPACECOP] IOB Detected: SPARTA ID=%s (insmod executed by process %s, PID=%d)", 
                                     info->iob, event.process, event.pid);
                }
            }
            
            /* SIUU-10: Priority modification detection */
            if (IsSyscallEnabled("priority"))
            {
                const SyscallInfo *info = FindSyscall("priority");
                if (strstr(event.program, "renice") != NULL ||
                    strstr(event.program, "setpriority") != NULL)
                {
                    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                    snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (Priority modification by process %s, PID=%d)", 
                             info->iob, event.process, event.pid);
                    SPACECOP_ReportIDSMsg(message);
                    write_to_stix(event.process, NULL, info->iob);
                    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                     "[SPACECOP] IOB Detected: SPARTA ID=%s (Priority modification by process %s, PID=%d)", 
                                     info->iob, event.process, event.pid);
                } 
            }   
        }
        
        /*=======================================================================================
        ** OPENAT-BASED DETECTIONS
        **=======================================================================================*/
        
        else if (strstr(kernel_msg, "openat") != NULL)
        {
            /* Filter out noisy shell processes */
            if (is_noisy_process(event.process)) {
                /* Skip - don't count accesses from shells */
            }
            /* SIUU-15: Repeated dummy file access detection */
            else if (IsSyscallEnabled("repeated_null"))
            {
                if (strcmp(event.filename, "/dev/null") == 0 ||
                    strcmp(event.filename, "/dev/zero") == 0 ||
                    strcmp(event.filename, "/null") == 0)
                {
                    IncreaseCount("repeated_null");
                    const SyscallInfo *info2 = FindSyscall("repeated_null");

                    /* Check if threshold exceeded */
                    if (info2->curr_count >= info2->tolerance)
                    {
                        ResetCount("repeated_null");
                        memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                        snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                                 "[SPACECOP] IOB Detected: SPARTA ID=%s (Dummy File %s accessed %d+ times by process %s)", 
                                 info2->iob, event.filename, info2->tolerance, event.process);
                        SPACECOP_ReportIDSMsg(message);
                        write_to_stix(event.filename, NULL, info2->iob);
                        CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                         "[SPACECOP] IOB Detected: SPARTA ID=%s (Dummy File %s accessed %d+ times by process %s)", 
                                         info2->iob, event.filename, info2->tolerance, event.process);
                    }
                }
            }

            /* MIRE-17: Flash memory block access detection */
            if (IsSyscallEnabled("memory"))
            {
                if (strstr(event.filename, "/dev/mtd") != NULL)
                {
                    const SyscallInfo *info3 = FindSyscall("memory");
                    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                    snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (Flash Memory Block %s accessed by process %s, PID=%d)", 
                             info3->iob, event.filename, event.process, event.pid);
                    SPACECOP_ReportIDSMsg(message);
                    write_to_stix(event.filename, NULL, info3->iob);
                    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                     "[SPACECOP] IOB Detected: SPARTA ID=%s (Flash Memory Block %s accessed by process %s, PID=%d)", 
                                     info3->iob, event.filename, event.process, event.pid);
                }
            }
        }
        
        /*=======================================================================================
        ** INIT_MODULE DETECTION
        **=======================================================================================*/
        
        /* SIUU-12: Direct kernel module loading via INIT_MODULE syscall */
        else if (strstr(kernel_msg, "INIT_MODULE") != NULL)
        {
            if (IsSyscallEnabled("kernel_mod"))
            {
                const SyscallInfo *info = FindSyscall("kernel_mod");
                memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                         "[SPACECOP] IOB Detected: SPARTA ID=%s (Kernel module loaded by process %s, PID=%d)", 
                         info->iob, event.process, event.pid);
                SPACECOP_ReportIDSMsg(message);
                write_to_stix(event.process, NULL, info->iob);
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                 "[SPACECOP] IOB Detected: SPARTA ID=%s (Kernel module loaded by process %s, PID=%d)", 
                                 info->iob, event.process, event.pid);
            }
        }
        else
        {
            /* Unhandled message type - print for debugging */
            printf("Received message: %s\n", kernel_msg);   
        }
    }
    
    /* Cleanup on exit */
    printf("[SPACECOP] - Ending syscall thread\n");
    close(sock_fd);
    free(nlh);
    return;
}