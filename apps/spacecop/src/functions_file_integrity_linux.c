// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop - CE
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
 * @file functions_file_integrity_linux.c
 * @brief Implementation of file integrity monitoring for SpaceCop IDS
 *
 * This file implements a comprehensive file integrity monitoring system using
 * SHA-256 cryptographic hashing. The system operates in two phases:
 *
 * 1. Initialization: Scans monitored directories and establishes baselines
 * 2. Runtime Checking: Periodically rescans and compares against baselines
 *
 * The implementation uses OpenSSL's EVP API for cryptographic operations and
 * maintains sorted file lists for efficient comparison. Detected changes are
 * reported through multiple channels for comprehensive alerting.
 *
 * Key features:
 * - Recursive directory scanning with configurable exclusions
 * - SHA-256 hash computation using OpenSSL EVP API
 * - Memory-efficient dynamic arrays for file tracking
 * - Sorted file lists for O(n) comparison algorithm
 * - Multi-channel alerting (IDS telemetry, STIX, cFE events)
 */

#include "functions_file_integrity_linux.h"
#include "spacecop_platform_cfg.h"  /* SPACECOP_CF_DIR / SPACECOP_DATA_DIR */
#include <fnmatch.h>                /* glob matching for the add allowlist    */

/*=======================================================================================
** Add-allowlist configuration
**
** The data dir (/var/pisat/data) legitimately receives new files at runtime -
** notably camera captures ("capture_<N>.jpg"). Treating every one as a "File
** Added" IOB drowns the operator in benign alerts. The allowlist below names
** the glob patterns for EXPECTED new files: additions that match are not
** alerted. Modifications and deletions are ALWAYS alerted (a write-once picture
** being altered or wiped is still suspicious), and the cf dir is never
** allowlisted, so config/binary integrity stays strict.
**
** Patterns are loaded from SPACECOP_FIM_ALLOWLIST_FILE (in the integrity-
** protected /cf dir) if present, one glob per line ('#' comments allowed). If
** that file is missing or empty we fall back to the built-in default so the
** suppression works out of the box.
**=======================================================================================*/

/** @brief Optional operator-tunable allowlist file (data-dir-relative globs) */
#define SPACECOP_FIM_ALLOWLIST_FILE   SPACECOP_CF_DIR "/fim_allowlist.txt"

/** @brief Built-in default used when the allowlist file is absent/empty */
#define SPACECOP_FIM_DEFAULT_ADD_GLOB "capture_*.jpg"

/*=======================================================================================
** Static Global Variables
**=======================================================================================*/

/** @brief Monitored directory: cFE configuration files */
static const char *cf_dir = SPACECOP_CF_DIR;

/** @brief Monitored directory: application data files */
static const char *data_dir = SPACECOP_DATA_DIR;

/** @brief Baseline file list for cf directory */
static FileList cf_old = {NULL, 0, 0};

/** @brief Baseline file list for data directory */
static FileList data_old = {NULL, 0, 0};

/**
 * @brief Initialization state tracker
 *
 * Values:
 * - 0: Not initialized
 * - 1: Initialization in progress
 * - 2: Fully initialized and ready
 */
static int initialized = 0;

/** @brief Glob patterns for expected new files in the data dir (adds only) */
static char  **add_allow = NULL;

/** @brief Number of patterns in @ref add_allow */
static size_t  add_allow_len = 0;

/*=======================================================================================
** Memory Management Helper Functions
**=======================================================================================*/

/**
 * @brief Allocate memory with error checking
 *
 * Wrapper around malloc() that prints an error message and returns NULL
 * if allocation fails.
 *
 * @param[in] n Number of bytes to allocate
 *
 * @return void* Pointer to allocated memory, or NULL on failure
 */
static void* xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) 
    {
        printf("Out of memory\n");
        return NULL;
    }

    return p;
}

/**
 * @brief Duplicate a string on the heap
 *
 * Allocates memory and copies the input string, including null terminator.
 *
 * @param[in] s String to duplicate
 *
 * @return char* Pointer to duplicated string, or NULL on allocation failure
 */
static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    if (!p) return NULL;
    memcpy(p, s, n);
    return p;
}

/*=======================================================================================
** FileList Management Functions
**=======================================================================================*/

/**
 * @brief Reset a FileList to empty state
 *
 * Sets all fields to zero/NULL without freeing memory. Use filelist_free()
 * to properly deallocate before resetting.
 *
 * @param[in,out] l Pointer to FileList to reset
 *
 * @return void
 */
static void filelist_reset(FileList *l)
{
    l->items = NULL;
    l->len = 0;
    l->cap = 0;
}

/**
 * @brief Free all memory associated with a FileList
 *
 * Frees all relative path strings, the items array, and resets the structure.
 *
 * @param[in,out] l Pointer to FileList to free
 *
 * @return void
 */
static void filelist_free(FileList *l)
{
    for (size_t i = 0; i < l->len; i++)
    {
        free(l->items[i].rel_path);
    }
    free(l->items);
    filelist_reset(l);
}

/**
 * @brief Add a file entry to a FileList
 *
 * Appends a new FileEntry to the list, automatically growing the array
 * capacity as needed (doubling strategy). Copies the path string and hash.
 *
 * @param[in,out] l Pointer to FileList to append to
 * @param[in] rel_path Relative path string (will be duplicated)
 * @param[in] hash SHA-256 hash digest (32 bytes, will be copied)
 *
 * @return void
 *
 * @note Initial capacity is 128, doubles when full
 */
static void filelist_push(FileList *l, const char *rel_path, const unsigned char hash[SHA256_DIGEST_LENGTH])
{
    /* Grow array if at capacity */
    if (l->len == l->cap)
    {
        size_t newcap = (l->cap == 0) ? 128 : l->cap * 2;
        FileEntry *nitems = realloc(l->items, newcap * sizeof(FileEntry));
        if (!nitems)
        {
            printf("Out of memory\n");
            return;
        }
        l->items = nitems;
        l->cap = newcap;
    }
    
    /* Duplicate path string */
    l->items[l->len].rel_path = xstrdup(rel_path);
    if (!l->items[l->len].rel_path) return;
    
    /* Copy hash digest */
    memcpy(l->items[l->len].sha256, hash, SHA256_DIGEST_LENGTH);
    l->len++;
}

/**
 * @brief Move FileList contents from source to destination
 *
 * Transfers ownership of all data from src to dst, freeing dst's existing
 * contents and resetting src to empty.
 *
 * @param[out] dst Destination FileList (existing contents freed)
 * @param[in,out] src Source FileList (reset to empty after move)
 *
 * @return void
 */
static void filelist_move(FileList *dst, FileList *src)
{
    filelist_free(dst);

    dst->items = src->items;
    dst->len = src->len;
    dst->cap = src->cap;

    filelist_reset(src);
}

/*=======================================================================================
** Cryptographic Hash Functions
**=======================================================================================*/

/**
 * @brief Compute SHA-256 hash of a file
 *
 * Reads the file in chunks and computes its SHA-256 digest using OpenSSL's
 * EVP API. Handles interrupted reads and properly cleans up resources.
 *
 * @param[in] path Path to file to hash
 * @param[out] out Buffer to store 32-byte SHA-256 digest
 *
 * @return int Returns 0 on success, negative error code on failure:
 *         - -1: NULL parameter
 *         - -2: Failed to open file
 *         - -3: EVP context creation failed
 *         - -5: Read error
 *         - -6: Digest update failed
 *         - -7: Digest finalization failed
 *
 * @note Uses EVP_MAX_MD_SIZE buffer for reading
 * @note Properly handles EINTR during reads
 */
static int sha256_file(char *path, unsigned char out[SHA256_DIGEST_LENGTH])
{
    if (!path || !out) return -1;

    /* Open file for reading */
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        printf("Opening path failed: %s\n", path);
        return -2;
    }

    /* Initialize EVP digest context */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        close(fd);
        printf("EVP_MD_CTX_new failed\n");
        return -3;
    }

    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(ctx, md, NULL);

    /* Read file and update digest */
    unsigned char buf[EVP_MAX_MD_SIZE];
    for (;;)
    {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0)
        {
            if (errno == EINTR) continue;  /* Interrupted, retry */
            EVP_MD_CTX_free(ctx);
            close(fd);
            printf("Read path failed\n");
            return -5;
        }
        if (r == 0) break;  /* EOF */
        
        if (EVP_DigestUpdate(ctx, buf, (size_t)r) != 1)
        {
            EVP_MD_CTX_free(ctx);
            close(fd);
            printf("EVP_DigestUpdate failed\n");
            return -6;
        }
    }

    /* Finalize digest */
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1 || out_len != SHA256_DIGEST_LENGTH)
    {
        EVP_MD_CTX_free(ctx);
        close(fd);
        printf("EVP_DigestFinal_ex failed\n");
        return -7;
    }
    
    EVP_MD_CTX_free(ctx);
    close(fd);
    
    return 0;
}

/**
 * @brief Compare two SHA-256 hash digests for equality
 *
 * @param[in] a First hash digest (32 bytes)
 * @param[in] b Second hash digest (32 bytes)
 *
 * @return int Returns 1 if hashes are equal, 0 otherwise
 */
static int hash_equal(const unsigned char a[SHA256_DIGEST_LENGTH], const unsigned char b[SHA256_DIGEST_LENGTH])
{
    return memcmp(a, b, SHA256_DIGEST_LENGTH) == 0;
}

/*=======================================================================================
** Path Manipulation Functions
**=======================================================================================*/

/**
 * @brief Check if directory entry is "." or ".."
 *
 * @param[in] name Directory entry name to check
 *
 * @return int Returns 1 if name is "." or "..", 0 otherwise
 */
static int is_dot_or_dotdot(const char *name)
{
    if (!name) return 0;
    if (strcmp(name, ".") == 0) return 1;
    if (strcmp(name, "..") == 0) return 1;
    return 0;
}

/**
 * @brief Join two path components with a slash separator
 *
 * Allocates a new string containing "a/b", adding a slash only if needed.
 *
 * @param[in] a First path component
 * @param[in] b Second path component
 *
 * @return char* Heap-allocated joined path, or NULL on allocation failure
 *
 * @note Caller must free returned string
 */
static char* path_join_heap(const char *a, const char *b)
{
    size_t alen = strlen(a);
    int needs_slash = (alen > 0 && a[alen-1] != '/');
    size_t blen = strlen(b);

    size_t n = alen + (needs_slash ? 1 : 0) + blen + 1;
    char *out = xmalloc(n);
    if (!out) return NULL;

    memcpy(out, a, alen);
    size_t pos = alen;

    if (needs_slash)
        out[pos++] = '/';

    memcpy(out + pos, b, blen);
    out[pos + blen] = '\0';

    return out;
}

/*=======================================================================================
** Directory Scanning Functions
**=======================================================================================*/

/**
 * @brief Recursively scan a directory and compute file hashes
 *
 * Walks the directory tree starting at cur_abs, computing SHA-256 hashes
 * for all regular files. Skips symbolic links and ignores "logs" and "cti"
 * directories. Results are added to the output FileList.
 *
 * @param[in] cur_abs Current absolute path being scanned
 * @param[in] cur_rel Current relative path from scan root
 * @param[out] out FileList to append results to
 *
 * @return void
 *
 * @note Prints warnings for directories that cannot be accessed
 * @note Skips symbolic links to prevent infinite loops
 * @note Hardcoded exclusions: "logs" and "cti" directories
 */
static void walk_dir_recursive(const char *cur_abs, const char *cur_rel, FileList *out)
{
    DIR *d = opendir(cur_abs);
    if (!d)
    {
        printf("Warning: opendir failed on %s: %s\n", cur_abs, strerror(errno));
        return;
    }

    struct dirent *de;

    while ((de = readdir(d)) != NULL)
    {
        /* Skip . and .. */
        if (is_dot_or_dotdot(de->d_name)) 
        {
            continue;
        }

        /* Skip ignored directories */
        if (strcmp(de->d_name, "logs") == 0 || strcmp(de->d_name, "cti") == 0)
        {
            continue;
        }

        /* Build absolute path */
        char *child_abs = path_join_heap(cur_abs, de->d_name);
        if (!child_abs) continue;
        
        /* Build relative path */
        char *child_rel = NULL;
        if (cur_rel[0] == '\0')
        {
            child_rel = xstrdup(de->d_name);
        }
        else
        {
            child_rel = path_join_heap(cur_rel, de->d_name);
        }
        
        if (!child_rel)
        {
            free(child_abs);
            continue;
        }

        /* Get file status */
        struct stat st;
        if (lstat(child_abs, &st) != 0)
        {
            printf("lstat failed on %s: %s\n", child_abs, strerror(errno));
            free(child_abs);
            free(child_rel);
            continue;
        }

        /* Skip symbolic links */
        if (S_ISLNK(st.st_mode))
        {
            free(child_abs);
            free(child_rel);
            continue;
        }

        /* Recurse into directories */
        if (S_ISDIR(st.st_mode))
        {
            walk_dir_recursive(child_abs, child_rel, out);
        }
        /* Hash regular files */
        else if (S_ISREG(st.st_mode))
        {
            unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
            int32_t ret = sha256_file(child_abs, hash);
            if (ret == 0)
            {
                filelist_push(out, child_rel, hash);
            }
        }
        
        free(child_abs);
        free(child_rel);
    }
    closedir(d);
}

/*=======================================================================================
** Sorting and Comparison Functions
**=======================================================================================*/

/**
 * @brief Comparison function for qsort (by relative path)
 *
 * @param[in] a Pointer to first FileEntry
 * @param[in] b Pointer to second FileEntry
 *
 * @return int Negative if a < b, 0 if equal, positive if a > b
 */
static int cmp_entry_by_relpath(const void *a, const void *b)
{
    const FileEntry *ea = (const FileEntry *)a;
    const FileEntry *eb = (const FileEntry *)b;
    return strcmp(ea->rel_path, eb->rel_path);
}

/**
 * @brief Sort a FileList by relative path
 *
 * Uses qsort() to sort entries alphabetically by relative path for
 * efficient comparison.
 *
 * @param[in,out] l Pointer to FileList to sort
 *
 * @return void
 */
static void sort_filelist(FileList *l)
{
    if (l->len > 0)
    {
        qsort(l->items, l->len, sizeof(FileEntry), cmp_entry_by_relpath);
    }
}

/*=======================================================================================
** Add-Allowlist Functions
**=======================================================================================*/

/**
 * @brief Free the loaded add-allowlist and reset it to empty
 *
 * @return void
 */
static void add_allow_free(void)
{
    for (size_t i = 0; i < add_allow_len; i++)
    {
        free(add_allow[i]);
    }
    free(add_allow);
    add_allow = NULL;
    add_allow_len = 0;
}

/**
 * @brief Append a glob pattern to the add-allowlist
 *
 * @param[in] pat Glob pattern string (will be duplicated)
 *
 * @return void
 */
static void add_allow_push(const char *pat)
{
    char **n = realloc(add_allow, (add_allow_len + 1) * sizeof(char *));
    if (!n)
    {
        printf("Out of memory\n");
        return;
    }
    add_allow = n;
    add_allow[add_allow_len] = xstrdup(pat);
    if (add_allow[add_allow_len])
    {
        add_allow_len++;
    }
}

/**
 * @brief Load the data-dir add-allowlist
 *
 * Reads glob patterns from SPACECOP_FIM_ALLOWLIST_FILE (one per line, blank
 * lines and '#' comments ignored). If the file is absent or yields no
 * patterns, falls back to the built-in default so benign camera captures are
 * suppressed out of the box.
 *
 * @return void
 *
 * @note Replaces any previously loaded allowlist
 */
static void load_add_allowlist(void)
{
    add_allow_free();

    FILE *f = fopen(SPACECOP_FIM_ALLOWLIST_FILE, "r");
    if (f)
    {
        char line[256];
        while (fgets(line, sizeof(line), f))
        {
            /* Trim leading whitespace */
            char *s = line;
            while (*s == ' ' || *s == '\t') s++;

            /* Trim trailing whitespace / newline */
            size_t n = strlen(s);
            while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' ||
                             s[n-1] == ' '  || s[n-1] == '\t'))
            {
                s[--n] = '\0';
            }

            /* Skip blanks and comments */
            if (n == 0 || s[0] == '#') continue;

            add_allow_push(s);
        }
        fclose(f);
    }

    /* Built-in default if the file was missing or empty */
    if (add_allow_len == 0)
    {
        add_allow_push(SPACECOP_FIM_DEFAULT_ADD_GLOB);
    }
}

/**
 * @brief Test whether a newly-added file is an expected (allowlisted) one
 *
 * Matches each allowlist glob against both the data-dir-relative path and the
 * bare basename, so a pattern like "capture_*.jpg" suppresses the file whether
 * it lands at the root of the data dir or in a subdirectory.
 *
 * @param[in] rel_path Data-dir-relative path of the added file
 *
 * @return int 1 if allowlisted (suppress the add alert), 0 otherwise
 */
static int add_is_allowlisted(const char *rel_path)
{
    if (!rel_path) return 0;

    const char *base = strrchr(rel_path, '/');
    base = base ? base + 1 : rel_path;

    for (size_t i = 0; i < add_allow_len; i++)
    {
        if (fnmatch(add_allow[i], rel_path, 0) == 0) return 1;
        if (fnmatch(add_allow[i], base, 0) == 0) return 1;
    }
    return 0;
}

/*=======================================================================================
** Difference Detection and Reporting Functions
**=======================================================================================*/

/**
 * @brief Compare two sorted FileLists and report differences
 *
 * Performs a merge-like comparison of two sorted file lists to detect:
 * - Modified files (same path, different hash)
 * - Deleted files (in old list, not in new list)
 * - Added files (in new list, not in old list)
 *
 * For each detected change, generates alerts via:
 * - IDS telemetry message (SPACECOP_ReportIDSMsg)
 * - STIX report (write_to_stix)
 * - cFE error event (CFE_EVS_SendEvent)
 *
 * @param[in] oldL Pointer to baseline FileList (sorted)
 * @param[in] newL Pointer to current FileList (sorted)
 * @param[in] iob_id SPARTA/STIX identifier for alert correlation
 * @param[in] apply_add_allowlist If nonzero, suppress "File Added" alerts for
 *            files matching the add-allowlist (used for the data dir; pass 0
 *            for the cf dir so config/binary additions always alert)
 *
 * @return void
 *
 * @note Both lists must be sorted by relative path
 * @note Algorithm complexity is O(n + m) where n, m are list lengths
 * @note Only additions are allowlisted; modifications and deletions always alert
 */
static void diff_and_report(const FileList *oldL, const FileList *newL, const char* iob_id,
                            int apply_add_allowlist)
{
    size_t i = 0, j = 0;
    char message[IDS_REPORT_MESSAGE_LEN];
    
    /* Merge-like comparison of sorted lists */
    while (i < oldL->len || j < newL->len)
    {
        if (i < oldL->len && j < newL->len)
        {
            int c = strcmp(oldL->items[i].rel_path, newL->items[j].rel_path);
            
            if (c == 0)
            {
                /* Same file - check if hash changed */
                if (!hash_equal(oldL->items[i].sha256, newL->items[j].sha256))
                {
                    /* File modified */
                    memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                    snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                             "[SPACECOP] IOB Detected: SPARTA ID=%s (File Integrity Failed for %s)", 
                             iob_id, oldL->items[i].rel_path);
                    
                    SPACECOP_ReportIDSMsg(message);
                    CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                      "[SPACECOP] IOB Detected: SPARTA ID=%s (File Integrity Failed for %s)", 
                                      iob_id, oldL->items[i].rel_path);
                    
                    write_to_stix(newL->items[j].rel_path, newL->items[j].sha256, iob_id);
                }
                i++;
                j++;
            }
            else if (c < 0)
            {
                /* File in old but not in new - deleted */
                memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                         "[SPACECOP] IOB Detected: SPARTA ID=%s (File Deleted %s)", 
                         iob_id, oldL->items[i].rel_path);
                
                SPACECOP_ReportIDSMsg(message);
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                  "[SPACECOP] IOB Detected: SPARTA ID=%s (File Deleted %s)", 
                                  iob_id, oldL->items[i].rel_path);
                
                write_to_stix(oldL->items[i].rel_path, oldL->items[i].sha256, iob_id);
                i++;
            }
            else
            {
                /* File in new but not in old - added */

                /* Suppress expected new files (e.g. camera captures) in the
                 * data dir; still alert on anything not on the allowlist. */
                if (apply_add_allowlist && add_is_allowlisted(newL->items[j].rel_path))
                {
                    j++;
                    continue;
                }

                memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN,
                         "[SPACECOP] IOB Detected: SPARTA ID=%s (File Added %s)",
                         iob_id, newL->items[j].rel_path);

                SPACECOP_ReportIDSMsg(message);
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                  "[SPACECOP] IOB Detected: SPARTA ID=%s (File Added %s)", 
                                  iob_id, newL->items[j].rel_path);
                
                write_to_stix(newL->items[j].rel_path, newL->items[j].sha256, iob_id);
                j++;
            }
        }
        else if (i < oldL->len)
        {
            /* Remaining old files - deleted */
            memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
            snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                     "[SPACECOP] IOB Detected: SPARTA ID=%s (File Deleted %s)", 
                     iob_id, oldL->items[i].rel_path);
            
            SPACECOP_ReportIDSMsg(message);
            CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                              "[SPACECOP] IOB Detected: SPARTA ID=%s (File Deleted %s)", 
                              iob_id, oldL->items[i].rel_path);
            
            write_to_stix(oldL->items[i].rel_path, oldL->items[i].sha256, iob_id);
            i++;
        }
        else
        {
            /* Remaining new files - added */

            /* Suppress expected new files (e.g. camera captures) in the data
             * dir; still alert on anything not on the allowlist. */
            if (apply_add_allowlist && add_is_allowlisted(newL->items[j].rel_path))
            {
                j++;
                continue;
            }

            memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
            snprintf(message, IDS_REPORT_MESSAGE_LEN,
                     "[SPACECOP] IOB Detected: SPARTA ID=%s (File Added %s)",
                     iob_id, newL->items[j].rel_path);

            SPACECOP_ReportIDSMsg(message);
            CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                              "[SPACECOP] IOB Detected: SPARTA ID=%s (File Added %s)", 
                              iob_id, newL->items[j].rel_path);
            
            write_to_stix(newL->items[j].rel_path, newL->items[j].sha256, iob_id);
            j++;
        }
    }
}

/*=======================================================================================
** Public API Functions
**=======================================================================================*/

/**
 * @brief Scan a directory tree and build a file list with hashes
 *
 * Public interface for scanning a directory. Validates the path, resets
 * the output list, performs recursive scanning, and sorts the results.
 *
 * @param[in] root Absolute or relative path to directory to scan
 * @param[out] out Pointer to FileList to populate
 *
 * @return void
 *
 * @note Validates that root exists and is a directory
 * @note Resets output list before scanning
 * @note Results are sorted by relative path
 */
void scan_root(const char *root, FileList *out)
{
    if (!root || !out)
    {
        printf("ERROR: NULL parameter to scan_root\n");
        return;
    }
    
    /* Check if directory exists */
    struct stat st;
    if (stat(root, &st) != 0)
    {
        printf("Path '%s' does not exist: %s\n", root, strerror(errno));
        filelist_reset(out);
        return;
    }
    
    if (!S_ISDIR(st.st_mode))
    {
        printf("Path '%s' is not a directory\n", root);
        filelist_reset(out);
        return;
    }

    /* Reset the output list and scan */
    filelist_reset(out);
    walk_dir_recursive(root, "", out);
    sort_filelist(out);
}

/**
 * @brief Check if a file hash exists in the file list
 *
 * Searches for a matching hash, optionally filtering by filename substring.
 *
 * @param[in] l Pointer to FileList to search
 * @param[in] name Filename to match (partial match supported), max 128 chars
 * @param[in] sha256 SHA-256 hash to search for (32 bytes)
 *
 * @return int Returns 1 if found, 0 otherwise
 */
int does_hash_exist(const FileList *l, char name[128], unsigned char sha256[SHA256_DIGEST_LENGTH])
{
    for (size_t i = 0; i < l->len; i++)
    {
        /* Check if name is substring of rel_path */
        if (strstr(name, l->items[i].rel_path))
        {
            if (hash_equal(l->items[i].sha256, sha256))
                return 1;
        }
        /* Also check hash-only match */
        if (hash_equal(l->items[i].sha256, sha256))
            return 1;
    }
    return 0;
}

/**
 * @brief Initialize file integrity monitoring system
 *
 * Establishes baseline file lists for "cf" and "data" directories.
 * Must be called once before RunFileIntegrity(). Safe to call multiple times.
 *
 * @return void
 *
 * @note Only initializes once (subsequent calls are ignored)
 * @note Scans "cf" and "data" relative to current working directory
 */
void Init_FileIntegrity(void)
{
    if (initialized != 0)
    {
        return;
    }
    
    initialized = 1;  /* Mark as initializing */

    /* Load the data-dir add-allowlist (falls back to the built-in default) */
    load_add_allowlist();

    /* Initialize the lists */
    filelist_reset(&cf_old);
    filelist_reset(&data_old);
    
    /* Scan CF directory */
    scan_root(cf_dir, &cf_old);
    
    /* Scan data directory */
    scan_root(data_dir, &data_old);
    
    initialized = 2;  /* Mark as fully initialized */
}

/**
 * @brief Run file integrity check and report changes
 *
 * Rescans monitored directories, compares against baselines, reports
 * any changes, and updates baselines for next check.
 *
 * @param[in] iob_id SPARTA/STIX identifier for alert correlation
 *
 * @return void
 *
 * @note Returns immediately if not initialized
 * @note Updates baselines after each check
 *
 * @see Init_FileIntegrity()
 */
void RunFileIntegrity(const char* iob_id)
{
    if (initialized != 2)
    {
        return;
    }

    FileList cf_new;
    FileList data_new;
    
    filelist_reset(&cf_new);
    filelist_reset(&data_new);

    /* Scan current state */
    scan_root(cf_dir, &cf_new);
    scan_root(data_dir, &data_new);

    /* Compare and report differences. The cf dir is strict (0): every add is
     * alerted. The data dir (1) suppresses allowlisted additions (e.g. camera
     * captures) but still alerts on unexpected adds and on any modify/delete. */
    diff_and_report(&cf_old, &cf_new, iob_id, 0);
    diff_and_report(&data_old, &data_new, iob_id, 1);

    /* Update baselines */
    filelist_move(&cf_old, &cf_new);
    filelist_move(&data_old, &data_new);
}