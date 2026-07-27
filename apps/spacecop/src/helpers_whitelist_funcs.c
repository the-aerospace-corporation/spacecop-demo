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
 * @file helpers_whitelist_funcs.c
 * @brief Implementation of process whitelist management for SpaceCop IDS
 *
 * This file implements a thread-safe process whitelist system for filtering
 * known-good processes from IDS alerts. The whitelist is loaded from a text
 * file and stored in a sorted array for efficient lookups.
 *
 * **Design Principles:**
 * - Thread-safe: All operations protected by mutex
 * - Case-insensitive: All comparisons ignore case
 * - Flexible matching: Supports both exact and substring matching
 * - Efficient: Sorted storage enables fast lookups
 * - Robust: Handles comments, whitespace, and malformed input
 *
 * **Implementation Details:**
 * - Global whitelist stored in static variable
 * - Mutex protects all read/write operations
 * - Names normalized (trimmed, lowercased) before storage
 * - Sorted after loading for consistent ordering
 * - Temporary buffer used during loading to avoid partial updates
 *
 * **Use Cases:**
 * - Process monitoring (filter system processes)
 * - CPU usage monitoring (ignore known-intensive processes)
 * - Memory monitoring (exclude expected high-memory processes)
 * - Command execution monitoring (allow authorized commands)
 */

#include <pthread.h>
#include "helpers_whitelist_funcs.h"

/*=======================================================================================
** Global Variables
**=======================================================================================*/

/** @brief Global process whitelist structure */
static WhiteList_t g_proc_whitelist;

/** @brief Mutex for thread-safe whitelist access */
static pthread_mutex_t whitelist_mutex = PTHREAD_MUTEX_INITIALIZER;

/*=======================================================================================
** Internal Helper Functions
**=======================================================================================*/

/**
 * @brief Trim leading and trailing whitespace from a string in-place
 *
 * Removes all leading and trailing whitespace characters (space, tab, newline,
 * etc.) from the string. The string is modified in-place.
 *
 * @param[in,out] s Pointer to null-terminated string to trim
 *
 * @return void
 *
 * @note Uses isspace() to identify whitespace characters
 * @note Modifies the string in-place using memmove for leading whitespace
 */
static void Trim(char *s)
{
	char *p = s;
	
	/* Skip leading whitespace */
	while (*p && isspace((unsigned char)*p))
		p++;

	/* Move string to beginning if leading whitespace was found */
	if (p != s) 
		memmove(s, p, strlen(p) + 1);

	/* Remove trailing whitespace */
	size_t n = strlen(s);
	while (n > 0 && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

/**
 * @brief Convert a string to lowercase in-place
 *
 * Converts all uppercase characters in the string to lowercase using
 * the tolower() function. The string is modified in-place.
 *
 * @param[in,out] s Pointer to null-terminated string to convert
 *
 * @return void
 *
 * @note Uses tolower() for conversion
 * @note Handles unsigned char cast to avoid undefined behavior
 */
static void ToLowerInPlace(char *s)
{
	for (; *s; s++)
		*s = (char)tolower((unsigned char)*s);
}

/**
 * @brief Comparison function for qsort
 *
 * Compares two process names for sorting. Used by qsort() to maintain
 * the whitelist in sorted order.
 *
 * @param[in] a Pointer to first process name
 * @param[in] b Pointer to second process name
 *
 * @return int Negative if a < b, 0 if equal, positive if a > b
 *
 * @note Uses strncmp with WL_NAME_MAX limit
 */
static int CmpNames(const void *a, const void *b)
{
	const char *sa = (const char *)a;
	const char *sb = (const char *)b;
	return strncmp(sa, sb, WL_NAME_MAX);
}

/*=======================================================================================
** Public API Functions
**=======================================================================================*/

/**
 * @brief Load process whitelist from a file
 *
 * Reads a whitelist file line by line, processes each entry (trimming,
 * lowercasing, removing comments), and stores the results in a sorted array.
 * Uses a temporary buffer during loading to avoid partial updates if an
 * error occurs.
 *
 * File parsing:
 * 1. Read line from file
 * 2. Remove comments (everything after '#')
 * 3. Trim leading/trailing whitespace
 * 4. Skip empty lines
 * 5. Convert to lowercase
 * 6. Add to temporary whitelist
 * 7. Sort entries
 * 8. Replace global whitelist atomically
 *
 * @param[in] path Path to the whitelist file
 *
 * @return int Returns 0 on success, negative on error
 *
 * @note Thread-safe (acquires mutex during entire operation)
 * @note Previous whitelist is completely replaced
 * @note Maximum WL_MAX_ENTRIES entries supported
 * @note Temporary buffer ensures atomic update
 */
int WL_LoadFromFile_Proc(const char *path)
{
	pthread_mutex_lock(&whitelist_mutex);
	
	/* Open whitelist file */
	FILE *f = fopen(path, "r");
	if (!f) 
	{
		pthread_mutex_unlock(&whitelist_mutex);
		return -1;
	}

	/* Allocate temporary whitelist for loading */
	WhiteList_t *tmp = malloc(sizeof(*tmp));
	if (!tmp) 
	{
		fclose(f);
		pthread_mutex_unlock(&whitelist_mutex);
		return -2;
	}

	memset(tmp, 0, sizeof(*tmp));
	char line[256];

	/* Read and process each line */
	while (fgets(line, sizeof(line), f))
	{
		/* Remove newline characters */
		line[strcspn(line, "\r\n")] = '\0';

		/* Remove comments (everything after '#') */
		char *hash = strchr(line, '#');
		if (hash) *hash = '\0';

		/* Trim whitespace */
		Trim(line);
		
		/* Skip empty lines */
		if (line[0] == '\0') continue;

		/* Convert to lowercase for case-insensitive matching */
		ToLowerInPlace(line);

		/* Check if we've reached capacity */
		if (tmp->count >= WL_MAX_ENTRIES)
		{
			fclose(f);
			free(tmp);
			pthread_mutex_unlock(&whitelist_mutex);
			return -2;
		}

		/* Add entry to temporary whitelist */
		strncpy(tmp->items[tmp->count], line, WL_NAME_MAX);
		tmp->items[tmp->count][WL_NAME_MAX - 1] = '\0';
		tmp->count++;
	}
	fclose(f);
	
	/* Sort entries for consistent ordering and efficient lookups */
	qsort(tmp->items, tmp->count, WL_NAME_MAX, CmpNames);

	/* Atomically replace global whitelist */
	g_proc_whitelist = *tmp;
	free(tmp);
	
	pthread_mutex_unlock(&whitelist_mutex);
	return 0;
}

/**
 * @brief Check if a process name is in the whitelist (exact match)
 *
 * Performs a case-insensitive exact match against all whitelist entries.
 * The input name is normalized (trimmed and lowercased) before comparison.
 *
 * @param[in] name Process name to check
 *
 * @return int Returns 1 if found, 0 otherwise
 *
 * @note Thread-safe (acquires mutex)
 * @note Linear search through whitelist (O(n))
 * @note Returns 0 if name is NULL or whitelist is empty
 */
int WL_ContainsName_Proc(const char *name)
{
	if (!name || g_proc_whitelist.count == 0) return 0;

	pthread_mutex_lock(&whitelist_mutex);
	
	/* Normalize the search key */
	char key[WL_NAME_MAX];
	strncpy(key, name, WL_NAME_MAX);
	key[WL_NAME_MAX - 1] = '\0';
	Trim(key);
	ToLowerInPlace(key);

	/* Linear search for exact match */
	for (int i = 0; i < g_proc_whitelist.count; i++) 
	{
		if (strcmp(key, g_proc_whitelist.items[i]) == 0) 
		{
			pthread_mutex_unlock(&whitelist_mutex);
			return 1;
		}
	}
	
	pthread_mutex_unlock(&whitelist_mutex);
	return 0;
}

/**
 * @brief Check if a process name contains a whitelisted substring
 *
 * Performs a case-insensitive substring search to determine if any whitelist
 * entry appears within the process name. This allows matching process name
 * variations (e.g., "python3.8" contains "python").
 *
 * @param[in] name Process name to check
 *
 * @return int Returns 1 if any whitelist entry is a substring, 0 otherwise
 *
 * @note Thread-safe (acquires mutex)
 * @note Uses strstr() for substring matching
 * @note More permissive than exact matching
 * @note Returns 0 if name is NULL or whitelist is empty
 *
 * Example:
 * - Whitelist contains "python"
 * - Input "python3.8" returns 1 (match)
 * - Input "/usr/bin/python" returns 1 (match)
 * - Input "java" returns 0 (no match)
 */
int WL_ContainsSubName_Proc(const char *name)
{
	if (!name || g_proc_whitelist.count == 0) return 0;

	pthread_mutex_lock(&whitelist_mutex);
	
	/* Normalize the search key */
	char key[WL_NAME_MAX];
	strncpy(key, name, WL_NAME_MAX);
	key[WL_NAME_MAX - 1] = '\0';
	Trim(key);
	ToLowerInPlace(key);

	/* Search for substring matches */
	for (int i = 0; i < g_proc_whitelist.count; i++) 
	{
		if (strstr(key, g_proc_whitelist.items[i])) 
		{
			pthread_mutex_unlock(&whitelist_mutex);
			return 1;
		}
	}
	
	pthread_mutex_unlock(&whitelist_mutex);
	return 0;
}