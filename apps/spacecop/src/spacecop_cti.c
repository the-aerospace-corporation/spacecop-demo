// Copyright © 2026 Aerospace Corporation
// Project Title: SpaceCop
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
 * @file spacecop_cti.c
 * @brief Cyber Threat Intelligence (CTI) processing implementation for SpaceCop IDS
 *
 * This file implements CTI data ingestion and threat detection capabilities for
 * SpaceCop. It processes STIX-formatted threat intelligence bundles to detect
 * known malicious files and programs on the spacecraft file system.
 *
 * **Key Features:**
 * - STIX 2.x bundle parsing (JSON format)
 * - File hash-based threat detection (SHA-256)
 * - Indicator of Behavior (IOB) mapping
 * - Incremental CTI data loading from cf/cti/ directory
 * - Automatic file system scanning for matches
 * - Thread-safe CTI data storage
 *
 * **Architecture:**
 * The CTI system maintains a global array of threat indicators loaded from
 * JSON files in the cf/cti/ directory. A child task periodically:
 * 1. Scans for new CTI files
 * 2. Parses STIX bundles
 * 3. Extracts file hashes and IOB identifiers
 * 4. Scans cf/ and data/ directories for matches
 * 5. Generates IDS alerts for detected threats
 *
 * **STIX Object Types Supported:**
 * - indicator: Contains IOB identifier (x_sparta_iob_id)
 * - file: Contains filename and SHA-256 hash
 * - program: Contains program name
 *
 * **JSON Parser:**
 * This file includes a custom lightweight JSON parser designed for embedded
 * systems with limited memory. The parser uses a single-pass streaming approach
 * with minimal memory allocation.
 *
 * @note CTI files must have .dat extension
 * @note Files are loaded once and cached in memory
 * @note Duplicate entries are automatically filtered
 *
 * @see spacecop_cti.h for data structure definitions
 */

#include "spacecop_cti.h"
#include "spacecop_platform_cfg.h"  /* SPACECOP_CF_DIR / DATA_DIR / CTI_DIR */

/*=======================================================================================
** File-Scope Global Variables
**=======================================================================================*/

/**
 * @brief Global CTI data storage array
 * 
 * Dynamically-sized array containing all loaded CTI threat indicators.
 * Populated during CTI file scanning and used for threat detection.
 * 
 * @note Initialized by CTI_InitArray()
 * @note Freed by CTI_FreeArray()
 * @note Access is not thread-safe - caller must ensure synchronization
 */
static CTIArray *cti_array;

/*=======================================================================================
** Private Helper Functions - File Handling
**=======================================================================================*/

/**
 * @brief Check if filename has .dat extension
 *
 * Validates that a filename ends with the .dat extension, which is used
 * to identify CTI data files in the cf/cti/ directory.
 *
 * @param[in] name Filename to check
 *
 * @return int 1 if file has .dat extension, 0 otherwise
 *
 * @note Case-sensitive comparison
 * @note Requires at least 5 characters (e.g., "a.dat")
 *
 * Example:
 * @code
 * has_json_ext("threat.dat")  // returns 1
 * has_json_ext("threat.json") // returns 0
 * has_json_ext("dat")         // returns 0
 * @endcode
 */
static int has_json_ext(const char *name)
{
	size_t n = strlen(name);
	return (n > 5) && strcmp(name + (n - 4), ".dat") == 0;
}

/**
 * @brief Read entire file into memory
 *
 * Allocates a buffer and reads the complete contents of a file. The returned
 * buffer is null-terminated for use as a string.
 *
 * @param[in] path Path to file to read
 *
 * @return char* Pointer to allocated buffer containing file contents, or NULL on error
 *
 * @note Caller must free() the returned buffer
 * @note Returned buffer is null-terminated
 * @note Returns NULL if file cannot be opened, read, or memory allocation fails
 *
 * @warning Large files may exhaust available memory
 *
 * Example usage:
 * @code
 * char *json = read_entire_file("cf/cti/threat.dat");
 * if (json) {
 *     // Process JSON data
 *     free(json);
 * }
 * @endcode
 */
static char *read_entire_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;

	/* Seek to end to determine file size */
	if (fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return NULL;
	}

	long len = ftell(f);
	if (len < 0)
	{
		fclose(f);
		return NULL;
	}

	rewind(f);

	/* Allocate buffer with space for null terminator */
	char *buf = (char *)malloc((size_t)len + 1);
	if (!buf) 
	{
		fclose(f);
		return NULL;
	}

	/* Read entire file */
	size_t n = fread(buf, 1, (size_t)len, f);
	fclose(f);

	if (n != (size_t)len)
	{
		free(buf);
		return NULL;
	}
	
	buf[len] = '\0';  /* Null-terminate */
	return buf;
}

/*=======================================================================================
** Private Helper Functions - Root Object Management
**=======================================================================================*/

/**
 * @brief Append object to Root objects array
 *
 * Adds a CTI_Info object to the Root structure's dynamic array. Automatically
 * resizes the array if capacity is exceeded.
 *
 * @param[in,out] r Pointer to Root structure
 * @param[in] obj Pointer to CTI_Info object to append
 *
 * @return int 1 on success, 0 on memory allocation failure
 *
 * @note Uses exponential growth strategy (doubles capacity when full)
 * @note Initial capacity is 8 objects
 * @note Does not check for duplicate entries
 */
static int root_objects_append(Root *r, const CTI_Info *obj)
{
	/* Check if resize is needed */
	if (r->objects_count >= r->objects_cap)
	{
		size_t new_cap = (r->objects_cap == 0) ? 8 : r->objects_cap * 2;
		void *tmp = realloc(r->objects, new_cap * sizeof(CTI_Info));
		if (!tmp) return 0;
		r->objects = (CTI_Info *)tmp;
		r->objects_cap = new_cap;
	}
	
	/* Append object */
	r->objects[r->objects_count++] = *obj;
	return 1;
}

/**
 * @brief Free Root structure resources
 *
 * Releases all memory allocated for the Root structure's objects array
 * and resets the structure to empty state.
 *
 * @param[in,out] r Pointer to Root structure to free
 *
 * @return void
 *
 * @note Safe to call with NULL pointer
 * @note Safe to call multiple times
 * @note Does not free the Root structure itself
 */
static void free_root(Root *r)
{
	if (!r) return;
	free(r->objects);
	r->objects = NULL;
	r->objects_count = 0;
	r->objects_cap = 0;
}

/*=======================================================================================
** Private Helper Functions - JSON Parsing Utilities
**=======================================================================================*/

/**
 * @brief Skip whitespace characters in JSON stream
 *
 * Advances the JSON parser position past any whitespace characters
 * (space, newline, carriage return, tab).
 *
 * @param[in,out] j Pointer to Json parser state
 *
 * @return void
 *
 * @note Updates j->p to point to next non-whitespace character
 */
static void jskip_ws(Json *j)
{
	while (j->p < j->end && (*j->p == ' ' || *j->p == '\n' || *j->p == '\r' || *j->p == '\t'))
	{
		j->p++;
	}
}

/**
 * @brief Skip a JSON number value
 *
 * Validates and advances past a JSON number. Supports integers, decimals,
 * and scientific notation per JSON specification.
 *
 * **Supported Formats:**
 * - Integer: 123, -456
 * - Decimal: 3.14, -0.5
 * - Scientific: 1.23e10, -4.5E-6
 *
 * @param[in,out] j Pointer to Json parser state
 *
 * @return int 1 on success, 0 if invalid number format
 *
 * @note Sets j->err on parse error
 * @note Does not convert to numeric value (just validates syntax)
 */
static int jskip_number(Json *j) 
{ 
	jskip_ws(j);

	const char *start = j->p;

	/* Optional sign */
	if (j->p < j->end && (*j->p == '-' || *j->p == '+'))
		j->p++; 

	/* Integer part (required) */
	int digits = 0;
	while(j->p < j->end && isdigit((unsigned char)*j->p))
	{
		j->p++;
		digits = 1;
	}

	if (!digits)
	{
		j->err = start;
		return 0;
	}

	/* Fractional part (optional) */
	if (j->p < j->end && *j->p == '.')
	{
		j->p++;
		if (j->p >= j->end || !isdigit((unsigned char)*j->p))
		{
			j->err = j->p;
			return 0;
		}

		while (j->p < j->end && isdigit((unsigned char)*j->p))
			j->p++;
	}

	/* Exponent part (optional) */
	if (j->p < j->end && (*j->p == 'e' || *j->p == 'E'))
	{
		j->p++;
		if (j->p < j->end && (*j->p == '+' || *j->p == '-'))
			j->p++;
		if (j->p < j->end || !isdigit((unsigned char)*j->p))
		{
			j->err = j->p;
			return 0;
		}
		while (j->p < j->end && isdigit((unsigned char)*j->p))
			j->p++;
	}

	return 1; 
}

/**
 * @brief Match and consume a specific character
 *
 * Checks if the next non-whitespace character matches the expected character.
 * If it matches, advances past it.
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[in] c Character to match
 *
 * @return int 1 if character matched and consumed, 0 otherwise
 *
 * @note Skips leading whitespace before matching
 * @note Does not set error flag on mismatch
 */
static int jmatch(Json *j, char c)
{
	jskip_ws(j);
	if (j->p < j->end && *j->p == c)
	{
		j->p++;
		return 1;
	}
	return 0;
}

/**
 * @brief Convert hex digit to numeric value
 *
 * Converts a hexadecimal character ('0'-'9', 'a'-'f', 'A'-'F') to its
 * numeric value (0-15).
 *
 * @param[in] c Hexadecimal character
 *
 * @return int Numeric value (0-15), or -1 if not a valid hex digit
 *
 * @note Case-insensitive
 */
static int hexval(int c)
{
	if ('0' <= c && c <= '9') return c - '0';
	if ('a' <= c && c <= 'f') return 10 + (c - 'a');
	if ('A' <= c && c <= 'F') return 10 + (c - 'A');
	return -1;
}

/**
 * @brief Encode Unicode codepoint as UTF-8
 *
 * Converts a Unicode codepoint (Basic Multilingual Plane only) to UTF-8
 * byte sequence.
 *
 * @param[in] cp Unicode codepoint (0x0000 - 0xFFFF)
 * @param[out] out Output buffer (must be at least 3 bytes)
 *
 * @return int Number of bytes written (1-3)
 *
 * **Encoding:**
 * - 0x0000-0x007F: 1 byte  (ASCII)
 * - 0x0080-0x07FF: 2 bytes
 * - 0x0800-0xFFFF: 3 bytes
 *
 * @note Does not handle surrogate pairs or codepoints > 0xFFFF
 */
static int utf8_encode_bmp(unsigned cp, char out[3])
{
	if (cp <= 0x7F)
	{
		out[0] = (char)cp;
		return 1;
	}
	if (cp <= 0x7FF)
	{
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	out[0] = (char)(0xE0 | (cp >> 12));
	out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
	out[2] = (char)(0x80 | (cp & 0x3F));
	return 3;
}

/**
 * @brief Parse JSON string value
 *
 * Parses a JSON string value, handling escape sequences and Unicode escapes.
 * Writes the unescaped string to the destination buffer.
 *
 * **Supported Escape Sequences:**
 * - \" \\ \/ \b \f \n \r \t
 * - \uXXXX (Unicode escape)
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[out] dst Destination buffer for unescaped string
 * @param[in] dstsz Size of destination buffer in bytes
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Output is always null-terminated
 * @note If output exceeds buffer size, string is truncated
 * @note Sets j->err on parse error
 * @note Control characters (< 0x20) are not allowed in strings
 *
 * Example:
 * @code
 * char buf[128];
 * if (jparse_string(&j, buf, sizeof(buf))) {
 *     printf("Parsed: %s\n", buf);
 * }
 * @endcode
 */
static int jparse_string(Json *j, char *dst, size_t dstsz)
{
	jskip_ws(j);
	if (j->p >= j->end || *j->p != '"')
	{
		j->err = j->p;
		return 0;
	}
	j->p++;

	size_t out = 0;
	while (j->p < j->end)
	{
		char c = *j->p++;
		
		/* End of string */
		if (c == '"')
		{
			if (dstsz > 0)
				dst[(out < dstsz) ? out : (dstsz - 1)] = '\0';
			return 1;
		}

		/* Control characters not allowed */
		if ((unsigned char)c < 0x20) 
		{
			j->err = j->p - 1;
			return 0;
		}

		/* Handle escape sequences */
		if (c == '\\')
		{
			if (j->p >= j->end)
			{
				j->err = j->p;
				return 0;
			}
			char e = *j->p++;
			switch (e)
			{
				case '"':
					c = '"';
					break;
				case '\\':
					c = '\\';
					break;
				case '/':
					c = '/';
					break;
				case 'b': 
					c = '\b';
					break;
				case 'f':
					c = '\f';
					break;
				case 'n':
					c = '\n';
					break;
				case 'r':
					c = '\r';
					break;
				case 't':
					c = '\t';
					break;
				case 'u':
				{
					/* Unicode escape: \uXXXX */
					if (j->end - j->p < 4)
					{
						j->err = j->p;
						return 0;
					}
					int h1 = hexval(j->p[0]);
					int h2 = hexval(j->p[1]);
					int h3 = hexval(j->p[2]);
					int h4 = hexval(j->p[3]);
					if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0)
					{
						j->err = j->p;
						return 0;
					}
					unsigned cp = (unsigned)((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
					j->p += 4;

					/* Encode as UTF-8 */
					char tmp[3];
					int n = utf8_encode_bmp(cp, tmp);
					for (int i = 0; i < n; i++)
					{
						if (out + 1 < dstsz)
							dst[out] = tmp[i];
						out++;
					}
					continue;
				}
				default:
					j->err = j->p - 1;
					return 0;
			}
		}

		/* Append character to output */
		if (out + 1 < dstsz)
			dst[out] = c;
		out++;
	}
	
	j->err = j->p;
	return 0;
}

/**
 * @brief Convert hexadecimal string to byte array
 *
 * Converts a hexadecimal string (e.g., "A1B2C3") to binary byte array.
 * Used for parsing SHA-256 hashes from JSON.
 *
 * @param[in] hex Hexadecimal string (no 0x prefix)
 * @param[out] out Output byte array
 * @param[in] out_len Expected length of output in bytes
 *
 * @return int 1 on success, 0 if string length or format is invalid
 *
 * @note Input string must be exactly 2*out_len characters
 * @note Case-insensitive
 *
 * Example:
 * @code
 * unsigned char hash[32];
 * if (hex_to_bytes("a1b2c3...", hash, 32)) {
 *     // hash contains binary SHA-256
 * }
 * @endcode
 */
static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
	size_t len = strlen(hex);

	/* Must be exactly 2 hex digits per byte */
	if (len != out_len * 2) return 0;

	for (size_t i = 0; i < out_len; i++)
	{
		int hi = hexval(hex[i * 2]);
		int lo = hexval(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0) return 0;

		out[i] = (unsigned char)((hi << 4) | lo);
	}

	return 1;
}

/**
 * @brief Parse JSON string as hash value
 *
 * Parses a JSON string value and converts it from hexadecimal to binary
 * hash value. Wrapper around jparse_string() and hex_to_bytes().
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[out] out Output buffer for binary hash
 * @param[in] out_len Expected hash length in bytes
 *
 * @return int 1 on success, 0 on parse or conversion error
 *
 * @note Commonly used with out_len=32 for SHA-256 hashes
 */
static int jparse_hash(Json *j, unsigned char *out, size_t out_len)
{
	char tmp[129];  /* SHA-512 (64 bytes) = 128 hex chars + null */

	if (!jparse_string(j, tmp, sizeof(tmp))) return 0;

	return hex_to_bytes(tmp, out, out_len);
}

/*=======================================================================================
** Private Helper Functions - JSON Value Skipping
**=======================================================================================*/

/* Forward declaration for recursive call */
static int jskip_value(Json *j);

/**
 * @brief Skip a JSON array value
 *
 * Validates and advances past a complete JSON array, including all nested
 * values. Does not store array contents.
 *
 * @param[in,out] j Pointer to Json parser state
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Sets j->err on parse error
 * @note Handles nested arrays and objects
 */
static int jskip_array(Json *j)
{
	if (!jmatch(j, '[')) 
	{
		j->err = j->p;
		return 0;
	}
	jskip_ws(j);
	
	/* Empty array */
	if (jmatch(j, ']')) return 1;

	/* Skip array elements */
	for (;;)
	{
		if (!jskip_value(j)) return 0;
		jskip_ws(j);
		if (jmatch(j, ']')) return 1;
		if (!jmatch(j, ','))
		{
			j->err = j->p;
			return 0;
		}
	}
}

/**
 * @brief Skip a JSON object value
 *
 * Validates and advances past a complete JSON object, including all nested
 * values. Does not store object contents.
 *
 * @param[in,out] j Pointer to Json parser state
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Sets j->err on parse error
 * @note Handles nested arrays and objects
 */
static int jskip_object(Json *j)
{
	if (!jmatch(j, '{'))
	{
		j->err = j->p;
		return 0;
	}
	jskip_ws(j);
	
	/* Empty object */
	if (jmatch(j, '}')) return 1;

	/* Skip object members */
	for (;;)
	{
		char key[128];
		if (!jparse_string(j, key, sizeof(key))) return 0;
		if (!jmatch(j, ':')) 
		{
			j->err = j->p;
			return 0;
		}

		if (!jskip_value(j)) return 0;

		jskip_ws(j);
		if (jmatch(j, '}')) return 1;
		if (!jmatch(j, ',')) 
		{
			j->err = j->p;
			return 0;
		}
	}
}

/**
 * @brief Skip a JSON literal value
 *
 * Matches and advances past a JSON literal (true, false, null).
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[in] lit Expected literal string
 *
 * @return int 1 on success, 0 if literal doesn't match
 *
 * @note Sets j->err on mismatch
 */
static int jskip_literal(Json *j, const char *lit)
{
	jskip_ws(j);
	size_t n = strlen(lit);
	if ((size_t)(j->end - j->p) < n)
	{
		j->err = j->p;
		return 0;
	}
	if (strncmp(j->p, lit, n) != 0)
	{
		j->err = j->p;
		return 0;
	}
	j->p += n;
	return 1;
}

/**
 * @brief Skip any JSON value
 *
 * Validates and advances past any JSON value type (string, number, object,
 * array, true, false, null). Used when we need to skip uninteresting parts
 * of the JSON structure.
 *
 * @param[in,out] j Pointer to Json parser state
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Sets j->err on parse error
 * @note Recursively handles nested structures
 */
static int jskip_value(Json *j)
{
	jskip_ws(j);
	if (j->p >= j->end)
	{
		j->err = j->p;
		return 0;
	}

	char c = *j->p;
	
	if (c == '"')
	{
		char tmp[1];
		return jparse_string(j, tmp, sizeof(tmp));
	}

	if (c == '{') return jskip_object(j);
	if (c == '[') return jskip_array(j);
	if (c == 't') return jskip_literal(j, "true");
	if (c == 'f') return jskip_literal(j, "false");
	if (c == 'n') return jskip_literal(j, "null");

	if (c == '-' || isdigit((unsigned char)c))
	{
	    return jskip_number(j);
	}

	j->err = j->p;
	return 0;
}

/*=======================================================================================
** Private Helper Functions - STIX Object Parsing
**=======================================================================================*/

/**
 * @brief Parse STIX object type string to enum
 *
 * Converts a STIX object type string to the corresponding ObjectKind enum value.
 *
 * @param[in] t Type string from JSON "type" field
 *
 * @return ObjectKind Enum value, or OBJ_UNKNOWN if not recognized
 *
 * **Supported Types:**
 * - "indicator" -> OBJ_INDICATOR
 * - "file" -> OBJ_FILE
 * - "program" -> OBJ_PROGRAM
 */
static ObjectKind parse_kind(const char *t)
{
	if (!t) return OBJ_UNKNOWN;
	if (strcmp(t, "indicator") == 0) return OBJ_INDICATOR;
	if (strcmp(t, "file") == 0) return OBJ_FILE;
	if (strcmp(t, "program") == 0) return OBJ_PROGRAM;
	return OBJ_UNKNOWN;
}

/**
 * @brief Convert ObjectKind enum to string
 *
 * Converts an ObjectKind enum value to its string representation for
 * logging and debugging.
 *
 * @param[in] k ObjectKind enum value
 *
 * @return const char* String representation
 *
 * @note Returns static string - do not free
 */
static const char *kind_to_string(ObjectKind k)
{
	switch(k)
	{
		case OBJ_INDICATOR: return "indicator";
		case OBJ_FILE: return "file";
		case OBJ_PROGRAM: return "program";
		default: return "unknown";
	}
}

/**
 * @brief Parse STIX file hashes object
 *
 * Parses the "hashes" object within a STIX file object, extracting the
 * SHA-256 hash value.
 *
 * **Expected JSON Format:**
 * @code
 * "hashes": {
 *   "SHA-256": "a1b2c3d4..."
 * }
 * @endcode
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[out] out Pointer to CTI_Info structure to populate with hash
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Only SHA-256 hashes are extracted; other hash types are ignored
 * @note Sets j->err on parse error
 */
static int parse_hashes_object(Json *j, CTI_Info *out)
{
	if (!jmatch(j, '{'))
	{
		j->err = j->p;
		return 0;
	}

	jskip_ws(j);
	if (jmatch(j, '}')) return 1;

	for (;;)
	{
		char key[128];
		if (!jparse_string(j, key, sizeof(key))) return 0;
		if (!jmatch(j, ':'))
		{
			j->err = j->p;
			return 0;
		}

		if (strcmp(key, "SHA-256") == 0)
		{
			if (!jparse_hash(j, out->sha256, sizeof(out->sha256))) return 0;
		}
		else
		{
			/* Skip other hash types */
			if (!jskip_value(j)) return 0;
		}

		jskip_ws(j);
		if (jmatch(j, '}')) break;
		if (!jmatch(j, ','))
		{
			j->err = j->p;
			return 0;
		}
	}
	return 1;
}

/**
 * @brief Parse a STIX object entry
 *
 * Parses a single STIX object from the "objects" array in a STIX bundle.
 * Extracts relevant fields based on object type.
 *
 * **Extracted Fields by Type:**
 * - indicator: x_sparta_iob_id
 * - file: name, hashes (SHA-256)
 * - program: name
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[out] out Pointer to CTI_Info structure to populate
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Output structure is zeroed before parsing
 * @note Unknown fields are skipped
 * @note Sets j->err on parse error
 */
static int parse_object_entry(Json *j, CTI_Info *out)
{
	if (!out) return 0;
	memset(out, 0, sizeof(*out));

	if (!jmatch(j, '{'))
	{
		j->err = j->p;
		return 0;
	}
	jskip_ws(j);
	if (jmatch(j, '}')) return 1;

	char typebuf[32] = {0};

	for (;;)
	{
		char key[128];
		if (!jparse_string(j, key, sizeof(key))) return 0;
		if (!jmatch(j, ':')) 
		{
			j->err = j->p;
			return 0;
		}

		if (strcmp(key, "type") == 0)
		{
			/* Parse object type first */
			if (!jparse_string(j, typebuf, sizeof(typebuf))) return 0;
			out->kind = parse_kind(typebuf);
		}
		else if (out->kind == OBJ_INDICATOR && strcmp(key, "x_sparta_iob_id") == 0)
		{
			/* Extract IOB identifier from indicator */
			if (!jparse_string(j, out->id, sizeof(out->id))) return 0;
		}
		else if (out->kind == OBJ_FILE && strcmp(key, "name") == 0)
		{
			/* Extract filename from file object */
			if (!jparse_string(j, out->name, sizeof(out->name))) return 0;
		}
		else if (out->kind == OBJ_FILE && strcmp(key, "hashes") == 0)
		{
			/* Extract hash values from file object */
			if (!parse_hashes_object(j, out)) return 0;
		}
		else
		{
			/* Skip unknown fields */
			if (!jskip_value(j)) return 0;
		}

		jskip_ws(j);
		if (jmatch(j, '}')) break;
		if (!jmatch(j, ',')) 
		{
			j->err = j->p;
			return 0;
		}

	}
	return 1;
}

/**
 * @brief Parse STIX bundle root object
 *
 * Parses the top-level STIX bundle structure, extracting all objects and
 * associating file objects with their corresponding indicator IOB identifiers.
 *
 * **Expected JSON Structure:**
 * @code
 * {
 *   "type": "bundle",
 *   "objects": [
 *     { "type": "indicator", "x_sparta_iob_id": "IOB-1" },
 *     { "type": "file", "name": "malware.elf", "hashes": {...} }
 *   ]
 * }
 * @endcode
 *
 * **IOB Association Logic:**
 * When an indicator object is encountered, its IOB identifier is saved.
 * Subsequent file objects inherit this IOB identifier until a new indicator
 * is encountered.
 *
 * @param[in,out] j Pointer to Json parser state
 * @param[out] out Pointer to Root structure to populate
 *
 * @return int 1 on success, 0 on parse error
 *
 * @note Output structure is zeroed before parsing
 * @note Objects array is dynamically allocated
 * @note Caller must call free_root() to release memory
 * @note Sets j->err on parse error
 */
static int parse_root(Json *j, Root *out)
{
	memset(out, 0, sizeof(*out));

	char current_iob[IOB_ID_SZ] = {0};

	if (!jmatch(j, '{'))
	{
		j->err = j->p;
		return 0;
	}
	jskip_ws(j);
	if (jmatch(j, '}')) return 1;

	for (;;)
	{
		char key[128];
		if (!jparse_string(j, key, sizeof(key))) return 0;
		if (!jmatch(j, ':')) 
		{
			j->err = j->p;
			return 0;
		}

		if (strcmp(key, "type") == 0)
		{
			/* Parse bundle type */
			if (!jparse_string(j, out->kind, sizeof(out->kind))) return 0;
		}
		else if (strcmp(key, "objects") == 0)
		{
			/* Parse objects array */
			if (!jmatch(j, '['))
			{
				j->err = j->p;
				return 0;
			}
			jskip_ws(j);
			if (!jmatch(j, ']'))
			{
				for (;;)
				{
					CTI_Info e;
					if (!parse_object_entry(j, &e)) return 0;

					/* Associate IOB with file objects */
					if (e.kind == OBJ_INDICATOR)
					{
						/* Save IOB for subsequent file objects */
						snprintf(current_iob, sizeof(current_iob), "%s", e.id);
					}
					else if (e.kind == OBJ_FILE)
					{
						/* Assign current IOB to file */
						snprintf(e.id, sizeof(current_iob), "%s", current_iob);
					}

					if (!root_objects_append(out, &e)) 
					{
						j->err = j->p;
						return 0;
					}

					jskip_ws(j);
					if (jmatch(j, ']')) break;
					if (!jmatch(j, ','))
					{
						j->err = j->p;
						return 0;
					}
				}
			}
		}
		else
		{
			/* Skip unknown fields */
			if (!jskip_value(j)) return 0;
		}

		jskip_ws(j);
		if (jmatch(j, '}')) break;
		if (!jmatch(j, ','))
		{
			j->err = j->p;
			return 0;
		}
	}
	return 1;
}

/*=======================================================================================
** Private Helper Functions - Debug Output
**=======================================================================================*/

/**
 * @brief Print SHA-256 hash in hexadecimal format
 *
 * Prints a binary SHA-256 hash as a 64-character hexadecimal string to stdout.
 * Used for debugging and logging.
 *
 * @param[in] h Binary SHA-256 hash (32 bytes)
 *
 * @return void
 *
 * @note Output is lowercase hexadecimal
 * @note No newline is printed
 */
static void print_hex_hash(const unsigned char h[SHA256_DIGEST_LENGTH])
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02x", h[i]);
	}
}

/**
 * @brief Print summary of parsed STIX bundle
 *
 * Prints a human-readable summary of a parsed STIX bundle including all
 * objects and their key attributes. Used for debugging CTI file loading.
 *
 * @param[in] r Pointer to parsed Root structure
 * @param[in] source_name Name of source file (for display)
 *
 * @return void
 *
 * @note Output includes object count, types, IOBs, filenames, and hashes
 */
static void print_root_summary(const Root *r, const char *source_name)
{
	printf("\n==== %s ====\n", source_name);
	printf("root.type: %s\n", r->kind[0] ? r->kind : "(missing)");
	printf("objects : %zu\n", r->objects_count);

	for (size_t i = 0; i < r->objects_count; i++)
	{
		const CTI_Info *e = &r->objects[i];
		printf("\t-[%zu] kind=%s", i, kind_to_string(e->kind));
		if (e->id[0]) printf(" id=%s", e->id);
		printf("\n");

		if (e->kind == OBJ_INDICATOR)
		{
			printf("\t\tID: %s\n", e->id[0] ? e->id : "(missing)");;
		}
		else if (e->kind == OBJ_FILE)
		{
			printf("\t\tname: %s\n", e->name[0] ? e->name : "(missing)");
			printf("\t\tsha256-hash: ");
			print_hex_hash(e->sha256);
			printf("\n");
		}
	}
}

/*=======================================================================================
** Private Helper Functions - CTI Data Storage
**=======================================================================================*/

/**
 * @brief Check if CTI entry already exists in storage
 *
 * Searches the global CTI array for a duplicate entry. Duplicates are detected
 * based on object type:
 * - file: name and SHA-256 hash must match
 * - program: name must match
 *
 * @param[in] s Pointer to CTIArray to search
 * @param[in] e Pointer to CTI_Info entry to check
 *
 * @return int 1 if entry exists, 0 otherwise
 *
 * @note Used to prevent duplicate entries when loading multiple CTI files
 */
static int store_contains(const CTIArray *s, const CTI_Info *e)
{
	for (size_t i = 0; i < s->size; i++)
	{
		if (e->kind == OBJ_FILE)
		{
			if (strcmp(e->name, s->data[i].name) == 0 && 
			    memcmp(e->sha256, s->data[i].sha256, SHA256_DIGEST_LENGTH) == 0)
			{
				return 1;
			}
		}
		else if (e->kind == OBJ_PROGRAM)
		{
			if (strcmp(e->name, s->data[i].name) == 0) return 1;
		}
	}
	return 0;
}

/**
 * @brief Append CTI entry to storage array
 *
 * Adds a CTI_Info entry to the global storage array. Automatically resizes
 * the array if capacity is exceeded. Checks for duplicates before adding.
 *
 * @param[in,out] s Pointer to CTIArray storage
 * @param[in] e Pointer to CTI_Info entry to append
 *
 * @return int Result code
 * @retval 1 Entry added successfully
 * @retval 2 Entry already exists (duplicate)
 * @retval 0 Memory allocation failed
 *
 * @note Uses exponential growth strategy (doubles capacity when full)
 * @note Initial capacity is 64 entries
 */
static int store_append(CTIArray *s, const CTI_Info *e)
{
	/* Check for duplicate */
	if(store_contains(s, e))
	{
		return 2;
	}
	
	/* Resize if needed */
	if (s->size >= s->capacity)
	{
		size_t new_cap = (s->capacity == 0) ? 64 : s->capacity * 2;
		void *tmp = realloc(s->data, new_cap * sizeof(CTI_Info));
		if (!tmp) return 0;
		s->data = (CTI_Info *)tmp;
		s->capacity = new_cap;
	}
	
	/* Append entry */
	s->data[s->size++] = *e;
	return 1;
}

/*=======================================================================================
** Private Helper Functions - CTI File Processing
**=======================================================================================*/

/**
 * @brief Process a single CTI JSON file
 *
 * Reads, parses, and processes a STIX bundle JSON file. Extracts all threat
 * indicators and adds them to the global CTI storage array.
 *
 * **Processing Steps:**
 * 1. Read entire file into memory
 * 2. Parse JSON structure
 * 3. Extract STIX objects
 * 4. Associate IOBs with file objects
 * 5. Add entries to global storage (skipping duplicates)
 * 6. Print summary if new data was added
 *
 * @param[in] path Path to JSON file to process
 *
 * @return int 1 on success, 0 on error
 *
 * @note Prints error messages to stdout on failure
 * @note Prints summary for newly loaded files
 * @note Silently skips duplicate entries
 *
 * Example:
 * @code
 * if (process_json_file("cf/cti/threat1.dat")) {
 *     printf("Successfully loaded threat data\n");
 * }
 * @endcode
 */
static int process_json_file(const char *path)
{
	/* Read file */
	char *text = read_entire_file(path);
	if (!text)
	{
		printf("Failed to read file: %s (%s)\n", path, strerror(errno));
		return 0;
	}

	/* Initialize JSON parser */
	Json j = {0};
	j.s = text;
	j.p = text;
	j.end = text + strlen(text);
	j.err = NULL;

	/* Parse STIX bundle */
	Root r;
	int ok = parse_root(&j, &r);
	int ret = 0;
	if (ok)
	{
		jskip_ws(&j);
		if (j.p != j.end)
		{
			printf("[%s] Error: trailing data after JSON\n", path);
			ok = 0;
		}
	}

	if (!ok)
	{
		/* Print parse error with location */
		const char *where = j.err ? j.err : j.p;
		long off = (long)(where - j.s);
		printf("[%s] Parse error at byte offset %ld near %.40s\n", 
		       path, off, where ? where : "(null)");
		free_root(&r);
		free(text);
		return 0;
	}

	/* Add objects to global storage */
	for (size_t i = 0; i < r.objects_count; i++)
	{
		ret = store_append(cti_array, &r.objects[i]);
		if (!ret)
		{
			printf("Out of memory appending to global store\n");
			free_root(&r);
			return 0;
		}
	}

	printf("in process_json_file with ret of %d\n", ret);

	/* Print summary for new files */
	if (ret == 1)
	{
		printf("New file detected\n");
		print_root_summary(&r, path);
	}

	free_root(&r);
	free(text);
	return 1;
}

/*=======================================================================================
** Public API Functions
**=======================================================================================*/

/**
 * @brief Initialize CTI data array
 *
 * Allocates and initializes the global CTI data storage array. Must be called
 * before any other CTI functions.
 *
 * @return void
 *
 * @note Exits program on allocation failure
 * @note Initial capacity is 2 entries (will grow as needed)
 * @note Should be called once during application initialization
 *
 * @see CTI_FreeArray()
 */
void CTI_InitArray(void)
{
	/* Allocate CTIArray structure */
    cti_array = malloc(sizeof(CTIArray));
    if (!cti_array) {
        fprintf(stderr, "Failed to allocate memory for CTIArray\n");
        exit(EXIT_FAILURE);
    }
    
    /* Allocate initial data array */
    cti_array->data = malloc(2 * sizeof(*cti_array->data));
    if (!cti_array->data) {
        fprintf(stderr, "Failed to allocate memory for CTIArray data\n");
        free(cti_array);
        exit(EXIT_FAILURE);
    }
    
	cti_array->size = 0;
	cti_array->capacity = 2;
}

/**
 * @brief Scan for and process new CTI data files
 *
 * Scans the cf/cti/ directory for .dat files and processes any new or updated
 * CTI bundles. This function should be called periodically to detect newly
 * dropped threat intelligence files.
 *
 * **Operation:**
 * 1. Open cf/cti/ directory
 * 2. Iterate through all entries
 * 3. Filter for .dat files
 * 4. Process each JSON file
 * 5. Add new indicators to global storage
 *
 * @return void
 *
 * @note Silently returns if directory cannot be opened
 * @note Skips hidden files (starting with '.')
 * @note Only processes files with .dat extension
 * @note Duplicate entries are automatically filtered
 * @note Prints status messages to stdout
 *
 * @see process_json_file()
 * @see has_json_ext()
 */
void CTI_CheckForNewData(void)
{
	DIR *d = opendir(SPACECOP_CTI_DIR "/");
	if (!d) 
	{
		printf("Can't open cf/cti dir\n");
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(d)) != NULL)
	{
		/* Skip hidden files */
		if (ent->d_name[0] == '.') continue;
		
		/* Skip non-.dat files */
		if (!has_json_ext(ent->d_name)) continue;

		/* Process CTI file */
		char full[1024];
		snprintf(full, sizeof(full), SPACECOP_CTI_DIR "/%s",  ent->d_name);
		(void)process_json_file(full);
	}
	
	closedir(d);
}

/**
 * @brief Scan file system for CTI matches and generate alerts
 *
 * Scans the spacecraft file system (cf/ and data/ directories) for files
 * matching known threat indicators. Generates IDS alerts for any matches.
 *
 * **Operation:**
 * 1. Scan cf/ and data/ directories recursively
 * 2. Compute SHA-256 hash for each file
 * 3. Compare against loaded CTI indicators
 * 4. Generate IDS alert for matches
 * 5. Send EVS event for matches
 *
 * **Alert Format:**
 * "[SPACECOP] CTI-based Detected (SPARTA-ID {IOB}, file ({filename} (sha256={hash}))found"
 *
 * @return void
 *
 * @note Only processes OBJ_FILE indicators currently
 * @note Alerts include IOB identifier for correlation
 * @note Uses SPACECOP_ReportIDSMsg() for alert generation
 * @note Sends CFE_EVS error event (ID 2001)
 *
 * @see scan_root() (from spacecop_ids_helper.h)
 * @see does_hash_exist() (from spacecop_ids_helper.h)
 * @see SPACECOP_ReportIDSMsg()
 */
void CTI_WorkWithData(void)
{
	FileList cf_cti;
	FileList data_cti;
	char message[IDS_REPORT_MESSAGE_LEN];

	/* Scan file systems */
	scan_root(SPACECOP_CF_DIR, &cf_cti);
	scan_root(SPACECOP_DATA_DIR, &data_cti);

	/* Check each CTI indicator */
	for (size_t i = 0; i < cti_array->size; i++)
	{
		printf("Current kind: %d\n", cti_array->data[i].kind);
		
		if (cti_array->data[i].kind == OBJ_FILE)
		{
			printf("I'm here\n");
			
			/* Check if file exists with matching hash */
			if(does_hash_exist(&cf_cti, cti_array->data[i].name, cti_array->data[i].sha256))
			{
				/* Generate IDS alert */
				memset(message, 0, sizeof(char) * IDS_REPORT_MESSAGE_LEN);
                snprintf(message, IDS_REPORT_MESSAGE_LEN, 
                        "[SPACECOP] CTI-based Detected (SPARTA-ID %s, file (%s (sha256=%s))found", 
                        cti_array->data[i].id, 
                        cti_array->data[i].name, 
                        cti_array->data[i].sha256);
                
                /* Send alert via multiple channels */
                SPACECOP_ReportIDSMsg(message);
                CFE_EVS_SendEvent(2001, CFE_EVS_EventType_ERROR, 
                                 "[SPACECOP] CTI-based Detected (SPARTA-ID %s, file (%s (sha256=%s))found", 
                                 cti_array->data[i].id, 
                                 cti_array->data[i].name, 
                                 cti_array->data[i].sha256);
			}
		}
	}
}

/**
 * @brief Free CTI data array and release resources
 *
 * Releases all memory allocated for the global CTI storage array. Should be
 * called during application shutdown.
 *
 * @return void
 *
 * @note Safe to call multiple times
 * @note Sets global pointer to NULL after freeing
 *
 * @see CTI_InitArray()
 */
void CTI_FreeArray(void)
{
	if (cti_array) {
        free(cti_array->data);
        free(cti_array);
        cti_array = NULL;
    }
}