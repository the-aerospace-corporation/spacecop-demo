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
 * @file helpers_unpackers.c
 * @brief Implementation of binary data unpacking utilities for SpaceCop
 *
 * This file implements safe binary data unpacking functions that extract
 * native C types from byte buffers. Each function performs length validation
 * before copying to prevent buffer overruns.
 *
 * **Design Principles:**
 * - Validate before copying: All functions check buffer length first
 * - Simple interface: Returns 1 for success, 0 for failure
 * - Type safety: Separate function for each data type
 * - Null-termination: String unpacker ensures proper termination
 *
 * **Use Cases:**
 * - Table configuration parsing
 * - Command parameter extraction
 * - Telemetry data deserialization
 * - Binary protocol handling
 *
 * **Limitations:**
 * - No endianness conversion (assumes native byte order)
 * - Fixed-size types only (no variable-length data)
 * - No alignment handling (assumes properly aligned buffers)
 *
 * For systems with different endianness, consider using ntohl/ntohs or
 * implementing explicit byte-swapping functions.
 */

#include "helpers_unpackers.h"

/*=======================================================================================
** Function Implementations
**=======================================================================================*/

/**
 * @brief Unpack an 8-bit signed integer from a byte buffer
 *
 * Validates that the buffer is exactly 1 byte long, then copies the byte
 * to the output variable.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination int8_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note This is the simplest unpacker as int8_t is a single byte
 */
int UnpackI8(const uint8_t* buf, uint16_t len, int8_t* out)
{
	/* Validate buffer length */
	if (len != sizeof(int8_t)) return 0;
	
	/* Copy byte to output */
	memcpy(out, buf, sizeof(int8_t));
	return 1;
}

/**
 * @brief Unpack a 32-bit signed integer from a byte buffer
 *
 * Validates that the buffer is exactly 4 bytes long, then copies the bytes
 * to the output variable in native byte order.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination int32_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Assumes native byte order (no endianness conversion)
 * @note On little-endian systems, bytes are stored LSB first
 * @note On big-endian systems, bytes are stored MSB first
 */
int UnpackI32(const uint8_t* buf, uint16_t len, int32_t* out)
{
	/* Validate buffer length */
	if (len != sizeof(int32_t)) return 0;
	
	/* Copy 4 bytes to output */
	memcpy(out, buf, sizeof(int32_t));
	return 1;
}

/**
 * @brief Unpack a 32-bit unsigned integer from a byte buffer
 *
 * Validates that the buffer is exactly 4 bytes long, then copies the bytes
 * to the output variable in native byte order.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination uint32_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Assumes native byte order (no endianness conversion)
 * @note Identical to UnpackI32 except for output type
 */
int UnpackU32(const uint8_t* buf, uint16_t len, uint32_t* out)
{
	/* Validate buffer length */
	if (len != sizeof(uint32_t)) return 0;
	
	/* Copy 4 bytes to output */
	memcpy(out, buf, sizeof(uint32_t));
	return 1;
}

/**
 * @brief Unpack a 32-bit floating-point number from a byte buffer
 *
 * Validates that the buffer is exactly 4 bytes long, then copies the bytes
 * to the output variable, interpreting them as an IEEE 754 single-precision
 * float in native byte order.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination float variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Assumes IEEE 754 single-precision format
 * @note Assumes native byte order (no endianness conversion)
 * @note Does not validate that the bytes represent a valid float
 *       (e.g., NaN or infinity values are not checked)
 */
int UnpackF32(const uint8_t* buf, uint16_t len, float* out)
{
	/* Validate buffer length */
	if (len != sizeof(float)) return 0;
	
	/* Copy 4 bytes to output, interpreting as float */
	memcpy(out, buf, sizeof(float));
	return 1;
}

/**
 * @brief Unpack a fixed-length string from a byte buffer
 *
 * Validates that the buffer is exactly STR64_MAX bytes long, then copies
 * the bytes to the output string buffer. Ensures the output is properly
 * null-terminated by setting the last byte to '\0'.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Destination character array (must be at least STR64_MAX bytes)
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match STR64_MAX
 * @note Output is always null-terminated at position [STR64_MAX-1]
 * @note If source string is shorter than STR64_MAX, remaining bytes are copied
 * @note Useful for fixed-length string fields in binary structures
 */
int UnpackStr64(const uint8_t* buf, uint16_t len, char out[STR64_MAX])
{
	/* Validate buffer length */
	if (len != STR64_MAX) return 0;
	
	/* Copy all bytes to output */
	memcpy(out, buf, STR64_MAX);
	
	/* Ensure null-termination */
	out[STR64_MAX - 1] = '\0';
	return 1;
}