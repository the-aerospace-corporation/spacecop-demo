// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file helpers_unpackers.h
 * @brief Binary data unpacking utilities for SpaceCop
 *
 * This header provides function prototypes for safely unpacking binary data
 * from byte buffers into native C types. These utilities are used for:
 * - Parsing table configuration data
 * - Deserializing command parameters
 * - Processing telemetry packets
 * - Validating data length before extraction
 *
 * **Key Features:**
 * - Length validation before unpacking
 * - Type-safe extraction functions
 * - Null-termination for string data
 * - Simple success/failure return codes
 *
 * All functions validate that the buffer length matches the expected size
 * before performing the copy operation, preventing buffer overruns and
 * data corruption.
 */

#ifndef HELPER_UNPACKERS_H
#define HELPER_UNPACKERS_H

/*=======================================================================================
** Required Header Files
**=======================================================================================*/

#include "cfe.h"
#include "spacecop_table_defs.h"

/*=======================================================================================
** Function Prototypes
**=======================================================================================*/

/**
 * @brief Unpack an 8-bit signed integer from a byte buffer
 *
 * Extracts a single signed byte from the buffer after validating that the
 * buffer length matches the expected size.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination int8_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match sizeof(int8_t) (1 byte)
 * @note Does not perform endianness conversion
 *
 * Example usage:
 * @code
 * uint8_t buffer[1] = {-42};
 * int8_t value;
 * if (UnpackI8(buffer, sizeof(buffer), &value)) {
 *     printf("Value: %d\n", value);
 * }
 * @endcode
 */
int UnpackI8(const uint8_t* buf, uint16_t len, int8_t* out);

/**
 * @brief Unpack a 32-bit signed integer from a byte buffer
 *
 * Extracts a 4-byte signed integer from the buffer after validating that
 * the buffer length matches the expected size.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination int32_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match sizeof(int32_t) (4 bytes)
 * @note Does not perform endianness conversion
 * @note Assumes native byte order
 *
 * Example usage:
 * @code
 * uint8_t buffer[4] = {0x00, 0x00, 0x03, 0xE8};  // 1000 in little-endian
 * int32_t value;
 * if (UnpackI32(buffer, sizeof(buffer), &value)) {
 *     printf("Value: %d\n", value);
 * }
 * @endcode
 */
int UnpackI32(const uint8_t* buf, uint16_t len, int32_t* out);

/**
 * @brief Unpack a 32-bit unsigned integer from a byte buffer
 *
 * Extracts a 4-byte unsigned integer from the buffer after validating that
 * the buffer length matches the expected size.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination uint32_t variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match sizeof(uint32_t) (4 bytes)
 * @note Does not perform endianness conversion
 * @note Assumes native byte order
 *
 * Example usage:
 * @code
 * uint8_t buffer[4] = {0xFF, 0xFF, 0xFF, 0xFF};  // Max uint32
 * uint32_t value;
 * if (UnpackU32(buffer, sizeof(buffer), &value)) {
 *     printf("Value: %u\n", value);
 * }
 * @endcode
 */
int UnpackU32(const uint8_t* buf, uint16_t len, uint32_t* out);

/**
 * @brief Unpack a 32-bit floating-point number from a byte buffer
 *
 * Extracts a 4-byte IEEE 754 single-precision float from the buffer after
 * validating that the buffer length matches the expected size.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Pointer to destination float variable
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match sizeof(float) (4 bytes)
 * @note Does not perform endianness conversion
 * @note Assumes IEEE 754 single-precision format
 * @note Assumes native byte order
 *
 * Example usage:
 * @code
 * uint8_t buffer[4];
 * float input = 3.14159f;
 * memcpy(buffer, &input, sizeof(float));
 * 
 * float value;
 * if (UnpackF32(buffer, sizeof(buffer), &value)) {
 *     printf("Value: %f\n", value);
 * }
 * @endcode
 */
int UnpackF32(const uint8_t* buf, uint16_t len, float* out);

/**
 * @brief Unpack a fixed-length string from a byte buffer
 *
 * Extracts a fixed-length string (STR64_MAX bytes) from the buffer after
 * validating that the buffer length matches the expected size. Ensures
 * null-termination of the output string.
 *
 * @param[in] buf Pointer to source byte buffer
 * @param[in] len Length of the buffer in bytes
 * @param[out] out Destination character array (must be at least STR64_MAX bytes)
 *
 * @return int Returns 1 on success, 0 if length validation fails
 *
 * @note Buffer length must exactly match STR64_MAX
 * @note Output string is always null-terminated at position [STR64_MAX-1]
 * @note Useful for unpacking fixed-length string fields from tables
 *
 * Example usage:
 * @code
 * uint8_t buffer[STR64_MAX];
 * strncpy((char*)buffer, "Hello, World!", STR64_MAX);
 * 
 * char str[STR64_MAX];
 * if (UnpackStr64(buffer, sizeof(buffer), str)) {
 *     printf("String: %s\n", str);
 * }
 * @endcode
 */
int UnpackStr64(const uint8_t* buf, uint16_t len, char out[STR64_MAX]);

#endif /* HELPER_UNPACKERS_H */