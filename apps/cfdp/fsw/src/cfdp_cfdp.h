#ifndef CFDP_CFDP_H
#define CFDP_CFDP_H

#include "cfe.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CFDP_CHUNK_SIZE 256

/*
 * Bytes of file data carried per downlink PDU.
 *
 * The whole CFDP_CFDP_PDU_t struct is transmitted every PDU (fixed size set at
 * init), so this directly sets the UDP packet size:
 *   packet = 16 (TlmHeader) + 8 (fields) + CFDP_DATA_CHUNK_SIZE + 128 (names)
 * Keep the total under the link MTU (1500) so each PDU fits in ONE UDP datagram
 * and is NOT IP-fragmented. Over a lossy link (WiFi) a fragmented PDU loses the
 * whole chunk if ANY fragment drops; a single-datagram PDU only loses that one
 * chunk on a drop. At *4 = 1024 the packet is ~1176 bytes (safe margin).
 *
 * This is the single source of truth: the tlm buffer[] size, the send-loop
 * chunk_size, and the COSMOS FILE_DATA width (CFDP_DATA_CHUNK_SIZE * 8 bits)
 * must all track it.
 */
#define CFDP_DATA_CHUNK_SIZE (CFDP_CHUNK_SIZE * 4)   /* 1024 bytes -> ~1176B UDP packet */

typedef enum {
	CFDP_CFDP_CLASS_1 = 0,
	CFDP_CFDP_CLASS_2 = 1
} CFDP_CFDP_Class_t;

typedef struct
{
	const char *source;
	const char *destination;
	CFDP_CFDP_Class_t CFDP_class;
	uint32 chunk_size;	
	char buffer[CFDP_CHUNK_SIZE];
} CFDP_CFDP_Transaction_t;

void CFDP_CFDP_SendFile(const char *source, const char *destination);
void CFDP_CFDP_GetFile(uint8_t pdu_type, const char *buffer, const char *destination, uint16_t length,
                       uint32_t expected_size, uint32_t expected_crc);
void CFDP_CFDP_VerifyUpload(const char *destination, uint32_t expected_size, uint32_t expected_crc);
uint32_t CFDP_CFDP_Crc32(uint32_t crc, const uint8_t *data, uint32_t len);
void CFDP_CFDP_StartSendFileTransaction(CFDP_CFDP_Transaction_t *transaction);
void CFDP_CFDP_StartGetTransaction(CFDP_CFDP_Transaction_t *transaction, const char* buffer);
int32 CFDP_CFDP_SendPDU(void);
void CFDP_CFDP_ResendChunk(const char *source, const char *destination, uint32_t seq_num);
int32_t CFDP_CFDP_SendEOF(void);
int32_t CFDP_CFDP_IsEOFPDU(CFE_SB_Buffer_t *buffer);
int32_t CFDP_CFDP_SendRequest(const char *destination, const char *source);
uint8_t hexPairToByte(const char *hex_pair);

#endif