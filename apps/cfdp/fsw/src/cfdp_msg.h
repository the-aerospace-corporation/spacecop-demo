/*******************************************************************************
** File:
**   cfdp_msg.h
**
** Purpose:
**  Define CFDP application commands and telemetry messages
**
*******************************************************************************/
#ifndef _CFDP_MSG_H_
#define _CFDP_MSG_H_

#include "cfe.h"
#include "cfdp_cfdp.h"

/* 
** Telemetry Request Command Codes
** TODO: Add additional commands required by the specific component
*/
#define CFDP_REQ_HK_TLM              0
#define CFDP_REQ_DATA_TLM            1
#define CFDP_FILENAME_MAX_PATH      64
#define CFDP_CMD_MAX_LENGTH		   128

typedef struct 
{
    CFE_MSG_CommandHeader_t CommandHeader; /**< \brief Command header */
} CFDP_SendHkCmd_t;

typedef struct
{
    /* Every command requires a header used to identify it */
    uint8    CmdHeader[sizeof(CFE_MSG_CommandHeader_t)];

} CFDP_NoArgs_cmd_t;



/*
** CFDP housekeeping type definition
*/
typedef struct 
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8   cmdErrorCount;
    uint8   cmdCount;

} __attribute__((packed)) CFDP_Hk_tlm_t;
#define CFDP_HK_TLM_LNGTH sizeof ( CFDP_Hk_tlm_t )

typedef struct
{
	CFE_MSG_TelemetryHeader_t TlmHeader;
	uint8_t pdu_type;
	uint8_t direction;
	uint16_t data_len;   /* Number of VALID bytes in buffer for this chunk.
	                        Lets the ground write the exact size (esp. the final
	                        partial chunk) instead of the whole padded buffer. */
	uint32_t seq_num;    /* 0-based chunk sequence number, for gap detection.
	                        On the EOF PDU it carries the total chunk count. */
	char buffer[CFDP_DATA_CHUNK_SIZE]; /* sized to keep the PDU in one UDP datagram */
	char destination[CFDP_FILENAME_MAX_PATH];
	char source[CFDP_FILENAME_MAX_PATH];
} __attribute__((packed)) CFDP_CFDP_PDU_t;
#define CFDP_CFDP_PDU_TLM_LNGTH sizeof ( CFDP_CFDP_PDU_t )

typedef struct 
{
	CFE_MSG_CommandHeader_t CmdHeader;
	char Destination[CFDP_FILENAME_MAX_PATH];
	char Source[CFDP_FILENAME_MAX_PATH];
} CFDP_FileTxSatellite_t;

typedef struct
{
	CFE_MSG_CommandHeader_t CmdHeader;
	uint16_t length;
	uint8_t pdu_type;
	uint8_t padding;
	char destination[CFDP_FILENAME_MAX_PATH];
	char buffer[CFDP_CHUNK_SIZE*2];
	/* Upload integrity check: on the EOF command (pdu_type==2) these carry the
	 * ground's expected total size and CRC-32 of the file, so the FSW can verify
	 * the received file after write. Ignored (0) on data chunks. */
	uint32_t expected_size;
	uint32_t expected_crc;
} CFDP_FileSatellite_t;

/*
** Class 2 NAK: ground requests retransmission of a single missing chunk.
** The FSW seeks to seq_num * CFDP_DATA_CHUNK_SIZE in 'source' and resends that
** chunk as a normal DOWNLINK_FILE_PKT labeled with 'destination'.
*/
typedef struct
{
	CFE_MSG_CommandHeader_t CmdHeader;
	uint32_t seq_num;                          /* 0-based chunk index to resend */
	char     source[CFDP_FILENAME_MAX_PATH];      /* file on satellite to read */
	char     destination[CFDP_FILENAME_MAX_PATH]; /* ground filename label for the PDU */
} CFDP_ResendChunk_t;

#endif /* _CFDP_MSG_H_ */
