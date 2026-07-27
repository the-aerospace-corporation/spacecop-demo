#include "cfe.h"

#include "cfdp_app.h"
#include "cfdp_cfdp.h"
#include "cfdp_events.h"
#include "cfdp_msgids.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

void CFDP_CFDP_SendFile(const char *source, const char *destination)
{
	CFDP_CFDP_Transaction_t transaction;

	memset(&transaction, 0, sizeof(transaction));
	transaction.source = source;
	strncpy(CFDP_AppData.fileInfo.destination, destination, sizeof(CFDP_AppData.fileInfo.destination)-1);
	strncpy(CFDP_AppData.fileInfo.source, source, sizeof(CFDP_AppData.fileInfo.source)-1);
	CFDP_AppData.fileInfo.destination[sizeof(CFDP_AppData.fileInfo.destination)-1] = 0;
	CFDP_AppData.fileInfo.source[sizeof(CFDP_AppData.fileInfo.source)-1] = 0;
	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Preparing to send file: %s", CFDP_AppData.fileInfo.destination);
	transaction.CFDP_class = CFDP_CFDP_CLASS_1;
	transaction.chunk_size = CFDP_DATA_CHUNK_SIZE;

	CFDP_CFDP_StartSendFileTransaction(&transaction);
}

void CFDP_CFDP_GetFile(uint8_t pdu_type, const char *buffer, const char *destination, uint16_t length,
                       uint32_t expected_size, uint32_t expected_crc)
{
	if(pdu_type == 2)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: EOF Reached");
		CFDP_CFDP_VerifyUpload(destination, expected_size, expected_crc);
		CFDP_CFDP_SendEOF();
		return;
	}
	CFDP_CFDP_Transaction_t transaction;

	memset(&transaction, 0, sizeof(transaction));
	transaction.destination = destination;
	transaction.chunk_size = length;

	CFDP_CFDP_StartGetTransaction(&transaction, buffer);
}

void CFDP_CFDP_StartSendFileTransaction(CFDP_CFDP_Transaction_t *transaction)
{
	int32_t status;
	osal_id_t fd;

	status = OS_OpenCreate(&fd, transaction->source, OS_FILE_FLAG_NONE, OS_READ_ONLY);
	if(status != OS_SUCCESS)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to open source: %s with error: %d", transaction->source, (int)status);
		return;
	}

	int32    size;                /* OS_read returns a signed count; size_t made
	                                the (size < 0) error check dead code. */
	uint32_t seq_num = 0;

	while(1)
	{
		size = OS_read(fd, CFDP_AppData.fileInfo.buffer, transaction->chunk_size);

		if(size < 0)
		{
			CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to read from source file. Read %d bytes", (int)size);
			OS_close(fd);
			return;
		}
		else
		{
			if(size == 0)
			{
				CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Reached EOF after %u chunk(s)", (unsigned)seq_num);
				break;
			}

			/* Record the valid byte count + sequence number for this chunk so
			 * the ground writes exactly 'size' bytes (no stale-tail padding on
			 * the final partial chunk) and can detect any dropped chunk. */
			CFDP_AppData.fileInfo.data_len = (uint16_t)size;
			CFDP_AppData.fileInfo.seq_num  = seq_num++;

			/* Defensive: clear any unused tail so we never downlink stale bytes. */
			if((uint32)size < sizeof(CFDP_AppData.fileInfo.buffer))
			{
				memset(CFDP_AppData.fileInfo.buffer + size, 0,
				       sizeof(CFDP_AppData.fileInfo.buffer) - (uint32)size);
			}

			status = CFDP_CFDP_SendPDU();
			if(status != CFE_SUCCESS)
			{
				CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to send file data PDU");
				OS_close(fd);
				return;
			}

		}
		/* Inter-PDU pacing. Smaller chunks means more PDUs (e.g. 144 KB -> ~144
		 * PDUs), so the old sleep(2) would take minutes. Pace at 250 ms: fast
		 * enough (~36 s for 144 KB) while still throttling to avoid bursting the
		 * SB->TO downlink pipe and swamping the lossy WiFi link. */
		usleep(250 * 1000);
	}

	/* EOF PDU: no payload bytes, seq_num carries the total chunk count so the
	 * ground can confirm it received every chunk. */
	CFDP_AppData.fileInfo.data_len = 0;
	CFDP_AppData.fileInfo.seq_num  = seq_num;
	status = CFDP_CFDP_SendEOF();
	if(status != CFE_SUCCESS)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to send EOF");
	}
	else
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: File send complete");
	}

	OS_close(fd);
}

void CFDP_CFDP_StartGetTransaction(CFDP_CFDP_Transaction_t *transaction, const char* buffer)
{
	int32 status;
	osal_id_t fd;

	status = OS_OpenCreate(&fd, transaction->destination, OS_FILE_FLAG_CREATE , OS_READ_WRITE);
	if(status != OS_SUCCESS)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to open destination: %s with error: %d", transaction->destination, status);
		return;
	}
	status = OS_lseek(fd, 0, OS_SEEK_END);
	if(status < OS_SUCCESS)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to seek end of file");
		OS_close(fd);
		return;
	}

	//CFDP_PrintMe(buffer);
	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: About to write %d bytes to file", transaction->chunk_size);
	for(int i=0; i < transaction->chunk_size; i+=2)
	{
		uint8_t byte = hexPairToByte(&buffer[i]);
		status = OS_write(fd, &byte, 1);
		if(status < OS_SUCCESS)
		{
			CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Failed to write to destination file: Error: %d", (int)status);
			OS_close(fd);
			return;
		}
	}
	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR, "CFDP: Wrote to file with status: %d", status);
	OS_close(fd);
}

int32_t CFDP_CFDP_SendRequest(const char *destination, const char *source)
{
	strncpy(CFDP_AppData.fileInfo.destination, destination, sizeof(CFDP_AppData.fileInfo.destination)-1);
	strncpy(CFDP_AppData.fileInfo.source, source, sizeof(CFDP_AppData.fileInfo.source)-1);
	CFDP_AppData.fileInfo.destination[sizeof(CFDP_AppData.fileInfo.destination)-1] = 0;
	CFDP_AppData.fileInfo.source[sizeof(CFDP_AppData.fileInfo.source)-1] = 0;
	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Preparing to receive file %s and save to %s", CFDP_AppData.fileInfo.destination, CFDP_AppData.fileInfo.source);

	int32 status;
	CFDP_AppData.fileInfo.pdu_type = 0;
	CFDP_AppData.fileInfo.direction = 2;

	CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo);
    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo, true);
	if (status == CFE_SUCCESS)
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Successfully sent telemetry packet");
        return CFE_SUCCESS;
    }
    else
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Error sending tlm packet: %d", status);
    	return status;
    }
}

int32_t CFDP_CFDP_SendEOF()
{
	int32 status;
	CFDP_AppData.fileInfo.pdu_type = 2;
	CFDP_AppData.fileInfo.direction = 1;

	CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo);
    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo, true);
	if (status == CFE_SUCCESS)
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Successfully sent telemetry packet");
        return CFE_SUCCESS;
    }
    else
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Error sending tlm packet: %d", status);
    	return status;
    }
}

int32 CFDP_CFDP_SendPDU()
{
	int32 status;
	CFDP_AppData.fileInfo.pdu_type = 0;
	CFDP_AppData.fileInfo.direction = 1;

	CFE_SB_TimeStampMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo);
    status = CFE_SB_TransmitMsg((CFE_MSG_Message_t *) &CFDP_AppData.fileInfo, true);
    if (status == CFE_SUCCESS)
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Successfully sent telemetry packet for %s", CFDP_AppData.fileInfo.destination);
        return CFE_SUCCESS;
    }
    else
    {
    	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION, "CFDP: Error sending tlm packet: %d", status);
    	return status;
    }

	
}

/*
** Class 2 NAK handler: resend a single chunk the ground reported missing.
** Stateless - the command carries the source (to read) and destination (PDU
** label). Seeks to seq_num * CFDP_DATA_CHUNK_SIZE, reads that one chunk, and
** sends it as a normal data PDU (SendPDU sets pdu_type=0, direction=1), so the
** ground's normal receive path writes it at the correct file offset.
*/
void CFDP_CFDP_ResendChunk(const char *source, const char *destination, uint32_t seq_num)
{
	int32_t   status;
	osal_id_t fd;
	int32     size;
	int32     offset = (int32)(seq_num * (uint32_t)CFDP_DATA_CHUNK_SIZE);

	status = OS_OpenCreate(&fd, source, OS_FILE_FLAG_NONE, OS_READ_ONLY);
	if (status != OS_SUCCESS)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR,
			"CFDP: Resend seq %u - failed to open source %s: %d", (unsigned)seq_num, source, (int)status);
		return;
	}

	status = OS_lseek(fd, offset, OS_SEEK_SET);
	if (status != offset)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR,
			"CFDP: Resend seq %u - seek to %d failed: %d", (unsigned)seq_num, (int)offset, (int)status);
		OS_close(fd);
		return;
	}

	size = OS_read(fd, CFDP_AppData.fileInfo.buffer, CFDP_DATA_CHUNK_SIZE);
	OS_close(fd);

	if (size <= 0)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR,
			"CFDP: Resend seq %u - read failed (%d)", (unsigned)seq_num, (int)size);
		return;
	}

	/* Zero the unused tail so no stale bytes are downlinked. */
	if ((uint32)size < sizeof(CFDP_AppData.fileInfo.buffer))
	{
		memset(CFDP_AppData.fileInfo.buffer + size, 0,
		       sizeof(CFDP_AppData.fileInfo.buffer) - (uint32)size);
	}

	strncpy(CFDP_AppData.fileInfo.destination, destination, sizeof(CFDP_AppData.fileInfo.destination)-1);
	CFDP_AppData.fileInfo.destination[sizeof(CFDP_AppData.fileInfo.destination)-1] = 0;
	strncpy(CFDP_AppData.fileInfo.source, source, sizeof(CFDP_AppData.fileInfo.source)-1);
	CFDP_AppData.fileInfo.source[sizeof(CFDP_AppData.fileInfo.source)-1] = 0;
	CFDP_AppData.fileInfo.data_len = (uint16_t)size;
	CFDP_AppData.fileInfo.seq_num  = seq_num;

	CFDP_CFDP_SendPDU();
	CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION,
		"CFDP: Resent chunk seq %u (%d bytes)", (unsigned)seq_num, (int)size);
}

/*
** Incremental CRC-32 matching Python's zlib.crc32 / standard CRC-32:
** reflected, poly 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF.
** Seed the first call with 0xFFFFFFFF; XOR the final result with 0xFFFFFFFF.
*/
uint32_t CFDP_CFDP_Crc32(uint32_t crc, const uint8_t *data, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++)
	{
		crc ^= data[i];
		for (int b = 0; b < 8; b++)
		{
			if (crc & 1u) crc = (crc >> 1) ^ 0xEDB88320u;
			else          crc = (crc >> 1);
		}
	}
	return crc;
}

/*
** Verify an uploaded file against the ground's expected size and CRC-32.
** Reads the written destination file back and compares. Logs OK or MISMATCH
** and increments the command error counter on any mismatch.
*/
void CFDP_CFDP_VerifyUpload(const char *destination, uint32_t expected_size, uint32_t expected_crc)
{
	int32_t   status;
	osal_id_t fd;
	int32     n;
	uint8_t   buf[512];
	uint32_t  size = 0;
	uint32_t  crc  = 0xFFFFFFFFu;

	status = OS_OpenCreate(&fd, destination, OS_FILE_FLAG_NONE, OS_READ_ONLY);
	if (status != OS_SUCCESS)
	{
		CFDP_AppData.hk.cmdErrorCount++;
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR,
			"CFDP: Upload verify - cannot open %s: %d", destination, (int)status);
		return;
	}

	while ((n = OS_read(fd, buf, sizeof(buf))) > 0)
	{
		crc   = CFDP_CFDP_Crc32(crc, buf, (uint32_t)n);
		size += (uint32_t)n;
	}
	OS_close(fd);
	crc ^= 0xFFFFFFFFu;

	if (size == expected_size && crc == expected_crc)
	{
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_INFORMATION,
			"CFDP: Upload VERIFIED %s (%u bytes, crc 0x%08X)",
			destination, (unsigned)size, (unsigned)crc);
	}
	else
	{
		CFDP_AppData.hk.cmdErrorCount++;
		CFE_EVS_SendEvent(CFDP_CMD_UPLOAD_EID, CFE_EVS_EventType_ERROR,
			"CFDP: Upload INTEGRITY FAIL %s - size %u/%u, crc 0x%08X/0x%08X",
			destination, (unsigned)size, (unsigned)expected_size,
			(unsigned)crc, (unsigned)expected_crc);
	}
}

uint8_t hexPairToByte(const char *hex_pair)
{
	char buf[3] = {hex_pair[0], hex_pair[1], '\0'};
	return (uint8_t) strtol(buf, NULL, 16);
}
