/*
 * hw_lib.c -- CubeSatSim GPIO helper library.
 *
 * Supports BOTH libgpiod v2 (Trixie / Debian 13+) and libgpiod v1
 * (Bullseye / Bookworm), auto-detected at compile time, so the same source
 * builds regardless of which Pi OS you are on. The public API (hw_lib.h) is
 * identical for both; only the internal libgpiod calls differ.
 *
 * Version detection: libgpiod v1 defines GPIOD_LINE_BULK_MAX_LINES (the bulk
 * line API), which v2 removed -- use that as the compile-time discriminator.
 */
#include "hw_lib.h"
#include "hw_lib_version.h"

#include <gpiod.h>
#include <errno.h>
#include <string.h>

#if defined(GPIOD_LINE_BULK_MAX_LINES)
#define HW_LIB_GPIOD_V1 1
#else
#define HW_LIB_GPIOD_V1 0
#endif

/*************************************************************************
** Line table: logical id -> BCM offset + attributes (shared by both versions)
*************************************************************************/
typedef struct
{
	unsigned int offset;
	bool         is_output;
	bool         active_low; /* PTT and LPF-present are active-low */
	bool         pull_up;    /* strap inputs are pulled up */
} HW_LineDef_t;

static const HW_LineDef_t HW_Lines[HW_LINE_MAX] = {
	[HW_LINE_PTT]       = {HW_LIB_PIN_PTT,       true,  true,  false},
	[HW_LINE_FM_ENABLE] = {HW_LIB_PIN_FM_ENABLE, true,  false, false},
	[HW_LINE_TX_LED]    = {HW_LIB_PIN_TX_LED,    true,  false, false},
	[HW_LINE_PWR_LED]   = {HW_LIB_PIN_PWR_LED,   true,  false, false},
	[HW_LINE_SQUELCH]   = {HW_LIB_PIN_SQUELCH,   false, false, true },
	[HW_LINE_TXC]       = {HW_LIB_PIN_TXC,       false, false, true },
	[HW_LINE_LPF]       = {HW_LIB_PIN_LPF,       false, true,  true },
};

static struct gpiod_chip *HW_Chip;
static bool               HW_Available;

#if HW_LIB_GPIOD_V1
/* ========================== libgpiod v1 path ============================= */

static struct gpiod_line *HW_LineHandles[HW_LINE_MAX];

int32 HW_LIB_Init(void)
{
	int i, ok = 1;

	HW_Available = false;
	HW_Chip = gpiod_chip_open(HW_LIB_GPIOCHIP);
	if (HW_Chip == NULL)
	{
		OS_printf("HW_LIB: %s unavailable (%s); GPIO disabled\n", HW_LIB_GPIOCHIP, strerror(errno));
		return CFE_SUCCESS;
	}

	for (i = 0; i < HW_LINE_MAX; i++)
	{
		struct gpiod_line_request_config cfg;
		struct gpiod_line *line = gpiod_chip_get_line(HW_Chip, HW_Lines[i].offset);
		if (line == NULL) { ok = 0; break; }

		memset(&cfg, 0, sizeof(cfg));
		cfg.consumer     = "hw_lib";
		cfg.request_type = HW_Lines[i].is_output ? GPIOD_LINE_REQUEST_DIRECTION_OUTPUT
		                                         : GPIOD_LINE_REQUEST_DIRECTION_INPUT;
		cfg.flags = 0;
		if (HW_Lines[i].active_low) cfg.flags |= GPIOD_LINE_REQUEST_FLAG_ACTIVE_LOW;
		if (HW_Lines[i].pull_up)    cfg.flags |= GPIOD_LINE_REQUEST_FLAG_BIAS_PULL_UP;

		/* outputs come up inactive (LEDs off / PTT unkeyed); value ignored for inputs */
		if (gpiod_line_request(line, &cfg, 0) < 0) { ok = 0; break; }
		HW_LineHandles[i] = line;
	}

	if (!ok)
	{
		for (i = 0; i < HW_LINE_MAX; i++)
		{
			if (HW_LineHandles[i]) { gpiod_line_release(HW_LineHandles[i]); HW_LineHandles[i] = NULL; }
		}
		gpiod_chip_close(HW_Chip);
		HW_Chip = NULL;
		OS_printf("HW_LIB: line request failed (%s)\n", strerror(errno));
		return CFE_SUCCESS;
	}

	HW_Available = true;
	OS_printf("HW_LIB Initialized v%s (%s, libgpiod v1).\n", HW_LIB_VERSION_STRING, HW_LIB_GPIOCHIP);
	return CFE_SUCCESS;
}

int32 HW_LIB_SetLine(HW_LineId_t line, int value)
{
	if (line < 0 || line >= HW_LINE_MAX || !HW_Lines[line].is_output)
		return HW_LIB_ERROR;
	if (!HW_Available)
		return HW_LIB_ERROR;
	if (gpiod_line_set_value(HW_LineHandles[line], value ? 1 : 0) < 0)
		return HW_LIB_ERROR;
	return CFE_SUCCESS;
}

int32 HW_LIB_GetLine(HW_LineId_t line, int *value)
{
	int v;
	if (line < 0 || line >= HW_LINE_MAX || HW_Lines[line].is_output || value == NULL)
		return HW_LIB_ERROR;
	if (!HW_Available)
		return HW_LIB_ERROR;
	v = gpiod_line_get_value(HW_LineHandles[line]);
	if (v < 0)
		return HW_LIB_ERROR;
	*value = v ? 1 : 0;
	return CFE_SUCCESS;
}

#else
/* ========================== libgpiod v2 path ============================= */

static struct gpiod_line_request *HW_Request;

int32 HW_LIB_Init(void)
{
	struct gpiod_line_config    *lcfg = NULL;
	struct gpiod_request_config *rcfg = NULL;
	struct gpiod_line_settings  *settings[HW_LINE_MAX] = {0};
	int i, ok = 1;

	HW_Available = false;
	HW_Chip = gpiod_chip_open(HW_LIB_GPIOCHIP);
	if (HW_Chip == NULL)
	{
		OS_printf("HW_LIB: %s unavailable (%s); GPIO disabled\n", HW_LIB_GPIOCHIP, strerror(errno));
		return CFE_SUCCESS;
	}

	lcfg = gpiod_line_config_new();
	rcfg = gpiod_request_config_new();
	if (lcfg == NULL || rcfg == NULL) ok = 0;

	for (i = 0; ok && i < HW_LINE_MAX; i++)
	{
		unsigned int offset = HW_Lines[i].offset;
		settings[i] = gpiod_line_settings_new();
		if (settings[i] == NULL) { ok = 0; break; }

		gpiod_line_settings_set_direction(settings[i],
			HW_Lines[i].is_output ? GPIOD_LINE_DIRECTION_OUTPUT : GPIOD_LINE_DIRECTION_INPUT);
		if (HW_Lines[i].is_output)
			gpiod_line_settings_set_output_value(settings[i], GPIOD_LINE_VALUE_INACTIVE);
		if (HW_Lines[i].active_low)
			gpiod_line_settings_set_active_low(settings[i], true);
		if (HW_Lines[i].pull_up)
			gpiod_line_settings_set_bias(settings[i], GPIOD_LINE_BIAS_PULL_UP);

		if (gpiod_line_config_add_line_settings(lcfg, &offset, 1, settings[i]) < 0) { ok = 0; break; }
	}

	if (ok)
	{
		gpiod_request_config_set_consumer(rcfg, "hw_lib");
		HW_Request = gpiod_chip_request_lines(HW_Chip, rcfg, lcfg);
		if (HW_Request != NULL) HW_Available = true;
	}

	for (i = 0; i < HW_LINE_MAX; i++)
		if (settings[i]) gpiod_line_settings_free(settings[i]);
	if (lcfg) gpiod_line_config_free(lcfg);
	if (rcfg) gpiod_request_config_free(rcfg);

	if (!HW_Available)
	{
		if (HW_Chip) { gpiod_chip_close(HW_Chip); HW_Chip = NULL; }
		OS_printf("HW_LIB: line request failed (%s)\n", strerror(errno));
		return CFE_SUCCESS;
	}

	OS_printf("HW_LIB Initialized v%s (%s, libgpiod v2).\n", HW_LIB_VERSION_STRING, HW_LIB_GPIOCHIP);
	return CFE_SUCCESS;
}

int32 HW_LIB_SetLine(HW_LineId_t line, int value)
{
	if (line < 0 || line >= HW_LINE_MAX || !HW_Lines[line].is_output)
		return HW_LIB_ERROR;
	if (!HW_Available)
		return HW_LIB_ERROR;
	if (gpiod_line_request_set_value(HW_Request, HW_Lines[line].offset,
	        value ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE) < 0)
		return HW_LIB_ERROR;
	return CFE_SUCCESS;
}

int32 HW_LIB_GetLine(HW_LineId_t line, int *value)
{
	enum gpiod_line_value v;
	if (line < 0 || line >= HW_LINE_MAX || HW_Lines[line].is_output || value == NULL)
		return HW_LIB_ERROR;
	if (!HW_Available)
		return HW_LIB_ERROR;
	v = gpiod_line_request_get_value(HW_Request, HW_Lines[line].offset);
	if (v == GPIOD_LINE_VALUE_ERROR)
		return HW_LIB_ERROR;
	*value = (v == GPIOD_LINE_VALUE_ACTIVE) ? 1 : 0;
	return CFE_SUCCESS;
}

#endif /* HW_LIB_GPIOD_V1 */

/* =================== version-independent public API ====================== */

bool HW_LIB_IsAvailable(void)
{
	return HW_Available;
}

int32 HW_LIB_PowerLed(int on)
{
	return HW_LIB_SetLine(HW_LINE_PWR_LED, on);
}

int32 HW_LIB_TxLed(int on)
{
	return HW_LIB_SetLine(HW_LINE_TX_LED, on);
}
