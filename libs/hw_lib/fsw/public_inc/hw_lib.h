/*
 * hw_lib.h -- CubeSatSim GPIO helper library (libgpiod v2)
 *
 * Owns /dev/gpiochip0 and exposes a small logical API for the CubeSatSim
 * board's discrete signals: the status LEDs, the FM-radio control lines, and
 * the board-option straps.  All access uses the modern libgpiod v2 character-
 * device interface (Trixie / Debian 13).  wiringPi and /sys/class/gpio are
 * intentionally NOT used -- both are dead on Trixie.
 *
 * Line values are LOGICAL: 1 = asserted/on, 0 = deasserted/off.  Active-low
 * lines (PTT, LPF-present) are inverted internally, so callers never deal with
 * the electrical polarity.
 *
 * Pin map and semantics: CubeSatSim/trixie-cfs/HARDWARE_INTERFACE.md
 */
#ifndef HW_LIB_H
#define HW_LIB_H

#include "cfe.h"

/* Simple 0/negative return convention (matches the eps hardware driver). */
#define HW_LIB_ERROR (-1)

/* GPIO chip and BCM line offsets. */
#define HW_LIB_GPIOCHIP "/dev/gpiochip0"

#define HW_LIB_PIN_PTT        20 /* out, active-low : key the FM module   */
#define HW_LIB_PIN_FM_ENABLE  21 /* out             : power/enable FM mod  */
#define HW_LIB_PIN_TX_LED     27 /* out             : transmit LED         */
#define HW_LIB_PIN_PWR_LED    16 /* out             : power/health LED     */
#define HW_LIB_PIN_SQUELCH     6 /* in,  pull-up    : squelch strap        */
#define HW_LIB_PIN_TXC         7 /* in,  pull-up    : TX-command strap     */
#define HW_LIB_PIN_LPF        12 /* in,  pull-up, active-low : LPF/PA fitted*/

/* Logical signal identifiers. Outputs come first, then inputs. */
typedef enum
{
	HW_LINE_PTT = 0,   /* output */
	HW_LINE_FM_ENABLE, /* output */
	HW_LINE_TX_LED,    /* output */
	HW_LINE_PWR_LED,   /* output */
	HW_LINE_SQUELCH,   /* input  */
	HW_LINE_TXC,       /* input  */
	HW_LINE_LPF,       /* input  */
	HW_LINE_MAX
} HW_LineId_t;

/*
 * Library initialization -- registered in cfe_es_startup.scr as
 * "HW_LIB / HW_LIB_Init".  Opens the GPIO chip, requests all lines, and drives
 * every output to a safe idle state (FM disabled, PTT unkeyed, LEDs off).
 *
 * If no GPIO chip is present (e.g. an x86 build/test host) it logs a warning
 * and stays available-but-inert, returning CFE_SUCCESS so the rest of cFE
 * still boots.  Use HW_LIB_IsAvailable() to tell the two cases apart.
 */
int32 HW_LIB_Init(void);

/* True once Init holds a working GPIO request; false on a host with no chip. */
bool HW_LIB_IsAvailable(void);

/*
 * Set a logical OUTPUT (HW_LINE_PTT .. HW_LINE_PWR_LED).
 *   value != 0 -> assert (LED on / PTT keyed / FM enabled)
 *   value == 0 -> deassert
 * Returns CFE_SUCCESS, or HW_LIB_ERROR if the line is not an output, the id is
 * out of range, or the hardware is unavailable.
 */
int32 HW_LIB_SetLine(HW_LineId_t line, int value);

/*
 * Read a logical INPUT (HW_LINE_SQUELCH .. HW_LINE_LPF) into *value (0/1).
 * For HW_LINE_LPF, value == 1 means the LPF/PA board is fitted (OK to TX).
 * Returns CFE_SUCCESS or HW_LIB_ERROR.
 */
int32 HW_LIB_GetLine(HW_LineId_t line, int *value);

/* Convenience wrappers for the two status LEDs. */
int32 HW_LIB_PowerLed(int on);
int32 HW_LIB_TxLed(int on);

#endif /* HW_LIB_H */
