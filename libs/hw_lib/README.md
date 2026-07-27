# hw_lib -- CubeSatSim GPIO helper library

A cFS **library** (no task) that owns `/dev/gpiochip0` via **libgpiod v2** and
exposes a small logical API for the CubeSatSim board's discrete signals. It
replaces the wiringPi GPIO handling from the stock `main.c` / `transmit.py`,
which do not work on Trixie (Debian 13).

## Line map (BCM)

| Logical id | BCM | Dir | Meaning |
|---|---|---|---|
| `HW_LINE_PTT` | 20 | out (active-low) | Key the FM module. `SetLine(...,1)` transmits. |
| `HW_LINE_FM_ENABLE` | 21 | out | Power/enable the FM module. |
| `HW_LINE_TX_LED` | 27 | out | Transmit LED. |
| `HW_LINE_PWR_LED` | 16 | out | Power/health LED. |
| `HW_LINE_SQUELCH` | 6 | in (pull-up) | Squelch strap. |
| `HW_LINE_TXC` | 7 | in (pull-up) | TX-command strap. |
| `HW_LINE_LPF` | 12 | in (pull-up, active-low) | LPF/PA fitted -> value `1`. |

Values are **logical**: `1` = asserted/on, `0` = off. Active-low pins (PTT,
LPF) are inverted inside the library, so callers never touch electrical
polarity.

> The FM-radio pins (PTT / FM_ENABLE / TX_LED) are wired up but you don't have
> to use them yet -- they sit idle until a future `radio_app` drives them. The
> `PWR_LED` and the input straps are usable immediately.

## Using it from another app

`hw_lib` initializes before the apps (loaded as `CFE_LIB` at the top of the
startup script), so its API is ready by the time any app's `AppMain` runs.

```c
#include "hw_lib.h"   /* add hw_lib to your app's target_link/include if needed */

/* Heartbeat: blink the power LED */
HW_LIB_PowerLed(1);

/* Read a strap once at startup */
int lpf_fitted = 0;
if (HW_LIB_GetLine(HW_LINE_LPF, &lpf_fitted) == CFE_SUCCESS && lpf_fitted)
{
    /* RF low-pass filter board present */
}

/* Guard hardware-only paths on a dev host */
if (!HW_LIB_IsAvailable())
{
    /* no GPIO chip (x86 build box); skip */
}
```

## Portability

If `/dev/gpiochip0` cannot be opened (e.g. an x86 build/test host), `HW_LIB_Init`
logs a warning and returns success in an **inert** state: `HW_LIB_IsAvailable()`
returns `false` and all Set/Get calls return `HW_LIB_ERROR`. This keeps the same
flight image booting on both the Pi and a workstation.

## Build / registration

- Built via `MISSION_GLOBAL_APPLIST` in `sample_defs/targets.cmake`.
- Loaded via `CFE_LIB, hw_lib, HW_LIB_Init, HW_LIB, 0, 0, 0x0, 0;` in
  `sample_defs/cpu1_cfe_es_startup.scr`.
- Links the system `libgpiod` (`libgpiod-dev`), installed on the target by
  `CubeSatSim/trixie-cfs/setup-trixie-hardware.sh`.
