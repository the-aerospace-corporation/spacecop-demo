# CubeSatSim Hardware Interface — for cFS Flight Software on Trixie
### Target hardware: Raspberry Pi Zero 2 W + Pi Pico (stock v2 configuration)

This is the contract between your **cFS command/telemetry apps** and the
CubeSatSim boards. It replaces `main.c` + `transmit.py`; you keep 100% of the
hardware. Everything below uses **modern Linux kernel interfaces** (libgpiod v2,
`/dev/i2c-*`, termios, ALSA) — do **not** pull in wiringPi or RPi.GPIO on Trixie,
both are dead there.

## Division of labor (Pi Zero 2 W + Pico)

With a Pico attached, the Pico's firmware detects the Pi and runs in
**payload-only mode** (`payload_pico.ino` → `payload_OK_only()`). So:

| | Reads INA219 power | Reads BME280/MPU6050 payload | Programs FM radio | Keys PTT / audio / rpitx | Camera |
|---|---|---|---|---|---|
| **Pi (your cFS)** | ✅ I2C bus 1 | — (gets them from Pico) | ✅ UART @9600 | ✅ | — |
| **Pico** | — | ✅ (its own I2C) | — (only in Pi-less "Lite" build) | — | ✅ (ESP32-CAM) |

So the Pi/cFS is the transmitter and flight computer; the Pico is a **serial
sensor peripheral**. Keep the Pico's stock firmware (`payload_pico.ino`) — it's
part of "their hardware"; your cFS just consumes its serial output.

Prerequisite: run `setup-trixie-hardware.sh` and reboot first.

---

## 1. GPIO map (BCM numbering, `/dev/gpiochip0`)

| Signal | BCM | Dir | Meaning |
|---|---|---|---|
| **PTT** | 20 | out | Key the FM module. **Active LOW**: drive `0` to transmit, `1` to unkey. |
| **FM enable** (`pd`) | 21 | out | `1` = module powered/enabled, `0` = disabled. Enable before UART programming. |
| **TX LED** | 27 | out | `1` = on. Light while transmitting. |
| **Power/ON LED** (`green`) | 16 | out | `1` = on. Health/heartbeat LED. |
| **Squelch jumper** | 6 | in, pull-up | Board option strap; read at boot. |
| **TX-command jumper** (`txc`) | 7 | in, pull-up | Board option strap; read at boot. |
| **LPF present** | 12 | in, pull-up | Low-pass-filter/PA detect. Reads LOW when the RF filter board is fitted → OK to transmit. |
| **Power button** | 3 | — | Handled by the `gpio-shutdown` overlay, **not** by your app. |

libgpiod v2 C sketch (link `-lgpiod`, header `<gpiod.h>`):

```c
#include <gpiod.h>
// Request PTT (GPIO20) and TX-LED (GPIO27) as outputs, idle state:
struct gpiod_chip *chip = gpiod_chip_open("/dev/gpiochip0");
struct gpiod_line_settings *out = gpiod_line_settings_new();
gpiod_line_settings_set_direction(out, GPIOD_LINE_DIRECTION_OUTPUT);
// ... build a line_config for offsets {20, 27}, request via
//     gpiod_chip_request_lines(...). Then to transmit:
//   PTT(20) = 0  (active-low key down), TXLED(27) = 1
//   ...unkey: PTT(20) = 1, TXLED(27) = 0
```

CLI equivalents for quick tests (gpiod **v2** syntax on Trixie):

```bash
gpioset -t0 gpiochip0 21=1        # enable FM module
gpioset -t0 gpiochip0 27=1 20=0   # TX LED on, key PTT (transmit)
gpioset -t0 gpiochip0 20=1 27=0   # unkey, TX LED off
gpioget gpiochip0 12              # read LPF-present strap
```

---

## 2. I2C sensors (Pi side)

| Bus | Device | Sensors / addresses | Who reads it |
|---|---|---|---|
| `/dev/i2c-1` | hardware I2C (GPIO2/3) | **INA219** power monitors: `0x40 0x41 0x44 0x45` (solar +X/+Y/−X/−Y, battery, bus) | **your cFS** |
| `/dev/i2c-3` | bit-banged (GPIO23/24) | **BME280** `0x76`/`0x77`, **MPU6050** `0x68` | the **Pico** (bus 3 is only your fallback) |

The INA219 power/current sensors are yours to read (bus 1). The BME280/MPU6050
payload sensors are read by the **Pico** and arrive over the UART (see §3.5) —
you only touch bus 3 if you ever run without the Pico. Verify: `i2cdetect -y 1`
(expect `40 41 44 45`).

Read from C with the standard kernel interface (no external lib needed):

```c
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
int fd = open("/dev/i2c-1", O_RDWR);
ioctl(fd, I2C_SLAVE, 0x40);              // an INA219
// INA219: write config (0x00), calibration (0x05), then read
// bus-voltage reg 0x02 and current reg 0x04 (see datasheet).
```

The stock `ina219.py` (repo root) documents the exact register setup and the
address→panel mapping if you want a reference for the shunt/calibration math.

---

## 3. The shared UART `/dev/ttyAMA0` — radio (9600) AND Pico (115200)

> **Critical:** one physical port (GPIO14/15) is used by **two** devices at
> **two** baud rates. Give your cFS a single "serial manager" that owns
> `/dev/ttyAMA0` and switches baud; never let two apps open it at once.
>
> * **9600 8N1** → program the SR_FRS FM radio (§3, brief, at boot/mode-change)
> * **115200 8N1** → read the Pico payload (§3.5, every telemetry cycle)
>
> Sequence per cycle: (re)program radio @9600 if needed → close → reopen @115200
> → read Pico → close. The radio ignores 115200 chatter and the Pico ignores the
> AT commands, but only one baud rate can be active at a time.

### 3.1 FM radio module — UART programming (9600 8N1)

The UHF FM module (SR_FRS / SA818-class) is configured over the freed hardware
UART **before** each transmit session. This is the sequence `program_radio()`
in `main.c` performs — reproduce it verbatim in your radio-manager app:

1. `gpioset` FM-enable **GPIO21 = 1**, PTT **GPIO20 = 1** (enabled, unkeyed).
2. Open `/dev/ttyAMA0` at **9600 8N1**, no flow control.
3. Send (CRLF-terminated), ~1 s apart:
   ```
   AT+DMOSETGROUP=0,<RXfreq>,<TXfreq>,0,<squelch>,0,0\r\n
   AT+DMOSETMIC=8,0\r\n
   ```
   Defaults from `sim.cfg`: TX `434.9000`, RX `435.0000`, squelch `3`.
   (Field order matches the stock code — copy it exactly; the module firmware
   is picky.)
4. Close the port. To transmit: **GPIO20 → 0** (key), feed audio, then
   **GPIO20 → 1** (unkey).

termios sketch:

```c
#include <termios.h>
int u = open("/dev/ttyAMA0", O_RDWR | O_NOCTTY);
struct termios t; tcgetattr(u, &t);
cfsetispeed(&t, B9600); cfsetospeed(&t, B9600);
t.c_cflag = (t.c_cflag & ~CSIZE) | CS8;      // 8N1
t.c_cflag &= ~(PARENB | CSTOPB | CRTSCTS);
t.c_cflag |= (CLOCAL | CREAD);
tcsetattr(u, TCSANOW, &t);
dprintf(u, "AT+DMOSETGROUP=0,435.0000,434.9000,0,3,0,0\r\n");
```

---

### 3.5 Pico payload — reading it (115200 8N1)

The Pico streams payload telemetry to the Pi over the same UART at **115200**.
`get_payload_serial()` in `main.c` is the reference reader. Format:

- An ASCII line that **begins with `OK`** followed by space-separated sensor
  tokens (temperature, pressure, altitude, humidity, gyro X/Y/Z, accel X/Y/Z,
  and any extended/user tokens). Parse on whitespace; ignore the line if it
  doesn't start with `OK` (that's how the stock code validates it).
- Optionally, a camera JPEG **framed between the literal markers
  `_START_FLAG_` … `_END_FLAG_`** (only if an ESP32-CAM is attached to the
  Pico). Buffer bytes between the flags; strip the flags; that's the image.
  A ~2 s read timeout (`CAMERA_TIMEOUT`) bounds the wait.

```c
// after switching /dev/ttyAMA0 to 115200:
tcflush(u, TCIFLUSH);                 // flush stale bytes first
char line[512]; int n = read_line(u, line, sizeof line, 2000 /*ms*/);
if (n >= 2 && line[0]=='O' && line[1]=='K') { /* strtok on ' ' -> telemetry */ }
```

Your cFS `SENSOR_APP` merges this Pico string with the INA219 values it read on
bus 1 to build the full telemetry frame. If the Pico is absent/silent, fall back
to reading BME280/MPU6050 yourself on `/dev/i2c-3` (that's what `pi_sensors()`
does).

## 4. RF transmit paths (pick per telemetry mode)

There are **two independent transmitters** sharing the antenna. Your cFS "radio
app" chooses one per downlink mode:

**A. FM-module path** — AFSK/APRS, FM, CW, SSTV audio.
Audio → ALSA card → FM module mic. Key with PTT (GPIO20).
- For APRS/AFSK/DTMF you can shell out to **direwolf** (installed by setup),
  same as the stock build, reading from the `snd-aloop` loopback that
  `asound.conf` sets up. `direwolf-cc.conf` / `direwolf-cc` in the repo are
  working examples.
- Or generate your own WAV/tones and `aplay` them to the module's card.
- **Identify the card first:** `aplay -l`. The repo `asound.conf` assumes a
  card named `Device` plus a `Loopback` (snd-aloop). Adjust to your build.

**B. rpitx direct synthesis** — BPSK/FSK/SSTV without the FM module.
`rpitx` bit-bangs GPIO4/GPIO18 to emit RF directly. Invoke its binaries
(`sendiq`, `pifsk`, etc.) as subprocesses from your app.
- Works on Pi Zero/Zero 2/3/4. **Does not work on Pi 5.**

From cFS these are just child processes (OSAL/`system()` or a POSIX
`fork/exec` wrapper). Keep PTT/LED GPIO control in your app; let direwolf/rpitx
own the modulation.

---

## 5. cFS integration notes

- **PSP/OSAL:** build on the `pc-linux` PSP. Hardware access is *not* part of
  OSAL — put I2C/GPIO/UART/ALSA code in your own library or hardware-abstraction
  app, called by your CI (command ingest) and TO (telemetry output) apps.
- **Permissions:** cFS FSW is commonly run as **root** (simplest, and matches a
  "flight" model). If you run as a normal user instead, the setup script already
  adds you to `gpio i2c dialout audio spi` and installs a udev rule for
  `/dev/gpiochip*` — log out/in after first run.
- **Threading/timing — the Zero 2 W tradeoff (important):** the stock image
  forces `maxcpus=1` on the Pi Zero 2 W specifically to make **rpitx** (BPSK/FSK
  direct synthesis) transmit cleanly — the quad-core's DMA/clock contention
  otherwise jitters the RF. That would kneecap cFS.
    - If you use **only the FM-module modes** (AFSK/APRS/FM/CW via audio + PTT):
      keep **all 4 cores** — rpitx isn't involved, no `maxcpus` needed.
    - If you need **BPSK/FSK via rpitx**: either accept `maxcpus=1` (matching
      stock, simplest/most reliable) **or** keep multicore and pin rpitx to an
      isolated core (`isolcpus=3` + `taskset`/RT priority) and test for jitter.
    Decide based on which downlink modes your mission actually flies.
- **Watchdog / reset count:** the stock app persists `reset_count` in
  `sim.cfg`. In cFS use the OSAL/CFE persistent tables or a file for the same
  purpose.
- **Suggested app split:**
  - `HW_LIB` — libgpiod/i2c/uart helpers (this document, in code).
  - `SERIAL_MGR` — **owns `/dev/ttyAMA0`**; arbitrates radio(9600)/Pico(115200)
    baud switching so nothing else opens the port. Everyone else asks it.
  - `SENSOR_APP` — reads INA219 (bus 1), requests the Pico string from
    `SERIAL_MGR`, merges → telemetry msgs.
  - `RADIO_APP` — asks `SERIAL_MGR` to program the FM module, owns PTT/LEDs,
    launches direwolf/rpitx.
  - `CMD_APP` — command ingest (uplink), e.g. via direwolf DTMF/APRS decode.

---

## 6. Trixie gotchas already handled / to watch

- Boot files are at **`/boot/firmware/`** (not `/boot/`). ✔ handled.
- **wiringPi / RPi.GPIO are dead** on Trixie → use libgpiod v2 / i2c-dev / termios. ✔ this doc.
- **Camera:** on this build the **Pico** owns the camera (ESP32-CAM) and hands
  you the JPEG over serial (§3.5) — you do **not** need `raspistill`/libcamera on
  the Pi at all. (Legacy `raspistill` is gone in Trixie anyway.)
- **No hard-coded `/home/pi`.** Your cFS tree can live anywhere; nothing here
  assumes the `pi` user.
- **Pico firmware is unchanged.** Keep the stock `payload_pico.ino` flashed on
  the Pico (Arduino-pico core). It auto-detects the Pi (via its 3V3-sense pin)
  and stays in payload-only mode. Your cFS only consumes its serial output.
- **You're on Zero 2 W — good.** Analog audio (audremap) and rpitx both work on
  the Zero 2 W, so both RF paths are available (subject to the core tradeoff
  above). The Pi-5 limitations don't apply to you.
