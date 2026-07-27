#!/usr/bin/env python3
"""
Hold-to-shutdown for the CubeSatSim power button on Trixie.

The button is on GPIO3, which is ALSO the I2C1 SCL line the INA219 sensors use.
That means neither the kernel `gpio-shutdown` overlay nor modern rpi-lgpio can
claim GPIO3 (I2C owns it -- see dmesg). The stock Bullseye software got around
this by reading GPIO3's level register DIRECTLY (old RPi.GPIO poked registers,
bypassing driver ownership) and requiring a multi-second hold so brief I2C clock
pulses on SCL wouldn't look like a button press.

This recreates exactly that: mmap /dev/gpiomem, read the GPIO level register
(GPLEV0), and if GPIO3 stays LOW continuously for HOLD_SECONDS, shut down.
Reading GPLEV is safe and non-intrusive -- it reflects the physical pin level
regardless of the pin's I2C function, and never touches the I2C traffic.

Run as root (needs /dev/gpiomem):  sudo python3 power_button_hold.py
"""

import mmap
import os
import struct
import subprocess
import time

PIN = 3                 # BCM GPIO3 (shared with I2C1 SCL)
HOLD_SECONDS = 3.0      # how long you must hold the button to trigger shutdown
POLL_SECONDS = 0.05     # sample rate (50 ms -> I2C clock blips never persist)
GPLEV0 = 0x34           # GPIO pin-level register 0, offset within the GPIO block

fd = os.open("/dev/gpiomem", os.O_RDONLY)
mem = mmap.mmap(fd, 4096, mmap.MAP_SHARED, mmap.PROT_READ)


def button_pressed():
    """True when GPIO3 reads LOW (button pulls the line to ground)."""
    mem.seek(GPLEV0)
    level = struct.unpack("<I", mem.read(4))[0]
    return not ((level >> PIN) & 1)


def main():
    print(f"Power-button watcher running: hold GPIO{PIN} for "
          f"{HOLD_SECONDS:.0f}s to shut down.", flush=True)
    low_since = None
    while True:
        if button_pressed():
            if low_since is None:
                low_since = time.monotonic()
            elif time.monotonic() - low_since >= HOLD_SECONDS:
                print("Button held -> clean shutdown.", flush=True)
                subprocess.run(["shutdown", "-h", "now"])
                return
        else:
            low_since = None            # released (or just an I2C clock blip)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        mem.close()
        os.close(fd)
