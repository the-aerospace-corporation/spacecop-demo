#!/usr/bin/env python3
"""
CubeSatSim board bring-up + power-button shutdown, for Raspberry Pi OS Trixie.

Replicates the stock behavior on the modern stack (gpiozero/lgpio; wiringPi and
RPi.GPIO are dead on Trixie):

  * lights the green "ON" LED (GPIO16), boot blink then solid
  * puts the radio in a SAFE, un-keyed, disabled state (no accidental TX)
  * scans I2C bus 1 for the power boards (INA219)
  * watches the POWER BUTTON on GPIO26 (the pin the stock pi-power-button uses):
      hold it -> after HOLD_READY seconds the green LED blinks steadily to say
      "ready to power off" -> release while it's blinking -> clean shutdown.
      Release before the blink starts -> nothing happens (back to solid).

The button is GPIO26 with an internal pull-up; pressing pulls it to ground.
GPIO26 has no I2C/UART conflict, so this is rock-solid.
"""

import signal
import subprocess
import sys
import time

from gpiozero import LED, OutputDevice, Button

# --- BCM pin map ---
ON_LED = 16   # green "power on" LED  (active high)
TX_LED = 27   # red TX LED            (active high)
FM_EN  = 21   # FM module enable      (HIGH = on)   -> OFF for no-RF bring-up
PTT    = 20   # push-to-talk          (LOW = keyed) -> HIGH = un-keyed / safe
BUTTON = 26   # power button          (pull-up; pressed = LOW)

I2C_BUS      = 1
INA219_ADDRS = [0x40, 0x41, 0x44, 0x45]

HOLD_READY = 2.0    # seconds to hold before the "ready to power off" blink
BLINK_S    = 0.25   # steady blink period once ready

green = LED(ON_LED)
txled = LED(TX_LED)
fm_en = OutputDevice(FM_EN, active_high=True, initial_value=False)  # disabled
ptt   = OutputDevice(PTT,   active_high=True, initial_value=True)   # un-keyed
button = Button(BUTTON, pull_up=True)


def cleanup(*_):
    green.off()
    txled.off()
    sys.exit(0)


signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)


def scan_boards():
    found = []
    try:
        from smbus2 import SMBus
        with SMBus(I2C_BUS) as bus:
            for addr in INA219_ADDRS:
                try:
                    bus.read_byte(addr)
                    found.append(addr)
                except OSError:
                    pass
    except Exception as exc:
        print(f"[bringup] I2C scan skipped: {exc}", flush=True)
    return found


def boot_blink(n=3, on=0.15, off=0.15):
    for _ in range(n):
        green.on(); time.sleep(on)
        green.off(); time.sleep(off)


def handle_button():
    """Hold GPIO26: after HOLD_READY the LED blinks 'ready'; release -> shutdown."""
    pressed_at = time.monotonic()
    ready = False
    while button.is_pressed:
        held = time.monotonic() - pressed_at
        if held >= HOLD_READY:
            if not ready:
                ready = True
                print("[bringup] hold detected -> release to power off", flush=True)
            green.toggle()               # steady blink = "ready to shut down"
            time.sleep(BLINK_S)
        else:
            time.sleep(0.02)
    # button released
    green.on()
    if ready:
        print("[bringup] button released after hold -> shutting down", flush=True)
        subprocess.run(["shutdown", "-h", "now"])
        return True
    return False                          # released too early: no action


def main():
    print("[bringup] CubeSatSim bring-up + power button starting (Trixie)", flush=True)
    boot_blink()

    boards = scan_boards()
    if boards:
        print(f"[bringup] power boards present at: {[hex(a) for a in boards]}",
              flush=True)
        for _ in boards:
            txled.on(); time.sleep(0.1); txled.off(); time.sleep(0.1)
    else:
        print("[bringup] WARNING: no INA219 power boards found on i2c-1", flush=True)

    green.on()   # solid green = powered up and running
    print(f"[bringup] ready. Hold the button on GPIO{BUTTON} ~{HOLD_READY:.0f}s, "
          "then release when green blinks to power off.", flush=True)

    while True:
        if button.is_pressed:
            if handle_button():
                break                     # shutting down
        else:
            time.sleep(0.05)


if __name__ == "__main__":
    main()
