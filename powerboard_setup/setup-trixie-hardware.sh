#!/usr/bin/env bash
# ============================================================================
#  setup-trixie-hardware.sh
#
#  One-shot hardware enablement for a CubeSatSim board running a FRESH
#  Raspberry Pi OS "Trixie" (Debian 13) install, intended to be driven by a
#  cFS-based flight software stack (NOT the stock CubeSatSim C app).
#
#  What it does:
#    * enables I2C(1), i2c-gpio(3), UART, audio, power button via config.txt
#    * turns OFF the serial login console (frees /dev/ttyAMA0 for the radio)
#    * installs the low-level libs cFS/RF need (libgpiod2, i2c, alsa, ...)
#    * installs the RF tooling (direwolf, rpitx) + snd-aloop + asound.conf
#    * grants the flight-software user access to gpio / i2c / serial / audio
#
#  It does NOT install the CubeSatSim application, wiringPi, RPi.GPIO,
#  FoxTelem, or any telemetry logic -- that is what your cFS apps replace.
#
#  Run as:   sudo ./setup-trixie-hardware.sh
#  Idempotent: safe to re-run.
# ============================================================================
set -euo pipefail

# ---- Who is the flight-software user? (defaults to the sudo caller) ---------
FSW_USER="${SUDO_USER:-$(id -un)}"
BOOT_CFG="/boot/firmware/config.txt"
BOOT_CMD="/boot/firmware/cmdline.txt"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the CubeSatSim clone

echo ">>> Flight-software user : $FSW_USER"
echo ">>> Boot config          : $BOOT_CFG"
echo ">>> CubeSatSim repo       : $REPO_DIR"

if [[ ! -f "$BOOT_CFG" ]]; then
  echo "!! $BOOT_CFG not found. On Trixie the boot files live in /boot/firmware."
  echo "!! Confirm you are on Raspberry Pi OS (Debian 13) before continuing."
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. Packages -- modern Linux hardware interfaces only (no wiringPi)
# ---------------------------------------------------------------------------
echo ">>> Installing packages ..."
apt-get update
# NOTE: Trixie (Debian 13) ships libgpiod v2, so the runtime lib is libgpiod3
# (it was libgpiod2 on Bookworm). We install `gpiod` + `libgpiod-dev`, which
# pull the correct runtime lib in automatically; the runtime pkg name is only
# needed explicitly below and is resolved for whichever release you're on.
GPIOD_RT="$(apt-cache pkgnames | grep -E '^libgpiod[0-9]+$' | sort -V | tail -1)"
apt-get install -y \
  build-essential cmake git \
  gpiod libgpiod-dev ${GPIOD_RT} \
  i2c-tools libi2c-dev \
  alsa-utils libasound2-dev \
  libudev-dev libavahi-client-dev \
  python3-smbus python3-serial \
  minicom

# RF audio: direwolf (APRS/AFSK/DTMF) is in Debian; build from source only if
# you need the CubeSatSim fork's tweaks.
apt-get install -y direwolf || echo "!! direwolf not in apt; build from source if needed"

# ---------------------------------------------------------------------------
# 2. Boot firmware config -- append the hardware-enable block (idempotent)
# ---------------------------------------------------------------------------
echo ">>> Applying $BOOT_CFG ..."
cp -n "$BOOT_CFG" "${BOOT_CFG}.pre-cubesat" || true   # one-time backup

add_cfg () {   # add a line only if a matching key is not already present
  local match="$1" line="$2"
  if grep -qF "$match" "$BOOT_CFG"; then
    echo "    ok: $match"
  else
    echo "    + $line"
    echo "$line" >> "$BOOT_CFG"
  fi
}

if ! grep -q "CubeSatSim hardware enablement" "$BOOT_CFG"; then
  echo "" >> "$BOOT_CFG"
  echo "# ---- CubeSatSim hardware enablement (Trixie / cFS) ----" >> "$BOOT_CFG"
fi
add_cfg "dtparam=i2c_arm=on"                              "dtparam=i2c_arm=on"
add_cfg "dtoverlay=i2c-gpio,bus=3"                        "dtoverlay=i2c-gpio,bus=3,i2c_gpio_delay_us=1,i2c_gpio_sda=23,i2c_gpio_scl=24"
add_cfg "enable_uart=1"                                   "enable_uart=1"
add_cfg "dtoverlay=disable-bt"                            "dtoverlay=disable-bt"
add_cfg "dtparam=audio=on"                                "dtparam=audio=on"
add_cfg "dtoverlay=audremap,enable_jack=on"               "dtoverlay=audremap,enable_jack=on"
add_cfg "dtoverlay=pwm,pin=18,func=2"                     "dtoverlay=pwm,pin=18,func=2"
add_cfg "dtoverlay=dwc2"                                  "dtoverlay=dwc2"
add_cfg "dtoverlay=gpio-shutdown"                         "dtoverlay=gpio-shutdown,gpio_pin=3,active_low=1,gpio_pull=up"
add_cfg "disable_splash=1"                                "disable_splash=1"
add_cfg "boot_delay=0"                                    "boot_delay=0"
add_cfg "force_turbo=1"                                   "force_turbo=1"

# ---------------------------------------------------------------------------
# 3. Serial: enable HW UART, DISABLE the login console (radio owns ttyAMA0)
# ---------------------------------------------------------------------------
echo ">>> Freeing /dev/ttyAMA0 for the radio ..."
raspi-config nonint do_serial_hw 0    2>/dev/null || true   # enable UART hardware
raspi-config nonint do_serial_cons 1  2>/dev/null || true   # disable serial console
# belt-and-suspenders: strip any leftover console=serial0 from cmdline
sed -i 's/console=serial0,[0-9]* //g' "$BOOT_CMD" || true
systemctl disable --now serial-getty@ttyAMA0.service 2>/dev/null || true

# Enable I2C via raspi-config too (in case dtparam alone isn't picked up)
raspi-config nonint do_i2c 0 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Audio loopback for direwolf + CubeSatSim ALSA routing
# ---------------------------------------------------------------------------
echo ">>> Configuring ALSA (snd-aloop + asound.conf) ..."
grep -qxF 'snd-aloop' /etc/modules || echo 'snd-aloop' >> /etc/modules
modprobe snd-aloop || true
if [[ -f "$REPO_DIR/asound.conf" ]]; then
  cp -n /etc/asound.conf /etc/asound.conf.pre-cubesat 2>/dev/null || true
  cp "$REPO_DIR/asound.conf" /etc/asound.conf
  echo "    installed /etc/asound.conf from repo"
fi

# ---------------------------------------------------------------------------
# 5. rpitx (direct-synthesis RF for BPSK/FSK/SSTV) -- optional, Pi Zero2/3/4
# ---------------------------------------------------------------------------
echo ">>> rpitx ..."
if command -v rpitx >/dev/null 2>&1 || [[ -d /home/$FSW_USER/rpitx ]]; then
  echo "    rpitx already present"
else
  echo "    (skipping auto-build) To install: "
  echo "      git clone https://github.com/F5OEO/rpitx ~/rpitx && cd ~/rpitx && ./install.sh"
  echo "    NOTE: rpitx works on Pi Zero/Zero2/3/4. It does NOT work on Pi 5."
fi

# ---------------------------------------------------------------------------
# 6. Device permissions for the flight-software user
#    (Alternatively run cFS as root, which is common for FSW.)
# ---------------------------------------------------------------------------
echo ">>> Granting $FSW_USER access to gpio / i2c / serial / audio ..."
for grp in gpio i2c dialout audio spi; do
  getent group "$grp" >/dev/null 2>&1 && usermod -aG "$grp" "$FSW_USER" || true
done
# udev rule so /dev/gpiochip* is group-gpio writable (libgpiod v2)
cat > /etc/udev/rules.d/99-cubesat-gpio.rules <<'EOF'
SUBSYSTEM=="gpio", GROUP="gpio", MODE="0660"
KERNEL=="gpiochip*", GROUP="gpio", MODE="0660"
EOF
udevadm control --reload-rules 2>/dev/null || true

# ---------------------------------------------------------------------------
echo ""
echo ">>> DONE. Review $BOOT_CFG, then reboot."
echo ">>> After reboot, verify with:"
echo "      ls -l /dev/i2c-1 /dev/i2c-3 /dev/ttyAMA0 /dev/gpiochip0"
echo "      i2cdetect -y 1     # expect 40 41 44 45 (INA219)"
echo "      i2cdetect -y 3     # expect payload sensors (e.g. 76/77 BME280, 68 MPU6050)"
echo "      gpioinfo gpiochip0 # confirm GPIO access"
echo "      aplay -l           # identify the sound card feeding the FM module"
