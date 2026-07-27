# PISAT Flight Software — Build Guide

How to build the cFS flight image (`core-cpu1` + apps) from a clean checkout.

> This covers the **flight software** only. The other pieces build separately:
> - Ground station (OpenC3 COSMOS + Zeek): `gsw/README.md`
> - SpaceCop ML anomaly server (Rust): `spacecop_ml/README.md`
> - Access portal / kiosk / hardening: `deploy/`
> - Pi hardware enablement for a fresh Trixie: `../CubeSatSim/trixie-cfs/`

---

## 1. Prerequisites (packages)

| Need it for | Debian/Ubuntu/Raspberry Pi OS packages |
|---|---|
| **Core cFS build** (always) | `build-essential cmake git` |
| **`hw_lib`** (GPIO, libgpiod **v2**) | `libgpiod-dev`  ← must be v2; **Trixie/Debian 13 only** (Bookworm/Bullseye ship v1 — wrong API) |
| **`spacecop`** (IDS, SHA-256) | `libssl-dev` |
| **`spacecop` kernel module** (`aerospace.ko`) | `linux-headers-$(uname -r)`  (Raspberry Pi OS: `raspberrypi-kernel-headers`) |
| **`eps` / `stpyld`** (I2C, serial) | headers come with `build-essential` (`linux-libc-dev`); no extra package |
| Legacy `tools/cFS-GroundSystem` (optional; you use OpenC3 instead) | `python3 python3-pyqt5` |

One-shot install (native build on the Pi):
```bash
sudo apt update
sudo apt install build-essential cmake git libgpiod-dev libssl-dev \
                 linux-headers-$(uname -r)
# verify libgpiod is v2 (hw_lib needs the v2 API):
pkg-config --modversion libgpiod        # expect 2.x
```
> On a fresh Trixie Pi, `CubeSatSim/trixie-cfs/setup-trixie-hardware.sh` already
> installs `libgpiod-dev` (plus enabling I2C/UART/etc.) — run that first.

> **The two lines above are the complete BUILD set** — verified by scanning every
> external `#include` and CMake link in the tree. Everything else the code uses
> (`pthread`, sockets, `dlfcn`, `linux/i2c-dev.h`) comes from glibc /
> `linux-libc-dev`, already in `build-essential`.

### Runtime packages (not needed to build, but the apps use them)

| App | Needs at runtime | Package |
|---|---|---|
| `camera` | `rpicam-still` (falls back to `libcamera-still`) | `rpicam-apps` (usually preinstalled on Raspberry Pi OS) |
| `spacecop` | `insmod` (loads `aerospace.ko`) | `kmod` (default) |
| `eps` (debug) | `i2cdetect` etc. (optional) | `i2c-tools` |
| future `radio_app` | direwolf / rpitx (not built yet) | see `CubeSatSim/trixie-cfs/setup-trixie-hardware.sh` |

---

## 2. Get the source (with submodules)

Nine apps (`cs ds fm hk hs lc md mm sc`) are **git submodules** — a plain clone
leaves them empty and the build fails. Initialize them:
```bash
git clone <this repo> pisat && cd pisat        # or: cd /fep/pisat
git submodule update --init --recursive
```

---

## 3. Choose the target architecture (important)

The cFS image must be built **for the machine it will run on**. The target
toolchain is set by `cpu1_SYSTEM` in `sample_defs/targets.cmake`:

```
SET(cpu1_SYSTEM i686-linux-gnu)     # <-- default: 32-bit x86
```

- **Building natively on the Pi (recommended):** set `cpu1_SYSTEM` to a toolchain
  matching the Pi (or the native compiler). This is the simplest path and the
  only one where `libgpiod-dev` (v2, from the Pi's Trixie) is naturally present
  for `hw_lib` to compile *and* link. cFS is light enough to compile on the Pi.
- **Cross-compiling on an x86 host:** use one of the `sample_defs/toolchain-*.cmake`
  files (e.g. `toolchain-arm-cortexa8_neon-linux-gnueabi.cmake`). You must also
  provide the target's `libgpiod` (v2) + `libssl` **in the cross sysroot**
  (`CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY` means headers are found there, not on
  the host).
- **x86 test build (default):** leave `i686-linux-gnu`. Runs on the dev box;
  `hw_lib` is inert at runtime (no `/dev/gpiochip0`), which is by design.

---

## 4. Build (order matters)

From the repo root:
```bash
make prep          # 1. run CMake, configure the build tree  (build/ dir)
make               # 2. compile everything (core + apps + libs)
make install       # 3. stage the /cf image (mission-install)
sudo make deploy-dirs   # 4. create absolute deploy layout (needs root for /opt + /var)
```
What each does:
- **`make prep`** — runs `cmake` on `cfe/`. Options via env vars, e.g.
  `make prep BUILDTYPE=release`. Re-run `prep` after changing `targets.cmake`,
  toolchains, or after `make install`.
- **`make`** — builds `core-cpu1` and all apps/libs into `build/`.
- **`make install`** — stages the runtime `cf` image (apps `.so`, tables, startup
  script).
- **`sudo make deploy-dirs`** — creates and owns:
  - `/opt/pisat/` — read-only code/tables (mapped to `/cf` at runtime)
  - `/var/pisat/{data,logs,cti}` — writable, owned by the invoking user

> `make clean` (rebuild objects) / `make distclean` (nuke the build tree, then
> `prep` again).

---

## 5. SpaceCop kernel module (separate build)

`aerospace.ko` is built against the **running kernel's** headers and must match
the kernel it will `insmod` into (build it on the Pi, or cross-build with `KDIR`):
```bash
cd apps/spacecop/kernel
make                      # -> aerospace.ko  (native: uses /lib/modules/$(uname -r)/build)
# cross example:  make KDIR=/path/to/linux ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
```
SpaceCop loads it at startup and also opens `/dev/mem`, so cFS runs as **root**
(see `deploy/systemd/pisat-cfs.service`).

---

## 6. Hardware enablement (Pi, one-time)

Before running on the Pi, enable the buses the apps use (I2C for `eps`, UART for
`stpyld`, GPIO for `hw_lib`, camera for `camera`). On a fresh Trixie:
```bash
sudo ../CubeSatSim/trixie-cfs/setup-trixie-hardware.sh   # + reboot
```
See `CubeSatSim/trixie-cfs/HARDWARE_INTERFACE.md` for the pin/bus contract.

---

## 7. Run

Directly:
```bash
cd /opt/pisat && sudo ./core-cpu1        # root: SpaceCop needs the kernel module + /dev/mem
```
Or via systemd (auto-start on boot):
```bash
sudo cp deploy/systemd/pisat-cfs.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now pisat-cfs
journalctl -u pisat-cfs -f
```
The `pisat-ml` (SpaceCop ML) service is separate and depends on `pisat-cfs` — see
`spacecop_ml/README.md` for building/deploying that binary.

---

## Quick reference (native Pi build, from scratch)

```bash
sudo apt install build-essential cmake git libgpiod-dev libssl-dev linux-headers-$(uname -r)
git submodule update --init --recursive
# (set cpu1_SYSTEM in sample_defs/targets.cmake to your Pi's arch first)
make prep && make && make install && sudo make deploy-dirs
( cd apps/spacecop/kernel && make )
sudo cp deploy/systemd/pisat-cfs.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now pisat-cfs
```
