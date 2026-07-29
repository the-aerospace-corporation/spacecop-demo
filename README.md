# Pisat

This is the cFS code used to run the CubeSatSim based off of the build found here (https://github.com/alanbjohnston/CubeSatSim/tree/master)

Build the physical machine the same as the guide. Then, upload this code and build on the Raspberry Pi. This is intended to utilize all hardware modules and communicate over both RF and Wifi.

## Building

See **[BUILD.md](BUILD.md)** for the full flight-software build guide — required
packages, cloning with submodules, target architecture, and the
`prep → make → install → deploy-dirs` sequence.

Other components build separately:
- **Ground station** (OpenC3 COSMOS + Zeek) — `gsw/README.md`
- **SpaceCop ML** anomaly server (Rust) — `spacecop_ml/README.md`