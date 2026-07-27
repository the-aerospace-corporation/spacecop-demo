# Toolchain for building cFS as 32-bit ARM (armhf / arm-linux-gnueabihf).
#
# WHY: this codebase stores memory addresses in 32-bit fields
# (CFE_ES_MemAddress_t = uint32, used by CS, MM, and the OpenC3 tlm defs). A
# 64-bit (aarch64) build truncates real 64-bit pointers into those fields, which
# is what crashed CS (CS_ComputeEepromMemory dereffing a truncated address).
# Building 32-bit keeps every address the code stores == an actual pointer.
#
# Unlike the stock toolchain-i686-linux-gnu.cmake (which just uses the native
# /usr/bin/gcc, so the arch silently follows the build host), this pins the
# 32-bit ARM cross compiler explicitly, so the output is deterministic no matter
# what machine you build on.
#
# BUILD HOST needs the cross compiler:
#   sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
# TARGET (if it runs a 64-bit OS) needs the armhf runtime libs to load it:
#   sudo dpkg --add-architecture armhf && sudo apt update
#   sudo apt install libc6:armhf libstdc++6:armhf
# (On a native 32-bit / armhf OS none of that is needed -- the system libs match.)

SET(CMAKE_SYSTEM_NAME           Linux)
SET(CMAKE_SYSTEM_VERSION        1)
SET(CMAKE_SYSTEM_PROCESSOR      arm)

# 32-bit ARM cross compiler. If you build natively inside a 32-bit/armhf
# environment instead, point these at the native "gcc"/"g++".
SET(CMAKE_C_COMPILER            "arm-linux-gnueabihf-gcc")
SET(CMAKE_CXX_COMPILER          "arm-linux-gnueabihf-g++")

# Configure the find commands (same policy as the stock linux toolchains)
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM   NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY   NEVER)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE   NEVER)

# cFE/OSAL abstraction layers for a hosted Linux target
SET(CFE_SYSTEM_PSPNAME      "pc-linux")
SET(OSAL_SYSTEM_OSTYPE      "posix")
