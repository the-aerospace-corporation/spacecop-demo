project(CFS_HW_LIB C)

# GPIO helper library (libgpiod v2) -- owns /dev/gpiochip0 for the CubeSatSim
# board. Loaded as a CFE_LIB (see cpu1_cfe_es_startup.scr); other apps call
# its API (HW_LIB_SetLine / HW_LIB_GetLine / ...).
add_cfe_app(hw_lib fsw/src/hw_lib.c)

# The public API for other apps (radio, sensor, health) lives in public_inc.
target_include_directories(hw_lib PUBLIC fsw/public_inc)

# Link the system libgpiod v2 (Debian package: libgpiod-dev, provided by
# CubeSatSim/trixie-cfs/setup-trixie-hardware.sh on the Pi target). find_library
# gives a clearer error if the dev package (or cross sysroot copy) is missing.
find_library(GPIOD_LIBRARY NAMES gpiod)
if(GPIOD_LIBRARY)
  target_link_libraries(hw_lib ${GPIOD_LIBRARY})
else()
  message(WARNING
    "hw_lib: libgpiod not found. Install libgpiod-dev on the build host / "
    "target sysroot, or hw_lib will fail to link.")
  target_link_libraries(hw_lib gpiod)
endif()
