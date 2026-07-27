cmake_minimum_required(VERSION 2.6.4)
project(CFS_SYSMON_APP C)

include_directories(public_inc)
include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)

aux_source_directory(src APP_SRC_FILES)

# Create the app module
add_cfe_app(sysmon ${APP_SRC_FILES})

target_include_directories(sysmon PUBLIC platform_inc)
