cmake_minimum_required(VERSION 2.6.4)
project(CFS_EPS_APP C)

include_directories(public_inc)
include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)

aux_source_directory(src APP_SRC_FILES)

# Create the app module
add_cfe_app(eps ${APP_SRC_FILES})

target_include_directories(eps PUBLIC platform_inc)
