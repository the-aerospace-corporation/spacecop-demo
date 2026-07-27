cmake_minimum_required(VERSION 2.6.4)
project(CFS_SCH C)

include_directories(fsw/public_inc)
include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)
include_directories(fsw/src)

aux_source_directory(fsw/src APP_SRC_FILES)
aux_source_directory(fsw/tables APP_TABLE_FILES)

foreach(EXT_APP ci_lab cs ds eps fm hk hs lc md mm sc sch spacecop stpyld sysmon camera)
  list (FIND TGTSYS_${SYSVAR}_APPS ${EXT_APP} HAVE_APP)
  if (HAVE_APP GREATER_EQUAL 0)
    include_directories($<TARGET_PROPERTY:${EXT_APP},INTERFACE_INCLUDE_DIRECTORIES>)
    string(TOUPPER "HAVE_${EXT_APP}" APP_MACRO)
    add_definitions(-D${APP_MACRO})
  endif()
endforeach()

# Create the app module
add_cfe_app(sch ${APP_SRC_FILES})
add_cfe_tables(sch ${APP_TABLE_FILES})

target_include_directories(sch PUBLIC fsw/platform_inc)
