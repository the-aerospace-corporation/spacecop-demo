##################################################################
#
# Coverage Unit Test build recipe
#
# This CMake file contains the recipe for building the sysmon unit tests.
# It is invoked from the parent directory when unit tests are enabled.
#
##################################################################

#
#
# NOTE on the subdirectory structures here:
#
# - "inc" provides local header files shared between the coveragetest,
#    wrappers, and overrides source code units
# - "coveragetest" contains source code for the actual unit test cases
#    The primary objective is to get line/path coverage on the FSW 
#    code units.
#
 
# Use the UT assert public API, and allow direct
# inclusion of source files that are normally private
include_directories(${PROJECT_SOURCE_DIR}/fsw/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc)
include_directories(${hwlib_MISSION_DIR}/fsw/public_inc)


# Add a coverage test executable called "sysmon-ALL" that 
# covers all of the functions in sysmon_app.  
#
# Also note in a more complex app/lib the coverage test can also
# be broken down into smaller units (in which case one should use
# a unique suffix other than "ALL" for each unit).  For example,
# OSAL implements a separate coverage test per source unit.
add_cfe_coverage_test(sysmon ALL 
    "coveragetest/coveragetest_sysmon_app.c"
    "../src/sysmon_app.c"
    "../../shared/sysmon_device.c"
    "../../../../../fsw/apps/hwlib/fsw/stubs/libuart.c"
)

# The sysmon uses library functions provided by sysmon_lib so must be linked
# with the sysmon_lib stub library (this is mainly just an example of how this 
# can be done).
#add_cfe_coverage_dependency(sysmon ALL sysmon_lib)

