cmake_minimum_required(VERSION 2.6.4)
project(CFS_SPACECOP_APP C)

# SpaceCop's file-integrity monitor (functions_file_integrity_linux.c) uses
# OpenSSL's EVP SHA-256 API (EVP_MD_CTX_new/free, EVP_DigestInit_ex, ...).
# cFE apps are shared modules loaded via dlopen, so an un-linked libcrypto
# symbol isn't caught at link time - it shows up at runtime as
# "undefined symbol: EVP_MD_CTX_free". libcrypto is linked by name at the bottom.

include_directories(public_inc)
include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)

include_directories(${MISSION_BINARY_DIR}/inc)

foreach(EXT_APP
    camera cfdp ci_lab cs ds eps fm hk hs lc md mm sc sch stpyld sysmon to_lab)
  list(FIND TGTSYS_${SYSVAR}_APPS ${EXT_APP} HAVE_APP)
  if(HAVE_APP GREATER_EQUAL 0)
    include_directories($<TARGET_PROPERTY:${EXT_APP},INTERFACE_INCLUDE_DIRECTORIES>)
    string(TOUPPER "HAVE_${EXT_APP}" APP_MACRO)
    add_definitions(-D${APP_MACRO})
  endif()
endforeach()

include_directories(../to_lab/fsw/inc)

aux_source_directory(src APP_SRC_FILES)

aux_source_directory(table APP_TABLE_FILES)

add_cfe_tables(spacecop ${APP_TABLE_FILES})

# Create the app module
add_cfe_app(spacecop ${APP_SRC_FILES})

target_include_directories(spacecop PUBLIC platform_inc)

# Link libcrypto (SHA-256) BY NAME so the LINKER resolves it from its own arch
# search path -- the armhf multiarch dir on a 32-bit cross-build, the host dir on
# a native build. Using find_package(OpenSSL)'s absolute OPENSSL_CRYPTO_LIBRARY
# instead baked in the HOST's 64-bit path and broke the 32-bit cross-link
# ("/usr/lib/aarch64-linux-gnu/libcrypto.so: file format not recognized").
# "crypto" -> -lcrypto, the same arch-agnostic pattern hw_lib uses for -lgpiod.
# (OpenSSL::Crypto can't be used here: cmake_minimum_required(2.6.4) passes "::"
# target names through literally -> "cannot find -lOpenSSL::Crypto".)
target_link_libraries(spacecop crypto)

