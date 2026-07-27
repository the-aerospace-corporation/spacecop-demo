cmake_minimum_required(VERSION 2.6.4)
project(CFS_SPACECOP_APP C)

# SpaceCop's file-integrity monitor (functions_file_integrity_linux.c) uses
# OpenSSL's EVP SHA-256 API (EVP_MD_CTX_new/free, EVP_DigestInit_ex, ...).
# cFE apps are shared modules loaded via dlopen, so an un-linked libcrypto
# symbol isn't caught at link time - it shows up at runtime as
# "undefined symbol: EVP_MD_CTX_free". Link libcrypto so the loader resolves it.
find_package(OpenSSL REQUIRED)

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

# Link libcrypto so the SHA-256 file-integrity code resolves at dlopen time.
# NOTE: use the resolved library path (OPENSSL_CRYPTO_LIBRARY) rather than the
# OpenSSL::Crypto imported target - this file's cmake_minimum_required(2.6.4)
# sets the old policy where "::" target names are passed through literally
# (which produced "cannot find -lOpenSSL::Crypto").
target_link_libraries(spacecop ${OPENSSL_CRYPTO_LIBRARY})

