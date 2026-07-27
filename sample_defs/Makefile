#
# Core Flight Software CMake / GNU make wrapper
#
# ABOUT THIS MAKEFILE:
# It is a GNU-make wrapper that calls the CMake tools appropriately
# so that setting up a new build is fast and easy with no need to
# learn the CMake commands.  It also makes it easier to integrate
# the build with IDE tools such as Eclipse by providing a default
# makefile that has the common targets such as all/clean/etc.
#
# Use of this file is optional.
#
# This file is intended to be placed at the TOP-MOST level of the mission
# source tree, i.e. a level above "cfe".  Note this is outside the cfe
# repository which is why it cannot be delivered directly in place.
# To use it, simply copy it to the top directory.  As this just contains
# wrappers for the CMake targets, it is unlikely to change.  Projects
# are also free to customize this file and add their own targets after
# copying it to the top of the source tree.
#
# For _ALL_ targets defined in this file the build tree location may
# be specified via the "O" variable (i.e. make O=<my-build-dir> all).
# If not specified then the "build" subdirectory will be assumed.
#
# This wrapper defines the following major targets:
#  prep -- Runs CMake to create a new or re-configure an existing build tree
#    Note that multiple build trees can exist from a single source
#    Other control options (such as "SIMULATION") may be passed to CMake via
#    make variables depending on the mission build scripts.  These will be
#    cached in the build tree so they do not need to be set again thereafter.
#
#  all -- Build all targets in the CMake build tree
#
#  install -- Copy all files to the installation tree and run packaging scripts
#     The "DESTDIR" environment variable controls where the files are copied
#
#  clean -- Clean all targets in the CMake build tree, but not the build tree itself.
#
#  distclean -- Entirely remove the build directory specified by "O"
#      Note that after this the "prep" step must be run again in order to build.
#      Use caution with this as it does an rm -rf - don't set O to your home dir!
#
#  doc -- Build all doxygen source documentation.  The HTML documentation will be
#      generated under the build tree specified by "O".
#
#  usersguide -- Build all API/Cmd/Tlm doxygen documentation.  The HTML documentation
#      will be generated under the build tree specified by "O".
#
#  osalguide -- Build OSAL API doxygen documentation.  The HTML documentation will
#      be generated under the build tree specified by "O".
#
#  test -- Run all unit tests defined in the build.  Unit tests will typically only
#      be executable when building with the "SIMULATION=native" option.  Otherwise
#      it is up to the user to copy the executables to the target and run them.
#
#  lcov -- Runs the "lcov" tool on the build tree to collect all code coverage
#      analysis data and build the reports.  Code coverage data may be output by
#      the "make test" target above.
#

# Establish default values for critical variables.  Any of these may be overridden
# on the command line or via the make environment configuration in an IDE
O ?= build
ARCH ?= native/default_cpu1
BUILDTYPE ?= debug
INSTALLPREFIX ?= /exe
DESTDIR ?= $(O)

# ---------------------------------------------------------------------------
# Deploy filesystem layout (pisat)
# These MUST match SPACECOP_*_DIR in
#   apps/spacecop/platform_inc/spacecop_platform_cfg.h
# and the OS_FileSysAddFixedMap() targets in
#   psp/fsw/pc-linux/src/cfe_psp_start.c
# Populated by the "deploy-dirs" target (see below).
# ---------------------------------------------------------------------------
# (keep values free of trailing whitespace - make includes spaces before '#')
# DEPLOY_CF: read-only .so/.tbl/.ko/startup + whitelist
DEPLOY_CF   ?= /opt/pisat/cf
# DEPLOY_DATA: writable pictures
DEPLOY_DATA ?= /var/pisat/data
# DEPLOY_LOGS: writable IDS + app logs
DEPLOY_LOGS ?= /var/pisat/logs
# DEPLOY_CTI: writable threat-intel sharing
DEPLOY_CTI  ?= /var/pisat/cti
# Owner of the writable data dirs. Under "sudo make deploy-dirs" this resolves
# to the invoking user (not root) so cFS can run unprivileged where possible.
CFS_USER    ?= $(if $(SUDO_USER),$(SUDO_USER),$(shell id -un))
# Staged cf image produced by "make install" (mission-install + extras).
BUILD_CF    ?= $(O)/exe/cpu1/cf

# The "DESTDIR" variable is a bit more complicated because it should be an absolute
# path for CMake, but we want to accept either absolute or relative paths.  So if
# the path does NOT start with "/", prepend it with the current directory.
ifeq ($(filter /%, $(DESTDIR)),)
DESTDIR := $(CURDIR)/$(DESTDIR)
endif

# The "LOCALTGTS" defines the top-level targets that are implemented in this makefile
# Any other target may also be given, in that case it will simply be passed through.
LOCALTGTS := doc usersguide osalguide prep all clean install distclean test lcov deploy-dirs
OTHERTGTS := $(filter-out $(LOCALTGTS),$(MAKECMDGOALS))

# As this makefile does not build any real files, treat everything as a PHONY target
# This ensures that the rule gets executed even if a file by that name does exist
.PHONY: $(LOCALTGTS) $(OTHERTGTS)

# If the target name appears to be a directory (ends in /), do a make all in that directory
DIRTGTS := $(filter %/,$(OTHERTGTS))
ifneq ($(DIRTGTS),)
$(DIRTGTS):
	$(MAKE) -C $(O)/$(patsubst $(O)/%,%,$(@)) all
endif

# For any other goal that is not one of the known local targets, pass it to the arch build
# as there might be a target by that name.  For example, this is useful for rebuilding
# single unit test executable files while debugging from the IDE
FILETGTS := $(filter-out $(DIRTGTS),$(OTHERTGTS))
ifneq ($(FILETGTS),)
$(FILETGTS):
	$(MAKE) -C $(O)/$(ARCH) $(@)
endif

# The "prep" step requires extra options that are specified via environment variables.
# Certain special ones should be passed via cache (-D) options to CMake.
# These are only needed for the "prep" target but they are computed globally anyway.
PREP_OPTS :=

ifneq ($(CFE_EDS_ENABLED),)
PREP_OPTS += -DCFE_EDS_ENABLED=$(CFE_EDS_ENABLED)
endif

ifneq ($(INSTALLPREFIX),)
PREP_OPTS += -DCMAKE_INSTALL_PREFIX=$(INSTALLPREFIX)
endif

ifneq ($(VERBOSE),)
PREP_OPTS += --trace
endif

ifneq ($(BUILDTYPE),)
PREP_OPTS += -DCMAKE_BUILD_TYPE=$(BUILDTYPE)
endif

ifneq ($(CMAKE_PREFIX_PATH),)
PREP_OPTS += -DCMAKE_PREFIX_PATH=$(CMAKE_PREFIX_PATH)
endif

all:
	$(MAKE) --no-print-directory -C "$(O)" mission-all

install:
	$(MAKE) --no-print-directory -C "$(O)" DESTDIR="$(DESTDIR)" mission-install
	# Stage the SpaceCop extras into the built cf image so it is complete.
	# (The runtime dirs are the absolute deploy paths now - see "deploy-dirs" -
	# so the old relative build/exe/cpu1/{data,logs,cf/cti} dirs are gone.)
	cp apps/spacecop/kernel/aerospace.ko "$(BUILD_CF)"
	cp apps/spacecop/whitelists/* "$(BUILD_CF)"

# Create + populate the absolute deploy filesystem layout. Needs root for
# /opt and /var, so run:   sudo make deploy-dirs
# Requires the cf image to be staged first:   make ; make install
deploy-dirs:
	@test -d "$(BUILD_CF)" || { echo "ERROR: $(BUILD_CF) missing - run 'make && make install' first"; exit 1; }
	# --- read-only code/tables/module + config ---
	install -d -m 0755 "$(DEPLOY_CF)"
	cp -af "$(BUILD_CF)/." "$(DEPLOY_CF)/"
	chown -R root:root "$(DEPLOY_CF)"
	# --- writable data, owned by the cFS user (separate noexec mount advised) ---
	install -d -m 0750 -o "$(CFS_USER)" -g "$(CFS_USER)" "$(DEPLOY_DATA)"
	install -d -m 0750 -o "$(CFS_USER)" -g "$(CFS_USER)" "$(DEPLOY_LOGS)"
	install -d -m 0750 -o "$(CFS_USER)" -g "$(CFS_USER)" "$(DEPLOY_CTI)"
	@echo ""
	@echo ">>> Deploy dirs ready:"
	@echo ">>>   $(DEPLOY_CF)   (code - owned root:root)"
	@echo ">>>   $(DEPLOY_DATA) $(DEPLOY_LOGS) $(DEPLOY_CTI)  (data - owned $(CFS_USER))"
	@echo ">>> HARDENING (do once, in /etc/fstab or a systemd unit):"
	@echo ">>>   - mount $(DEPLOY_CF) READ-ONLY"
	@echo ">>>   - put /var/pisat on its own partition with: noexec,nosuid,nodev"

prep $(O)/.prep:
	mkdir -p "$(O)"
	(cd "$(O)" && cmake $(PREP_OPTS) "$(CURDIR)/cfe")
	echo "$(PREP_OPTS)" > "$(O)/.prep"

clean:
	$(MAKE) --no-print-directory -C "$(O)" mission-clean

distclean:
	rm -rf "$(O)"

# Grab lcov baseline before running tests
test:
	lcov --capture --initial --directory $(O)/$(ARCH) --output-file $(O)/$(ARCH)/coverage_base.info
	(cd $(O)/$(ARCH) && ctest -O ctest.log)

lcov:
	lcov --capture --rc lcov_branch_coverage=1 --directory $(O)/$(ARCH) --output-file $(O)/$(ARCH)/coverage_test.info
	lcov --rc lcov_branch_coverage=1 --add-tracefile $(O)/$(ARCH)/coverage_base.info --add-tracefile $(O)/$(ARCH)/coverage_test.info --output-file $(O)/$(ARCH)/coverage_total.info
	genhtml $(O)/$(ARCH)/coverage_total.info --branch-coverage --output-directory $(O)/$(ARCH)/lcov
	@/bin/echo -e "\n\nCoverage Report Link: file:$(CURDIR)/$(O)/$(ARCH)/lcov/index.html\n"

doc:
	$(MAKE) --no-print-directory -C "$(O)" mission-doc

usersguide:
	$(MAKE) --no-print-directory -C "$(O)" cfe-usersguide

osalguide:
	$(MAKE) --no-print-directory -C "$(O)" osal-apiguide

# Make all the commands that use the build tree depend on a flag file
# that is used to indicate the prep step has been done.  This way
# the prep step does not need to be done explicitly by the user
# as long as the default options are sufficient.
$(filter-out prep distclean,$(LOCALTGTS)): $(O)/.prep
