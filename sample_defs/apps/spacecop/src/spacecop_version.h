// Copyright © 2026 Aerospace Corporation
// SPDX-License-Identifier: LGPL-3.0-or-later

/**
 * @file spacecop_app_version.h
 * @brief SpaceCop application version identification
 *
 * This header defines the version number for the SpaceCop Intrusion Detection
 * System application. Version information is used for:
 * - Software configuration management
 * - Compatibility verification
 * - Telemetry reporting
 * - Ground system displays
 * - Mission planning and operations
 *
 * **Version Numbering Scheme:**
 * SpaceCop follows semantic versioning: MAJOR.MINOR.REVISION.MISSION_REV
 *
 * - **MAJOR:** Incremented for incompatible API changes or major architecture updates
 * - **MINOR:** Incremented for backward-compatible functionality additions
 * - **REVISION:** Incremented for backward-compatible bug fixes
 * - **MISSION_REV:** Mission-specific patches and customizations
 *
 * **Version Format:**
 * @code
 * Version String: "MAJOR.MINOR.REVISION.MISSION_REV"
 * Example: "1.0.0.0" (Initial release)
 *          "1.2.3.5" (Version 1.2.3 with 5 mission-specific patches)
 * @endcode
 *
 * **When to Increment:**
 *
 * - **MAJOR version:**
 *   - Breaking changes to rule table format
 *   - Incompatible changes to configuration interfaces
 *   - Major detection engine redesign
 *   - Changes requiring ground system updates
 *   - Non-backward-compatible protocol changes
 *
 * - **MINOR version:**
 *   - New detection rules added
 *   - New STIX components added
 *   - New monitoring capabilities
 *   - New configuration options (backward-compatible)
 *   - Enhanced telemetry (backward-compatible)
 *
 * - **REVISION:**
 *   - Bug fixes in detection logic
 *   - Performance improvements
 *   - Documentation updates
 *   - Code refactoring (no functional changes)
 *   - Memory leak fixes
 *
 * - **MISSION_REV:**
 *   - Mission-specific customizations
 *   - Temporary patches
 *   - Site-specific configurations
 *   - Hotfixes for specific deployments
 *
 * **Usage in Code:**
 * @code
 * // Build version string
 * char version_str[32];
 * snprintf(version_str, sizeof(version_str), "%d.%d.%d.%d",
 *          SPACECOP_MAJOR_VERSION,
 *          SPACECOP_MINOR_VERSION,
 *          SPACECOP_REVISION,
 *          SPACECOP_MISSION_REV);
 * 
 * // Include in telemetry
 * SPACECOP_HkTelemetryPkt.MajorVersion = SPACECOP_MAJOR_VERSION;
 * SPACECOP_HkTelemetryPkt.MinorVersion = SPACECOP_MINOR_VERSION;
 * SPACECOP_HkTelemetryPkt.Revision = SPACECOP_REVISION;
 * SPACECOP_HkTelemetryPkt.MissionRev = SPACECOP_MISSION_REV;
 * 
 * // Log at startup
 * CFE_EVS_SendEvent(SPACECOP_INIT_INF_EID, CFE_EVS_INFORMATION,
 *                   "SpaceCop IDS initialized - Version %s", version_str);
 * 
 * // Version compatibility check
 * if (table_major_version != SPACECOP_MAJOR_VERSION) {
 *     CFE_EVS_SendEvent(SPACECOP_TABLE_ERR_EID, CFE_EVS_ERROR,
 *                      "Rule table version %d incompatible with app version %d",
 *                      table_major_version, SPACECOP_MAJOR_VERSION);
 *     return CFE_TBL_ERR_INVALID_SIZE;
 * }
 * @endcode
 *
 * **Version History:**
 * - **1.0.0.0** - Initial public release
 *   - Core detection engine
 *   - STIX component system
 *   - Command monitoring
 *   - Rule table framework
 *   - Basic ML integration
 *
 * **Ground System Integration:**
 * Version information should be:
 * - Displayed in ground system UI
 * - Logged in telemetry databases
 * - Included in anomaly reports
 * - Tracked in configuration management
 * - Verified during software uploads
 *
 * **Table Compatibility:**
 * Rule tables and configuration tables should include version fields
 * that are checked against these application version numbers to ensure
 * compatibility:
 * @code
 * typedef struct {
 *     uint16_t TableFormatVersion;  // Must match MAJOR
 *     uint16_t MinAppVersion;       // Minimum compatible app version
 *     // ... table data ...
 * } RuleTable;
 * @endcode
 *
 * @note Update these values in version control before each release
 * @note Version must be updated in coordination with release notes
 * @note Mission-specific branches should increment MISSION_REV
 *
 * @see SPACECOP_HkTelemetryPkt for version telemetry reporting
 */

#ifndef _SPACECOP_VERSION_H_
#define _SPACECOP_VERSION_H_

/*=======================================================================================
** Version Definitions
**=======================================================================================*/

/**
 * @brief Major version number
 * 
 * Indicates incompatible API changes or major architectural updates.
 * Increment when making changes that break backward compatibility.
 * 
 * **Current Value:** 1 (Initial release)
 * 
 * **Increment for:**
 * - Breaking changes to rule table format
 * - Incompatible configuration changes
 * - Major detection engine redesign
 * - Protocol changes requiring ground system updates
 * 
 * @note Reset MINOR and REVISION to 0 when incrementing MAJOR
 */
#define SPACECOP_MAJOR_VERSION    1

/**
 * @brief Minor version number
 * 
 * Indicates backward-compatible functionality additions.
 * Increment when adding new features that don't break existing functionality.
 * 
 * **Current Value:** 0 (Initial release - no feature additions yet)
 * 
 * **Increment for:**
 * - New detection rules
 * - New STIX components
 * - New monitoring capabilities
 * - Backward-compatible enhancements
 * 
 * @note Reset REVISION to 0 when incrementing MINOR
 */
#define SPACECOP_MINOR_VERSION    0

/**
 * @brief Revision number (patch level)
 * 
 * Indicates backward-compatible bug fixes and minor improvements.
 * Increment for patches that don't add new features.
 * 
 * **Current Value:** 0 (Initial release - no patches yet)
 * 
 * **Increment for:**
 * - Bug fixes
 * - Performance improvements
 * - Documentation updates
 * - Code cleanup and refactoring
 * 
 * @note Frequently incremented during maintenance phase
 */
#define SPACECOP_REVISION         1

/**
 * @brief Mission-specific revision number
 * 
 * Indicates mission-specific customizations and patches applied to
 * the baseline SpaceCop application. Used to track deployment-specific
 * modifications.
 * 
 * **Current Value:** 0 (Baseline - no mission-specific changes)
 * 
 * **Increment for:**
 * - Mission-specific rule customizations
 * - Site-specific configurations
 * - Temporary hotfixes
 * - Deployment-specific patches
 * 
 * **Usage:**
 * Different missions or deployments may have different MISSION_REV values
 * while using the same baseline version:
 * - Mission A: 1.0.0.3 (baseline 1.0.0 + 3 mission patches)
 * - Mission B: 1.0.0.7 (baseline 1.0.0 + 7 mission patches)
 * 
 * @note Reset to 0 when merging mission changes back to baseline
 * @note Track mission-specific changes in separate documentation
 */
#define SPACECOP_MISSION_REV      0

#endif /* _SPACECOP_VERSION_H_ */