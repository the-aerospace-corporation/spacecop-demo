# =====================================================================
# PISAT - "Day in the Life" nominal operations (OpenC3 COSMOS, Python)
#
# Simulates normal, anomaly-free operations for the pisat imaging mission:
#   * Enables telemetry downlink (TO_LAB)
#   * Takes pictures on a relaxed cadence - never more than ~1 per few minutes
#   * CFDP-downlinks captured images to the ground every so often
#   * Polls housekeeping from the flight apps on a steady cadence
#   * Runs routine, read-only fleet checks (FM storage, CS integrity)
#   * Performs light storage housekeeping (deletes an old image now and then)
#
# It deliberately AVOIDS anything SpaceCop would treat as suspicious - no
# time-set, no app start/stop, no memory pokes, no rapid-fire commanding - so
# the resulting cmd/tlm stream is a clean nominal baseline. Doubles as
# "normal behavior" training data for the SpaceCop ML models.
#
# Run from Script Runner. Adjust the tunables below to taste.
# =====================================================================

import random

# ----------------------------- Tunables -----------------------------
#DEST_IP            = "cosmos"  # host TO_LAB downlinks telemetry to (ground station)
NUM_PASSES         = 16        # imaging passes to run (16 ~= a day of ~90-min orbits)
PIC_MIN_GAP_SEC    = 180       # hard floor between pictures (>= a few minutes)
PIC_MAX_GAP_SEC    = 300       # upper bound of the randomized inter-picture wait
HK_PERIOD_SEC      = 30        # housekeeping poll cadence while idling
DOWNLINK_EVERY_N   = 3         # CFDP-downlink the latest image every N pictures
DELETE_EVERY_N     = 5         # tidy storage: delete an old image every N pictures
MAINT_EVERY_PASSES = 4         # FM/CS routine-check cadence (in passes)
CHECK_TIMEOUT      = 15        # seconds to wait for a telemetry check to pass
REAL_DATA_PATH     = '/var/pisat/data'
REAL_LOG_PATH      = '/var/pisat/logs'


def hk_sweep():
    """Poll housekeeping from each flight app - routine health checks."""
    cmd("CAMERA CAMERA_REQUEST_HK_CC")
    cmd("EPS EPS_REQUEST_HK_CC")
    cmd("SYSMON SYSMON_REQUEST_HK_CC")
    cmd("STPYLD STPYLD_REQUEST_HK_CC")
    cmd("SPACECOP SPACECOP_REQUEST_HK_CC")


def idle_with_hk(seconds):
    """Idle for `seconds`, sweeping housekeeping every HK_PERIOD_SEC."""
    elapsed = 0
    while elapsed < seconds:
        step = min(HK_PERIOD_SEC, seconds - elapsed)
        wait(step)
        hk_sweep()
        elapsed += step


def downlink_last_image(seq):
    """CFDP-downlink the most recently captured image. Source must be in /data/."""
    src = str(tlm("CAMERA CAMERA_HK_TLM LastImagePath")).strip()
    src = src.replace(REAL_DATA_PATH, '/data')
    if not src or not src.startswith("/data"):
        print(f"[DITL] Skipping CFDP downlink - LastImagePath '{src}' not in /data/")
        return
    dest = f"pisat_img_{seq:04d}_" + src.split("/")[-1]
    print(f"[DITL] CFDP downlink: {src} -> ground:{dest}")
    cmd(f'CFDP DOWNLOAD_FROM_SATELLITE_CC with SOURCE "{src}", DESTINATION "{dest}"')


def routine_checks():
    """Read-only fleet checks an operator runs periodically (all nominal)."""
    cmd("FM FM_GET_FREE_SPACE")        # storage headroom -> FM_FREESPACEPKT
    cmd("FM FM_GET_OPEN_FILES")        # what's currently open
    cmd("CS CS_REPORT_BASELINE_OS")    # background integrity reports (pre-computed)
    cmd("CS CS_REPORT_BASELINE_CFECORE")
    cmd("SPACECOP SPACECOP_REQUEST_IDS_CC")  # operator checks IDS status

def download_last_stix(seq):
    cmd(f'CFDP DOWNLOAD_FROM_SATELLITE_CC with SOURCE "/logs/stix_log_{seq:04d}.json", DESTINATION "stix_log.json"')


# ----------------------------- Setup --------------------------------
print("[DITL] Starting pisat day-in-the-life (nominal ops)")

# Bring the telemetry downlink online
#cmd(f'CFS TO_DEBUG_ENABLE_OUTPUT_CC with DEST_IP "{DEST_IP}"')
#wait(3)

# Confirm apps are alive, enable background integrity checking, baseline sweep
cmd("CAMERA NOOP")
cmd("SPACECOP SPACECOP_NOOP_CC")
cmd("CS CS_ENABLE_ALL_CS")             # let CS run its background checksums
cmd("FM FM_GET_FREE_SPACE")            # baseline storage reading
hk_sweep()
wait(3)

# Informational: is the camera reporting available? (don't hard-fail if not)
avail = int(tlm("CAMERA CAMERA_HK_TLM CameraAvailable"))
if avail != 1:
    print(f"[DITL] WARNING: CameraAvailable={avail} (expected 1) - proceeding anyway")

# ----------------------------- Main loop ----------------------------
pics_taken = 0
for p in range(1, NUM_PASSES + 1):
    # Relaxed, jittered wait so images are always spaced out
    gap = random.randint(PIC_MIN_GAP_SEC, PIC_MAX_GAP_SEC)
    print(f"[DITL] Pass {p}/{NUM_PASSES}: idling {gap}s (HK every {HK_PERIOD_SEC}s)")
    idle_with_hk(gap)

    # Snapshot image count, take the picture, verify it incremented
    before = int(tlm("CAMERA CAMERA_HK_TLM ImageCounter"))
    print(f"[DITL] Pass {p}: taking picture (expecting image #{before + 1})")
    cmd("CAMERA TAKE_PIC")
    wait(3)                            # let the capture complete on the Pi
    cmd("CAMERA CAMERA_REQUEST_HK_CC")
    wait_check(f"CAMERA CAMERA_HK_TLM ImageCounter >= {before + 1}", CHECK_TIMEOUT)
    pics_taken += 1

    # Downlink the freshly captured image every few pictures (before any cleanup)
    if pics_taken % DOWNLINK_EVERY_N == 0:
        downlink_last_image(pics_taken)

    # Light storage housekeeping every few pictures (after it's been downlinked)
    if pics_taken % DELETE_EVERY_N == 0:
        print("[DITL] Storage housekeeping: deleting last image")
        cmd("CAMERA DELETE_LAST")
        cmd("CAMERA CAMERA_REQUEST_HK_CC")

    # Periodic read-only fleet checks
    if p % MAINT_EVERY_PASSES == 0:
        print("[DITL] Routine fleet checks (FM storage, CS integrity, IDS status)")
        routine_checks()
        download_last_stix(p)

print(f"[DITL] Complete: {pics_taken} pictures over {NUM_PASSES} passes")
