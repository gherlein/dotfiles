#!/usr/bin/env bash
# gx10-healthcheck.sh
# Assert an ASUS Ascent GX10 (GB10 / DGX Spark-class) is running at full power.
#
# Checks: PD adapter / power negotiation, GPU clock throttle reasons, clock
# ceiling, driver + CUDA version, pending firmware, thermals.
#
# Notes:
#   * GB10 is NOT Jetson. There is no nvpmodel. Ignore Jetson power-mode advice.
#   * nvidia-smi reports GPU power only, not total system (wall) power, and may
#     report power.limit as N/A on GB10. The script treats that as informational.
#   * The authoritative throttle signal is "Clocks Throttle Reasons" under load,
#     plus the kernel PCIe-power message. Run with --load to make it meaningful.
#
# Exit: 0 = all PASS, 1 = at least one WARN, 2 = at least one FAIL.

set -uo pipefail

# ---- thresholds ---------------------------------------------------------------
MIN_DRIVER="580.95.05"   # 550.x + CUDA 12.4 is a known stuck-at-low-power combo
EXPECT_WATTS=240         # bundled adapter
WARN_WATTS=140           # below this == almost certainly PD safety-mode throttle
LOAD_SECS=15             # duration of optional GPU load

# ---- output helpers -----------------------------------------------------------
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
[ -t 1 ] || { RED=""; GRN=""; YEL=""; DIM=""; RST=""; }
RC=0
pass() { printf '%s[ PASS ]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s[ WARN ]%s %s\n' "$YEL" "$RST" "$1"; [ "$RC" -lt 1 ] && RC=1; }
fail() { printf '%s[ FAIL ]%s %s\n' "$RED" "$RST" "$1"; RC=2; }
info() { printf '%s[ .... ]%s %s\n' "$DIM" "$RST" "$1"; }
hdr()  { printf '\n%s== %s ==%s\n' "$DIM" "$1" "$RST"; }

# A >= B  (semantic version compare)
ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -n1)" = "$1" ]; }

DO_LOAD=0
[ "${1:-}" = "--load" ] && DO_LOAD=1

command -v nvidia-smi >/dev/null 2>&1 || { fail "nvidia-smi not found — driver not installed?"; exit 2; }

# ---- driver + CUDA ------------------------------------------------------------
hdr "Driver / CUDA"
DRV=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -n1 | tr -d ' ')
if [ -n "$DRV" ]; then
  if ver_ge "$DRV" "$MIN_DRIVER"; then
    pass "driver $DRV (>= $MIN_DRIVER)"
  else
    fail "driver $DRV is below $MIN_DRIVER — known stuck-at-low-power on GB10. Upgrade driver + CUDA 13.0+."
  fi
else
  warn "could not read driver version"
fi
CUDA=$(nvidia-smi 2>/dev/null | sed -n 's/.*CUDA Version: \([0-9.]*\).*/\1/p' | head -n1)
[ -n "$CUDA" ] && info "CUDA runtime visible to driver: $CUDA"

# ---- GPU identity -------------------------------------------------------------
hdr "GPU"
NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1)
info "${NAME:-unknown}"
case "$NAME" in
  *GB10*|*Spark*|*Blackwell*) : ;;
  "" ) warn "could not identify GPU" ;;
  * ) info "name does not contain GB10 — verify this is actually a GX10/Spark" ;;
esac

# ---- power negotiation (PD) ---------------------------------------------------
hdr "Power delivery"
# 1) Kernel is the most reliable signal across firmware revisions.
PWRLOG=$(dmesg 2>/dev/null | grep -iE 'insufficient power|PCIe slot|safety mode|PD .*contract|tcpm' | tail -n 8)
if [ -z "$PWRLOG" ] && ! dmesg >/dev/null 2>&1; then
  info "dmesg unreadable without root — re-run with sudo for the PCIe-power check"
elif echo "$PWRLOG" | grep -qiE 'insufficient power|safety mode'; then
  fail "kernel reports insufficient PCIe power / safety mode:"
  echo "$PWRLOG" | sed 's/^/         /'
elif [ -n "$PWRLOG" ]; then
  info "recent power-related kernel lines:"
  echo "$PWRLOG" | sed 's/^/         /'
else
  pass "no insufficient-power / safety-mode messages in dmesg"
fi

# 2) Best-effort negotiated wattage from USB-C PD / power_supply sysfs.
NEG_W=""
for ps in /sys/class/power_supply/*; do
  [ -d "$ps" ] || continue
  v=$(cat "$ps/voltage_now" 2>/dev/null || echo "")
  c=$(cat "$ps/current_now" 2>/dev/null || echo "")
  if [ -n "$v" ] && [ -n "$c" ] && [ "$v" != "0" ] && [ "$c" != "0" ]; then
    NEG_W=$(( v / 1000000 * c / 1000000 ))   # uV * uA -> W
    [ "$NEG_W" -gt 0 ] && break
  fi
done
# typec partner advertised source PDOs (max available, not necessarily negotiated)
PDO_MAX=""
for f in /sys/class/typec/*-partner/usb_power_delivery/*/source-capabilities/*/maximum_voltage \
         /sys/class/typec/*-partner/usb_power_delivery/*/source-capabilities/*/operational_current; do
  :  # presence probe only; parsing PDOs is firmware-specific, left as a hint below
done

if [ -n "$NEG_W" ] && [ "$NEG_W" -gt 0 ]; then
  if [ "$NEG_W" -ge "$EXPECT_WATTS" ]; then
    pass "negotiated input ~${NEG_W}W (>= ${EXPECT_WATTS}W expected)"
  elif [ "$NEG_W" -ge "$WARN_WATTS" ]; then
    warn "negotiated input ~${NEG_W}W (< ${EXPECT_WATTS}W) — verify the bundled 240W adapter in the PD-in port"
  else
    fail "negotiated input ~${NEG_W}W — PD safety-mode territory. Wrong charger or PD wedge."
  fi
else
  info "could not read negotiated wattage from sysfs (firmware-dependent). Confirm manually:"
  info "  - bundled 240W adapter, into the dedicated PD-in Type-C port (not a peripheral port/dock)"
  info "  - check: ls /sys/class/typec/ ; ls /sys/class/power_supply/"
fi

# ---- clocks + throttle reasons ------------------------------------------------
hdr "Clocks / throttle"
load_pid=""
if [ "$DO_LOAD" = 1 ]; then
  if python3 -c 'import torch' >/dev/null 2>&1; then
    info "running ~${LOAD_SECS}s GPU load to surface throttle reasons..."
    python3 - "$LOAD_SECS" >/dev/null 2>&1 <<'PY' &
import sys, time, torch
end = time.time() + int(sys.argv[1])
d = "cuda" if torch.cuda.is_available() else "cpu"
a = torch.randn(8192, 8192, device=d)
while time.time() < end:
    a = a @ a
    a /= a.norm()
torch.cuda.synchronize() if d == "cuda" else None
PY
    load_pid=$!
    sleep 3   # let it ramp
  else
    warn "--load requested but python3+torch unavailable; readings are idle-only"
  fi
fi

THR=$(nvidia-smi -q -d PERFORMANCE 2>/dev/null | sed -n '/Clocks Throttle Reasons/,/^$/p')
ACTIVE=$(echo "$THR" | grep -iE ': Active' | grep -ivE 'GpuIdle' || true)
if [ -z "$THR" ]; then
  info "throttle reasons not exposed on this unit (common on GB10)"
elif [ -n "$ACTIVE" ]; then
  if [ "$DO_LOAD" = 1 ]; then
    warn "active throttle reason(s) under load:"
    echo "$ACTIVE" | sed 's/^/         /'
  else
    info "active throttle reason(s) at idle (expected — re-run with --load):"
    echo "$ACTIVE" | sed 's/^/         /'
  fi
else
  pass "no active throttle reasons (HW slowdown / power / thermal all clear)"
fi

CUR=$(nvidia-smi --query-gpu=clocks.sm --format=csv,noheader,nounits 2>/dev/null | head -n1 | tr -d ' ')
MAX=$(nvidia-smi --query-gpu=clocks.max.sm --format=csv,noheader,nounits 2>/dev/null | head -n1 | tr -d ' ')
if [ -n "$CUR" ] && [ -n "$MAX" ] && [ "$MAX" != "0" ] && echo "$MAX" | grep -qE '^[0-9]+$'; then
  PCT=$(( CUR * 100 / MAX ))
  if [ "$DO_LOAD" = 1 ]; then
    if [ "$PCT" -ge 90 ]; then pass "SM clock ${CUR}/${MAX} MHz (${PCT}% of ceiling under load)"
    elif [ "$PCT" -ge 60 ]; then warn "SM clock ${CUR}/${MAX} MHz (${PCT}%) — below ceiling under load"
    else fail "SM clock ${CUR}/${MAX} MHz (${PCT}%) — heavily capped (PD wedge signature is ~611MHz)"; fi
  else
    info "SM clock ${CUR}/${MAX} MHz (${PCT}%) at idle — low is normal; use --load"
  fi
else
  info "SM clock query returned N/A (common on GB10); rely on throttle reasons + dmesg"
fi

[ -n "$load_pid" ] && { wait "$load_pid" 2>/dev/null; }

# ---- power draw (informational) ----------------------------------------------
hdr "Power draw (GPU only — not wall power)"
PD=$(nvidia-smi --query-gpu=power.draw,power.limit --format=csv,noheader 2>/dev/null | head -n1)
if echo "$PD" | grep -qiE '[0-9]'; then
  info "$PD  ${DIM}(reminder: this excludes CPU/system; ~100W here can still be full power)${RST}"
else
  info "power.draw/limit = N/A on this unit (expected on GB10)"
fi

# ---- thermals -----------------------------------------------------------------
hdr "Thermals"
T=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | head -n1 | tr -d ' ')
if echo "$T" | grep -qE '^[0-9]+$'; then
  if [ "$T" -lt 85 ]; then pass "GPU temp ${T}C"
  else warn "GPU temp ${T}C — check airflow / sustained-load cooling"; fi
else
  info "GPU temp = N/A; check /sys/class/thermal/thermal_zone*/temp"
fi

# ---- firmware -----------------------------------------------------------------
hdr "Firmware"
if command -v fwupdmgr >/dev/null 2>&1; then
  if fwupdmgr get-updates 2>/dev/null | grep -qiE 'upgrade|update available'; then
    warn "pending firmware updates (stale EC/PD firmware can pin a 30W safety lock):"
    fwupdmgr get-updates 2>/dev/null | sed 's/^/         /'
  else
    pass "no pending firmware updates reported by fwupdmgr"
  fi
else
  info "fwupdmgr not found — verify EC/PD/SoC/UEFI firmware manually"
fi

# ---- verdict ------------------------------------------------------------------
hdr "Result"
case "$RC" in
  0) printf '%sAll checks passed — running at full power.%s\n' "$GRN" "$RST" ;;
  1) printf '%sPassed with warnings — review WARN lines above.%s\n' "$YEL" "$RST" ;;
  2) printf '%sFAIL — not at full power. Triage: 240W adapter in PD-in port -> dmesg -> firmware -> driver -> cold drain.%s\n' "$RED" "$RST" ;;
esac
exit "$RC"
