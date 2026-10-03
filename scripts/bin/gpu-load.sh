#!/usr/bin/env bash
#
# gpu-load.sh - show live GPU load, auto-detecting AMD (ROCm/amdgpu) or NVIDIA.
#
# AMD load is read straight from the amdgpu sysfs interface (gpu_busy_percent,
# mem_info_*), so it works without rocm-smi on PATH and reports the unified
# memory (GTT) that APUs such as Strix Halo actually use. NVIDIA load comes
# from nvidia-smi.
#
# Usage:
#   gpu-load.sh          one-shot snapshot
#   gpu-load.sh -w [N]   refresh every N seconds (default 2) until Ctrl-C
#   gpu-load.sh -h       help

set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

header() { echo -e "\n${CYAN}${BOLD}=== $1 ===${RESET}"; }
field()  { printf "  ${BOLD}%-20s${RESET} %s\n" "$1" "$2"; }

usage() {
    sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

WATCH=0
INTERVAL=2
while [[ $# -gt 0 ]]; do
    case "$1" in
        -w|--watch) WATCH=1; [[ "${2:-}" =~ ^[0-9]+$ ]] && { INTERVAL="$2"; shift; } ;;
        -h|--help)  usage 0 ;;
        *)          echo "unknown argument: $1" >&2; usage 1 ;;
    esac
    shift
done

# Detect the accelerator via PATH-independent sysfs/dev markers (sudo-safe).
detect_vendor() {
    if [[ -e /proc/driver/nvidia/version ]] || command -v nvidia-smi >/dev/null 2>&1; then
        echo "nvidia"
    elif [[ -d /sys/module/amdgpu ]]; then
        echo "amd"
    else
        echo "none"
    fi
}

# milli-units -> whole units with one decimal, or "n/a" when the file is absent.
read_scaled() {
    local file="$1" divisor="$2" suffix="$3"
    [[ -r "$file" ]] || { echo "n/a"; return; }
    awk -v d="$divisor" -v s="$suffix" '{printf "%.1f%s", $1/d, s}' "$file"
}

# bytes -> GiB
read_gib() {
    local file="$1"
    [[ -r "$file" ]] || { echo "n/a"; return; }
    awk '{printf "%.1f GiB", $1/1073741824}' "$file"
}

show_nvidia() {
    header "NVIDIA GPU load"
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        echo -e "  ${YELLOW}NVIDIA driver present but nvidia-smi not found${RESET}"
        return
    fi
    field "Driver:" "$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)"
    while IFS=',' read -r idx name util mem_used mem_total temp power_draw power_limit; do
        echo
        echo -e "  ${GREEN}${BOLD}GPU$(echo "$idx" | xargs): $(echo "$name" | xargs)${RESET}"
        field "  Utilization:" "$(echo "$util" | xargs)"
        field "  Memory:" "$(echo "$mem_used" | xargs) / $(echo "$mem_total" | xargs)"
        field "  Temperature:" "$(echo "$temp" | xargs) C"
        field "  Power:" "$(echo "$power_draw" | xargs) / $(echo "$power_limit" | xargs) W"
    done < <(nvidia-smi \
        --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit \
        --format=csv,noheader,nounits 2>/dev/null)
}

show_amd() {
    header "AMD GPU load"

    # Marketing name is nice-to-have; skip silently if rocminfo is unavailable.
    local rocminfo_bin name=""
    rocminfo_bin="$(command -v rocminfo 2>/dev/null || true)"
    [[ -z "$rocminfo_bin" && -x /opt/rocm/bin/rocminfo ]] && rocminfo_bin="/opt/rocm/bin/rocminfo"
    # awk must not exit early here: closing the pipe would SIGPIPE rocminfo,
    # which under pipefail aborts the script. Consume all input, keep first hit.
    [[ -n "$rocminfo_bin" ]] && name="$("$rocminfo_bin" 2>/dev/null | awk -F: '/Marketing Name/ && !seen {gsub(/^[ \t]+/,"",$2); print $2; seen=1}')" || true

    local found=0 dev
    for dev in /sys/class/drm/card*/device; do
        [[ -r "$dev/gpu_busy_percent" ]] || continue   # only real GPUs expose this
        found=1
        local hwmon temp="n/a" power="n/a"
        hwmon=$(echo "$dev"/hwmon/hwmon* 2>/dev/null | awk '{print $1}')
        if [[ -d "$hwmon" ]]; then
            temp="$(read_scaled "$hwmon/temp1_input" 1000 " C")"
            power="$(read_scaled "$hwmon/power1_average" 1000000 " W")"
        fi

        echo
        echo -e "  ${GREEN}${BOLD}$(basename "$(dirname "$dev")"): ${name:-AMD GPU}${RESET}"
        field "  Utilization:" "$(cat "$dev/gpu_busy_percent" 2>/dev/null || echo n/a)%"
        field "  VRAM (dedicated):" "$(read_gib "$dev/mem_info_vram_used") / $(read_gib "$dev/mem_info_vram_total")"
        field "  GTT (shared):" "$(read_gib "$dev/mem_info_gtt_used") / $(read_gib "$dev/mem_info_gtt_total")"
        field "  Temperature:" "$temp"
        field "  Power:" "$power"
    done

    [[ "$found" -eq 1 ]] || echo -e "  ${YELLOW}amdgpu loaded but no GPU exposes gpu_busy_percent${RESET}"
}

render() {
    local vendor
    vendor="$(detect_vendor)"
    echo -e "${BOLD}GPU load${RESET}  ($(date '+%H:%M:%S'))  vendor: $vendor"
    case "$vendor" in
        nvidia) show_nvidia ;;
        amd)    show_amd ;;
        *)      echo -e "\n  ${YELLOW}No NVIDIA or AMD GPU detected${RESET}" ;;
    esac
}

if [[ "$WATCH" -eq 1 ]]; then
    while true; do
        clear
        render
        echo -e "\n${BOLD}refresh ${INTERVAL}s - Ctrl-C to stop${RESET}"
        sleep "$INTERVAL"
    done
else
    render
    echo
fi
