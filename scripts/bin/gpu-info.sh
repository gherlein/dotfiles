#!/usr/bin/env bash
set -euo pipefail

# Colors
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

header() { echo -e "\n${CYAN}${BOLD}=== $1 ===${RESET}"; }
field() { printf "  ${BOLD}%-28s${RESET} %s\n" "$1" "$2"; }

echo -e "${BOLD}GPU & System Compatibility Summary${RESET}"
echo -e "Generated: $(date)"

# ── OS ────────────────────────────────────────────────────────────────────────
header "Operating System"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    field "Distro:" "${PRETTY_NAME:-unknown}"
fi
field "Kernel:" "$(uname -r)"
field "Architecture:" "$(uname -m)"

# ── CPU ───────────────────────────────────────────────────────────────────────
header "CPU"
cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo "unknown")
cpu_cores=$(nproc 2>/dev/null || echo "?")
cpu_threads=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?")
field "Model:" "$cpu_model"
field "Physical cores:" "$cpu_cores"
field "Threads:" "$cpu_threads"

# ── RAM ───────────────────────────────────────────────────────────────────────
header "System Memory"
total_ram=$(awk '/MemTotal/ {printf "%.1f GB", $2/1024/1024}' /proc/meminfo)
avail_ram=$(awk '/MemAvailable/ {printf "%.1f GB", $2/1024/1024}' /proc/meminfo)
field "Total RAM:" "$total_ram"
field "Available RAM:" "$avail_ram"

# ── GPU ───────────────────────────────────────────────────────────────────────
header "GPU(s)"
if ! command -v nvidia-smi &>/dev/null; then
    echo -e "  ${YELLOW}nvidia-smi not found — no NVIDIA GPU or driver not installed${RESET}"
else
    gpu_count=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l)
    field "GPU count:" "$gpu_count"

    # Driver and CUDA version from nvidia-smi header
    driver_ver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
    cuda_driver=$(nvidia-smi --query-gpu=cuda_version --format=csv,noheader 2>/dev/null | head -1 \
                  || nvidia-smi 2>/dev/null | grep -oP 'CUDA Version: \K[0-9.]+' | head -1)
    field "Driver version:" "$driver_ver"
    field "Max CUDA (driver):" "${cuda_driver:-unknown}"

    # Per-GPU details
    while IFS=',' read -r idx name vram_total vram_free compute_cap util temp power_draw power_limit uuid; do
        idx=$(echo "$idx" | xargs)
        echo
        echo -e "  ${GREEN}${BOLD}GPU $idx: $(echo "$name" | xargs)${RESET}"
        field "  VRAM total:" "$(echo "$vram_total" | xargs)"
        field "  VRAM free:" "$(echo "$vram_free" | xargs)"
        field "  Compute capability:" "$(echo "$compute_cap" | xargs)"
        field "  Utilization:" "$(echo "$util" | xargs)"
        field "  Temperature:" "$(echo "$temp" | xargs)"
        field "  Power draw / limit:" "$(echo "$power_draw" | xargs) / $(echo "$power_limit" | xargs)"
        field "  UUID:" "$(echo "$uuid" | xargs)"
    done < <(nvidia-smi \
        --query-gpu=index,name,memory.total,memory.free,compute_cap,utilization.gpu,temperature.gpu,power.draw,power.limit,gpu_uuid \
        --format=csv,noheader 2>/dev/null)
fi

# ── CUDA Toolkit ──────────────────────────────────────────────────────────────
header "CUDA Toolkit"
if command -v nvcc &>/dev/null; then
    nvcc_ver=$(nvcc --version 2>/dev/null | grep -oP 'release \K[0-9.]+')
    field "nvcc version:" "$nvcc_ver"
    field "nvcc path:" "$(command -v nvcc)"
else
    field "nvcc:" "not found (toolkit may not be installed)"
fi

# ── Python ────────────────────────────────────────────────────────────────────
header "Python"
if command -v python3 &>/dev/null; then
    field "Python:" "$(python3 --version 2>&1)"
    field "python3 path:" "$(command -v python3)"

    # PyTorch
    torch_info=$(python3 -c "
import sys
try:
    import torch
    cc = ''
    if torch.cuda.is_available():
        props = torch.cuda.get_device_properties(0)
        cc = f'{props.major}.{props.minor}'
    print(f'version={torch.__version__}')
    print(f'cuda_build={torch.version.cuda or \"none\"}')
    print(f'cuda_available={torch.cuda.is_available()}')
    print(f'device_count={torch.cuda.device_count()}')
    print(f'compute_cap={cc}')
    print(f'bf16_supported={torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False}')
except ImportError:
    print('not_installed=true')
" 2>/dev/null || echo "error=true")

    if echo "$torch_info" | grep -q 'not_installed\|error'; then
        field "PyTorch:" "not installed"
    else
        torch_ver=$(echo "$torch_info" | grep 'version=' | cut -d= -f2)
        cuda_build=$(echo "$torch_info" | grep 'cuda_build=' | cut -d= -f2)
        cuda_avail=$(echo "$torch_info" | grep 'cuda_available=' | cut -d= -f2)
        bf16=$(echo "$torch_info" | grep 'bf16_supported=' | cut -d= -f2)
        field "PyTorch version:" "$torch_ver"
        field "PyTorch CUDA build:" "${cuda_build:-none}"
        field "CUDA available:" "$cuda_avail"
        field "bf16 supported:" "$bf16"
    fi
else
    field "Python:" "not found"
fi

# ── Storage ───────────────────────────────────────────────────────────────────
header "Storage (relevant paths)"
for path in / /tmp /home /mnt /data /scratch; do
    if mountpoint -q "$path" 2>/dev/null || [[ "$path" == "/" ]]; then
        avail=$(df -h "$path" 2>/dev/null | awk 'NR==2 {print $4 " avail / " $2 " total (" $5 " used)"}')
        field "$path:" "$avail"
    fi
done

# ── Model Compatibility Notes ─────────────────────────────────────────────────
header "Model Compatibility Notes"
if command -v nvidia-smi &>/dev/null; then
    compute_cap=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | xargs)
    vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 | xargs)
    vram_gb=$(awk "BEGIN {printf \"%.0f\", $vram_mb/1024}" 2>/dev/null)

    # bf16 native: SM 8.0+ (A100+)
    major=$(echo "$compute_cap" | cut -d. -f1)
    minor=$(echo "$compute_cap" | cut -d. -f2)

    [[ "$major" -ge 8 ]] && bf16_note="yes (SM >= 8.0)" || bf16_note="no (requires SM >= 8.0)"
    [[ "$major" -ge 8 && "$minor" -ge 9 ]] || [[ "$major" -ge 9 ]] && fp8_note="yes (SM >= 8.9)" || fp8_note="no (requires SM >= 8.9)"
    [[ "$major" -ge 8 ]] && flash_note="yes" || flash_note="limited (best on SM >= 8.0)"

    field "Compute capability:" "$compute_cap"
    field "VRAM:" "${vram_gb} GB"
    field "Native bf16:" "$bf16_note"
    field "fp8 (H100-class):" "$fp8_note"
    field "Flash Attention:" "$flash_note"

    echo
    echo -e "  ${BOLD}Rough VRAM thresholds for large models:${RESET}"
    echo    "    8GB   — small quantized models (7B Q4)"
    echo    "    12GB  — 7B fp16, distilled video models (LTX-2 distilled)"
    echo    "    24GB  — 13B fp16, most 1080p video gen"
    echo    "    40GB  — 30B fp16, comfortable video gen"
    echo    "    80GB  — 70B fp16, full LTX-2 19B bf16, A100/H100 class"
fi

echo
