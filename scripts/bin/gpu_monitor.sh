#!/bin/bash

# GPU Load Monitor - Detects GPU vendor and displays load

detect_gpu_vendor() {
    # Check for NVIDIA GPU using nvidia-smi
    if command -v nvidia-smi &> /dev/null; then
        if nvidia-smi --query-gpu=name --format=csv,noheader,nounits 2>/dev/null | grep -q .; then
            echo "NVIDIA"
            return 0
        fi
    fi
    
    # Check for AMD GPU using rocm-smi or other methods
    if command -v rocm-smi &> /dev/null; then
        if rocm-smi --showproductname 2>/dev/null | grep -q .; then
            echo "AMD"
            return 0
        fi
    fi
    
    # Fallback: Check /sys/class/drm for AMD GPUs
    if [ -d "/sys/class/drm" ]; then
        for card in /sys/class/drm/card*/device/driver; do
            if [ -L "$card" ]; then
                driver=$(basename "$(readlink -f "$card")")
                case "$driver" in
                    amdgpu|radeon)
                        echo "AMD"
                        return 0
                        ;;
                    nvidia)
                        echo "NVIDIA"
                        return 0
                        ;;
                esac
            fi
        done
    fi
    
    echo "Unknown"
    return 1
}

get_nvidia_load() {
    if command -v nvidia-smi &> /dev/null; then
        # Get GPU utilization percentage
        load=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null | tr -d '%')
        echo "NVIDIA GPU Load: ${load}%"
        
        # Also show memory usage if available
        mem_load=$(nvidia-smi --query-gpu=utilization.memory --format=csv,noheader,nounits 2>/dev/null | tr -d '%')
        if [ -n "$mem_load" ]; then
            echo "NVIDIA Memory Load: ${mem_load}%"
        fi
        
        # Show temperature
        temp=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null)
        if [ -n "$temp" ]; then
            echo "GPU Temperature: ${temp}°C"
        fi
    else
        echo "Error: nvidia-smi not found"
    fi
}

get_amd_load() {
    # Try rocm-smi first (modern AMD GPUs)
    if command -v rocm-smi &> /dev/null; then
        load=$(rocm-smi --showuse --format=csv 2>/dev/null | grep -oP '\d+(?=%)' | head -1)
        if [ -n "$load" ]; then
            echo "AMD GPU Load: ${load}%"
        else
            # Alternative parsing for rocm-smi
            load=$(rocm-smi --showuse 2>/dev/null | grep -i "gpu use" | grep -oP '\d+(?=%)' | head -1)
            if [ -n "$load" ]; then
                echo "AMD GPU Load: ${load}%"
            fi
        fi
        
        # Show temperature with rocm-smi
        temp=$(rocm-smi --showtemperature 2>/dev/null | grep -oP '\d+(?=°C)' | head -1)
        if [ -n "$temp" ]; then
            echo "GPU Temperature: ${temp}°C"
        fi
        
        # Show memory usage with rocm-smi
        mem=$(rocm-smi --showmeminfo vram 2>/dev/null | grep -oP '\d+(?=\s*MiB used)' | tail -1)
        if [ -n "$mem" ]; then
            echo "VRAM Used: ${mem} MiB"
        fi
        
    # Fallback for older AMD GPUs using sysfs
    elif [ -f "/sys/class/drm/card0/device/power_dpm_force_performance_level" ]; then
        echo "AMD GPU (using sysfs fallback)"
        
        # Check if amdgpu is loaded
        if lsmod | grep -q amdgpu; then
            # Try to read gpu utilization from amdgpu
            for file in /sys/class/drm/card0/device/hwmon/hwmon*/input; do
                if [ -f "$file" ]; then
                    value=$(cat "$file" 2>/dev/null)
                    if [ -n "$value" ] && [ "$value" != "0" ]; then
                        echo "Hardware monitor input: $value"
                        break
                    fi
                fi
            done
            
            # Try to get temperature
            for file in /sys/class/drm/card0/device/hwmon/hwmon*/temp1_input; do
                if [ -f "$file" ]; then
                    temp=$(cat "$file" 2>/dev/null)
                    if [ -n "$temp" ] && [ "$temp" != "0" ]; then
                        echo "GPU Temperature: $((temp / 1000))°C"
                        break
                    fi
                fi
            done
        else
            echo "AMD GPU detected but amdgpu module not loaded"
        fi
    else
        echo "Error: AMD monitoring tools not available"
    fi
}

# Main script
echo "=== GPU Load Monitor ==="
echo ""

vendor=$(detect_gpu_vendor)

case "$vendor" in
    NVIDIA)
        echo "GPU Vendor: NVIDIA"
        get_nvidia_load
        ;;
    AMD)
        echo "GPU Vendor: AMD"
        get_amd_load
        ;;
    *)
        echo "Could not detect GPU vendor"
        echo ""
        echo "Available tools for monitoring:"
        echo "- For NVIDIA: nvidia-smi (from NVIDIA drivers)"
        echo "- For AMD: rocm-smi (from ROCm) or check /sys/class/drm"
        exit 1
        ;;
esac

echo ""
echo "=== Monitor complete ==="
