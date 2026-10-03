#!/usr/bin/env bash
# Apply all permanent fixes from fix-mouse.md for HP ZBook Ultra G1a 14" USB mouse issues.
# Run as a normal user with sudo available.

set -euo pipefail

need_reboot=0
need_logout=0

# --- 1. Udev rule: disable autosuspend on Genesys Logic hub ---
UDEV_RULE=/etc/udev/rules.d/99-usb-autosuspend.rules
if [[ ! -f "$UDEV_RULE" ]]; then
    echo "Installing udev rule: $UDEV_RULE"
    sudo tee "$UDEV_RULE" <<'EOF'
# Disable autosuspend for Genesys Logic USB hubs to keep connected HID devices alive
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="05e3", ATTR{power/control}="on"
EOF
    sudo udevadm control --reload-rules && sudo udevadm trigger
    echo "  -> udev rule installed and applied"
else
    echo "  -> udev rule already present, skipping"
fi

# --- 2. Blacklist amd_pmf ---
MODPROBE_CONF=/etc/modprobe.d/disable-amd-pmf.conf
if [[ ! -f "$MODPROBE_CONF" ]]; then
    echo "Blacklisting amd_pmf: $MODPROBE_CONF"
    echo "blacklist amd_pmf" | sudo tee "$MODPROBE_CONF" > /dev/null
    sudo update-initramfs -u
    need_reboot=1
    echo "  -> amd_pmf blacklisted; initramfs updated"
else
    echo "  -> amd_pmf blacklist already present, skipping"
fi

# Unload amd_pmf from the running kernel if it is loaded
if lsmod | grep -q amd_pmf; then
    echo "  -> unloading amd_pmf from running kernel"
    sudo modprobe -r amd_pmf
fi

# --- 3. Systemd service: AMD EPP = performance ---
EPP_SERVICE=/etc/systemd/system/amd-epp.service
if [[ ! -f "$EPP_SERVICE" ]]; then
    echo "Installing systemd service: $EPP_SERVICE"
    sudo tee "$EPP_SERVICE" <<'EOF'
[Unit]
Description=Set AMD CPU EPP to performance
After=suspend.target hibernate.target hybrid-sleep.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference'

[Install]
WantedBy=default.target suspend.target hibernate.target hybrid-sleep.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now amd-epp.service
    echo "  -> amd-epp.service installed and started"
else
    echo "  -> amd-epp.service already present, skipping"
fi

# Apply EPP immediately regardless
echo "  -> setting EPP=performance now"
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference > /dev/null

# --- 4. GNOME KMS modifiers + fractional scaling ---
CURRENT_FEATURES=$(gsettings get org.gnome.mutter experimental-features 2>/dev/null || echo "[]")
if echo "$CURRENT_FEATURES" | grep -q "kms-modifiers"; then
    echo "  -> kms-modifiers already set in GNOME experimental-features, skipping"
else
    echo "Setting GNOME experimental-features"
    gsettings set org.gnome.mutter experimental-features "['scale-monitor-framebuffer', 'kms-modifiers']"
    need_logout=1
    echo "  -> done"
fi

# --- 5. Kitty: disable sync_to_monitor ---
KITTY_CONF="${HOME}/.config/kitty/kitty.conf"
if [[ -f "$KITTY_CONF" ]] && grep -q "sync_to_monitor" "$KITTY_CONF"; then
    echo "  -> kitty sync_to_monitor already configured, skipping"
else
    echo "Adding sync_to_monitor no to kitty.conf"
    mkdir -p "$(dirname "$KITTY_CONF")"
    echo "sync_to_monitor no" >> "$KITTY_CONF"
    echo "  -> done"
fi

# --- Done ---
echo ""
echo "All fixes applied."
if [[ $need_reboot -eq 1 ]]; then
    echo "REBOOT REQUIRED: amd_pmf blacklist / initramfs update takes effect after reboot."
fi
if [[ $need_logout -eq 1 ]]; then
    echo "LOG OUT REQUIRED: GNOME experimental-features change takes effect after log out/in."
fi
