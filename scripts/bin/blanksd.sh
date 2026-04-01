#!/usr/bin/env bash
set -euo pipefail

DEVICE="${1:-}"

if [[ -z "$DEVICE" ]]; then
    echo "Usage: $0 <device>  (e.g. /dev/sdb or /dev/mmcblk0)"
    exit 1
fi

if [[ ! -b "$DEVICE" ]]; then
    echo "Error: $DEVICE is not a block device"
    exit 1
fi

echo "WARNING: This will erase all data on $DEVICE"
read -rp "Type YES to continue: " confirm
[[ "$confirm" == "YES" ]] || { echo "Aborted."; exit 1; }

echo "==> Unmounting any mounted partitions..."
while IFS= read -r mp; do
    sudo umount "$mp" && echo "    unmounted $mp"
done < <(lsblk -lno MOUNTPOINT "$DEVICE" | grep -v '^$')

echo "==> Wiping partition table..."
sudo wipefs -a "$DEVICE"

echo "==> Creating MBR partition table and single FAT32 partition..."
sudo parted -s "$DEVICE" \
    mklabel msdos \
    mkpart primary fat32 1MiB 100%

# Resolve partition device (handles both /dev/sdX1 and /dev/mmcblk0p1)
if [[ "$DEVICE" =~ mmcblk[0-9]+$ ]] || [[ "$DEVICE" =~ loop[0-9]+$ ]]; then
    PARTITION="${DEVICE}p1"
else
    PARTITION="${DEVICE}1"
fi

echo "==> Formatting $PARTITION as FAT32..."
sudo mkfs.fat -F 32 "$PARTITION"

echo "==> Setting volume label to NONE..."
sudo fatlabel "$PARTITION" "NONE"

echo "==> Done."
lsblk -o NAME,FSTYPE,LABEL,SIZE "$DEVICE"

udisksctl mount -b /dev/sdc1
