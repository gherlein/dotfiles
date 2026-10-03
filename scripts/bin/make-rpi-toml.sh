#!/usr/bin/env bash
set -euo pipefail

GH_USER="${USER:-$(id -un)}"   # local running user == github username == pi user

# arg1: bootfs mountpoint (writes user-data there). omit to print to stdout.
OUT="${1:+$1/user-data}"; OUT="${OUT:-/dev/stdout}"

ask() { local p="$1" d="$2" v; read -rp "$p [$d]: " v; printf '%s' "${v:-$d}"; }

read -rp "hostname: " HOSTNAME
[[ -n "$HOSTNAME" ]] || { echo "hostname required" >&2; exit 1; }
TZ=$(ask "timezone" "America/Los_Angeles")
KEYMAP=$(ask "keymap" "us")

# pull public keys from github (running user's name)
mapfile -t keys < <(curl -fsSL "https://github.com/${GH_USER}.keys")
(( ${#keys[@]} )) || { echo "no keys for ${GH_USER}" >&2; exit 1; }
akeys=$(printf '      - "%s"\n' "${keys[@]}")

# hashed password: required to create the account + for sudo/console/password SSH
read -rsp "password for ${GH_USER}: " pw; echo
[[ -n "$pw" ]] || { echo "password required" >&2; exit 1; }
hash=$(openssl passwd -6 "$pw"); unset pw

cat > "$OUT" <<EOF
#cloud-config
hostname: ${HOSTNAME}
manage_etc_hosts: true

users:
  - name: ${GH_USER}
    gecos: ${GH_USER}
    groups: [adm,dialout,cdrom,sudo,audio,video,plugdev,games,users,input,render,netdev,spi,i2c,gpio]
    shell: /bin/bash
    lock_passwd: false
    passwd: "${hash}"
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
${akeys}

ssh_pwauth: true

timezone: ${TZ}
locale: en_US.UTF-8
keyboard:
  layout: ${KEYMAP}
EOF
