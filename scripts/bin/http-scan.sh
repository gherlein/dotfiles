#!/usr/bin/env bash
# http-scan.sh
# HTTP GET every host in a subnet on port 80 and report the ones that answer.
#
# For each responsive IP the reverse-DNS hostname (if any) is shown alongside
# the HTTP status code. A host counts as "responsive" when curl completes an
# HTTP exchange on port 80 -- any status (2xx/3xx/4xx/5xx) means something is
# listening and speaking HTTP.
#
# Usage:
#   http-scan.sh                 # auto-detect the local subnet and scan it
#   http-scan.sh 10.0.0.0/24     # scan an explicit CIDR
#   PARALLEL=128 http-scan.sh    # override concurrency (default 64)
#   TIMEOUT=3 http-scan.sh       # override per-host timeout seconds (default 2)
#
# Deps: curl, ip, dig.

set -uo pipefail

# ---- config -------------------------------------------------------------------
PORT=80
PARALLEL="${PARALLEL:-64}"   # concurrent probes
TIMEOUT="${TIMEOUT:-2}"      # per-host connect+response ceiling, seconds

# ---- output helpers -----------------------------------------------------------
GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
[ -t 1 ] || { GRN=""; YEL=""; DIM=""; RST=""; }
err() { printf '%s\n' "$*" >&2; }

for dep in curl ip dig; do
    command -v "$dep" >/dev/null || { err "missing dependency: $dep"; exit 2; }
done

# ---- IPv4 <-> integer ---------------------------------------------------------
ip2int() {
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    printf '%u\n' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}
int2ip() {
    local n="$1"
    printf '%d.%d.%d.%d\n' "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" \
        "$(( (n >> 8) & 255 ))" "$(( n & 255 ))"
}

# ---- resolve the CIDR to scan -------------------------------------------------
# An explicit CIDR arg wins; otherwise use the source address / prefix of the
# route toward the internet, which is the interface facing the local network.
cidr="${1:-}"
if [ -z "$cidr" ]; then
    dev="$(ip -o route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+')"
    [ -n "$dev" ] || { err "could not detect the default interface; pass a CIDR"; exit 2; }
    cidr="$(ip -o -f inet addr show dev "$dev" | grep -oP 'inet \K\S+' | head -n1)"
    [ -n "$cidr" ] || { err "no IPv4 address on $dev; pass a CIDR"; exit 2; }
fi

[[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || {
    err "not a valid IPv4 CIDR: $cidr"; exit 2
}
base="${cidr%/*}"
prefix="${cidr#*/}"
[ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || { err "bad prefix length: /$prefix"; exit 2; }

base_int="$(ip2int "$base")"
if [ "$prefix" -eq 0 ]; then
    mask=0
else
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
fi
network=$(( base_int & mask ))
broadcast=$(( network | (~mask & 0xFFFFFFFF) ))

# Usable host range: skip network and broadcast addresses for /0../30; a /31 or
# /32 has no such reserved pair, so scan every address in it.
if [ "$prefix" -ge 31 ]; then
    first="$network"; last="$broadcast"
else
    first=$(( network + 1 )); last=$(( broadcast - 1 ))
fi
count=$(( last - first + 1 ))

err "${DIM}scanning $(int2ip "$network")/$prefix -- $count hosts on port $PORT, ${PARALLEL} at a time${RST}"

# ---- probe one host -----------------------------------------------------------
# Prints "IP\tSTATUS\tHOSTNAME" on any HTTP response; silent otherwise.
probe() {
    local ip="$1" port="$2" timeout="$3" code host
    code="$(curl -s -o /dev/null -m "$timeout" -w '%{http_code}' "http://$ip:$port/" 2>/dev/null)"
    [ -n "$code" ] && [ "$code" != "000" ] || return 0
    host="$(dig +short +time=1 +tries=1 -x "$ip" 2>/dev/null | head -n1 | sed 's/\.$//')"
    [ -n "$host" ] || host="-"
    printf '%s\t%s\t%s\n' "$ip" "$code" "$host"
}
export -f probe int2ip ip2int

# ---- fan out ------------------------------------------------------------------
results="$(
    for (( n = first; n <= last; n++ )); do int2ip "$n"; done \
        | xargs -P "$PARALLEL" -I{} bash -c 'probe "$@"' _ {} "$PORT" "$TIMEOUT" \
        | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
)"

if [ -z "$results" ]; then
    err "no hosts responded on port $PORT"
    exit 1
fi

printf '%s%-16s %-6s %s%s\n' "$YEL" "IP" "STATUS" "HOSTNAME" "$RST"
while IFS=$'\t' read -r ip code host; do
    printf '%s%-16s%s %-6s %s\n' "$GRN" "$ip" "$RST" "$code" "$host"
done <<<"$results"

err "${DIM}$(printf '%s' "$results" | grep -c .) responsive${RST}"
