#!/usr/bin/env bash
#
# scan-artifact.sh - Static security scan of a self-contained HTML artifact.
#
# Reads a single saved HTML file (e.g. a claude.ai artifact exported via the
# Artifact "read" action, or any flat HTML page) and reports the patterns that
# matter for trusting it: outbound network calls, off-origin resource loads,
# browser storage, dynamic code execution, and HTML-injection sinks.
#
# It never executes the file. It only greps. Treat the input as untrusted data.
#
# Usage:   scan-artifact.sh <file.html>
# Exit:    0 = no outbound calls, off-origin resource loads, or dynamic exec
#          1 = at least one of those three is present (read the flagged lines)
#          2 = usage / file error
#
# Exit 1 is a "read these" signal, not a verdict of malicious. Storage,
# clipboard, innerHTML on internal content, and bare off-origin URL strings are
# common and usually benign; they are listed but never trip the exit code.

set -euo pipefail

readonly SELF="${0##*/}"

# Off-origin script/style hosts the artifact runtime allows. A resource load
# from one of these is expected; a load from anywhere else trips the verdict.
readonly ALLOWED_HOST_RE='fonts\.googleapis\.com|fonts\.gstatic\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|cdn\.tailwindcss\.com|code\.jquery\.com'

# Namespace/schema URLs that appear inside embedded image (XMP/SVG) metadata and
# are not links or loads. Filtered from the off-origin URL listing to cut noise.
readonly METADATA_HOST_RE='w3\.org|xmlns|purl\.org|ns\.adobe\.com|adobe\.com/xap|sRGB|iec\.ch'

# Set by section() to the count of matching lines in the most recent call.
SECTION_HITS=0

usage() {
  cat >&2 <<EOF
$SELF - static security scan of a self-contained HTML artifact

Usage: $SELF <file.html>

Reports outbound network calls, off-origin loads, storage, dynamic code
execution, and HTML-injection sinks. Does not execute the file.
EOF
  exit 2
}

[ $# -eq 1 ] || usage
readonly FILE="$1"
[ -f "$FILE" ] || { echo "$SELF: not a file: $FILE" >&2; exit 2; }

# Print a titled section: run a case-insensitive regex with line numbers,
# optionally drop lines matching a filter regex, truncate long minified lines,
# and set SECTION_HITS to the match count. Output always goes to the terminal.
#
# mode "match" (default): grep -o, so only the matched token prints -- good for
#   short signatures like fetch( or localStorage.
# mode "line": the whole matching line prints -- required when the filter must
#   see text that sits past the match (e.g. an allowlisted host in an href=).
section() {
  local title="$1" regex="$2" filter="${3:-}" mode="${4:-match}"
  local grepflags='-noiE'
  [ "$mode" = line ] && grepflags='-niE'
  local hits
  if [ -n "$filter" ]; then
    hits=$(grep "$grepflags" "$regex" "$FILE" | grep -viE "$filter" || true)
  else
    hits=$(grep "$grepflags" "$regex" "$FILE" || true)
  fi
  printf '\n\033[1m== %s ==\033[0m\n' "$title"
  if [ -z "$hits" ]; then
    echo "  (none)"
    SECTION_HITS=0
    return 0
  fi
  echo "$hits" | cut -c1-200
  SECTION_HITS=$(echo "$hits" | wc -l | tr -d ' ')
  printf '  [%s line(s)]\n' "$SECTION_HITS"
}

echo "scan-artifact: $FILE"
printf 'size: %s bytes, %s lines\n' \
  "$(wc -c <"$FILE" | tr -d ' ')" "$(wc -l <"$FILE" | tr -d ' ')"

# --- Verdict-bearing sections: any hit here means "go read it". ---

section "NETWORK / EXFIL (outbound data paths)" \
  'fetch\(|XMLHttpRequest|\.sendBeacon|navigator\.sendBeacon|new WebSocket|EventSource|<form[^>]*action'
network=$SECTION_HITS

section "EXTERNAL RESOURCE LOADS (off-origin script/style/import, minus allowlist)" \
  '<script[^>]*src=|<link[^>]*href=|@import[^;]*url|import\(' \
  "$ALLOWED_HOST_RE" line
external=$SECTION_HITS

section "DYNAMIC CODE EXECUTION" \
  'eval\(|new Function|setTimeout\( *["'"'"']|setInterval\( *["'"'"']|document\.write|javascript:'
dynexec=$SECTION_HITS

# --- Informational sections: listed for human judgement, never trip the exit. ---

section "OFF-ORIGIN URL STRINGS (links/text, not necessarily loads)" \
  'https?://[a-z0-9.-]+' \
  "$ALLOWED_HOST_RE|$METADATA_HOST_RE"

section "STORAGE (local to each viewer)" \
  'localStorage|sessionStorage|document\.cookie|indexedDB'

section "HTML-INJECTION SINKS (confirm the source is internal, not typed input)" \
  'innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML'

section "CROSS-FRAME / NAV" \
  'postMessage|window\.open|location\.(href|assign|replace) *='

printf '\n\033[1m== VERDICT ==\033[0m\n'
if [ "$network" -gt 0 ] || [ "$external" -gt 0 ] || [ "$dynexec" -gt 0 ]; then
  printf '  REVIEW: network=%s external-loads=%s dynamic-exec=%s -- read the flagged lines.\n' \
    "$network" "$external" "$dynexec"
  exit 1
fi
echo "  CLEAN: no outbound calls, no off-origin resource loads (beyond allowlist),"
echo "         no dynamic exec. Any storage / sink / URL findings above are local or"
echo "         static -- confirm by eye, but none transmit data on their own."
exit 0
