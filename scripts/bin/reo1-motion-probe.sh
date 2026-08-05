#!/usr/bin/env bash
#
# reo1-motion-probe.sh - discover what motion/event sources a camera exposes.
#
# Walks the cheap-to-expensive path:
#   1. reachability + open ports
#   2. WS-Discovery
#   3. ONVIF GetSystemDateAndTime (unauthenticated) -> clock skew
#   4. ONVIF GetServices / GetCapabilities
#   5. ONVIF GetEventProperties -> supported topics
#   6. Reolink native CGI (GetAbility / GetMdState / GetAiState)
#   7. RTSP SDP -> inline ONVIF metadata track
#   8. live watch: poll/subscribe and print state transitions
#
# Usage:
#   REO_USER=admin REO_PASS=secret ./reo1-motion-probe.sh
#   ./reo1-motion-probe.sh --host 192.168.1.50 --watch 60
#   ./reo1-motion-probe.sh --watch 0        # probe only, no live watch
#
# Credentials come from $REO_USER/$REO_PASS or an interactive prompt.
# Nothing is written outside $TMPDIR.

set -uo pipefail

HOST="${REO_HOST:-reo1}"
USER_="${REO_USER:-admin}"
PASS="${REO_PASS:-BrightSign}"
WATCH_SECS=30
ONVIF_PORT=""
HTTP_PORT=""
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)        HOST="$2"; shift 2 ;;
    --user)        USER_="$2"; shift 2 ;;
    --watch)       WATCH_SECS="$2"; shift 2 ;;
    --onvif-port)  ONVIF_PORT="$2"; shift 2 ;;
    --http-port)   HTTP_PORT="$2"; shift 2 ;;
    -v|--verbose)  VERBOSE=1; shift ;;
    -h|--help)     sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- output ----

if [[ -t 1 ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; DIM=""; R=""; G=""; Y=""; C=""; N=""
fi

declare -a FINDINGS=()

section() { printf '\n%s== %s %s\n' "$B$C" "$*" "$N"; }
ok()      { printf '  %s[ ok ]%s %s\n' "$G" "$N" "$*"; }
warn()    { printf '  %s[warn]%s %s\n' "$Y" "$N" "$*"; }
fail()    { printf '  %s[fail]%s %s\n' "$R" "$N" "$*"; }
info()    { printf '  %s%s%s\n' "$DIM" "$*" "$N"; }
found()   { FINDINGS+=("$1"); }
vdump()   { [[ $VERBOSE -eq 1 ]] && printf '%s%s%s\n' "$DIM" "$(cat)" "$N" || cat >/dev/null; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }

pretty() {
  if have xmllint; then xmllint --format - 2>/dev/null || cat
  else cat
  fi
}

# ------------------------------------------------------------ deps/creds ----

section "Environment"
for t in curl openssl; do
  have "$t" || { fail "missing required tool: $t"; exit 1; }
done
ok "curl, openssl present"
for t in nmap xmllint ffprobe python3 jq; do
  have "$t" && info "optional: $t present" || warn "optional: $t missing (some checks will be skipped)"
done

if [[ -z "$PASS" ]]; then
  read -rsp "  password for ${USER_}@${HOST}: " PASS; echo
fi

IP="$(getent hosts "$HOST" 2>/dev/null | awk '{print $1; exit}')"
[[ -z "$IP" ]] && IP="$HOST"
ok "target ${B}${HOST}${N} -> ${IP}"

# --------------------------------------------------------------- 1. ports ---

section "1. Reachability and open ports"

if have nmap; then
  nmap -Pn -p 80,443,554,1935,2020,8000,8080,8443,8554,8899,9000 --open "$IP" \
    2>/dev/null | sed -n '/PORT/,/^$/p' | sed 's/^/  /'
  OPEN="$(nmap -Pn -p 80,443,554,2020,8000,8080,8443,8899 --open -oG - "$IP" 2>/dev/null \
          | awk -F'Ports: ' '/Ports:/{print $2}')"
else
  warn "nmap not installed - probing with bash /dev/tcp"
  OPEN=""
  for p in 80 443 554 2020 8000 8080 8443 8899; do
    if timeout 1 bash -c "exec 3<>/dev/tcp/$IP/$p" 2>/dev/null; then
      ok "port $p open"; OPEN="$OPEN $p/open"
    fi
  done
fi

portopen() { timeout 2 bash -c "exec 3<>/dev/tcp/$IP/$1" 2>/dev/null; }

if [[ -z "$HTTP_PORT" ]]; then
  for p in 80 8080 443; do portopen "$p" && { HTTP_PORT=$p; break; }; done
fi
if [[ -z "$ONVIF_PORT" ]]; then
  # Reolink defaults ONVIF to 8000; others use the web port or 2020/8899.
  for p in 8000 2020 8899 80 8080; do portopen "$p" && { ONVIF_PORT=$p; break; }; done
fi
[[ -n "$HTTP_PORT"  ]] && ok "web port: $HTTP_PORT"   || warn "no web port reachable"
[[ -n "$ONVIF_PORT" ]] && ok "onvif candidate port: $ONVIF_PORT" || warn "no ONVIF candidate port"

SCHEME="http"; [[ "$HTTP_PORT" == "443" ]] && SCHEME="https"
WEB="${SCHEME}://${IP}:${HTTP_PORT:-80}"
DEVSVC="http://${IP}:${ONVIF_PORT:-80}/onvif/device_service"

# ----------------------------------------------------------- 2. discovery ---

section "2. WS-Discovery probe"

if have python3; then
python3 - "$IP" <<'PY' | sed 's/^/  /'
import socket, sys, uuid, re
target = sys.argv[1]
msg = f'''<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header><w:MessageID>uuid:{uuid.uuid4()}</w:MessageID>
<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>
</e:Envelope>'''.encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
s.settimeout(4)
try: s.sendto(msg, ('239.255.255.250', 3702))
except OSError as e: print("multicast send failed:", e); sys.exit(0)
seen = 0
while True:
    try:
        data, addr = s.recvfrom(65535)
    except socket.timeout:
        break
    seen += 1
    body = data.decode(errors='replace')
    xaddrs = re.findall(r'<[^>]*XAddrs[^>]*>(.*?)</[^>]*XAddrs>', body, re.S)
    scopes = re.findall(r'onvif://www\.onvif\.org/(\S+)', body)
    mark = " <-- target" if addr[0] == target else ""
    print(f"{addr[0]}{mark}")
    for x in xaddrs: print(f"    XAddrs: {x.strip()}")
    for sc in scopes[:8]: print(f"    scope:  {sc}")
if not seen:
    print("no WS-Discovery replies (camera may have discovery disabled, or you are on a different L2 segment)")
PY
else
  warn "python3 missing - skipping WS-Discovery"
fi

# --------------------------------------------------- SOAP helper functions ---

# ws_security_header -> prints a <s:Header> with a UsernameToken digest
ws_security_header() {
  local nf created nonce_b64 digest
  nf="$TMP/nonce.bin"
  openssl rand 16 > "$nf"
  created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  nonce_b64="$(base64 < "$nf" | tr -d '\n')"
  digest="$( { cat "$nf"; printf '%s%s' "$created" "$PASS"; } \
             | openssl dgst -sha1 -binary | base64 | tr -d '\n')"
  cat <<EOF
<s:Header>
 <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
  <UsernameToken>
   <Username>${USER_}</Username>
   <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">${digest}</Password>
   <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${nonce_b64}</Nonce>
   <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${created}</Created>
  </UsernameToken>
 </Security>
</s:Header>
EOF
}

HTTP_CODE=""

# soap <url> <body-inner-xml> [--anon]
# Tries WS-UsernameToken first, falls back to HTTP digest on 401/fault.
soap() {
  local url="$1" body="$2" anon="${3:-}" hdr="" out="$TMP/soap.out"
  : > "$out"
  [[ "$anon" != "--anon" ]] && hdr="$(ws_security_header)"

  local env="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">${hdr}<s:Body>${body}</s:Body></s:Envelope>"

  HTTP_CODE="$(curl -sk -m 12 -o "$out" -w '%{http_code}' "$url" \
      -H 'Content-Type: application/soap+xml; charset=utf-8' --data-binary "$env")"

  if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "400" ]] && [[ "$anon" != "--anon" ]]; then
    HTTP_CODE="$(curl -sk -m 12 --digest -u "${USER_}:${PASS}" -o "$out" -w '%{http_code}' "$url" \
        -H 'Content-Type: application/soap+xml; charset=utf-8' \
        --data-binary "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body>${body}</s:Body></s:Envelope>")"
  fi
  cat "$out"
}

# ------------------------------------------------------------ 3. clock -------

section "3. ONVIF GetSystemDateAndTime (unauthenticated) + clock skew"

DT="$(soap "$DEVSVC" '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>' --anon)"
if grep -qi 'SystemDateAndTime' <<<"$DT"; then
  ok "ONVIF device service responds at $DEVSVC"
  found "onvif-device-service"
  CY=$(grep -oP '(?<=<tt:Year>)[0-9]+' <<<"$DT" | tail -1)
  CMO=$(grep -oP '(?<=<tt:Month>)[0-9]+' <<<"$DT" | tail -1)
  CD=$(grep -oP '(?<=<tt:Day>)[0-9]+' <<<"$DT" | tail -1)
  CH=$(grep -oP '(?<=<tt:Hour>)[0-9]+' <<<"$DT" | tail -1)
  CMI=$(grep -oP '(?<=<tt:Minute>)[0-9]+' <<<"$DT" | tail -1)
  CS=$(grep -oP '(?<=<tt:Second>)[0-9]+' <<<"$DT" | tail -1)
  if [[ -n "${CY:-}" ]]; then
    CAM_EPOCH=$(date -u -d "${CY}-${CMO}-${CD}T${CH}:${CMI}:${CS}Z" +%s 2>/dev/null || echo "")
    NOW=$(date -u +%s)
    if [[ -n "$CAM_EPOCH" ]]; then
      SKEW=$(( CAM_EPOCH - NOW ))
      info "camera UTC: ${CY}-${CMO}-${CD} ${CH}:${CMI}:${CS}  host UTC: $(date -u +%F\ %T)"
      if (( ${SKEW#-} <= 2 )); then
        ok "clock skew ${SKEW}s - safe to use event timestamps as seek offsets"
      elif (( ${SKEW#-} <= 30 )); then
        warn "clock skew ${SKEW}s - correct before correlating events to recordings"
      else
        fail "clock skew ${SKEW}s - event timestamps are NOT usable for seeking; enable NTP on the camera"
      fi
    fi
  fi
  grep -oP '(?<=<tt:TimeZone>).*?(?=</tt:TimeZone>)' <<<"$DT" | head -1 | sed 's/^/  TZ: /'
  grep -oP '(?<=<tt:DateTimeType>)[A-Za-z]+' <<<"$DT" | head -1 | sed 's/^/  time source: /'
else
  warn "no ONVIF response at $DEVSVC (http $HTTP_CODE)"
  info "on Reolink, ONVIF is off by default: Settings > Network > Advanced > Port Settings > ONVIF"
  pretty <<<"$DT" | head -20 | vdump
fi

# --------------------------------------------------------- 4. services ------

section "4. ONVIF services and capabilities"

EVENTSVC=""
SVC="$(soap "$DEVSVC" '<GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"><IncludeCapability>true</IncludeCapability></GetServices>')"
if grep -qi 'GetServicesResponse' <<<"$SVC"; then
  ok "GetServices authenticated (http $HTTP_CODE)"
  pretty <<<"$SVC" \
    | grep -oP '(?<=<tds:Namespace>|<Namespace>).*?(?=</)' \
    | sed 's|http://www.onvif.org/||' | sed 's/^/  service: /'
  EVENTSVC="$(pretty <<<"$SVC" | grep -A4 'events/wsdl' | grep -oP '(?<=<tds:XAddr>|<XAddr>).*?(?=</)' | head -1)"
else
  warn "GetServices failed (http $HTTP_CODE) - trying GetCapabilities"
  CAP="$(soap "$DEVSVC" '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>All</Category></GetCapabilities>')"
  EVENTSVC="$(pretty <<<"$CAP" | grep -A3 '<tt:Events>' | grep -oP '(?<=<tt:XAddr>).*?(?=</)' | head -1)"
  grep -qi 'GetCapabilitiesResponse' <<<"$CAP" && ok "GetCapabilities ok" || fail "authenticated ONVIF calls failing - check credentials / ONVIF user permissions"
  pretty <<<"$CAP" | head -40 | vdump
fi

if [[ -n "$EVENTSVC" ]]; then
  ok "events service: $EVENTSVC"
  found "onvif-events-service"
else
  warn "no Events service advertised"
  # last resort: the conventional path
  EVENTSVC="http://${IP}:${ONVIF_PORT:-80}/onvif/Events"
  info "will still try conventional endpoint: $EVENTSVC"
fi

# ----------------------------------------------------------- 5. topics ------

section "5. ONVIF event topics (GetEventProperties)"

EP="$(soap "$EVENTSVC" '<GetEventProperties xmlns="http://www.onvif.org/ver10/events/wsdl"/>')"
if grep -qi 'GetEventPropertiesResponse' <<<"$EP"; then
  ok "event properties retrieved"
  TOPICS="$(pretty <<<"$EP" | grep -oP '<tns1:[A-Za-z]+|<(?<=<)[A-Za-z]+(?= wstop:topic="true")' | tr -d '<' | sort -u)"
  # Reconstruct dotted topic paths as best we can from the tree
  pretty <<<"$EP" | grep -oiE '(MotionAlarm|CellMotionDetector|Motion|FieldDetector|ObjectsInside|LineDetector|Crossed|TamperDetector|Tamper|ObjectDetection|MyRuleDetector|People|Vehicle|Visitor|Package|DogCat|FaceDetect|AudioDetect|AudioAlarm)' \
    | sort -u | sed 's/^/  topic fragment: /'
  for t in MotionAlarm CellMotionDetector FieldDetector LineDetector TamperDetector ObjectDetection; do
    grep -qi "$t" <<<"$EP" && { ok "supports: $t"; found "topic:$t"; }
  done
  pretty <<<"$EP" > "$TMP/eventprops.xml"
  info "full response saved: $TMP/eventprops.xml (copy it out before this script exits)"
  cp "$TMP/eventprops.xml" "./reo1-eventprops.xml" 2>/dev/null && info "also written to ./reo1-eventprops.xml"
else
  warn "GetEventProperties failed (http $HTTP_CODE)"
  pretty <<<"$EP" | grep -oP '(?<=<SOAP-ENV:Text>|<s:Text>).*?(?=</)' | sed 's/^/  fault: /'
fi

# --------------------------------------------------- 6. Reolink native API ---

section "6. Reolink native CGI API"

API="${WEB}/cgi-bin/api.cgi"
RTOKEN=""

LOGIN="$(curl -sk -m 10 -X POST "${API}?cmd=Login" -H 'Content-Type: application/json' \
  -d "[{\"cmd\":\"Login\",\"param\":{\"User\":{\"userName\":\"${USER_}\",\"password\":\"${PASS}\"}}}]" 2>/dev/null)"

if have jq && jq -e '.[0].value.Token.name' >/dev/null 2>&1 <<<"$LOGIN"; then
  RTOKEN="$(jq -r '.[0].value.Token.name' <<<"$LOGIN")"
  ok "Reolink login ok, token acquired"
  found "reolink-api"
else
  RTOKEN="$(grep -oP '(?<="name" : ")[^"]+' <<<"$LOGIN" | head -1)"
  if [[ -n "$RTOKEN" ]]; then
    ok "Reolink login ok (token parsed without jq)"
    found "reolink-api"
  else
    warn "Reolink login failed or this is not a Reolink device"
    printf '  %s\n' "$(head -c 300 <<<"$LOGIN")" | vdump
  fi
fi

rl() { # rl <cmd>  -> GET a token-authenticated Reolink command
  local cmd="$1"
  curl -sk -m 10 "${API}?cmd=${cmd}&token=${RTOKEN}" 2>/dev/null
}

if [[ -n "$RTOKEN" ]]; then
  AB="$(curl -sk -m 10 -X POST "${API}?cmd=GetAbility&token=${RTOKEN}" -H 'Content-Type: application/json' \
        -d "[{\"cmd\":\"GetAbility\",\"param\":{\"User\":{\"userName\":\"${USER_}\"}}}]" 2>/dev/null)"
  for k in alarmMd alarmAudio supportAi supportAiPeople supportAiVehicle supportAiAnimal supportAiDogCat mdWithPir onvif push ftp; do
    if grep -q "\"$k\"" <<<"$AB"; then
      v="$(grep -oP "(?<=\"$k\" : \{)[^}]*" <<<"$AB" | grep -oP '(?<="ver" : )[0-9]+' | head -1)"
      [[ "${v:-0}" != "0" ]] && ok "ability $k = $v" || info "ability $k = 0 (unsupported)"
    fi
  done

  MD="$(rl GetMdState)"
  if grep -q '"state"' <<<"$MD"; then
    ok "GetMdState works -> $(grep -oP '(?<="state" : )[0-9]+' <<<"$MD" | head -1)"
    found "reolink-mdstate"
  else
    warn "GetMdState unavailable"
  fi

  AI="$(rl GetAiState)"
  if grep -q 'alarm_state\|"people"\|"vehicle"' <<<"$AI"; then
    ok "GetAiState works - AI object classes available:"
    grep -oP '"(people|vehicle|dog_cat|face|package)"' <<<"$AI" | sort -u | sed 's/^/    /'
    found "reolink-aistate"
  else
    info "GetAiState unavailable (older model or non-AI camera)"
  fi
fi

# ------------------------------------------------- 7. RTSP metadata track ---

section "7. RTSP streams and inline metadata track"

if have ffprobe; then
  for path in h264Preview_01_main h264Preview_01_sub Preview_01_main; do
    URL="rtsp://${USER_}:${PASS}@${IP}:554/${path}"
    OUT="$(ffprobe -v error -rtsp_transport tcp -timeout 5000000 -show_streams "$URL" 2>&1)"
    if grep -q 'codec_type' <<<"$OUT"; then
      ok "stream up: rtsp://${USER_}:***@${IP}:554/${path}"
      grep -E '^codec_name=|^codec_type=|^width=|^height=|^r_frame_rate=' <<<"$OUT" \
        | paste -sd' ' - | sed 's/^/    /'
      if grep -qiE 'vnd\.onvif\.metadata|codec_type=data' <<<"$OUT"; then
        ok "inline ONVIF metadata track present - analytics are frame-synchronised"
        found "rtsp-metadata-track"
      else
        info "no metadata track on this stream"
      fi
      break
    fi
  done
  grep -q 'codec_type' <<<"${OUT:-}" || warn "no RTSP stream answered on :554 with the usual Reolink paths"
else
  warn "ffprobe missing - skipping RTSP inspection"
fi

# ------------------------------------------------------------- 8. watch -----

if [[ "$WATCH_SECS" -gt 0 ]]; then
section "8. Live watch (${WATCH_SECS}s) - go wave at the camera"

WATCHED=0

# 8a. Reolink polling (1 Hz), prints only transitions
if [[ -n "$RTOKEN" ]] && printf '%s\n' "${FINDINGS[@]}" | grep -q reolink-mdstate; then
  WATCHED=1
  info "polling GetMdState/GetAiState at 1 Hz..."
  LAST=""
  END=$(( $(date +%s) + WATCH_SECS ))
  while [[ $(date +%s) -lt $END ]]; do
    S="$(rl GetMdState | grep -oP '(?<="state" : )[0-9]+' | head -1)"
    A="$(rl GetAiState | grep -oP '"(people|vehicle|dog_cat)" : \{[^}]*"alarm_state" : [0-9]+' \
         | grep -oP '^"[a-z_]+|[0-9]+$' | paste -sd: - )"
    CUR="md=${S:-?} ai=${A:-none}"
    if [[ "$CUR" != "$LAST" ]]; then
      printf '  %s %s%s%s\n' "$(date +%H:%M:%S)" "$B" "$CUR" "$N"
      LAST="$CUR"
    fi
    sleep 1
  done
  ok "polling window ended"
fi

# 8b. ONVIF PullPoint
if printf '%s\n' "${FINDINGS[@]}" | grep -q onvif-events-service; then
  WATCHED=1
  info "creating ONVIF PullPoint subscription..."
  SUB="$(soap "$EVENTSVC" '<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>PT120S</InitialTerminationTime></CreatePullPointSubscription>')"
  PULLURL="$(pretty <<<"$SUB" | grep -oP '(?<=<wsa5?:Address>|<Address>)http[^<]*' | head -1)"
  if [[ -n "$PULLURL" ]]; then
    ok "pullpoint: $PULLURL"
    # Some firmware returns an unroutable address (0.0.0.0 or internal name) - rewrite the host.
    if ! grep -q "$IP" <<<"$PULLURL"; then
      FIXED="$(sed -E "s|://[^/:]+(:[0-9]+)?|://${IP}:${ONVIF_PORT}|" <<<"$PULLURL")"
      warn "subscription address does not point at ${IP}; rewriting to $FIXED"
      PULLURL="$FIXED"
    fi
    END=$(( $(date +%s) + WATCH_SECS ))
    while [[ $(date +%s) -lt $END ]]; do
      MSG="$(soap "$PULLURL" '<PullMessages xmlns="http://www.onvif.org/ver10/events/wsdl"><Timeout>PT10S</Timeout><MessageLimit>20</MessageLimit></PullMessages>')"
      if grep -qi 'NotificationMessage' <<<"$MSG"; then
        pretty <<<"$MSG" \
          | grep -oP '(Topic[^>]*>[^<]+|Name="[A-Za-z]+" Value="[^"]*")' \
          | sed "s/^/  $(date +%H:%M:%S)  /"
      elif grep -qi 'Fault' <<<"$MSG"; then
        warn "pull fault - subscription likely expired; re-run with a shorter --watch"
        pretty <<<"$MSG" | grep -oP '(?<=<s:Text>|<SOAP-ENV:Text>).*?(?=</)' | sed 's/^/    /'
        break
      fi
    done
    soap "$PULLURL" '<Unsubscribe xmlns="http://docs.oasis-open.org/wsn/b-2"/>' >/dev/null 2>&1
    ok "pullpoint watch ended, unsubscribed"
  else
    warn "no SubscriptionReference address returned"
    pretty <<<"$SUB" | head -30 | vdump
  fi
fi

[[ $WATCHED -eq 0 ]] && warn "no usable event source to watch"
fi

# ------------------------------------------------------------- summary ------

section "Summary"

if [[ ${#FINDINGS[@]} -eq 0 ]]; then
  fail "no event source found on ${HOST}"
  cat <<'EOS'

  Next steps:
    - Reolink: enable ONVIF in Settings > Network > Advanced > Port Settings,
      and confirm the user has ONVIF permissions (admin, not a restricted user).
    - Confirm motion detection itself is enabled and has a schedule/zone set.
    - Fall back to decode-side scanning (packet-size or scene-score) on the
      MediaMTX recordings instead.
EOS
  exit 1
fi

printf '  event sources found:\n'
printf '    - %s\n' "${FINDINGS[@]}"

cat <<EOS

  ${B}Recommended wiring${N}
  Pick the cheapest source above and write timestamps to a sidecar as
  MediaMTX segments land, then pull only interesting windows:

    GET http://<mediamtx>:9996/get?path=cam1&start=<event_ts-5s>&duration=30&format=mp4

  If 'rtsp-metadata-track' is listed, prefer it - the analytics are already
  synchronised to frame PTS, so no clock-skew correction is needed.
  Otherwise correct every event timestamp by the skew reported in section 3.

  For a long-running watcher, port section 8 to Go (github.com/use-go/onvif),
  renewing the subscription before InitialTerminationTime rather than
  re-subscribing on fault.
EOS
