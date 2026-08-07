#!/usr/bin/env bash
#
# add-dns-record.sh — create/update an A record in a Route 53 public hosted zone.
#
# Wraps the lookup -> inspect -> UPSERT -> wait -> verify sequence so the record
# is never written blind over an existing value.
#
#   ./add-dns-record.sh --name stats.herlein.com --ip 34.195.40.188
#   ./add-dns-record.sh --name stats.herlein.com --ip auto --dry-run
#
# Exit codes: 0 ok | 1 usage | 2 missing dependency | 3 AWS error | 4 aborted

set -euo pipefail

NAME=""
IP=""
ZONE=""
ZONE_ID=""
TYPE="A"
TTL=300
COMMENT=""
PROFILE=""
REGION=""
DRY_RUN=0
ASSUME_YES=0
SKIP_WAIT=0

readonly PROG="${0##*/}"

usage() {
	cat <<EOF
$PROG — create or update a Route 53 A/AAAA record.

Required:
  --name FQDN        Record to write, e.g. stats.herlein.com
  --ip ADDR          Target address, or 'auto' to use this EC2 instance's
                     public IPv4 (queried via IMDSv2)

Optional:
  --zone DOMAIN      Hosted zone name (default: --name minus its first label)
  --zone-id ID       Use this hosted zone ID directly, skipping lookup
  --type TYPE        A or AAAA (default: $TYPE)
  --ttl SECONDS      Record TTL (default: $TTL)
  --comment TEXT     Change-batch comment
  --profile NAME     AWS CLI profile
  --region NAME      AWS region for the CLI call
  --dry-run          Print the change batch and exit without writing
  --yes              Do not prompt before overwriting an existing record
  --no-wait          Return immediately instead of waiting for INSYNC
  -h, --help         Show this help

Examples:
  $PROG --name stats.herlein.com --ip 34.195.40.188
  $PROG --name stats.herlein.com --ip auto --profile personal --yes
EOF
}

die() {
	printf '%s: error: %s\n' "$PROG" "$1" >&2
	exit "${2:-1}"
}

note() { printf '==> %s\n' "$1"; }
warn() { printf 'warning: %s\n' "$1" >&2; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--name)    NAME="${2:-}"; shift 2 ;;
		--ip)      IP="${2:-}"; shift 2 ;;
		--zone)    ZONE="${2:-}"; shift 2 ;;
		--zone-id) ZONE_ID="${2:-}"; shift 2 ;;
		--type)    TYPE="${2:-}"; shift 2 ;;
		--ttl)     TTL="${2:-}"; shift 2 ;;
		--comment) COMMENT="${2:-}"; shift 2 ;;
		--profile) PROFILE="${2:-}"; shift 2 ;;
		--region)  REGION="${2:-}"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--yes|-y)  ASSUME_YES=1; shift ;;
		--no-wait) SKIP_WAIT=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*)         die "unknown argument: $1" ;;
	esac
done

[[ -n "$NAME" ]] || { usage >&2; die "--name is required"; }
[[ -n "$IP"   ]] || { usage >&2; die "--ip is required (or 'auto')"; }

command -v aws >/dev/null 2>&1 || die "aws CLI not found in PATH" 2

case "$TYPE" in
	A|AAAA) ;;
	*) die "--type must be A or AAAA" ;;
esac

[[ "$TTL" =~ ^[0-9]+$ ]] || die "--ttl must be an integer"

# Strip any trailing dot so comparisons against Route 53's FQDN form are exact.
NAME="${NAME%.}"

# Resolve the instance's own public IPv4 when asked. IMDSv2 needs a token first;
# a plain IMDSv1 GET is refused on instances with the hop limit locked down.
if [[ "$IP" == "auto" ]]; then
	note "Querying instance metadata for public IPv4"
	imds_token="$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
		-H "X-aws-ec2-metadata-token-ttl-seconds: 60" --max-time 5 2>/dev/null || true)"
	[[ -n "$imds_token" ]] || die "could not reach instance metadata (not on EC2?); pass --ip explicitly" 2
	IP="$(curl -sf -H "X-aws-ec2-metadata-token: $imds_token" \
		"http://169.254.169.254/latest/meta-data/public-ipv4" --max-time 5 2>/dev/null || true)"
	[[ -n "$IP" ]] || die "instance has no public IPv4; pass --ip explicitly" 2
	note "Resolved to $IP"
fi

if [[ "$TYPE" == "A" && ! "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
	die "--ip '$IP' is not a valid IPv4 address"
fi

ZONE="${ZONE%.}"

[[ -n "$COMMENT" ]] || COMMENT="$TYPE record for $NAME set by $PROG"

# Shared CLI flags, kept as an array so empty values never become stray args.
aws_args=()
[[ -n "$PROFILE" ]] && aws_args+=(--profile "$PROFILE")
[[ -n "$REGION"  ]] && aws_args+=(--region "$REGION")

# Run an AWS call capturing stdout and stderr separately, into AWS_OUT/AWS_ERR.
# Merging them with 2>&1 would let CLI warnings (deprecation notices, retry
# chatter) contaminate parsed values like zone IDs and change IDs.
AWS_OUT=""
AWS_ERR=""
aws_capture() {
	local tmp rc=0
	tmp="$(mktemp "${TMPDIR:-/tmp}/r53-err.XXXXXX")"
	AWS_OUT="$(aws "${aws_args[@]}" "$@" 2>"$tmp")" || rc=$?
	AWS_ERR="$(cat "$tmp")"
	rm -f "$tmp"
	return "$rc"
}

note "Verifying AWS credentials"
aws_capture sts get-caller-identity --query Arn --output text \
	|| die "no usable AWS credentials: ${AWS_ERR:-unknown error}" 3
note "Authenticated as $AWS_OUT"

# --- Resolve the hosted zone -------------------------------------------------

# Return the public hosted zone ID for an exact zone name, or empty if none.
# Dies only on an API failure, so callers can probe candidate names safely.
lookup_zone_id() {
	local zone="$1" ids
	# JMESPath: 'string' literals in single quotes, `false` raw literal in backticks.
	local query="HostedZones[?Name=='${zone}.' && Config.PrivateZone==\`false\`].Id"

	aws_capture route53 list-hosted-zones-by-name --dns-name "$zone" \
		--query "$query" --output text \
		|| die "list-hosted-zones-by-name failed: ${AWS_ERR:-unknown error}" 3

	ids="$(printf '%s\n' "$AWS_OUT" | tr '\t' '\n' | sed '/^$/d;/^None$/d')"
	[[ -n "$ids" ]] || return 0

	if [[ "$(printf '%s\n' "$ids" | wc -l)" -gt 1 ]]; then
		printf '%s\n' "$ids" >&2
		die "multiple public hosted zones matched '$zone'; pass --zone-id" 3
	fi
	printf '%s' "$ids"
}

if [[ -z "$ZONE_ID" && -n "$ZONE" ]]; then
	note "Looking up public hosted zone for $ZONE"
	ZONE_ID="$(lookup_zone_id "$ZONE")"
	[[ -n "$ZONE_ID" ]] || die "no public hosted zone found for '$ZONE'" 3
fi

# With no zone given, walk up from the record name and take the first ancestor
# that is a hosted zone. This gets the apex case right (herlein.com lives in
# zone herlein.com, not 'com') and needs no public-suffix table for co.uk-style
# TLDs, since only a real zone can match.
if [[ -z "$ZONE_ID" ]]; then
	note "Searching for the hosted zone containing $NAME"
	candidate="$NAME"
	while [[ "$candidate" == *.* ]]; do
		if ZONE_ID="$(lookup_zone_id "$candidate")" && [[ -n "$ZONE_ID" ]]; then
			ZONE="$candidate"
			break
		fi
		candidate="${candidate#*.}"
	done
	[[ -n "$ZONE_ID" ]] || die "no public hosted zone found for '$NAME' or any parent domain" 3
	note "Matched zone: $ZONE"
fi

ZONE_ID="${ZONE_ID##*/}"   # accept either Z123... or /hostedzone/Z123...
note "Hosted zone: $ZONE_ID"

# --- Inspect what is already there -------------------------------------------

aws_capture route53 list-resource-record-sets --hosted-zone-id "$ZONE_ID" \
	--query "ResourceRecordSets[?Name=='${NAME}.' && Type=='${TYPE}'].ResourceRecords[].Value" \
	--output text \
	|| die "list-resource-record-sets failed: ${AWS_ERR:-unknown error}" 3

existing="$(printf '%s' "$AWS_OUT" | tr '\t' ' ' | sed 's/^ *//;s/ *$//')"
[[ "$existing" == "None" ]] && existing=""

if [[ -n "$existing" ]]; then
	if [[ "$existing" == "$IP" ]]; then
		note "$NAME $TYPE already points at $IP — nothing to change"
		exit 0
	fi
	warn "$NAME $TYPE currently resolves to: $existing"
	warn "this run will replace it with: $IP"
	if (( ! ASSUME_YES && ! DRY_RUN )); then
		read -r -p "Overwrite existing record? [y/N] " reply
		[[ "$reply" =~ ^[Yy]$ ]] || { note "Aborted, no change made"; exit 4; }
	fi
else
	note "No existing $TYPE record for $NAME — will create it"
fi

# --- Build and apply the change batch ----------------------------------------

batch_file="$(mktemp "${TMPDIR:-/tmp}/r53-batch.XXXXXX.json")"
trap 'rm -f "$batch_file"' EXIT

cat >"$batch_file" <<EOF
{
  "Comment": "$COMMENT",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$NAME",
        "Type": "$TYPE",
        "TTL": $TTL,
        "ResourceRecords": [ { "Value": "$IP" } ]
      }
    }
  ]
}
EOF

if (( DRY_RUN )); then
	note "Dry run — change batch that would be submitted to zone $ZONE_ID:"
	cat "$batch_file"
	exit 0
fi

note "Submitting UPSERT: $NAME $TYPE -> $IP (TTL ${TTL}s)"
aws_capture route53 change-resource-record-sets \
	--hosted-zone-id "$ZONE_ID" \
	--change-batch "file://$batch_file" \
	--query ChangeInfo.Id --output text \
	|| die "change-resource-record-sets failed: ${AWS_ERR:-unknown error}" 3

change_id="${AWS_OUT##*/}"
note "Change submitted: $change_id"

if (( SKIP_WAIT )); then
	note "Skipping propagation wait (--no-wait)"
else
	note "Waiting for change to reach INSYNC (usually under a minute)"
	if ! aws "${aws_args[@]}" route53 wait resource-record-sets-changed \
		--id "$change_id" 2>/dev/null; then
		warn "wait returned non-zero; check status with:"
		warn "  aws route53 get-change --id $change_id"
	else
		note "Change is INSYNC across Route 53"
	fi
fi

# --- Verify ------------------------------------------------------------------

resolver=""
for candidate in dig host nslookup; do
	command -v "$candidate" >/dev/null 2>&1 && { resolver="$candidate"; break; }
done

if [[ -z "$resolver" ]]; then
	warn "no dig/host/nslookup available — skipping resolution check"
	note "Done. Verify on the web host with: dig +short $NAME $TYPE"
	exit 0
fi

note "Checking public resolution with $resolver"
case "$resolver" in
	dig)     resolved="$(dig +short "$NAME" "$TYPE" | tail -1)" ;;
	host)    resolved="$(host -t "$TYPE" "$NAME" 2>/dev/null | awk '{print $NF}' | tail -1)" ;;
	nslookup) resolved="$(nslookup -type="$TYPE" "$NAME" 2>/dev/null | awk '/^Address: /{print $2}' | tail -1)" ;;
esac

if [[ "$resolved" == "$IP" ]]; then
	note "$NAME resolves to $IP — ready for Caddy"
else
	warn "$NAME resolved to '${resolved:-nothing}', expected '$IP'"
	warn "your local resolver may have cached a negative answer; retry shortly."
	warn "what matters is resolution from the web host, since Caddy's ACME"
	warn "validation runs from there. Confirm before reloading Caddy:"
	warn "  dig +short $NAME $TYPE"
fi
