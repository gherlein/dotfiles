#!/usr/bin/env bash
# Fail if any shipped skill references an UNDECLARED plugin namespace.
#
# Declared-dependency invariant: skills under skills/ may reference the
# `gherlein:` namespace (this plugin) and the namespaces of declared runtime
# dependencies. Today those are `superpowers:` (required -- the plugin builds on
# the Superpowers pipeline) and `claude-security:` (recommended -- used by the
# Phase D security review). `build-autonomous` verifies both via a preflight (see
# skills/build-autonomous/SKILL.md, Phase 0): superpowers is a hard gate,
# claude-security is a warning. A reference to any OTHER plugin namespace is an
# error: it is an undeclared dependency, almost always a typo or a stray
# copy-paste. URL schemes (http, https, ...) are not skill references and are
# allowed.
#
# To add a new declared dependency: append its namespace to $allow below AND
# document/verify it (README prerequisites + a preflight in the skill that needs
# it), so the dependency is enforced at runtime, not just permitted here.
#
# The pristine baseline under vendor/ is intentionally NOT checked -- it is an
# unmodified upstream snapshot and legitimately contains upstream namespaces.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skills_dir="$repo_root/skills"

# A skill reference looks like `<namespace>:<skill-name>` with no space after
# the colon. Declared-dependency namespaces and URL schemes are stripped before
# we look for any survivors (which would be undeclared foreign references).
allow='gherlein|superpowers|claude-security|https?|ftp|ftps|git|ssh|file|mailto|data|tel'

# MAC-address octets (e.g. `aa:bb:cc:dd:ee:ff`) tokenize into hex pairs like
# `aa:bb` that match the namespace pattern. A namespace ref never has both sides
# be two hex digits, so drop trailing two-hex:two-hex matches to avoid false
# positives from example MAC addresses in skills.
offenders="$(
  grep -rEno '\b[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]+' "$skills_dir" --include=SKILL.md \
    | grep -vE ":(${allow}):" \
    | grep -vE ':[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$' \
    || true
)"

if [[ -n "$offenders" ]]; then
  echo "ERROR: undeclared plugin-namespace references found in shipped skills:" >&2
  echo "$offenders" >&2
  echo >&2
  echo "Skills may reference only declared namespaces (gherlein:, superpowers:)." >&2
  echo "Add a new dependency to \$allow in this script only after documenting and" >&2
  echo "preflighting it; otherwise fix the reference." >&2
  exit 1
fi

echo "OK: no undeclared plugin-namespace references in skills/"
