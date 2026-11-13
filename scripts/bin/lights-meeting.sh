#!/bin/bash
# lights-meeting.sh - gocamdet hook: set the meeting light from device state.
# gocamdet passes one event ($1): cam-only-on | both-on | mic-only-on | off.
# The event-to-color mapping lives in the pctl groups file (group
# meeting-status): camera -> red, mic only -> blue, off -> off.
# gocamdet runs as root, so the config path is explicit rather than root's own.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 {cam-only-on|both-on|mic-only-on|off}" >&2
    exit 1
fi

exec /home/gherlein/bin/pctl --quiet --config /home/gherlein/.config/pctl/config.yaml meeting-status "$1"
