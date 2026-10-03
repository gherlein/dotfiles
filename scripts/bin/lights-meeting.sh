#!/bin/bash
# lights-meeting.sh - set the meeting-status Kauf RGBWW bulb from device state.
# Driven by gocamdet transition events (passed as $1):
#   cam-only-on | both-on -> red   (camera in use)
#   mic-only-on           -> blue  (microphone only)
#   off                   -> off   (camera and mic both idle)
# Controls the bulb via the ESPHome web REST API (light object_id kauf_bulb_59629d).

BULB="http://lights-meeting/light/kauf_bulb_59629d"

case "$1" in
    cam-only-on|both-on)
        curl -s -o /dev/null -X POST "$BULB/turn_on?brightness=240&color_mode=rgb&r=255&g=0&b=0"
        ;;
    mic-only-on)
        curl -s -o /dev/null -X POST "$BULB/turn_on?brightness=240&color_mode=rgb&r=0&g=0&b=255"
        ;;
    off)
        curl -s -o /dev/null -X POST "$BULB/turn_off"
        ;;
    *)
        echo "usage: $0 {cam-only-on|both-on|mic-only-on|off}" >&2
        exit 1
        ;;
esac
