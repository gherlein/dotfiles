#!/bin/bash
# lights-meeting.sh - set the meeting-status Kauf RGBWW bulb by mode.
#   on -> red, off -> off.
# Controls the bulb via the ESPHome web REST API (light object_id kauf_bulb_59629d).

BULB="http://lights-meeting/light/kauf_bulb_59629d"

if [ "$1" = "on" ]; then
    curl -s -o /dev/null -X POST "$BULB/turn_on?brightness=240&color_mode=rgb&r=255&g=0&b=0"
fi
if [ "$1" = "off" ]; then
    curl -s -o /dev/null -X POST "$BULB/turn_off"
fi
