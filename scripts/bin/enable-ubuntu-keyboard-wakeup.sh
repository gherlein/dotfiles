echo enabled | sudo tee /sys/bus/usb/devices/5-1.4.1/power/wakeup
sudo tee /etc/udev/rules.d/90-usb-wakeup.rules <<'EOF'
ACTION=="add", SUBSYSTEM=="usb", DRIVERS=="usbhid", ATTR{power/wakeup}="enabled"
EOF
sudo udevadm control --reload-rules
