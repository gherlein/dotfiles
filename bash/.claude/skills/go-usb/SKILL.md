---
name: go-usb
description: Go USB device development with gousb, karalabe/usb, serial ports, HID, udev rules, and troubleshooting
disable-model-invocation: true
---

# Go USB Device Development

## Library Selection

| Library | Use Case | Notes |
|---------|----------|-------|
| `gousb` | Comprehensive USB access | CGO required, wraps libusb |
| `karalabe/usb` | HID + generic USB | Self-contained, no libusb dep |
| `karalabe/hid` | HID devices only | Lightweight |
| `go.bug.st/serial` | USB-serial ports | Pure Go on Linux |

## Linux udev Rules

For non-root USB device access, create `/etc/udev/rules.d/99-usb.rules`:
```
SUBSYSTEM=="usb", ATTR{idVendor}=="XXXX", ATTR{idProduct}=="YYYY", MODE="0666"
```
Then: `sudo udevadm control --reload-rules && sudo udevadm trigger`

## USB Concepts

- Device hierarchy: Device > Configuration > Interface > Endpoint
- Endpoint types: Control (ep0), Bulk (data), Interrupt (events), Isochronous (streaming)
- Endpoint addresses: bit 7 indicates direction (0x80 = IN, 0x00 = OUT)

## Best Practices

- Close resources in reverse order of opening (endpoint -> interface -> config -> device)
- Use `SetAutoDetach(true)` to handle kernel driver detachment
- Size buffers using `MaxPacketSize` from the endpoint descriptor
- Implement hot-plug detection for dynamic device attachment

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| Permission denied | Missing udev rules | Add udev rule, reload |
| Device busy | Kernel driver attached | `SetAutoDetach(true)` |
| Device not found | Wrong VID/PID or unplugged | Verify with `lsusb` |
| Timeout | Device not responding | Check endpoint direction and type |
| macOS dylib issues | libusb not found | `brew install libusb`, set `DYLD_LIBRARY_PATH` |
| CGO cross-compile | Missing cross-compiler | Install target toolchain, set `CC` |
