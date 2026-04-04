# Pawcap

Autonomous WiFi handshake capture tool for Raspberry Pi. Scans nearby networks, captures WPA/WPA2 handshakes via PMKID, deauth, and passive methods, learns from failures, and serves a real-time web dashboard -- all unattended.

## Features

- **Multi-strategy capture** -- PMKID, deauthentication + 4-way handshake, and passive listening
- **Smart targeting** -- Scoring algorithm prioritizes networks by signal, clients, encryption, and past results
- **Persistent learning** -- Tracks successes and failures per network across reboots, decays over time
- **Dual-band support** -- Simultaneous 2.4GHz and 5GHz scanning with two adapters
- **Bonus captures** -- Automatically saves handshakes from non-target networks on the same channel
- **Real-time web UI** -- Dashboard with live stats, activity feed, theme customization, and device controls
- **GPS tagging** -- Captures tagged with coordinates when a USB GPS module is connected
- **Battery monitoring** -- Geekworm X728 UPS HAT support with capacity, voltage, and health reporting
- **Whitelist protection** -- Your own networks are never targeted
- **Blacklist with retrace** -- Failed networks are deprioritized, then retried on alternate bands
- **Social mode** -- Discovers nearby Pawcap and Pwnagotchi devices via beacon frames
- **Organic mode** -- Randomized naturalistic behavior breaks between scan cycles
- **Dog personality** -- Configurable device name, ASCII faces, moods, and activity messages

## Requirements

- Raspberry Pi 4 (2GB+ RAM)
- USB WiFi adapter with monitor mode and packet injection support
- Raspberry Pi OS Lite (64-bit)

## Setup

See [DOCUMENTATION.md](DOCUMENTATION.md) for full installation instructions, configuration reference, API endpoints, and troubleshooting.

## License

MIT -- see [DOCUMENTATION.md](DOCUMENTATION.md#license) for details.
