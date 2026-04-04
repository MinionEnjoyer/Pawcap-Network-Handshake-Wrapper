# Pawcap Documentation

**Pawcap** is an autonomous WiFi auditing tool that runs on a Raspberry Pi. It scans for nearby networks, captures WPA/WPA2 handshakes using multiple attack strategies, and learns from its successes and failures over time. It has a real-time web UI, GPS tagging, battery monitoring, and a dog-themed personality system.

**GitHub:** [github.com/MinionEnjoyer](https://github.com/MinionEnjoyer)
**License:** MIT

---

## Legal Disclaimer

Pawcap is intended for **authorized security testing and educational purposes only**. Capturing WiFi handshakes from networks you don't own or have explicit permission to test is illegal in most jurisdictions.

**You are responsible for:**
- Only targeting networks you own or have written authorization to test
- Adding your own networks to the whitelist to prevent accidental capture
- Complying with all applicable local, state, and federal laws
- Understanding that deauthentication attacks disrupt legitimate network connections

The authors assume no liability for misuse of this tool.

---

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [How It Works](#how-it-works)
6. [Attack Methods](#attack-methods)
7. [Scoring & Targeting](#scoring--targeting)
8. [Learning System](#learning-system)
9. [Web Interface](#web-interface)
10. [GPS Integration](#gps-integration)
11. [Battery Monitoring](#battery-monitoring)
12. [Social Mode](#social-mode)
13. [Organic Mode](#organic-mode)
14. [Whitelist & Blacklist](#whitelist--blacklist)
15. [Deployment & Updates](#deployment--updates)
16. [Troubleshooting](#troubleshooting)
17. [File Reference](#file-reference)
18. [API Reference](#api-reference)
19. [Legal Disclaimer](#legal-disclaimer)
20. [License](#license)

---

## Hardware Requirements

### Required

| Component | Notes |
|-----------|-------|
| **Raspberry Pi 4** | 2GB+ RAM recommended |
| **USB WiFi Adapter** | Must support monitor mode + packet injection. Recommended chipsets: Atheros AR9271, Ralink RT3070, Realtek RTL8812AU |
| **MicroSD Card** | 16GB+ |
| **Power Supply** | 5V 3A USB-C, or UPS HAT for portable use |

### Optional

| Component | Notes |
|-----------|-------|
| **Second USB WiFi Adapter** | Enables dual-mode: simultaneous scanning + capturing on separate bands |
| **USB GPS Module** | Serial NMEA GPS (e.g., VK-162, BN-220). Enables location tagging on captures |
| **Geekworm X728 UPS HAT** | Battery monitoring, portable operation, graceful shutdown |

### Dual-Mode vs Single-Mode

- **Single adapter**: Time-shares between scanning and capturing. Stops scanning during capture attempts.
- **Two adapters**: One scans continuously while the other captures. Significantly faster and more effective.

---

## Installation

### 1. Flash Raspberry Pi OS

Flash **Raspberry Pi OS Lite (64-bit)** to your MicroSD card. Enable SSH during flashing.

### 2. Transfer Files to the Pi

From your computer:

```bash
scp -r pawcap/ pi@<PI_IP>:/tmp/pawcap-src/
```

### 3. Run Setup

SSH into the Pi and run:

```bash
ssh pi@<PI_IP>
sudo bash /tmp/pawcap-src/setup.sh
```

The setup script will:
- Detect your USB WiFi adapter(s)
- Ask you to **name your device** (this name appears in the UI and logs)
- Install system packages: `aircrack-ng`, `python3`, `sqlite3`, `network-manager`, etc.
- Install Python packages: `flask`, `flask-cors`, `pyserial`
- Create the directory structure at `/opt/pawcap/`
- Copy all application files
- Install and enable the systemd service
- Preserve existing config if upgrading

### 4. Configure Your Whitelist

Edit `/opt/pawcap/config/whitelist.conf` and add your own network SSIDs (one per line). These networks will **never** be targeted:

```
MyHomeNetwork
MyHomeNetwork_5G
```

### 5. Start Pawcap

```bash
sudo systemctl start pawcap
```

### 6. Access the Web UI

Open a browser and go to:

```
http://<PI_IP>:8080
```

The web server only starts when the Pi is connected to your LAN (configurable).

---

## Configuration

All settings live in `/opt/pawcap/config/settings.json`. The setup script writes initial values, but you can edit them anytime.

```json
{
  "device": {
    "name": "Pawcap",
    "lan_network": "192.168.1.0/24",
    "lan_ip": "192.168.1.100",
    "web_port": 8080
  },
  "wifi": {
    "interface": "wlan1",
    "capture_interface": "wlan2",
    "channel_hop_interval": 2,
    "auto_deauth": true,
    "deauth_packets": 10,
    "min_signal_strength": -85,
    "skip_no_clients": true,
    "smart_targeting": true,
    "organic_mode": true,
    "social_mode": false
  },
  "gps": {
    "enabled": true,
    "device": "/dev/ttyUSB0",
    "baud_rate": 9600
  },
  "capture": {
    "handshake_dir": "/opt/pawcap/captures/handshakes",
    "database": "/opt/pawcap/data/handshakes.db",
    "max_capture_time": 120
  },
  "whitelist": {
    "enabled": true,
    "file": "/opt/pawcap/config/whitelist.conf"
  },
  "performance": {
    "web_only_on_lan": true
  }
}
```

### Key Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `device.name` | Pawcap | Your device's name. Appears in the UI, logs, and social beacons. Set during setup. |
| `device.lan_network` | 192.168.1.0/24 | Your home LAN subnet. Web server only starts when connected to this network. |
| `device.web_port` | 8080 | Port for the web UI |
| `wifi.interface` | wlan1 | Primary scanning adapter (auto-detected during setup) |
| `wifi.capture_interface` | wlan2 | Second adapter for dedicated capture. Leave empty for single-mode. |
| `wifi.channel_hop_interval` | 2 | Seconds spent on each channel during scanning |
| `wifi.auto_deauth` | true | Send deauthentication frames to force handshake captures |
| `wifi.deauth_packets` | 10 | Number of deauth frames per burst |
| `wifi.min_signal_strength` | -85 | Minimum signal (dBm) to consider a network targetable |
| `wifi.skip_no_clients` | true | Don't attempt deauth on networks with no visible clients |
| `wifi.smart_targeting` | true | Use the scoring algorithm to pick the best target |
| `wifi.organic_mode` | true | Enable naturalistic behavior breaks between scan cycles |
| `wifi.social_mode` | false | Broadcast beacons and discover other Pawcap/Pwnagotchi devices |
| `gps.enabled` | true | Enable GPS module |
| `gps.device` | /dev/ttyUSB0 | Serial device path for GPS |
| `capture.max_capture_time` | 120 | Maximum seconds per capture attempt before timeout |
| `performance.web_only_on_lan` | true | Only run the web server when connected to your home LAN (saves battery) |

---

## Usage

### Service Commands

```bash
sudo systemctl start pawcap      # Start
sudo systemctl stop pawcap       # Stop
sudo systemctl restart pawcap    # Restart
sudo systemctl status pawcap     # Check status
sudo journalctl -u pawcap -f     # Live logs
```

### Web UI Controls

The web interface at `http://<PI_IP>:8080` provides toggle controls for:

- **Scanner** — Start/stop WiFi scanning and capture
- **GPS** — Enable/disable GPS logging
- **Character** — Show/hide the ASCII dog character and mood
- **Feed** — Show/hide the live activity log
- **Organic** — Toggle organic mode (naturalistic behavior breaks)
- **Social** — Toggle social mode (peer discovery)
- **Settings** — Theme customization

### Portable Operation

When running on battery (away from your LAN):
1. The web server is disabled to save power
2. Pawcap runs fully autonomously — scanning, capturing, and learning
3. When you return home and connect to your LAN, the web server starts automatically
4. All captures and stats are available in the web UI

---

## How It Works

### Scan Cycle

Pawcap operates in continuous sweep cycles:

1. **Channel Sweep** — Hops through all WiFi channels, spending more time on high-traffic ones (channels 1, 6, 11 get 5 seconds; others get 2 seconds)
2. **Network Discovery** — Parses airodump-ng output to build a list of visible networks with signal strength, encryption type, client count, and channel
3. **Target Selection** — Scores all discovered networks and picks the best candidate
4. **Capture Attempt** — Runs the appropriate attack based on the target's characteristics
5. **Passive Check** — Checks background pcap files for handshakes captured without active attacks
6. **Learning Update** — Records success/failure to the database for future targeting decisions
7. **Repeat** — Starts the next sweep

### Band Scanning

Pawcap scans in escalating phases:

1. **2.4 GHz** (channels 1–14) — Most common, scanned every cycle
2. **5 GHz Safe** (channels 36, 40, 44, 48, 149, 153, 157, 161, 165) — Non-DFS channels
3. **5 GHz DFS** (channels 52–144) — Radar-shared channels, scanned less frequently

In dual-mode, both bands are scanned simultaneously on separate adapters.

---

## Attack Methods

Pawcap uses multiple attack strategies, ordered by effectiveness:

### 1. PMKID Capture (hcxdumptool)

- **How**: Sends association requests to the AP. Some routers respond with a PMKID hash in the first message — no clients needed.
- **Time**: ~60 seconds per attempt
- **Requires**: hcxdumptool v6+ installed (`sudo apt install hcxdumptool`)
- **Best for**: WPA2 networks, even with no connected clients
- **Bonus captures**: When running on a channel, hcxdumptool may capture PMKIDs from *other* networks on the same channel. These are saved automatically as free wins.

### 2. Deauthentication + 4-Way Handshake

- **How**: Sends deauth frames to disconnect clients from the AP. When they reconnect, the WPA 4-way handshake is captured.
- **Time**: 15–120 seconds per attempt
- **Requires**: At least one client connected to the target network
- **Best for**: Networks with active clients

### 3. Passive Capture

- **How**: Listens for handshakes that occur naturally (clients roaming, reconnecting, etc.) without sending any deauth frames.
- **Time**: Runs continuously in the background
- **Best for**: WPA3 networks (which are deauth-resistant) and stealthy operation

### Capture Files

Handshakes are saved to `/opt/pawcap/captures/handshakes/` as:
- `.pcapng` files (PMKID captures from hcxdumptool)
- `.cap` files (4-way handshakes from airodump-ng)
- `.22000` hash files (hashcat-ready format, extracted automatically)

---

## Scoring & Targeting

When `smart_targeting` is enabled, each visible network gets a score (0–100+). The highest-scoring network is targeted next.

### Score Breakdown

| Factor | Points | Details |
|--------|--------|---------|
| **Signal Strength** | 0–35 | -30 dBm = 35 pts, -85 dBm = 0 pts, linear scale |
| **Client Count** | 0–25 | More clients = more handshake opportunities |
| **Encryption** | 0–15 | WPA2 (15) > WPA2/WPA3-mixed (13) > WPA1 (12) > WPA3-only (2–5) |
| **WPS Enabled** | 0–20 | Unlocked WPS networks get +20 (Pixie-Dust opportunity) |
| **Failure Penalty** | -40 to 0 | Consecutive failures reduce score exponentially |
| **Recent Failure** | -15 to 0 | Failed earlier this session |
| **Channel Congestion** | -10 to 0 | Crowded channels are harder to work on |

### Targeting Rules

A network is **skippable** if:
- It's in the whitelist
- It's already been captured this session
- Signal is below `min_signal_strength`
- It has no clients and `skip_no_clients` is enabled (deauth only — PMKID doesn't need clients)
- It has 5+ consecutive failures (blacklisted)
- It was attempted in the last 10 minutes (cooldown)

---

## Learning System

Pawcap maintains a persistent SQLite database that tracks every network it encounters. This knowledge persists across reboots and sessions.

### What It Tracks Per Network

| Field | Purpose |
|-------|---------|
| `total_attempts` | Lifetime capture attempts |
| `total_successes` | Lifetime successful captures |
| `consecutive_failures` | Current failure streak |
| `last_failure_reason` | Why the last attempt failed (timeout, no clients, WPA3, etc.) |
| `max_clients` | Highest client count ever observed |
| `best_signal` | Strongest signal ever seen |
| `attempted_bands` | Which frequency bands have been tried (2.4, 5, or both) |

### Failure Decay

Failure counts decay over time so networks get retried eventually:
- **Infrastructure errors** (interface issues, tool crashes): Decay 1 point per 4 hours
- **Network-specific failures** (timeout, no handshake): Decay 1 point per 24 hours

### Blacklist & Retrace

Networks with 5+ consecutive failures are **blacklisted** — skipped during normal targeting. However, before permanent blacklist:
- If only attempted on 2.4 GHz, Pawcap will search for the same SSID on 5 GHz channels (retrace phase)
- The blacklist can be cleared from the web UI

---

## Web Interface

### Dashboard

The main page shows real-time stats updating every 1–10 seconds:

- **Character panel** — ASCII dog face with mood and activity message
- **System stats** — Battery, uptime, CPU temperature, storage
- **Scan stats** — Networks seen, candidates, handshakes, success rate
- **Scanner activity** — Current mode, channel, interface status, active target
- **Auth activity** — Capture stats, deauth count, GPS status, learning stats
- **Recent networks** — Last 10 discovered networks with signal, encryption, score
- **Handshakes** — All captured handshakes with timestamps, GPS coordinates, cracked status
- **Blacklist** — Failed networks with failure reasons and retry info
- **Protected networks** — Your whitelist entries
- **Social/Friends** — Other Pawcap/Pwnagotchi devices encountered (when social mode is on)

### Themes

6 built-in themes plus custom theme support:

| Theme | Colors |
|-------|--------|
| **Redline** | Red, black, white (default) |
| **Forest** | Green tones |
| **Oasis** | Brown, tan |
| **Professional** | Blue, white |
| **Subaru** | Blue, gold |
| **Ferrari** | Red, gold |

Custom themes are saved to localStorage and persist across sessions. You can create unlimited custom themes with the color pickers.

### Activity Feed

A live-scrolling log of everything Pawcap is doing, color-coded by type:
- **INFO** — General status updates
- **SUCCESS** — Handshake captured
- **TARGET** — New target selected
- **DEAUTH** — Deauth frames sent
- **WARN** — Warnings (timeouts, failures)
- **ERROR** — Errors (interface issues, crashes)

---

## GPS Integration

### Hardware

Any USB serial GPS module that outputs NMEA sentences will work. Recommended: VK-162 or BN-220.

### Setup

1. Plug the GPS module into a USB port
2. Verify it shows up: `ls /dev/ttyUSB*` or `ls /dev/ttyACM*`
3. Set the device path in `settings.json` under `gps.device`
4. Enable GPS from the web UI toggle (or set `gps.auto_start: true` in config)

### What It Does

- Parses NMEA sentences (GPGGA, GPRMC) for latitude, longitude, altitude, satellite count
- Tags every captured handshake with GPS coordinates
- Displays fix status and coordinates in the web UI
- Handshakes with GPS data get a "GPS" badge in the UI

---

## Battery Monitoring

### Hardware

Supports the **Geekworm X728 UPS HAT** via I2C (address 0x36, bus 1).

### Features

- Real-time voltage and capacity percentage
- Charging status detection (AC power connected)
- Health status: Excellent (>80%), Good (50–80%), Fair (20–50%), Low (10–20%), Critical (<10%)
- Estimated runtime calculation
- Low battery alerts at 20% and 10%
- Displayed in the web UI header stats

If no X728 is detected, battery monitoring is silently disabled.

---

## Social Mode

When enabled, Pawcap broadcasts custom beacon frames and listens for other devices.

### Compatible Devices

- Other Pawcap devices
- Pwnagotchi devices

### What It Does

- Broadcasts your device name, version, stats, and mood face
- Discovers nearby peers and records encounters
- Tracks encounter count, signal strength, and peer info
- Shows discovered friends in the web UI with their face, name, version, and stats

### Enable

Toggle "Social" in the web UI, or set `wifi.social_mode: true` in config.

---

## Organic Mode

Organic mode adds naturalistic, randomized behavior breaks between scan cycles (~35% chance per cycle).

### Behaviors

| Action | What It Does |
|--------|-------------|
| **Dig** | Extended listening on a random channel |
| **Scratch** | Brief scan pause |
| **Sniff** | Slow channel sweep with longer dwell times |
| **Roll Over** | Network reassessment phase |
| **Fetch** | Quick burst of scanning |
| **Hop Fence** | Jump to a distant channel |
| **Socialize** | Extended peer discovery window |

These breaks make scanning patterns less predictable and add personality to the device.

---

## Whitelist & Blacklist

### Whitelist (Protected Networks)

**Purpose**: Networks you own or don't want to target.

**Location**: `/opt/pawcap/config/whitelist.conf`

**Format**:
```
# Comments start with #
MyHomeNetwork
MyHomeNetwork_5G
WorkNetwork
```

Whitelisted networks are:
- Never targeted for deauth or capture
- Never saved as bonus PMKID captures
- Shown as "Protected" in the web UI

### Blacklist (Failed Networks)

**Purpose**: Automatically tracks networks that consistently fail.

**How it works**:
- Networks with 5+ consecutive failures are blacklisted
- Blacklisted networks are skipped during targeting
- Before permanent blacklist, Pawcap attempts a 5GHz retrace (in case the 2.4GHz BSSID is the problem)
- Failure counts decay over time (networks get retried eventually)
- You can clear the blacklist from the web UI

---

## Deployment & Updates

### deploy.sh

For pushing code updates from your dev machine to the Pi:

1. Edit `deploy.sh` and set your Pi's IP, username, and password
2. Install `sshpass` on your dev machine: `brew install sshpass` (macOS) or `apt install sshpass`

```bash
# Deploy everything
./deploy.sh all

# Deploy only the scanner
./deploy.sh scanner

# Deploy only web UI files
./deploy.sh web

# Deploy only config
./deploy.sh config
```

The script SCPs files to `/tmp/` on the Pi, then uses sudo to copy them to `/opt/pawcap/`, and restarts the service.

### Manual Deployment

```bash
scp wifi_scanner.py pi@<PI_IP>:/tmp/
ssh pi@<PI_IP> "sudo cp /tmp/wifi_scanner.py /opt/pawcap/ && sudo systemctl restart pawcap"
```

---

## Troubleshooting

### Pawcap won't start

```bash
sudo systemctl status pawcap
sudo journalctl -u pawcap --no-pager -n 50
```

Common causes:
- No USB WiFi adapter detected
- Interface name changed (check `ip link` and update `settings.json`)
- Python dependency missing (re-run `pip3 install flask flask-cors pyserial`)

### No handshakes being captured

- Check signal strength — networks below -85 dBm are usually too far
- Check if targets have clients — deauth needs at least one connected client
- Check the blacklist — networks with 5+ failures are skipped
- Check the whitelist — your own networks are protected
- Try PMKID mode — it doesn't need clients (requires hcxdumptool)
- Watch the activity feed for failure reasons

### Web UI not loading

- Verify you're on the same LAN subnet as `device.lan_network` in config
- Check the port: `ss -tlnp | grep 8080`
- If `web_only_on_lan` is true, the web server won't start unless the Pi sees a matching IP

### GPS not working

- Check the device path: `ls /dev/ttyUSB*`
- Test raw output: `cat /dev/ttyUSB0`
- Verify baud rate matches your GPS module (usually 9600)
- GPS modules need a clear sky view for initial fix (can take several minutes)

### Monitor mode issues

- Verify your adapter supports monitor mode: `iw phy phy0 info | grep monitor`
- Pawcap never runs `airmon-ng check kill` (which would kill your SSH connection). If networking is broken, your adapter may not support safe monitor mode toggling.
- Check for interfering processes: `airmon-ng check`

### hcxdumptool / PMKID not working

- Install it: `sudo apt install hcxdumptool hcxtools`
- Verify: `which hcxdumptool && hcxdumptool --version`
- hcxdumptool manages its own monitor mode — the interface must be in managed mode before it runs. Pawcap handles this automatically.
- Some APs (especially WPA3-only) don't respond to PMKID requests

---

## File Reference

```
/opt/pawcap/
├── pawcap_daemon.py        # Main entry point — starts all components
├── wifi_scanner.py         # Core scanner: channel hopping, attacks, learning
├── web_server.py           # Flask REST API + serves web UI
├── pawcap_db.py            # SQLite database for handshakes & knowledge
├── gps_logger.py           # GPS serial NMEA parser
├── battery_monitor.py      # X728 UPS HAT I2C battery monitor
├── config/
│   ├── settings.json       # All configuration
│   └── whitelist.conf      # Protected network SSIDs
├── web/
│   ├── index.html          # Web UI page
│   ├── app.js              # Frontend logic (real-time updates, themes)
│   └── style.css           # Styling and theme system
├── captures/
│   └── handshakes/         # Captured pcap/pcapng/hash files
├── data/
│   └── handshakes.db       # SQLite database
└── services/
    └── pawcap.service      # Systemd service file
```

---

## API Reference

All endpoints return JSON. Base URL: `http://<PI_IP>:8080`

### Status & Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Full system status: stats, GPS, battery, mood, interfaces, learning stats |
| GET | `/api/handshakes` | All captured handshakes with metadata |
| GET | `/api/handshakes/map` | Handshakes with GPS coordinates (for mapping) |
| GET | `/api/stats` | Database statistics (total, cracked, with-GPS counts) |
| GET | `/api/activity` | Recent activity feed entries (up to 100) |
| GET | `/api/blacklisted` | Networks with 5+ consecutive failures |
| GET | `/api/social/friends` | Social encounters with other devices |

### Controls

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/control/start` | — | Start WiFi scanner |
| POST | `/api/control/stop` | — | Stop WiFi scanner |
| POST | `/api/control/gps` | `{"enabled": bool}` | Toggle GPS |
| POST | `/api/control/organic` | — | Toggle organic mode |
| POST | `/api/control/social` | — | Toggle social mode |
| POST | `/api/blacklist/clear` | — | Reset all blacklisted networks |

### Settings

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/settings/name` | `{"name": "string"}` | Update device name (max 32 chars, persists to config) |

---

## License

MIT License

Copyright (c) 2026 [MinionEnjoyer](https://github.com/MinionEnjoyer)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
