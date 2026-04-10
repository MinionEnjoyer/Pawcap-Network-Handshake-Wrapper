#!/bin/bash
# Pawcap First-Time Setup
# Run this ON the Pi (or pipe via SSH) to set up a fresh installation.
#
# Usage (on the Pi):
#   sudo bash setup.sh
#
# Or from your dev machine after SCP'ing the whole project:
#   scp -r pawcap/ pi@<PI_IP_ADDRESS>:/tmp/pawcap-src/
#   ssh pi@<PI_IP_ADDRESS> "sudo bash /tmp/pawcap-src/setup.sh"

set -e

echo "=========================================="
echo "  Pawcap - First-Time Setup"
echo "=========================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/pawcap"

# --- Detect USB WiFi adapter ---
echo ""
echo "Detecting WiFi interfaces..."

# Helper: get supported bands for an interface
get_adapter_bands() {
    local iface="$1"
    local phy
    phy=$(cat "/sys/class/net/$iface/phy80211/name" 2>/dev/null || echo "")
    if [ -z "$phy" ]; then
        echo "unknown"
        return
    fi
    local has_24=false
    local has_5=false
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^\s+\* 2[0-9]{3}\.' ; then
            has_24=true
        fi
        if echo "$line" | grep -qE '^\s+\* 5[0-9]{3}\.' ; then
            has_5=true
        fi
    done < <(iw phy "$phy" info 2>/dev/null)
    if $has_24 && $has_5; then
        echo "dual-band (2.4GHz + 5GHz)"
    elif $has_5; then
        echo "5GHz only"
    elif $has_24; then
        echo "2.4GHz only"
    else
        echo "unknown"
    fi
}

# Helper: get chipset/driver for an interface
get_adapter_chipset() {
    local iface="$1"
    local device_path
    device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || echo "")
    if [ -z "$device_path" ]; then
        echo "unknown"
        return
    fi
    # Try USB product name first
    local product
    product=$(cat "$device_path/../product" 2>/dev/null || echo "")
    if [ -n "$product" ]; then
        echo "$product"
        return
    fi
    # Fall back to driver name
    local driver
    driver=$(basename "$(readlink -f "$device_path/driver" 2>/dev/null)" 2>/dev/null || echo "unknown")
    echo "$driver"
}

USB_ADAPTERS=()
for iface in $(ls /sys/class/net | grep -E '^wl'); do
    driver_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null || true)
    if echo "$driver_path" | grep -q "usb"; then
        USB_ADAPTERS+=("$iface")
        bands=$(get_adapter_bands "$iface")
        chipset=$(get_adapter_chipset "$iface")
        echo "  USB adapter: $iface ($chipset, $bands)"
    else
        echo "  Built-in:    $iface (will not be touched)"
    fi
done

if [ ${#USB_ADAPTERS[@]} -lt 1 ]; then
    echo ""
    echo "Error: No USB WiFi adapters detected."
    echo "Pawcap needs at least one USB WiFi adapter for scanning."
    exit 1
fi

SCAN_IFACE="${USB_ADAPTERS[0]}"
echo ""
echo "Using $SCAN_IFACE for scanning."
if [ ${#USB_ADAPTERS[@]} -gt 1 ]; then
    echo "Second adapter ${USB_ADAPTERS[1]} available for dedicated capture."
fi

# --- Name your device ---
echo ""
echo "Every good dog needs a name."
# Support non-interactive mode: use PAWCAP_NAME env var or hostname as fallback
if [ -t 0 ]; then
    read -p "  Name your device [Pawcap]: " DEVICE_NAME
    DEVICE_NAME="${DEVICE_NAME:-Pawcap}"
else
    DEVICE_NAME="${PAWCAP_NAME:-$(hostname)}"
    echo "  Non-interactive mode: using name '$DEVICE_NAME'"
fi
echo "  Welcome, $DEVICE_NAME!"

# --- Install system dependencies ---
echo ""
echo "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    python3 \
    python3-pip \
    python3-smbus \
    iw \
    wireless-tools \
    net-tools \
    sqlite3 \
    network-manager

# --- Install Python dependencies ---
echo ""
echo "Installing Python packages..."
pip3 install --break-system-packages -q \
    flask==3.0.0 \
    flask-cors==4.0.0 \
    pyserial==3.5 \
    scapy

# --- Create directory structure ---
echo ""
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/config"
mkdir -p "$INSTALL_DIR/web"
mkdir -p "$INSTALL_DIR/captures/handshakes"
mkdir -p "$INSTALL_DIR/data"

# --- Copy application files ---
echo ""
echo "Installing application files..."

for f in pawcap_daemon.py wifi_scanner.py web_server.py pawcap_db.py \
         gps_logger.py battery_monitor.py; do
    if [ -f "$SCRIPT_DIR/$f" ]; then
        cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/$f"
        echo "  $f"
    fi
done

chmod +x "$INSTALL_DIR/pawcap_daemon.py"

# --- Copy web files ---
if [ -d "$SCRIPT_DIR/web" ]; then
    cp "$SCRIPT_DIR/web/"* "$INSTALL_DIR/web/"
    echo "  web/ (app.js, index.html, style.css)"
fi

# --- Copy config (only if not already present — preserve existing) ---
if [ ! -f "$INSTALL_DIR/config/settings.json" ]; then
    cp "$SCRIPT_DIR/config/settings.json" "$INSTALL_DIR/config/settings.json"
    # Patch device name and detected interface into the config
    sed -i "s/\"name\": \"Pawcap\"/\"name\": \"$DEVICE_NAME\"/" \
        "$INSTALL_DIR/config/settings.json"
    sed -i "s/\"interface\": \"wlan1\"/\"interface\": \"$SCAN_IFACE\"/" \
        "$INSTALL_DIR/config/settings.json"
    echo "  config/settings.json (new, name=$DEVICE_NAME, interface=$SCAN_IFACE)"
else
    echo "  config/settings.json (existing — preserved)"
fi

if [ -f "$SCRIPT_DIR/config/whitelist.conf" ]; then
    cp "$SCRIPT_DIR/config/whitelist.conf" "$INSTALL_DIR/config/whitelist.conf"
    echo "  config/whitelist.conf"
fi

# --- Install systemd service ---
echo ""
echo "Installing systemd service..."
cp "$SCRIPT_DIR/services/pawcap.service" /etc/systemd/system/pawcap.service
systemctl daemon-reload
systemctl enable pawcap

echo ""
echo "=========================================="
echo "  $DEVICE_NAME is ready!"
echo "=========================================="
echo ""
echo "  Device name:  $DEVICE_NAME"
echo "  Install dir:  $INSTALL_DIR"
echo "  Scan adapter: $SCAN_IFACE"
echo "  Web port:     8080"
echo ""
echo "  Start:   sudo systemctl start pawcap"
echo "  Stop:    sudo systemctl stop pawcap"
echo "  Status:  sudo systemctl status pawcap"
echo "  Logs:    sudo journalctl -u pawcap -f"
echo ""
echo "  Web UI:  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
