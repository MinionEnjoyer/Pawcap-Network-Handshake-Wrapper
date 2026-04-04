#!/bin/bash
# Pawcap Quick Deploy
# Pushes local files to the Pi and restarts the service.
# Run from the Pawcap directory on your dev machine.
#
# Usage:
#   ./deploy.sh              # Deploy all files
#   ./deploy.sh scanner      # Deploy only wifi_scanner.py
#   ./deploy.sh web          # Deploy only web files
#   ./deploy.sh config       # Deploy only settings.json

set -e

PI_USER="pi"                    # SSH username on the Pi
PI_HOST="192.168.1.100"          # Pi's IP address on your LAN
PI_PASS="YOUR_PASSWORD_HERE"     # SSH password (or use key auth)
REMOTE_DIR="/opt/pawcap"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check sshpass is installed
if ! command -v sshpass &>/dev/null; then
    echo "Error: sshpass is required. Install with: brew install hudochenkov/sshpass/sshpass"
    exit 1
fi

SSH="sshpass -p $PI_PASS ssh -o StrictHostKeyChecking=no ${PI_USER}@${PI_HOST}"
SCP="sshpass -p $PI_PASS scp -o StrictHostKeyChecking=no"

deploy_file() {
    local src="$1"
    local dest="$2"
    local name=$(basename "$src")
    $SCP "$src" "${PI_USER}@${PI_HOST}:/tmp/${name}"
    $SSH "echo '$PI_PASS' | sudo -S cp /tmp/${name} ${dest}" 2>/dev/null
    echo "  $name -> $dest"
}

deploy_all() {
    echo "Deploying all files..."
    deploy_file "$SCRIPT_DIR/pawcap_daemon.py"    "$REMOTE_DIR/pawcap_daemon.py"
    deploy_file "$SCRIPT_DIR/wifi_scanner.py"     "$REMOTE_DIR/wifi_scanner.py"
    deploy_file "$SCRIPT_DIR/web_server.py"       "$REMOTE_DIR/web_server.py"
    deploy_file "$SCRIPT_DIR/pawcap_db.py"        "$REMOTE_DIR/pawcap_db.py"
    deploy_file "$SCRIPT_DIR/gps_logger.py"       "$REMOTE_DIR/gps_logger.py"
    deploy_file "$SCRIPT_DIR/battery_monitor.py"  "$REMOTE_DIR/battery_monitor.py"
    deploy_file "$SCRIPT_DIR/config/settings.json" "$REMOTE_DIR/config/settings.json"
    deploy_file "$SCRIPT_DIR/web/app.js"          "$REMOTE_DIR/web/app.js"
    deploy_file "$SCRIPT_DIR/web/index.html"      "$REMOTE_DIR/web/index.html"
    deploy_file "$SCRIPT_DIR/web/style.css"       "$REMOTE_DIR/web/style.css"
}

deploy_scanner() {
    echo "Deploying scanner..."
    deploy_file "$SCRIPT_DIR/wifi_scanner.py" "$REMOTE_DIR/wifi_scanner.py"
}

deploy_web() {
    echo "Deploying web files..."
    deploy_file "$SCRIPT_DIR/web_server.py"   "$REMOTE_DIR/web_server.py"
    deploy_file "$SCRIPT_DIR/web/app.js"      "$REMOTE_DIR/web/app.js"
    deploy_file "$SCRIPT_DIR/web/index.html"  "$REMOTE_DIR/web/index.html"
    deploy_file "$SCRIPT_DIR/web/style.css"   "$REMOTE_DIR/web/style.css"
}

deploy_config() {
    echo "Deploying config..."
    deploy_file "$SCRIPT_DIR/config/settings.json" "$REMOTE_DIR/config/settings.json"
}

restart_service() {
    echo "Restarting pawcap service..."
    $SSH "nohup bash -c 'echo $PI_PASS | sudo -S systemctl restart pawcap' &>/dev/null &" 2>/dev/null
    sleep 8
    # Check if it came up
    STATUS=$($SSH "echo '$PI_PASS' | sudo -S systemctl is-active pawcap 2>/dev/null" 2>/dev/null)
    if [ "$STATUS" = "active" ]; then
        echo "Pawcap is running."
    else
        echo "Warning: service status is '$STATUS'. Check with: sudo systemctl status pawcap"
    fi
}

case "${1:-all}" in
    all)      deploy_all ;;
    scanner)  deploy_scanner ;;
    web)      deploy_web ;;
    config)   deploy_config ;;
    *)
        echo "Usage: $0 [all|scanner|web|config]"
        exit 1
        ;;
esac

restart_service
echo "Done."
