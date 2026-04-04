#!/usr/bin/env python3
"""
Pawcap - Main Daemon
Lightweight autonomous WiFi auditing daemon with GPS logging
"""

import sys
import time
import signal
import threading
from wifi_scanner import WiFiScanner
from gps_logger import GPSLogger
from pawcap_db import PawcapDatabase
from web_server import WebServer
import json
import os
import subprocess

class PawcapDaemon:
    def __init__(self, config_path='/opt/pawcap/config/settings.json'):
        self.running = False
        self.config = self.load_config(config_path)
        self.scanner = None
        self.gps = None
        self.db = None
        self.web_server = None
        self.on_lan = False
        
    def load_config(self, path):
        """Load configuration"""
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        # Fallback config
        return {
            'device': {'lan_network': '192.168.1.0/24', 'web_port': 8080},
            'wifi': {'interface': 'wlan0'},
            'gps': {'enabled': True},
            'capture': {'database': '/opt/pawcap/data/handshakes.db'},
            'performance': {'web_only_on_lan': True}
        }
    
    def start(self):
        """Start the daemon"""
        print("=" * 60)
        print("🐕 Pawcap - Autonomous WiFi Auditor")
        print("=" * 60)
        
        self.running = True
        
        # Initialize components
        self.db = PawcapDatabase(self.config['capture']['database'])
        
        # GPS starts off by default — user enables via web UI toggle
        self.gps = GPSLogger(self.config)
        if self.config['gps'].get('auto_start', False):
            self.gps.start()
            print("✓ GPS logging enabled")
        else:
            print("✓ GPS ready (enable via web UI)")
        
        self.scanner = WiFiScanner(self.config, self.gps, self.db)
        self.scanner.start()
        print("✓ WiFi scanner started")
        
        # Check if we're on LAN and start web server if needed
        if self.config['performance']['web_only_on_lan']:
            lan_check_thread = threading.Thread(target=self.lan_monitor, daemon=True)
            lan_check_thread.start()
        
        print("\n🚀 Pawcap is active and hunting!\n")
        
        # Main loop
        try:
            while self.running:
                self.print_status()
                time.sleep(10)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the daemon"""
        print("\n\nStopping Pawcap...")
        self.running = False
        
        if self.scanner:
            self.scanner.stop()
        
        if self.gps:
            self.gps.stop()
        
        if self.web_server:
            self.web_server.stop()
        
        print("Goodbye! 🐕")
        sys.exit(0)
    
    def lan_monitor(self):
        """Monitor LAN connection and manage web server"""
        while self.running:
            was_on_lan = self.on_lan
            self.on_lan = self.check_lan_connection()
            
            if self.on_lan and not was_on_lan:
                # Just connected to LAN - start web server
                print("\n📡 LAN detected - Starting web interface...")
                self.start_web_server()
            elif not self.on_lan and was_on_lan:
                # Disconnected from LAN - stop web server
                print("\n📴 LAN lost - Stopping web interface (battery save mode)...")
                self.stop_web_server()
            
            time.sleep(5)  # Check every 5 seconds
    
    def check_lan_connection(self):
        """Check if we're connected to the home LAN"""
        try:
            result = subprocess.run(['hostname', '-I'], 
                                  capture_output=True, text=True, timeout=2)
            ip_addresses = result.stdout.strip().split()
            
            # Check if any IP is in the LAN network
            lan_network = self.config['device']['lan_network'].split('/')[0].rsplit('.', 1)[0]
            for ip in ip_addresses:
                if ip.startswith(lan_network):
                    return True
            return False
        except:
            return False
    
    def start_web_server(self):
        """Start the web interface"""
        if not self.web_server:
            self.web_server = WebServer(self.config, self.scanner, self.gps, self.db)
            self.web_server.start()
    
    def stop_web_server(self):
        """Stop the web interface"""
        if self.web_server:
            self.web_server.stop()
            self.web_server = None
    
    def print_status(self):
        """Print current status to console"""
        stats = self.scanner.get_stats() if self.scanner else {}
        gps_data = self.gps.get_current() if self.gps else {}
        
        print(f"\r[{time.strftime('%H:%M:%S')}] " 
              f"Networks: {stats.get('networks', 0)} | "
              f"Handshakes: {stats.get('handshakes', 0)} | "
              f"Channel: {stats.get('channel', '?')} | "
              f"GPS: {'✓' if gps_data.get('fix') else '✗'} | "
              f"Web: {'ON' if self.web_server else 'OFF'}", end='')

def main():
    # Setup signal handlers
    daemon = PawcapDaemon()
    signal.signal(signal.SIGINT, lambda s, f: daemon.stop())
    signal.signal(signal.SIGTERM, lambda s, f: daemon.stop())
    
    # Start daemon
    daemon.start()

if __name__ == '__main__':
    main()
