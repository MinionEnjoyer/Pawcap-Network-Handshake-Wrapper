#!/usr/bin/env python3
"""
Pawcap - Web Server
Lightweight Flask server that only runs when connected to LAN
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import threading
import time
import socket
import getpass
import shutil

try:
    from battery_monitor import get_battery_monitor
except ImportError:
    get_battery_monitor = None

class WebServer:
    def __init__(self, config, scanner, gps, database):
        self.config = config
        self.scanner = scanner
        self.gps = gps
        self.db = database
        self.battery_monitor = None
        self.running = False
        self.server_thread = None
        self.start_time = time.time()  # Track server start time
        self._lifetime_stats_cache = {}
        self._lifetime_stats_time = 0
        
        # Create Flask app
        self.app = Flask(__name__, static_folder='web')
        CORS(self.app)
        
        # Register routes
        self._register_routes()
    
    def _safe_battery_read(self):
        """Read battery status with a timeout to prevent I2C hangs"""
        if not self.battery_monitor:
            return {'available': False}
        try:
            result = [None]
            def _read():
                result[0] = self.battery_monitor.get_status()
            t = threading.Thread(target=_read, daemon=True)
            t.start()
            t.join(timeout=2)
            if result[0] is not None:
                return result[0]
        except:
            pass
        return {'available': False}

    def _get_capture_count(self):
        """Thread-safe method to get current capture count"""
        if not self.scanner:
            return 0
        try:
            with self.scanner.capture_lock:
                return len(self.scanner.capturing)
        except:
            return 0
    
    def _get_social_encounters_snapshot(self):
        """Thread-safe method to get snapshot of social encounters"""
        if not self.scanner or not hasattr(self.scanner, 'social_encounters'):
            return []
        try:
            return list(self.scanner.social_encounters.items())
        except:
            return []
    
    def _get_network_knowledge_snapshot(self):
        """Thread-safe method to get snapshot of network knowledge"""
        if not self.scanner or not hasattr(self.scanner, 'network_knowledge'):
            return []
        try:
            return list(self.scanner.network_knowledge.items())
        except:
            return []
    
    def _register_routes(self):
        """Register Flask routes"""
        
        @self.app.route('/')
        def index():
            return send_from_directory('web', 'index.html')
        
        @self.app.route('/<path:path>')
        def serve_static(path):
            return send_from_directory('web', path)
        
        @self.app.route('/api/status')
        def get_status():
            """Get current system status"""
            stats = self.scanner.get_stats() if self.scanner else {}
            gps_data = self.gps.get_current() if self.gps else {}
            recent_captures = self.scanner.get_recent_networks() if self.scanner else []
            interfaces = self.scanner.get_interface_status() if self.scanner else []
            
            # Get system information
            try:
                username = getpass.getuser()
                hostname = socket.gethostname()
            except:
                username = 'user'
                hostname = 'pawcap'
            
            # Calculate uptime in seconds
            uptime_seconds = int(time.time() - self.start_time)
            
            # Get battery status (with timeout to prevent I2C hangs)
            battery = self._safe_battery_read()
            
            # Get CPU temperature
            cpu_temp = None
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    cpu_temp = round(int(f.read().strip()) / 1000, 1)
            except:
                pass
            
            # Get disk usage
            disk_info = {'available': False}
            try:
                usage = shutil.disk_usage('/')
                disk_info = {
                    'available': True,
                    'total_gb': round(usage.total / (1024**3), 1),
                    'used_gb': round(usage.used / (1024**3), 1),
                    'free_gb': round(usage.free / (1024**3), 1),
                }
            except:
                pass
            
            # Get learning stats (cached, refresh every 60s)
            learning = {}
            now = time.time()
            if now - self._lifetime_stats_time > 60:
                if self.db and hasattr(self.db, 'get_lifetime_stats'):
                    self._lifetime_stats_cache = self.db.get_lifetime_stats()
                self._lifetime_stats_time = now
            ls = self._lifetime_stats_cache
            if self.scanner and hasattr(self.scanner, 'network_knowledge'):
                nk = self.scanner.network_knowledge
                learning = {
                    'known_networks': len(nk),
                    'repeat_offenders': len([k for k in nk.values()
                                             if k.get('consecutive_failures', 0) >= 5]),
                    'lifetime_handshakes': ls.get('total_handshakes', 0),
                    'lifetime_attempts': ls.get('total_attempts', 0),
                    'total_sessions': ls.get('total_sessions', 0),
                }
            
            return jsonify({
                'stats': {
                    'networks_scanned': stats.get('networks', 0),
                    'handshakes_captured': stats.get('handshakes', 0),
                    'packets_collected': stats.get('packets', 0),
                    'deauths_sent': stats.get('deauths_sent', 0),
                    'candidates': stats.get('candidates', 0),
                    'success_rate': stats.get('success_rate', 0.0),
                    'smart_targeting': stats.get('smart_targeting', False),
                    'passive_captures': stats.get('passive_captures', 0),
                    'wps_captures': stats.get('wps_captures', 0)
                },
                'gps': {
                    'enabled': True,
                    'latitude': gps_data.get('latitude'),
                    'longitude': gps_data.get('longitude'),
                    'altitude': gps_data.get('altitude'),
                    'satellites': gps_data.get('satellites', 0),
                    'fix': gps_data.get('fix', False)
                },
                'battery': battery,
                'activity': {
                    'mode': 'Scanning' if (self.scanner and self.scanner.is_running()) else 'Stopped',
                    'channel': stats.get('channel'),
                    'target': self._get_capture_count(),
                    'scanner_running': self.scanner.is_running() if self.scanner else False,
                    'scan_phase': stats.get('scan_phase', ''),
                    'dual_mode': self.scanner.dual_mode if self.scanner else False,
                    'organic_mode': self.scanner.organic_mode if self.scanner and hasattr(self.scanner, 'organic_mode') else False,
                    'social_mode': self.scanner.social_mode if self.scanner and hasattr(self.scanner, 'social_mode') else False,
                    'find_friends_mode': self.scanner.find_friends_mode if self.scanner and hasattr(self.scanner, 'find_friends_mode') else False,
                    'pack_mode': self.scanner.pack_mode if self.scanner and hasattr(self.scanner, 'pack_mode') else False,
                    'pack_peers': len(self.scanner._pack_peers) if self.scanner and hasattr(self.scanner, '_pack_peers') else 0
                },
                'device_name': self.config.get('device', {}).get('name', 'Pawcap'),
                'mood': self.scanner.get_mood() if self.scanner and hasattr(self.scanner, 'get_mood') else {'state': 'sleeping', 'face': 'U´-ᴥ-`U', 'message': 'Offline'},
                'interfaces': interfaces,
                'recent_captures': recent_captures[:10],
                'system': {
                    'username': username,
                    'hostname': hostname,
                    'version': 'v1.0',
                    'uptime': uptime_seconds,
                    'cpu_temp': cpu_temp
                },
                'learning': learning,
                'disk': disk_info
            })
        
        @self.app.route('/api/handshakes')
        def get_handshakes():
            """Get all captured handshakes"""
            if self.db:
                handshakes = self.db.get_all_handshakes()
                return jsonify(handshakes)
            return jsonify([])
        
        @self.app.route('/api/handshakes/map')
        def get_handshakes_map():
            """Get handshakes with GPS coordinates for map display"""
            if self.db:
                handshakes = self.db.get_handshakes_with_location()
                return jsonify(handshakes)
            return jsonify([])
        
        @self.app.route('/api/stats')
        def get_database_stats():
            """Get database statistics"""
            if self.db:
                stats = self.db.get_stats()
                return jsonify(stats)
            return jsonify({})
        
        @self.app.route('/api/control/start', methods=['POST'])
        def control_start():
            """Start the WiFi scanner"""
            try:
                if self.scanner and not self.scanner.is_running():
                    self.scanner.start()
                    return jsonify({'status': 'success', 'message': 'Scanner started'}), 200
                elif self.scanner and self.scanner.is_running():
                    return jsonify({'status': 'info', 'message': 'Scanner already running'}), 200
                else:
                    return jsonify({'status': 'error', 'message': 'Scanner not available'}), 500
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/control/stop', methods=['POST'])
        def control_stop():
            """Stop the WiFi scanner"""
            try:
                if self.scanner and self.scanner.is_running():
                    self.scanner.stop()
                    return jsonify({'status': 'success', 'message': 'Scanner stopped'}), 200
                elif self.scanner and not self.scanner.is_running():
                    return jsonify({'status': 'info', 'message': 'Scanner already stopped'}), 200
                else:
                    return jsonify({'status': 'error', 'message': 'Scanner not available'}), 500
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/control/gps', methods=['POST'])
        def control_gps():
            """Toggle GPS on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', False)
                
                if self.gps:
                    if enabled:
                        self.gps.start()
                    else:
                        self.gps.stop()
                    return jsonify({'status': 'success', 'message': f'GPS {"enabled" if enabled else "disabled"}'}), 200
                else:
                    return jsonify({'status': 'error', 'message': 'GPS not available'}), 500
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500
        
        @self.app.route('/api/control/organic', methods=['POST'])
        def toggle_organic():
            """Toggle organic mode on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', True)
                if self.scanner:
                    self.scanner.organic_mode = enabled
                return jsonify({'status': 'success', 'message': f'Organic mode {"enabled" if enabled else "disabled"}'}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/control/social', methods=['POST'])
        def toggle_social():
            """Toggle social mode on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', False)
                if self.scanner:
                    self.scanner.social_mode = enabled
                actual = self.scanner.social_mode if self.scanner else enabled
                return jsonify({'status': 'success', 'enabled': actual}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/control/find-friends', methods=['POST'])
        def toggle_find_friends():
            """Toggle find friends mode on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', False)
                if self.scanner:
                    self.scanner.find_friends_mode = enabled
                actual = self.scanner.find_friends_mode if self.scanner else enabled
                return jsonify({'status': 'success', 'enabled': actual}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/control/pack-mode', methods=['POST'])
        def toggle_pack_mode():
            """Toggle pack mode on/off"""
            try:
                data = request.get_json()
                enabled = data.get('enabled', False)
                if self.scanner:
                    self.scanner.pack_mode = enabled
                actual = self.scanner.pack_mode if self.scanner else enabled
                return jsonify({'status': 'success', 'enabled': actual}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/social/friends')
        def get_friends():
            """Get social encounters (friends list)"""
            if self.scanner and hasattr(self.scanner, 'social_encounters'):
                friends = []
                pack_peers = dict(self.scanner._pack_peers) if hasattr(self.scanner, '_pack_peers') else {}
                for peer_id, data in self._get_social_encounters_snapshot():
                    name = data['name']
                    in_pack = name in pack_peers and self.scanner._pack_mode
                    friends.append({
                        'peer_id': peer_id,
                        'name': name,
                        'type': data['type'],
                        'face': data['face'],
                        'signal': data['signal'],
                        'count': data['count'],
                        'first_seen': data['first_seen'],
                        'last_seen': data['last_seen'],
                        'version': data.get('version', '?'),
                        'pwnd_tot': data.get('pwnd_tot', 0),
                        'in_pack': in_pack,
                    })
                friends.sort(key=lambda f: f.get('last_seen', 0) if isinstance(f.get('last_seen', 0), (int, float)) else 0, reverse=True)
                return jsonify(friends)
            return jsonify([])

        @self.app.route('/api/blacklisted')
        def get_blacklisted():
            """Get networks with 5+ consecutive failures"""
            if self.scanner and hasattr(self.scanner, 'network_knowledge'):
                blacklisted = []
                for bssid, info in self._get_network_knowledge_snapshot():
                    if info.get('consecutive_failures', 0) >= 5:
                        bands = (info.get('attempted_bands', '') or '').split(',')
                        bands = [b for b in bands if b]
                        blacklisted.append({
                            'bssid': bssid,
                            'ssid': info.get('ssid', 'Unknown'),
                            'channel': info.get('channel'),
                            'encryption': info.get('encryption'),
                            'consecutive_failures': info.get('consecutive_failures', 0),
                            'total_attempts': info.get('total_attempts', 0),
                            'total_successes': info.get('total_successes', 0),
                            'last_failure_reason': info.get('last_failure_reason'),
                            'attempted_bands': bands,
                            'retrace_pending': '5' not in bands
                        })
                blacklisted.sort(key=lambda x: x['consecutive_failures'], reverse=True)
                return jsonify(blacklisted)
            return jsonify([])
        
        @self.app.route('/api/blacklist/clear', methods=['POST'])
        def clear_blacklist():
            """Clear blacklist by resetting consecutive failures and cooldowns"""
            if self.scanner and hasattr(self.scanner, 'network_knowledge'):
                cleared_count = 0
                for bssid, info in self._get_network_knowledge_snapshot():
                    if info.get('consecutive_failures', 0) >= 5:
                        self.scanner.network_knowledge[bssid]['consecutive_failures'] = 0
                        # Also clear the 10-minute retry cooldown
                        self.scanner.failed_bssids.pop(bssid, None)
                        cleared_count += 1
                # Persist to database
                if self.db and hasattr(self.db, 'clear_blacklist'):
                    self.db.clear_blacklist()
                return jsonify({'success': True, 'cleared': cleared_count})
            return jsonify({'success': False, 'error': 'Scanner not available'})

        @self.app.route('/api/settings/name', methods=['POST'])
        def update_device_name():
            """Update the device name and persist to config"""
            try:
                import json, os
                data = request.get_json()
                new_name = (data.get('name') or '').strip()
                if not new_name:
                    return jsonify({'status': 'error', 'message': 'Name cannot be empty'}), 400
                if len(new_name) > 32:
                    return jsonify({'status': 'error', 'message': 'Name must be 32 characters or less'}), 400

                # Update in-memory config
                self.config.setdefault('device', {})['name'] = new_name

                # Update scanner's device_name for log messages
                if self.scanner and hasattr(self.scanner, 'device_name'):
                    self.scanner.device_name = new_name

                # Persist to settings.json
                config_path = '/opt/pawcap/config/settings.json'
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        disk_config = json.load(f)
                    disk_config.setdefault('device', {})['name'] = new_name
                    with open(config_path, 'w') as f:
                        json.dump(disk_config, f, indent=2)

                return jsonify({'status': 'success', 'name': new_name}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/whitelist')
        def get_whitelist():
            """Get protected network SSIDs"""
            if self.scanner and hasattr(self.scanner, 'whitelist'):
                return jsonify(sorted(self.scanner.whitelist))
            return jsonify([])

        @self.app.route('/api/whitelist', methods=['POST'])
        def add_whitelist():
            """Add an SSID to the whitelist"""
            try:
                data = request.get_json()
                ssid = (data.get('ssid') or '').strip()
                if not ssid:
                    return jsonify({'status': 'error', 'message': 'SSID cannot be empty'}), 400

                whitelist_file = self.config.get('whitelist', {}).get('file', '/opt/pawcap/config/whitelist.conf')

                # Add to scanner's in-memory set
                if self.scanner and hasattr(self.scanner, 'whitelist'):
                    self.scanner.whitelist.add(ssid)

                # Persist to file (read existing, append if not present)
                import os
                existing = set()
                if os.path.exists(whitelist_file):
                    with open(whitelist_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                existing.add(line)
                if ssid not in existing:
                    with open(whitelist_file, 'a') as f:
                        f.write(ssid + '\n')

                return jsonify({'status': 'success', 'ssid': ssid}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/whitelist', methods=['DELETE'])
        def remove_whitelist():
            """Remove an SSID from the whitelist"""
            try:
                data = request.get_json()
                ssid = (data.get('ssid') or '').strip()
                if not ssid:
                    return jsonify({'status': 'error', 'message': 'SSID cannot be empty'}), 400

                whitelist_file = self.config.get('whitelist', {}).get('file', '/opt/pawcap/config/whitelist.conf')

                # Remove from scanner's in-memory set
                if self.scanner and hasattr(self.scanner, 'whitelist'):
                    self.scanner.whitelist.discard(ssid)

                # Rewrite file without the removed SSID
                import os
                if os.path.exists(whitelist_file):
                    with open(whitelist_file, 'r') as f:
                        lines = f.readlines()
                    with open(whitelist_file, 'w') as f:
                        for line in lines:
                            stripped = line.strip()
                            if stripped.startswith('#') or stripped != ssid:
                                f.write(line)

                return jsonify({'status': 'success', 'ssid': ssid}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @self.app.route('/api/activity')
        def get_activity():
            """Get activity feed entries"""
            if self.scanner and hasattr(self.scanner, 'get_activity_feed'):
                return jsonify(self.scanner.get_activity_feed())
            return jsonify([])

        # --- Pack tunnel API endpoints ---

        @self.app.route('/api/pack/sync', methods=['POST'])
        def pack_sync():
            """Bidirectional pack state exchange. Peer POSTs its state, receives ours."""
            if not self.scanner or not getattr(self.scanner, '_pack_mode', False):
                return jsonify({'error': 'Pack mode not active'}), 403
            try:
                data = request.get_json()
                peer_name = data.get('device_name', 'Unknown')
                # Update peer data from the incoming sync
                if hasattr(self.scanner, '_pack_peers') and peer_name in self.scanner._pack_peers:
                    self.scanner._pack_peers[peer_name]['scan_state'] = data.get('scan_state', {})
                    self.scanner._pack_peers[peer_name]['handshake_bssids'] = data.get('handshake_bssids', [])
                    self.scanner._pack_peers[peer_name]['deauth_claims'] = data.get('deauth_claims', {})
                    self.scanner._pack_peers[peer_name]['http_reachable'] = True
                    self.scanner._pack_peers[peer_name]['last_seen'] = time.time()
                # Return our state
                our_state = {
                    'device_name': self.config.get('device', {}).get('name', 'Pawcap'),
                    'scan_state': self.scanner._get_pack_scan_state() if hasattr(self.scanner, '_get_pack_scan_state') else {},
                    'handshake_bssids': self.scanner._get_handshake_bssids() if hasattr(self.scanner, '_get_handshake_bssids') else [],
                    'deauth_claims': self.scanner._get_deauth_claims() if hasattr(self.scanner, '_get_deauth_claims') else {}
                }
                return jsonify(our_state), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/pack/handshake', methods=['POST'])
        def pack_receive_handshake():
            """Receive a handshake capture file from a pack peer."""
            if not self.scanner or not getattr(self.scanner, '_pack_mode', False):
                return jsonify({'error': 'Pack mode not active'}), 403
            try:
                import os, json as json_mod
                # Parse multipart: metadata field + capture file
                metadata_raw = request.form.get('metadata')
                if not metadata_raw:
                    return jsonify({'error': 'Missing metadata'}), 400
                metadata = json_mod.loads(metadata_raw)
                bssid = metadata.get('bssid')
                ssid = metadata.get('ssid', 'Unknown')
                channel = metadata.get('channel')
                if not bssid:
                    return jsonify({'error': 'Missing BSSID'}), 400

                # Skip if we already have this handshake
                if self.db and self.db.has_handshake(bssid):
                    return jsonify({'status': 'duplicate', 'message': f'Already have handshake for {bssid}'}), 200

                capture = request.files.get('capture')
                if not capture:
                    return jsonify({'error': 'Missing capture file'}), 400

                # Save to handshake_dir with PACK_ prefix
                handshake_dir = self.config.get('capture', {}).get('handshake_dir', '/opt/pawcap/captures/handshakes')
                os.makedirs(handshake_dir, exist_ok=True)
                safe_ssid = "".join(c for c in ssid if c.isalnum() or c in ('-', '_'))
                safe_bssid = bssid.replace(':', '')
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                dest_file = os.path.join(handshake_dir, f'PACK_{safe_ssid}_{safe_bssid}_{timestamp}.cap')
                capture.save(dest_file)

                # Register in database
                if self.db:
                    self.db.add_handshake(bssid, ssid, dest_file, channel=channel)
                    if self.scanner:
                        self.scanner.stats['handshakes'] = self.scanner.stats.get('handshakes', 0) + 1
                        self.scanner._log_activity('SUCCESS', f'Pack: received handshake for {ssid} ({bssid}) from peer')

                return jsonify({'status': 'saved', 'file': os.path.basename(dest_file)}), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/pack/handshakes')
        def pack_list_handshakes():
            """Return list of BSSIDs we have handshakes for (lightweight, for diffing)."""
            if not self.scanner or not getattr(self.scanner, '_pack_mode', False):
                return jsonify({'error': 'Pack mode not active'}), 403
            bssids = []
            if self.db:
                try:
                    bssids = [h['bssid'] for h in self.db.get_all_handshakes()]
                except:
                    pass
            return jsonify({'bssids': bssids}), 200

    def start(self):
        """Start the web server"""
        if self.running:
            return
        
        # Start battery monitor if available
        if self.battery_monitor is None and get_battery_monitor is not None:
            self.battery_monitor = get_battery_monitor()
            if not self.battery_monitor.is_alive():
                self.battery_monitor.start()
        
        self.running = True
        port = self.config['device'].get('web_port', 8080)
        
        self.server_thread = threading.Thread(
            target=self._run_server,
            args=(port,),
            daemon=True
        )
        self.server_thread.start()
        
        print(f"✓ Web interface started on port {port}")
    
    def stop(self):
        """Stop the web server"""
        self.running = False
    
    def _run_server(self, port):
        """Run the Flask server in single-threaded mode.
        
        threaded=True leaks OS threads on the Pi Zero (416MB RAM, 587
        thread ulimit) because Werkzeug never joins finished request
        threads.  Single-threaded mode prevents this.  Pack sync timeouts
        are handled by increasing the comms worker's HTTP timeout.
        """
        try:
            self.app.run(
                host='0.0.0.0',
                port=port,
                debug=False,
                use_reloader=False,
                threaded=False
            )
        except Exception as e:
            print(f"Web server error: {e}")
