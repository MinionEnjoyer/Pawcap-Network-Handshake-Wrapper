#!/usr/bin/env python3
"""
Pawcap - Database
SQLite database for handshakes, network knowledge, and session tracking.
Expanded from handshake_db.py to support persistent learning.
"""

import sqlite3
import os
import json
import time
from datetime import datetime


class PawcapDatabase:
    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # --- Handshakes table (original) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT NOT NULL UNIQUE,
                ssid TEXT NOT NULL,
                capture_file TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                gps_fix BOOLEAN,
                gps_satellites INTEGER,
                cracked BOOLEAN DEFAULT 0,
                password TEXT,
                notes TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_bssid ON handshakes(bssid)')

        # Migrate: add channel column if missing
        cursor.execute("PRAGMA table_info(handshakes)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'channel' not in columns:
            cursor.execute('ALTER TABLE handshakes ADD COLUMN channel TEXT')

        # --- Network knowledge table (new) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_knowledge (
                bssid TEXT PRIMARY KEY,
                ssid TEXT NOT NULL,
                channel INTEGER,
                encryption TEXT,
                max_clients INTEGER DEFAULT 0,
                total_attempts INTEGER DEFAULT 0,
                total_successes INTEGER DEFAULT 0,
                total_failures INTEGER DEFAULT 0,
                last_failure_reason TEXT,
                consecutive_failures INTEGER DEFAULT 0,
                last_attempt_time REAL,
                last_success_time REAL,
                last_seen_time REAL,
                best_signal INTEGER DEFAULT -100,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_nk_consec ON network_knowledge(consecutive_failures)')

        # Migrate: add attempted_bands column if missing
        cursor.execute("PRAGMA table_info(network_knowledge)")
        nk_columns = [col[1] for col in cursor.fetchall()]
        if 'attempted_bands' not in nk_columns:
            cursor.execute("ALTER TABLE network_knowledge ADD COLUMN attempted_bands TEXT DEFAULT ''")

        # --- Social encounters table ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS social_encounters (
                peer_id TEXT PRIMARY KEY,
                peer_name TEXT NOT NULL,
                peer_type TEXT DEFAULT 'pawcap',
                last_payload TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                encounter_count INTEGER DEFAULT 1,
                best_signal INTEGER DEFAULT -100
            )
        ''')

        # --- Sessions table (new) ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                networks_seen INTEGER DEFAULT 0,
                handshakes_captured INTEGER DEFAULT 0,
                capture_attempts INTEGER DEFAULT 0,
                total_deauths INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    # ----------------------------------------------------------------
    # Handshake methods (unchanged from handshake_db.py)
    # ----------------------------------------------------------------

    def add_handshake(self, bssid, ssid, capture_file, gps_data=None, channel=None):
        """Add a new handshake to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            latitude = longitude = altitude = None
            gps_fix = False
            gps_satellites = 0
            if gps_data:
                latitude = gps_data.get('latitude')
                longitude = gps_data.get('longitude')
                altitude = gps_data.get('altitude')
                gps_fix = gps_data.get('fix', False)
                gps_satellites = gps_data.get('satellites', 0)

            cursor.execute('''
                INSERT OR REPLACE INTO handshakes
                (bssid, ssid, capture_file, latitude, longitude, altitude, gps_fix, gps_satellites, channel)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (bssid, ssid, capture_file, latitude, longitude, altitude, gps_fix, gps_satellites, channel))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding handshake to database: {e}")
            return False
        finally:
            conn.close()

    def has_handshake(self, bssid):
        """Check if we already have a handshake for this BSSID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM handshakes WHERE bssid = ?', (bssid,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def get_all_handshakes(self):
        """Get all handshakes from database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM handshakes ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        handshakes = []
        for row in rows:
            handshakes.append({
                'id': row['id'],
                'bssid': row['bssid'],
                'ssid': row['ssid'],
                'capture_file': row['capture_file'],
                'timestamp': row['timestamp'],
                'latitude': row['latitude'],
                'longitude': row['longitude'],
                'altitude': row['altitude'],
                'gps_fix': bool(row['gps_fix']),
                'gps_satellites': row['gps_satellites'],
                'cracked': bool(row['cracked']),
                'password': row['password'],
                'channel': row['channel']
            })
        conn.close()
        return handshakes

    def get_stats(self):
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM handshakes')
        total = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM handshakes WHERE cracked = 1')
        cracked = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM handshakes WHERE gps_fix = 1')
        with_gps = cursor.fetchone()[0]
        conn.close()
        return {
            'total_handshakes': total,
            'cracked_handshakes': cracked,
            'handshakes_with_gps': with_gps
        }

    def update_password(self, bssid, password):
        """Update password for a cracked handshake"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE handshakes SET cracked = 1, password = ? WHERE bssid = ?',
                       (password, bssid))
        conn.commit()
        conn.close()

    def export_to_json(self, output_file):
        """Export all handshakes to JSON file"""
        handshakes = self.get_all_handshakes()
        with open(output_file, 'w') as f:
            json.dump(handshakes, f, indent=2)
        return len(handshakes)

    def get_handshakes_with_location(self):
        """Get only handshakes that have GPS coordinates"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM handshakes
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND gps_fix = 1
            ORDER BY timestamp DESC
        ''')
        rows = cursor.fetchall()
        handshakes = []
        for row in rows:
            handshakes.append({
                'ssid': row['ssid'],
                'bssid': row['bssid'],
                'latitude': row['latitude'],
                'longitude': row['longitude'],
                'altitude': row['altitude'],
                'timestamp': row['timestamp'],
                'cracked': bool(row['cracked'])
            })
        conn.close()
        return handshakes

    # ----------------------------------------------------------------
    # Network knowledge methods (new)
    # ----------------------------------------------------------------

    def update_network_seen(self, bssid, ssid, channel, encryption, signal, clients):
        """Upsert network sighting — updates last_seen, best_signal, max_clients"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            signal_int = int(signal) if signal else -100
        except (ValueError, TypeError):
            signal_int = -100
        try:
            cursor.execute('''
                INSERT INTO network_knowledge (bssid, ssid, channel, encryption, max_clients, best_signal, last_seen_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid = excluded.ssid,
                    channel = excluded.channel,
                    encryption = excluded.encryption,
                    max_clients = MAX(network_knowledge.max_clients, excluded.max_clients),
                    best_signal = MAX(network_knowledge.best_signal, excluded.best_signal),
                    last_seen_time = excluded.last_seen_time
            ''', (bssid, ssid, channel, encryption, clients, signal_int, time.time()))
            conn.commit()
        except Exception as e:
            print(f"Error updating network knowledge: {e}")
        finally:
            conn.close()

    def batch_update_network_seen(self, networks):
        """Batch upsert network sightings in a single transaction.
        networks: list of (bssid, ssid, channel, encryption, signal, clients) tuples
        """
        if not networks:
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('BEGIN')
            for bssid, ssid, channel, encryption, signal, clients in networks:
                try:
                    signal_int = int(signal) if signal else -100
                except (ValueError, TypeError):
                    signal_int = -100
                cursor.execute('''
                    INSERT INTO network_knowledge (bssid, ssid, channel, encryption, max_clients, best_signal, last_seen_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = excluded.ssid,
                        channel = excluded.channel,
                        encryption = excluded.encryption,
                        max_clients = MAX(network_knowledge.max_clients, excluded.max_clients),
                        best_signal = MAX(network_knowledge.best_signal, excluded.best_signal),
                        last_seen_time = excluded.last_seen_time
                ''', (bssid, ssid, channel, encryption, clients, signal_int, time.time()))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"Error in batch network update: {e}")
        finally:
            conn.close()

    def record_attempt(self, bssid, ssid, channel, encryption):
        """Record a capture attempt for a network"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            # Ensure row exists
            cursor.execute('''
                INSERT INTO network_knowledge (bssid, ssid, channel, encryption, total_attempts, last_attempt_time)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    total_attempts = network_knowledge.total_attempts + 1,
                    last_attempt_time = excluded.last_attempt_time
            ''', (bssid, ssid, channel, encryption, time.time()))
            conn.commit()
        except Exception as e:
            print(f"Error recording attempt: {e}")
        finally:
            conn.close()

    def record_success(self, bssid):
        """Record a successful capture — resets consecutive failures"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE network_knowledge SET
                    total_successes = total_successes + 1,
                    consecutive_failures = 0,
                    last_success_time = ?
                WHERE bssid = ?
            ''', (time.time(), bssid))
            conn.commit()
        except Exception as e:
            print(f"Error recording success: {e}")
        finally:
            conn.close()

    def record_failure(self, bssid, reason):
        """Record a failed capture with reason"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                UPDATE network_knowledge SET
                    total_failures = total_failures + 1,
                    consecutive_failures = consecutive_failures + 1,
                    last_failure_reason = ?
                WHERE bssid = ?
            ''', (reason, bssid))
            conn.commit()
        except Exception as e:
            print(f"Error recording failure: {e}")
        finally:
            conn.close()

    def get_network_knowledge(self, bssid):
        """Get knowledge for a single network"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_knowledge WHERE bssid = ?', (bssid,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_knowledge(self):
        """Get all network knowledge rows (for bulk load on init)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM network_knowledge')
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def decay_failures(self, bssid, new_count):
        """Set consecutive_failures to a decayed value"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE network_knowledge SET consecutive_failures = ? WHERE bssid = ?',
                (new_count, bssid))
            conn.commit()
        except Exception as e:
            print(f"Error decaying failures: {e}")
        finally:
            conn.close()

    def clear_blacklist(self):
        """Reset consecutive_failures to 0 for all blacklisted networks (5+ failures)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE network_knowledge SET consecutive_failures = 0 WHERE consecutive_failures >= 5')
            conn.commit()
            return cursor.rowcount
        except Exception as e:
            print(f"Error clearing blacklist: {e}")
            return 0
        finally:
            conn.close()

    def update_attempted_bands(self, bssid, bands_str):
        """Update the attempted_bands field for a network"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'UPDATE network_knowledge SET attempted_bands = ? WHERE bssid = ?',
                (bands_str, bssid))
            conn.commit()
        except Exception as e:
            print(f"Error updating attempted_bands: {e}")
        finally:
            conn.close()

    def get_repeat_offenders(self, min_failures=3):
        """Get networks with N+ consecutive failures"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM network_knowledge WHERE consecutive_failures >= ? ORDER BY consecutive_failures DESC',
            (min_failures,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ----------------------------------------------------------------
    # Session methods (new)
    # ----------------------------------------------------------------

    def start_session(self):
        """Start a new session, returns session_id"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO sessions DEFAULT VALUES')
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id

    def end_session(self, session_id, stats):
        """End a session with final stats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sessions SET
                end_time = CURRENT_TIMESTAMP,
                networks_seen = ?,
                handshakes_captured = ?,
                capture_attempts = ?,
                total_deauths = ?
            WHERE id = ?
        ''', (
            stats.get('networks_seen', 0),
            stats.get('handshakes_captured', 0),
            stats.get('capture_attempts', 0),
            stats.get('total_deauths', 0),
            session_id
        ))
        conn.commit()
        conn.close()

    def get_lifetime_stats(self):
        """Aggregate lifetime statistics across all sessions and knowledge"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM network_knowledge')
        total_known = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM handshakes')
        total_handshakes = cursor.fetchone()[0]

        cursor.execute('SELECT COALESCE(SUM(total_attempts), 0) FROM network_knowledge')
        total_attempts = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM sessions')
        total_sessions = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM network_knowledge WHERE consecutive_failures >= 3')
        repeat_offenders = cursor.fetchone()[0]

        conn.close()
        return {
            'total_known_networks': total_known,
            'total_handshakes': total_handshakes,
            'total_attempts': total_attempts,
            'total_sessions': total_sessions,
            'repeat_offenders': repeat_offenders
        }

    # ----------------------------------------------------------------
    # Social encounter methods
    # ----------------------------------------------------------------

    def record_social_encounter(self, peer_id, peer_name, peer_type, payload_json, signal):
        """Upsert a social encounter — increment count on conflict"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO social_encounters (peer_id, peer_name, peer_type, last_payload, best_signal)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(peer_id) DO UPDATE SET
                    last_payload = excluded.last_payload,
                    last_seen = CURRENT_TIMESTAMP,
                    encounter_count = social_encounters.encounter_count + 1,
                    best_signal = MAX(social_encounters.best_signal, excluded.best_signal)
            ''', (peer_id, peer_name, peer_type, payload_json, signal))
            conn.commit()
        except Exception as e:
            print(f"Error recording social encounter: {e}")
        finally:
            conn.close()

    def get_social_encounters(self):
        """Get all social encounters ordered by most recent"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM social_encounters ORDER BY last_seen DESC')
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
