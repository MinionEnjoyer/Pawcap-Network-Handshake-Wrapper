#!/usr/bin/env python3
"""
Pawcap - GPS Logger
Handles GPS data reading and logging
"""

import threading
import time
import serial

class GPSLogger:
    def __init__(self, config):
        self.config = config
        self.running = False
        self.gps_thread = None
        self.current_data = {
            'latitude': None,
            'longitude': None,
            'altitude': None,
            'satellites': 0,
            'fix': False,
            'timestamp': None
        }
        
        self.device = config['gps']['device']
        self.baud_rate = config['gps']['baud_rate']
        self.serial_conn = None
        self._connect_failures = 0
        
    def start(self):
        """Start GPS logging"""
        if self.running:
            return
        
        self.running = True
        self._connect_failures = 0
        self.gps_thread = threading.Thread(target=self._gps_loop, daemon=True)
        self.gps_thread.start()
    
    def stop(self):
        """Stop GPS logging"""
        self.running = False
        if self.gps_thread:
            self.gps_thread.join(timeout=5)
        if self.serial_conn:
            self.serial_conn.close()
    
    def get_current(self):
        """Get current GPS data"""
        return self.current_data.copy()
    
    def _gps_loop(self):
        """Main GPS reading loop with exponential backoff on connection failures"""
        while self.running:
            try:
                if not self.serial_conn:
                    self._connect()
                    if not self.serial_conn:
                        # Exponential backoff: 5s, 10s, 20s, 40s, ... capped at 120s
                        backoff = min(5 * (2 ** self._connect_failures), 120)
                        time.sleep(backoff)
                        continue
                
                if self.serial_conn and self.serial_conn.in_waiting:
                    line = self.serial_conn.readline().decode('ascii', errors='ignore').strip()
                    self._parse_nmea(line)
                
                time.sleep(0.1)
                
            except Exception as e:
                if self._connect_failures < 3:
                    print(f"GPS error: {e}")
                self.serial_conn = None
                self._connect_failures += 1
                backoff = min(5 * (2 ** self._connect_failures), 120)
                time.sleep(backoff)
    
    def _connect(self):
        """Connect to GPS device with backoff logging"""
        try:
            self.serial_conn = serial.Serial(
                self.device,
                self.baud_rate,
                timeout=1
            )
            self._connect_failures = 0
            print(f"Connected to GPS: {self.device}")
        except Exception as e:
            self._connect_failures += 1
            # Only log first failure and then every 10th attempt
            if self._connect_failures == 1:
                print(f"GPS not available: {e}")
            elif self._connect_failures % 10 == 0:
                print(f"GPS still unavailable (attempt {self._connect_failures})")
            self.serial_conn = None
    
    def _parse_nmea(self, sentence):
        """Parse NMEA sentences"""
        if not sentence.startswith('$'):
            return
        
        try:
            parts = sentence.split(',')
            
            # Parse GPGGA (Fix data)
            if parts[0] in ['$GPGGA', '$GNGGA']:
                if len(parts) > 9:
                    # Latitude
                    if parts[2] and parts[3]:
                        lat = self._nmea_to_decimal(parts[2], parts[3])
                        self.current_data['latitude'] = lat
                    
                    # Longitude
                    if parts[4] and parts[5]:
                        lon = self._nmea_to_decimal(parts[4], parts[5])
                        self.current_data['longitude'] = lon
                    
                    # Altitude
                    if parts[9]:
                        self.current_data['altitude'] = float(parts[9])
                    
                    # Fix quality
                    if parts[6]:
                        self.current_data['fix'] = int(parts[6]) > 0
                    
                    # Satellites
                    if parts[7]:
                        self.current_data['satellites'] = int(parts[7])
                    
                    self.current_data['timestamp'] = time.time()
            
            # Parse GPRMC (Recommended minimum)
            elif parts[0] in ['$GPRMC', '$GNRMC']:
                if len(parts) > 6:
                    # Status
                    if parts[2] == 'A':
                        self.current_data['fix'] = True
                        
                        # Latitude
                        if parts[3] and parts[4]:
                            lat = self._nmea_to_decimal(parts[3], parts[4])
                            self.current_data['latitude'] = lat
                        
                        # Longitude
                        if parts[5] and parts[6]:
                            lon = self._nmea_to_decimal(parts[5], parts[6])
                            self.current_data['longitude'] = lon
                    else:
                        self.current_data['fix'] = False
                        
        except Exception as e:
            pass  # Silently ignore parse errors
    
    def _nmea_to_decimal(self, coord, direction):
        """Convert NMEA coordinate to decimal degrees"""
        try:
            # NMEA format: DDMM.MMMM or DDDMM.MMMM
            if len(coord) == 0:
                return None
            
            # Find decimal point
            dot_pos = coord.find('.')
            if dot_pos == -1:
                return None
            
            # Extract degrees and minutes
            if dot_pos == 4:  # Latitude (DDMM.MMMM)
                degrees = float(coord[:2])
                minutes = float(coord[2:])
            else:  # Longitude (DDDMM.MMMM)
                degrees = float(coord[:3])
                minutes = float(coord[3:])
            
            # Convert to decimal
            decimal = degrees + (minutes / 60.0)
            
            # Apply direction
            if direction in ['S', 'W']:
                decimal = -decimal
            
            return round(decimal, 6)
            
        except:
            return None
