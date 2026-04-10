#!/usr/bin/env python3
"""
Battery Monitor for Geekworm X728 UPS HAT
Reads battery status via I2C and provides real-time monitoring
"""

import struct
import smbus
import time
import threading
from typing import Dict, Optional

class X728BatteryMonitor:
    """Monitor Geekworm X728 UPS battery status"""
    
    def __init__(self):
        self.bus = None
        self.enabled = False
        self.last_status = {}
        self.lock = threading.Lock()
        
        # X728 I2C configuration
        self.i2c_address = 0x36  # Default X728 address
        self.i2c_bus = 1  # Raspberry Pi I2C bus
        
        try:
            self.bus = smbus.SMBus(self.i2c_bus)
            # Probe the device with a timeout to avoid hanging on missing hardware.
            # smbus reads can block indefinitely if the I2C device isn't present.
            probe_ok = [False]
            def _probe():
                try:
                    self.bus.read_word_data(self.i2c_address, 0x02)
                    probe_ok[0] = True
                except:
                    pass
            t = threading.Thread(target=_probe, daemon=True)
            t.start()
            t.join(timeout=3)
            if not probe_ok[0]:
                raise RuntimeError("X728 not detected at I2C address 0x36 (probe timed out or failed)")
            self.enabled = True
            print("X728 Battery monitor initialized")
        except Exception as e:
            self.bus = None
            print(f"X728 Battery monitor unavailable: {e}")
            print("  (Running without UPS monitoring)")
    
    def read_voltage(self) -> Optional[float]:
        """Read battery voltage in volts"""
        if not self.enabled:
            return None
        
        try:
            # Read voltage from register 0x02 (VCELL)
            read = self.bus.read_word_data(self.i2c_address, 0x02)
            swapped = struct.unpack("<H", struct.pack(">H", read))[0]
            voltage = swapped * 1.25 / 1000 / 16
            return round(voltage, 2)
        except Exception as e:
            print(f"Failed to read voltage: {e}")
            return None
    
    def read_capacity(self) -> Optional[int]:
        """Read battery capacity percentage (0-100)"""
        if not self.enabled:
            return None
        
        try:
            # Read capacity from register 0x04 (SOC - State of Charge)
            read = self.bus.read_word_data(self.i2c_address, 0x04)
            swapped = struct.unpack("<H", struct.pack(">H", read))[0]
            capacity = swapped / 256
            return int(min(100, max(0, capacity)))
        except Exception as e:
            print(f"Failed to read capacity: {e}")
            return None
    
    def is_charging(self) -> Optional[bool]:
        """Check if battery is currently charging (AC power connected)"""
        if not self.enabled:
            return None
        
        try:
            # Read status register to determine charging state
            # This checks if external power is connected
            voltage = self.read_voltage()
            if voltage is None:
                return None
            
            # If voltage is rising or above 4.1V, likely charging
            # This is a simplified check - adjust based on your battery specs
            return voltage > 4.1
        except Exception:
            return None
    
    def get_status(self) -> Dict:
        """Get comprehensive battery status"""
        with self.lock:
            if not self.enabled:
                return {
                    'enabled': False,
                    'available': False
                }
            
            voltage = self.read_voltage()
            capacity = self.read_capacity()
            charging = self.is_charging()
            
            # Determine battery health/status
            status = "Unknown"
            if capacity is not None:
                if charging:
                    status = "Charging"
                elif capacity > 80:
                    status = "Excellent"
                elif capacity > 50:
                    status = "Good"
                elif capacity > 20:
                    status = "Fair"
                elif capacity > 10:
                    status = "Low"
                else:
                    status = "Critical"
            
            # Estimate runtime (rough calculation based on Pi 4 consumption)
            # Pi 4 typically uses 2-3W, adjust based on your usage
            runtime_minutes = None
            if capacity is not None and not charging:
                # Assuming 5000mAh battery at 3.7V nominal = ~18.5Wh
                # Pi 4 @ 2.5W average = ~7.4 hours at 100%
                runtime_minutes = int((capacity / 100) * 7.4 * 60)
            
            self.last_status = {
                'enabled': True,
                'available': True,
                'voltage': voltage,
                'capacity': capacity,
                'charging': charging,
                'status': status,
                'runtime_minutes': runtime_minutes
            }
            
            return self.last_status.copy()
    
    def get_cached_status(self) -> Dict:
        """Get last cached status without new I2C read"""
        with self.lock:
            if self.last_status:
                return self.last_status.copy()
            return self.get_status()


class BatteryMonitorThread(threading.Thread):
    """Background thread to monitor battery status"""
    
    def __init__(self, update_interval=30):
        super().__init__(daemon=True)
        self.monitor = X728BatteryMonitor()
        self.update_interval = update_interval  # seconds
        self.running = False
        self.last_capacity = None
        
    def run(self):
        """Monitor battery in background"""
        self.running = True
        print(f"Battery monitoring started (update every {self.update_interval}s)")
        
        while self.running:
            try:
                status = self.monitor.get_status()
                
                if status.get('available'):
                    capacity = status.get('capacity')
                    
                    # Alert on low battery
                    if capacity is not None:
                        if capacity <= 10 and (self.last_capacity is None or self.last_capacity > 10):
                            print(f"CRITICAL BATTERY: {capacity}% remaining!")
                        elif capacity <= 20 and (self.last_capacity is None or self.last_capacity > 20):
                            print(f"Low battery: {capacity}% remaining")
                        
                        self.last_capacity = capacity
                
                time.sleep(self.update_interval)
                
            except Exception as e:
                print(f"Battery monitor error: {e}")
                time.sleep(self.update_interval)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
    
    def get_status(self) -> Dict:
        """Get current battery status"""
        return self.monitor.get_cached_status()


# Singleton instance
_battery_monitor = None

def get_battery_monitor() -> BatteryMonitorThread:
    """Get or create battery monitor singleton"""
    global _battery_monitor
    if _battery_monitor is None:
        _battery_monitor = BatteryMonitorThread(update_interval=30)
    return _battery_monitor


if __name__ == "__main__":
    # Test battery monitoring
    print("Testing X728 Battery Monitor...")
    monitor = X728BatteryMonitor()
    
    if monitor.enabled:
        for i in range(5):
            status = monitor.get_status()
            print(f"\n--- Battery Status (reading {i+1}/5) ---")
            print(f"Voltage: {status['voltage']}V")
            print(f"Capacity: {status['capacity']}%")
            print(f"Charging: {status['charging']}")
            print(f"Status: {status['status']}")
            if status['runtime_minutes']:
                hours = status['runtime_minutes'] // 60
                minutes = status['runtime_minutes'] % 60
                print(f"Est. Runtime: {hours}h {minutes}m")
            time.sleep(2)
    else:
        print("Battery monitor not available")
