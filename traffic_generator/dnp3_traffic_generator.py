#!/usr/bin/env python3
"""
DNP3 Network Traffic Generator
Generates legitimate DNP3 network traffic for sensor capture
Perfect for Raspberry Pi deployment
"""

import socket
import struct
import time
import threading
import yaml
import random
import os
from datetime import datetime

class DNP3Protocol:
    """DNP3 Protocol Implementation for packet generation"""
    
    # Function Codes
    READ = 1
    DIRECT_OPERATE = 5
    UNSOLICITED_RESPONSE = 130
    
    # Object Groups
    BINARY_INPUT_EVENT = 2
    CROB = 12
    CLASS_OBJECTS = 60
    
    @staticmethod
    def calculate_crc16(data):
        """Calculate CRC16 for DNP3"""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc & 0xFFFF
    
    @staticmethod
    def create_data_link_header(length, control, dest, src):
        """Create DNP3 data link layer header"""
        header = struct.pack('<HHBBHH',
                           0x0564,     # Start bytes
                           length,     # Length
                           control,    # Control
                           dest,       # Destination
                           src,        # Source
                           0x0000)     # CRC placeholder
        
        crc = DNP3Protocol.calculate_crc16(header[:-2])
        return header[:-2] + struct.pack('<H', crc)

class DNP3TrafficGenerator:
    """Generate realistic DNP3 network traffic"""
    
    def __init__(self, config_file='traffic_generator/config.yaml'):
        self.config = self.load_config(config_file)
        self.running = False
        self.packet_count = 0
        self.sequence_number = 0
        
    def load_config(self, config_file):
        """Load configuration from YAML file"""
        default_config = {
            'network': {
                'master_ip': '192.168.1.100',
                'rtu_ip': '192.168.1.10',
                'dnp3_port': 20000
            },
            'timing': {
                'polling_interval': 30,
                'integrity_poll_interval': 300,
                'event_poll_interval': 5
            },
            'devices': {
                'master_address': 100,
                'rtu_address': 1
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        except FileNotFoundError:
            print(f"Config file {config_file} not found, using defaults")
            self.save_default_config(config_file, default_config)
            
        return default_config
    
    def save_default_config(self, config_file, config):
        """Save default configuration"""
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        try:
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            print(f"Default config saved to {config_file}")
        except Exception as e:
            print(f"Could not save config: {e}")
    
    def create_dnp3_packet(self, function_code, app_data=b''):
        """Create complete DNP3 packet"""
        # Application layer
        app_control = 0x41
        app_header = struct.pack('BB', app_control, function_code)
        app_layer = app_header + app_data
        
        # Transport layer
        transport_header = struct.pack('B', 0x40 | (self.sequence_number & 0x3F))
        self.sequence_number += 1
        
        # Data link layer
        data_length = len(transport_header) + len(app_layer)
        link_control = 0x44
        
        data_link_header = DNP3Protocol.create_data_link_header(
            length=data_length,
            control=link_control,
            dest=self.config['devices']['rtu_address'],
            src=self.config['devices']['master_address']
        )
        
        return data_link_header + transport_header + app_layer
    
    def generate_integrity_poll(self):
        """Generate integrity poll (Class 0 read)"""
        object_header = struct.pack('<BBB', 60, 1, 0x06)
        return self.create_dnp3_packet(DNP3Protocol.READ, object_header)
    
    def generate_event_poll(self):
        """Generate event poll (Class 1)"""
        object_header = struct.pack('<BBB', 60, 2, 0x06)
        return self.create_dnp3_packet(DNP3Protocol.READ, object_header)
    
    def generate_crob_command(self, control_code=0x41):
        """Generate CROB command"""
        object_header = struct.pack('<BBBBB', 12, 1, 0x28, 0, 0)
        crob_data = struct.pack('<BBHHB', control_code, 1, 1000, 1000, 0)
        return self.create_dnp3_packet(DNP3Protocol.DIRECT_OPERATE, 
                                     object_header + crob_data)
    
    def send_packet_tcp(self, packet_data, dst_ip, dst_port):
        """Send packet over TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((dst_ip, dst_port))
            sock.send(packet_data)
            sock.close()
            self.packet_count += 1
            return True
        except Exception as e:
            print(f"Error sending packet: {e}")
            return False
    
    def log_packet(self, packet_type, success=True):
        """Log packet transmission"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        status = "✅" if success else "❌"
        print(f"{status} [{timestamp}] {packet_type}")
    
    def start_traffic_generation(self):
        """Start generating DNP3 traffic"""
        print("🚀 Starting DNP3 Traffic Generation")
        print(f"📡 Master: {self.config['network']['master_ip']}")
        print(f"🏭 RTU: {self.config['network']['rtu_ip']}")
        print("=" * 40)
        
        self.running = True
        last_integrity = 0
        last_event = 0
        
        while self.running:
            current_time = time.time()
            
            try:
                # Integrity poll
                if current_time - last_integrity >= self.config['timing']['integrity_poll_interval']:
                    packet = self.generate_integrity_poll()
                    success = self.send_packet_tcp(packet, 
                                                 self.config['network']['rtu_ip'],
                                                 self.config['network']['dnp3_port'])
                    self.log_packet("Integrity Poll", success)
                    last_integrity = current_time
                
                # Event poll
                if current_time - last_event >= self.config['timing']['event_poll_interval']:
                    packet = self.generate_event_poll()
                    success = self.send_packet_tcp(packet,
                                                 self.config['network']['rtu_ip'],
                                                 self.config['network']['dnp3_port'])
                    self.log_packet("Event Poll", success)
                    last_event = current_time
                
                # Random CROB command (10% chance)
                if random.random() < 0.1:
                    control_code = random.choice([0x41, 0x81])  # Close/Trip
                    operation = "CLOSE" if control_code == 0x41 else "TRIP"
                    packet = self.generate_crob_command(control_code)
                    success = self.send_packet_tcp(packet,
                                                 self.config['network']['rtu_ip'],
                                                 self.config['network']['dnp3_port'])
                    self.log_packet(f"CROB {operation}", success)
                
                time.sleep(self.config['timing']['polling_interval'])
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)
    
    def stop_traffic_generation(self):
        """Stop traffic generation"""
        self.running = False
        print(f"\n🛑 Stopped. Total packets: {self.packet_count}")

def main():
    print("🏭 DNP3 Network Traffic Generator")
    print("💡 Generates legitimate DNP3 packets for capture")
    print("=" * 50)
    
    generator = DNP3TrafficGenerator()
    try:
        generator.start_traffic_generation()
    except KeyboardInterrupt:
        generator.stop_traffic_generation()

if __name__ == "__main__":
    main()
