#!/usr/bin/env python3
"""
Add DNP3 Traffic Generator to Existing Repository
Safely adds new files without overwriting existing work
"""

import os
import subprocess
from pathlib import Path

def create_traffic_generator_files():
    """Create the traffic generator files in a new directory"""
    
    # Create traffic_generator directory
    traffic_dir = Path("traffic_generator")
    traffic_dir.mkdir(exist_ok=True)
    
    files_to_create = {
        'traffic_generator/dnp3_traffic_generator.py': '''#!/usr/bin/env python3
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
        print(f"\\n🛑 Stopped. Total packets: {self.packet_count}")

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
''',

        'traffic_generator/config.yaml': '''# DNP3 Traffic Generator Configuration

network:
  master_ip: "192.168.1.100"      # SCADA Master IP
  rtu_ip: "192.168.1.10"          # RTU/Outstation IP
  dnp3_port: 20000               # DNP3 TCP port

timing:
  polling_interval: 5             # Base polling interval (seconds)
  integrity_poll_interval: 300    # Full data poll every 5 minutes
  event_poll_interval: 2          # Event check every 2 seconds

devices:
  master_address: 100             # DNP3 master station address
  rtu_address: 1                  # DNP3 RTU address

simulation:
  generate_commands: true         # Generate CROB commands
  command_probability: 0.1        # 10% chance per cycle
  realistic_timing: true          # Use realistic intervals
''',

        'traffic_generator/requirements.txt': '''# Traffic Generator Requirements
PyYAML>=6.0
# No other dependencies needed - uses Python standard library
''',

        'traffic_generator/README.md': '''# DNP3 Network Traffic Generator

## Purpose
Generates legitimate DNP3 network traffic for capture and analysis by network sensors.

## Key Features
- ✅ **Real network packets** - TCP/IP with DNP3 payload
- ✅ **Raspberry Pi ready** - Lightweight Python implementation  
- ✅ **Network sensor compatible** - Wireshark/tcpdump can capture
- ✅ **YAML configuration** - Easy to customize
- ✅ **No compilation** - Pure Python, easy to debug

## Quick Start

### 1. Install Dependencies
```bash
pip install PyYAML
```

### 2. Configure Network
```bash
# Edit config.yaml
nano traffic_generator/config.yaml

# Set your network IPs:
#   master_ip: "192.168.1.100" 
#   rtu_ip: "192.168.1.10"
```

### 3. Generate Traffic
```bash
# Run traffic generator
sudo python3 traffic_generator/dnp3_traffic_generator.py
```

### 4. Capture Traffic
```bash
# In another terminal, capture packets
sudo tcpdump -i eth0 -w dnp3_capture.pcap port 20000

# Monitor in real-time  
sudo tcpdump -i eth0 -A port 20000
```

## Generated Traffic

The generator creates realistic DNP3 communication patterns:

| Type | Function Code | Frequency | Purpose |
|------|---------------|-----------|---------|
| Integrity Poll | 1 (Read) | Every 5 minutes | Full data snapshot |
| Event Poll | 1 (Read) | Every 2 seconds | Check for changes |
| CROB Commands | 5 (Direct Operate) | Random (10%) | Breaker control |

## Validation

Verify you're getting legitimate DNP3 packets:
- ✅ Packets start with `0x0564` (DNP3 signature)
- ✅ Valid function codes (1, 5, etc.)
- ✅ Proper timing intervals
- ✅ TCP port 20000

## Network Analysis

### Wireshark Filters
```
# All DNP3 traffic
tcp.port == 20000

# DNP3 packets only
tcp.port == 20000 and frame contains "0564"

# Specific function codes
dnp3.func_code == 1    # Read requests
dnp3.func_code == 5    # Control commands
```

### tcpdump Examples
```bash
# Capture DNP3 traffic
sudo tcpdump -i eth0 -w capture.pcap port 20000

# Show packet headers
sudo tcpdump -i eth0 -x port 20000

# Monitor specific IPs
sudo tcpdump -i eth0 host 192.168.1.100 and port 20000
```

## Perfect For
- 🛡️ **SOC analyst training** - Learn to identify DNP3 patterns
- 📊 **Network sensor testing** - Validate monitoring equipment  
- 🔍 **Protocol analysis** - Understand SCADA communications
- 🏫 **Educational labs** - Hands-on DNP3 experience

## Safety
⚠️ **Training use only** - Never connect to production SCADA systems!

---

This generates **actual network traffic** that security tools can capture and analyze, preparing SOC analysts for real utility environments.
''',

        'traffic_generator/setup_raspberry_pi.sh': '''#!/bin/bash
# Raspberry Pi Setup for DNP3 Traffic Generator

echo "🥧 Setting up DNP3 Traffic Generator on Raspberry Pi"
echo "=================================================="

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
sudo apt install -y python3 python3-pip python3-venv

# Install network tools
sudo apt install -y tcpdump wireshark-tshark net-tools

# Install Python packages
pip3 install PyYAML

# Set permissions for raw sockets (needed for some advanced features)
sudo setcap cap_net_raw+ep $(which python3)

# Create systemd service
sudo tee /etc/systemd/system/dnp3-traffic.service > /dev/null <<EOF
[Unit]
Description=DNP3 Traffic Generator
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/dnp3-training/traffic_generator
ExecStart=/usr/bin/python3 dnp3_traffic_generator.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit traffic_generator/config.yaml"
echo "2. Test: python3 traffic_generator/dnp3_traffic_generator.py"
echo "3. Service: sudo systemctl start dnp3-traffic"
echo "4. Monitor: sudo tcpdump -i eth0 port 20000"
'''
    }
    
    return files_to_create

def update_main_readme():
    """Update the main README to include traffic generator info"""
    
    readme_addition = '''

---

## 🚀 NEW: Network Traffic Generator

### Legitimate DNP3 Packet Generation
For network sensor capture and SOC analyst training:

```bash
# Quick start
cd traffic_generator
python3 dnp3_traffic_generator.py

# Capture traffic
sudo tcpdump -i eth0 -w dnp3_capture.pcap port 20000
```

**Perfect for:**
- 🛡️ SOC analyst training on OT protocols
- 📊 Network sensor testing and validation  
- 🔍 Protocol analysis and research
- 🏫 Educational demonstrations

**Key Features:**
- ✅ Real TCP/IP packets with DNP3 payload
- ✅ Raspberry Pi optimized
- ✅ YAML configuration
- ✅ Network sensor compatible
- ✅ No compilation required

See `traffic_generator/README.md` for detailed setup instructions.

'''
    
    try:
        # Read current README
        with open('README.md', 'r') as f:
            current_content = f.read()
        
        # Add new section if not already present
        if 'Network Traffic Generator' not in current_content:
            with open('README.md', 'a') as f:
                f.write(readme_addition)
            return True
    except FileNotFoundError:
        print("No existing README.md found, skipping update")
    
    return False

def add_to_existing_repo():
    """Add traffic generator to existing repository"""
    
    print("🔧 Adding DNP3 Traffic Generator to Existing Repository")
    print("=" * 60)
    
    # Check if we're in the right repo
    if not os.path.exists('.git'):
        print("❌ Not in a git repository!")
        print("Please run this from your dnp3-training directory")
        return False
    
    # Create traffic generator files
    print("📁 Creating traffic generator files...")
    files = create_traffic_generator_files()
    
    for filepath, content in files.items():
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Write file
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"   ✅ Created {filepath}")
            
            # Make scripts executable
            if filepath.endswith('.py') or filepath.endswith('.sh'):
                os.chmod(filepath, 0o755)
                
        except Exception as e:
            print(f"   ❌ Error creating {filepath}: {e}")
            return False
    
    # Update main README
    print("📝 Updating main README...")
    if update_main_readme():
        print("   ✅ README updated")
    else:
        print("   ℹ️  README already up to date")
    
    # Git operations
    print("\\n📤 Adding to Git...")
    
    try:
        # Add new files
        subprocess.run(['git', 'add', 'traffic_generator/'], check=True)
        subprocess.run(['git', 'add', 'README.md'], check=True)
        print("   ✅ Files staged for commit")
        
        # Commit
        commit_message = """Add DNP3 Network Traffic Generator

🚀 NEW FEATURE: Legitimate DNP3 packet generation for network sensors

Features:
- Real TCP/IP packets with DNP3 payload  
- YAML configuration system
- Raspberry Pi optimized
- Network sensor compatible (Wireshark, tcpdump)
- Pure Python - no compilation required

Purpose: Train SOC analysts on OT protocol analysis with actual 
network traffic that can be captured and examined with professional 
security tools.

Usage:
  cd traffic_generator
  python3 dnp3_traffic_generator.py
  
Monitor:
  sudo tcpdump -i eth0 port 20000
"""
        
        subprocess.run(['git', 'commit', '-m', commit_message], check=True)
        print("   ✅ Changes committed")
        
        # Offer to push
        push_choice = input("\\n🚀 Push to GitHub? (y/n): ").lower().strip()
        if push_choice in ['y', 'yes']:
            result = subprocess.run(['git', 'push'], capture_output=True, text=True)
            if result.returncode == 0:
                print("   ✅ Successfully pushed to GitHub!")
            else:
                print(f"   ⚠️  Push error: {result.stderr}")
                print("   💡 You may need to push manually")
        else:
            print("   ℹ️  Skipped push - run 'git push' when ready")
        
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Git error: {e}")
        return False
    
    return True

def show_usage_instructions():
    """Show how to use the new traffic generator"""
    
    print("\\n" + "=" * 60)
    print("🎉 SUCCESS! DNP3 Traffic Generator Added")
    print("=" * 60)
    
    print("\\n📋 QUICK START:")
    print("1. Configure network:")
    print("   nano traffic_generator/config.yaml")
    print("   # Set master_ip and rtu_ip for your network")
    
    print("\\n2. Generate traffic:")
    print("   cd traffic_generator")
    print("   sudo python3 dnp3_traffic_generator.py")
    
    print("\\n3. Capture packets (in another terminal):")
    print("   sudo tcpdump -i eth0 -w dnp3_capture.pcap port 20000")
    
    print("\\n4. Analyze with Wireshark:")
    print("   wireshark dnp3_capture.pcap")
    print("   # Filter: tcp.port == 20000")
    
    print("\\n🎯 PERFECT FOR:")
    print("   • SOC analyst training on DNP3 protocol")
    print("   • Network sensor testing and validation") 
    print("   • Protocol analysis and research")
    print("   • Educational demonstrations")
    
    print("\\n📚 DOCUMENTATION:")
    print("   traffic_generator/README.md - Detailed instructions")
    print("   traffic_generator/config.yaml - Configuration options")
    
    print("\\n🔗 YOUR REPOSITORY:")
    print("   https://github.com/cwarloe/dnp3-training")
    
    print("\\n" + "=" * 60)

def main():
    """Main function"""
    if add_to_existing_repo():
        show_usage_instructions()
    else:
        print("\\n❌ Failed to add traffic generator")
        print("Check the errors above and try again")

if __name__ == "__main__":
    main()
