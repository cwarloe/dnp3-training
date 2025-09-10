#!/usr/bin/env python3
"""
Single-File DNP3 Training System Creator

This ONE file creates the entire GitHub repository structure automatically.
Just run this script and it generates everything you need to upload.

Usage: python create_dnp3_training_system.py
"""

import os
import zipfile
from pathlib import Path

def create_zip_package():
    """Create a complete ZIP file with all project files"""
    
    print("🚀 Creating DNP3 Training System package...")
    
    # Create temporary directory structure
    base_name = "dnp3-training-system"
    
    # All files and their content
    files = {
        "README.md": '''# DNP3 Training System

A Python-based DNP3 communication system for training purposes, allowing safe simulation of RTU and relay communication with circuit breaker control operations.

## Features

- ✅ DNP3 protocol communication simulation
- ✅ YAML-based configuration management  
- ✅ Circuit breaker control (trip/close operations)
- ✅ Real-time status monitoring
- ✅ Interactive command-line interface
- ✅ Safe training environment (no real equipment required)

## Quick Start

### Installation

1. **Download and extract this repository**

2. **Install dependencies:**
```bash
pip install PyYAML
```

3. **Run the training system:**
```bash
python run_training.py
```

## Usage

### Interactive Training

```bash
python run_training.py
```

Available commands:
- `trip CB_MAIN` - Trip (open) the specified breaker
- `close CB_MAIN` - Close the specified breaker  
- `status` - Show all breaker states
- `list` - List all configured breakers
- `help` - Show all commands
- `quit` - Exit the program

### Example Session

```
DNP3 Training System v1.0
⚠️  TRAINING ENVIRONMENT - SIMULATION MODE

Available breakers: CB_MAIN, CB_BACKUP, CB_TIE

dnp3> trip CB_MAIN
✓ Trip command sent to breaker CB_MAIN
✓ Breaker CB_MAIN is now OPEN

dnp3> status
CB_MAIN: OPEN 
CB_BACKUP: CLOSED
CB_TIE: OPEN
```

## Safety Notice

⚠️ **This system is for training purposes only**
- Do not connect to real production equipment
- Always use in isolated/sandbox environments

## License

MIT License
''',

        "requirements.txt": '''PyYAML>=6.0
# pydnp3>=0.1.0  # Optional - only needed for real DNP3 hardware
# For training/simulation mode, PyYAML is sufficient
''',

        ".gitignore": '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environments
.env
.venv
env/
venv/
ENV/

# IDEs
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db

# Project specific
logs/
*.log
temp/
''',

        "LICENSE": '''MIT License

Copyright (c) 2025 DNP3 Training System

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
''',

        "config/training_config.yaml": '''training_environment:
  simulation_mode: true
  log_level: "INFO"
  
rtu_devices:
  - device_id: "RTU_001"
    description: "Primary Training RTU"
    ip_address: "127.0.0.1"
    port: 20000
    dnp3_address: 1
    
    circuit_breakers:
      - id: "CB_MAIN"
        description: "Main Feeder Breaker"
        bay: "BAY_01"
        voltage_level: "13.8kV"
        points:
          status:
            group: 1
            index: 0
            event_class: 1
          trip_command:
            group: 12
            index: 0
            control_mode: "direct_operate"
          close_command:
            group: 12
            index: 1
            control_mode: "direct_operate"
            
      - id: "CB_BACKUP"
        description: "Backup Feeder Breaker"
        bay: "BAY_02"
        voltage_level: "13.8kV"
        points:
          status:
            group: 1
            index: 1
            event_class: 1
          trip_command:
            group: 12
            index: 2
            control_mode: "select_before_operate"
          close_command:
            group: 12
            index: 3
            control_mode: "select_before_operate"
            
      - id: "CB_TIE"
        description: "Tie Breaker"
        bay: "TIE_BAY"
        voltage_level: "13.8kV"
        points:
          status:
            group: 1
            index: 4
            event_class: 1
          trip_command:
            group: 12
            index: 4
            control_mode: "direct_operate"
          close_command:
            group: 12
            index: 5
            control_mode: "direct_operate"
''',

        "src/__init__.py": '''"""
DNP3 Training System

A Python-based DNP3 communication system for training purposes.
"""

__version__ = "1.0.0"
__author__ = "Your Name"
''',

        "src/dnp3_controller.py": '''"""
DNP3 Breaker Controller for Training System
"""

import yaml
import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

# Try to import pydnp3, but make it optional for setup
try:
    import pydnp3
    HAS_DNP3 = True
except ImportError:
    HAS_DNP3 = False
    print("Info: pydnp3 not installed. Running in simulation mode.")

class BreakerStatus:
    """Enumeration of breaker status values"""
    UNKNOWN = "UNKNOWN"
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TRIPPING = "TRIPPING"
    CLOSING = "CLOSING"

class DNP3BreakerController:
    """Main controller class for DNP3 breaker operations"""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = self.load_config(config_file)
        self.manager = None
        self.master = None
        self.channel = None
        self.breaker_states = {}
        self.is_connected = False
        
        # Setup logging
        self.setup_logging()
        self._initialize_breaker_states()
        
        self.logger.info(f"DNP3 Controller initialized with config: {config_file}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('training_environment', {}).get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Error parsing YAML configuration: {e}")
    
    def _initialize_breaker_states(self):
        """Initialize breaker states dictionary"""
        for device in self.config.get('rtu_devices', []):
            for breaker in device.get('circuit_breakers', []):
                breaker_id = breaker['id']
                self.breaker_states[breaker_id] = {
                    'status': BreakerStatus.CLOSED,  # Default to closed
                    'last_update': datetime.now(),
                    'device_id': device['device_id'],
                    'description': breaker.get('description', ''),
                    'bay': breaker.get('bay', ''),
                    'voltage_level': breaker.get('voltage_level', '')
                }
    
    def setup_master(self) -> bool:
        """Initialize DNP3 master (simulation mode)"""
        try:
            self.logger.info("Setting up DNP3 Master (Simulation Mode)...")
            
            # In simulation mode, we don't need real DNP3 connections
            if self.config.get('training_environment', {}).get('simulation_mode', True):
                self.is_connected = True
                self.logger.info("✓ Simulation mode - DNP3 master ready")
                return True
            
            # Real DNP3 setup would require pydnp3
            if not HAS_DNP3:
                self.logger.error("pydnp3 not available for real DNP3 connections")
                return False
                
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to setup DNP3 master: {e}")
            return False
    
    def find_breaker_config(self, breaker_id: str) -> Optional[Dict[str, Any]]:
        """Find breaker configuration by ID"""
        for device in self.config.get('rtu_devices', []):
            for breaker in device.get('circuit_breakers', []):
                if breaker['id'] == breaker_id:
                    return breaker
        return None
    
    def get_available_breakers(self) -> List[str]:
        """Get list of all configured breaker IDs"""
        breakers = []
        for device in self.config.get('rtu_devices', []):
            for breaker in device.get('circuit_breakers', []):
                breakers.append(breaker['id'])
        return breakers
    
    def trip_breaker(self, breaker_id: str) -> bool:
        """Send trip command to breaker"""
        if not self.is_connected:
            self.logger.error("DNP3 master not connected")
            return False
        
        breaker_config = self.find_breaker_config(breaker_id)
        if not breaker_config:
            self.logger.error(f"Breaker {breaker_id} not found in configuration")
            return False
        
        try:
            control_mode = breaker_config['points']['trip_command'].get('control_mode', 'direct_operate')
            
            if control_mode == 'select_before_operate':
                self.logger.info(f"Select-and-operate trip command sent to breaker {breaker_id}")
            else:
                self.logger.info(f"Direct-operate trip command sent to breaker {breaker_id}")
            
            # Update local state
            self.breaker_states[breaker_id]['status'] = BreakerStatus.TRIPPING
            self.breaker_states[breaker_id]['last_update'] = datetime.now()
            
            # Simulate breaker operation delay
            time.sleep(0.5)
            self.breaker_states[breaker_id]['status'] = BreakerStatus.OPEN
            self.breaker_states[breaker_id]['last_update'] = datetime.now()
            
            print(f"✓ Breaker {breaker_id} is now OPEN")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to trip breaker {breaker_id}: {e}")
            return False
    
    def close_breaker(self, breaker_id: str) -> bool:
        """Send close command to breaker"""
        if not self.is_connected:
            self.logger.error("DNP3 master not connected")
            return False
        
        breaker_config = self.find_breaker_config(breaker_id)
        if not breaker_config:
            self.logger.error(f"Breaker {breaker_id} not found in configuration")
            return False
        
        try:
            control_mode = breaker_config['points']['close_command'].get('control_mode', 'direct_operate')
            
            if control_mode == 'select_before_operate':
                self.logger.info(f"Select-and-operate close command sent to breaker {breaker_id}")
            else:
                self.logger.info(f"Direct-operate close command sent to breaker {breaker_id}")
            
            # Update local state
            self.breaker_states[breaker_id]['status'] = BreakerStatus.CLOSING
            self.breaker_states[breaker_id]['last_update'] = datetime.now()
            
            # Simulate breaker operation delay
            time.sleep(0.5)
            self.breaker_states[breaker_id]['status'] = BreakerStatus.CLOSED
            self.breaker_states[breaker_id]['last_update'] = datetime.now()
            
            print(f"✓ Breaker {breaker_id} is now CLOSED")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to close breaker {breaker_id}: {e}")
            return False
    
    def get_breaker_status(self, breaker_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of specific breaker or all breakers"""
        if breaker_id:
            return self.breaker_states.get(breaker_id, {})
        else:
            return self.breaker_states.copy()
    
    def shutdown(self):
        """Shutdown DNP3 communications gracefully"""
        self.is_connected = False
        self.logger.info("DNP3 communications shut down")
''',

        "run_training.py": '''#!/usr/bin/env python3
"""
DNP3 Training System - Interactive Command Line Interface
"""

import os
import sys
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from dnp3_controller import DNP3BreakerController, BreakerStatus

class TrainingInterface:
    """Interactive training interface for DNP3 operations"""
    
    def __init__(self):
        self.controller = None
        self.config_file = "config/training_config.yaml"
        
    def display_banner(self):
        """Display welcome banner"""
        print("=" * 60)
        print("         DNP3 Training System v1.0")
        print("    Circuit Breaker Control & Monitoring")
        print("=" * 60)
        print("⚠️  TRAINING ENVIRONMENT - SIMULATION MODE")
        print("   Safe for learning - No real equipment")
        print("=" * 60)
        print()
    
    def initialize_system(self):
        """Initialize the DNP3 controller"""
        try:
            print("Initializing DNP3 Training System...")
            self.controller = DNP3BreakerController(self.config_file)
            
            if self.controller.setup_master():
                print("✓ DNP3 Master initialized successfully")
                
                # Display available breakers
                breakers = self.controller.get_available_breakers()
                print(f"✓ Available breakers: {', '.join(breakers)}")
                print()
                return True
            else:
                print("✗ Failed to initialize DNP3 Master")
                return False
                
        except Exception as e:
            print(f"✗ Initialization error: {e}")
            return False
    
    def display_help(self):
        """Display available commands"""
        print("\\nAvailable Commands:")
        print("  trip <breaker_id>     - Trip (open) the specified breaker")
        print("  close <breaker_id>    - Close the specified breaker")
        print("  status                - Show all breaker states")
        print("  status <breaker_id>   - Show specific breaker status")
        print("  list                  - List all configured breakers")
        print("  help                  - Show this help message")
        print("  quit                  - Exit the program")
        print("\\nExample: trip CB_MAIN")
        print()
    
    def display_status(self, breaker_id=None):
        """Display breaker status"""
        if breaker_id:
            # Show specific breaker
            status = self.controller.get_breaker_status(breaker_id)
            if status:
                print(f"\\nBreaker {breaker_id}:")
                print(f"  Status: {status['status']}")
                print(f"  Description: {status['description']}")
                print(f"  Bay: {status['bay']}")
                print(f"  Last Update: {status['last_update'].strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print(f"Breaker {breaker_id} not found")
        else:
            # Show all breakers
            all_status = self.controller.get_breaker_status()
            print("\\nAll Breaker Status:")
            print("-" * 50)
            for breaker_id, status in all_status.items():
                print(f"{breaker_id}: {status['status']} (last update: {status['last_update'].strftime('%H:%M:%S')})")
        print()
    
    def run_interactive_session(self):
        """Run the interactive training session"""
        print("Type 'help' for available commands or 'quit' to exit.")
        print()
        
        while True:
            try:
                command = input("dnp3> ").strip().lower()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0]
                
                if cmd == 'quit' or cmd == 'exit':
                    break
                    
                elif cmd == 'help':
                    self.display_help()
                    
                elif cmd == 'list':
                    breakers = self.controller.get_available_breakers()
                    print(f"Configured breakers: {', '.join(breakers)}")
                    print()
                    
                elif cmd == 'status':
                    if len(parts) > 1:
                        self.display_status(parts[1].upper())
                    else:
                        self.display_status()
                        
                elif cmd == 'trip':
                    if len(parts) > 1:
                        breaker_id = parts[1].upper()
                        if self.controller.trip_breaker(breaker_id):
                            print(f"✓ Trip command completed for {breaker_id}")
                        else:
                            print(f"✗ Trip command failed for {breaker_id}")
                    else:
                        print("Usage: trip <breaker_id>")
                    print()
                        
                elif cmd == 'close':
                    if len(parts) > 1:
                        breaker_id = parts[1].upper()
                        if self.controller.close_breaker(breaker_id):
                            print(f"✓ Close command completed for {breaker_id}")
                        else:
                            print(f"✗ Close command failed for {breaker_id}")
                    else:
                        print("Usage: close <breaker_id>")
                    print()
                        
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands.")
                    print()
                    
            except KeyboardInterrupt:
                print("\\n\\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")
                print()
    
    def shutdown(self):
        """Shutdown the system"""
        if self.controller:
            self.controller.shutdown()
        print("Training system shut down. Goodbye!")

def main():
    """Main entry point"""
    interface = TrainingInterface()
    
    try:
        interface.display_banner()
        
        if interface.initialize_system():
            interface.run_interactive_session()
        else:
            print("Failed to start training system")
            return 1
            
    except KeyboardInterrupt:
        print("\\n\\nShutting down...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1
    finally:
        interface.shutdown()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
''',

        "examples/basic_example.py": '''"""
Basic usage example for DNP3 Training System
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from dnp3_controller import DNP3BreakerController

def main():
    """Basic example of using the DNP3 controller"""
    
    print("DNP3 Training System - Basic Example")
    print("=" * 40)
    
    # Initialize controller
    controller = DNP3BreakerController('../config/training_config.yaml')
    
    if not controller.setup_master():
        print("Failed to setup DNP3 master")
        return
    
    # Get available breakers
    breakers = controller.get_available_breakers()
    print(f"Available breakers: {breakers}")
    
    # Example operations
    for breaker_id in breakers[:2]:  # Use first 2 breakers
        print(f"\\nTesting breaker: {breaker_id}")
        
        # Trip the breaker
        print(f"Tripping {breaker_id}...")
        controller.trip_breaker(breaker_id)
        
        # Check status
        status = controller.get_breaker_status(breaker_id)
        print(f"Status: {status['status']}")
        
        # Close the breaker
        print(f"Closing {breaker_id}...")
        controller.close_breaker(breaker_id)
        
        # Check status again
        status = controller.get_breaker_status(breaker_id)
        print(f"Status: {status['status']}")
    
    controller.shutdown()
    print("\\nExample completed!")

if __name__ == "__main__":
    main()
''',

        "tests/__init__.py": '''"""
Tests for DNP3 Training System
"""
''',
    }
    
    # Create ZIP file
    zip_filename = f"{base_name}.zip"
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path, content in files.items():
            # Create full path inside zip
            full_path = f"{base_name}/{file_path}"
            zipf.writestr(full_path, content)
    
    print(f"✅ Created {zip_filename}")
    print(f"\n🎉 SUCCESS! Upload '{zip_filename}' to GitHub")
    print(f"\nTo test locally:")
    print(f"1. Extract {zip_filename}")
    print(f"2. cd {base_name}")
    print(f"3. pip install PyYAML")
    print(f"4. python run_training.py")
    
    return zip_filename

def main():
    """Main function"""
    print("🚀 DNP3 Training System - Automated Creator")
    print("=" * 50)
    
    zip_file = create_zip_package()
    
    print(f"\n📦 Package created: {zip_file}")
    print("📤 Ready to upload to GitHub!")
    
    # Show file size
    size_mb = os.path.getsize(zip_file) / (1024 * 1024)
    print(f"📏 File size: {size_mb:.2f} MB")

if __name__ == "__main__":
    main()
