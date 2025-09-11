#!/usr/bin/env python3
"""
GitHub Repository Migration Script
Automatically organizes DNP3 training system files for GitHub
"""

import os
import shutil
import json
from pathlib import Path
from datetime import datetime

class GitHubMigrationScript:
    """Organize DNP3 training system files for GitHub repository"""
    
    def __init__(self, repo_path="."):
        self.repo_path = Path(repo_path)
        self.backup_dir = self.repo_path / "backup_migration"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"🚀 DNP3 Training System Migration Script")
        print(f"📁 Repository path: {self.repo_path.absolute()}")
        print(f"🕒 Timestamp: {self.timestamp}")
    
    def create_directory_structure(self):
        """Create the new directory structure"""
        directories = [
            "src",
            "config", 
            "docs",
            "examples",
            "tests",
            "legacy",
            "training_outputs",
            "training_outputs/pcap_files",
            "training_outputs/analysis_reports", 
            "training_outputs/security_logs",
            "training_outputs/ioc_feeds",
            "training_outputs/training_scenarios"
        ]
        
        print("\n📂 Creating directory structure...")
        for directory in directories:
            dir_path = self.repo_path / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created: {directory}/")
    
    def backup_existing_files(self):
        """Backup existing files before migration"""
        print(f"\n💾 Creating backup in: {self.backup_dir}")
        self.backup_dir.mkdir(exist_ok=True)
        
        # Common files that might exist
        files_to_backup = [
            "README.md",
            "requirements.txt", 
            "setup.py",
            ".gitignore",
            "dnp3_training.py",
            "dnp3_soc_training.py",
            "config.yaml",
            "training_config.yaml"
        ]
        
        for file_name in files_to_backup:
            file_path = self.repo_path / file_name
            if file_path.exists():
                backup_path = self.backup_dir / f"{file_name}.{self.timestamp}"
                shutil.copy2(file_path, backup_path)
                print(f"   📋 Backed up: {file_name}")
    
    def create_main_readme(self):
        """Create comprehensive README.md"""
        readme_content = '''# Enhanced DNP3 SOC Training System v2.0

## Overview

This project provides a realistic DNP3 traffic generator for training Security Operations Center (SOC) analysts on OT (Operational Technology) security monitoring. The system generates proper DNP3 packets with realistic attack scenarios for hands-on security analysis practice.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Optional: Install pydnp3 for proper frame generation
pip install pydnp3  # Requires CMake and build tools

# Run basic training session
python src/enhanced_dnp3_soc_backend.py

# Run packet analyzer
python src/dnp3_hex_analyzer.py
```

## 🎯 Key Features

✅ **Proper DNP3 Protocol Structure** - Uses correct sync bytes (0x0564) and frame format  
✅ **Wireshark Compatible** - Packets recognized by DNP3 dissector when properly configured  
✅ **Library Support** - Uses pydnp3 library when available for authentic frame generation  
✅ **Multi-Device Network** - Simulates realistic utility network topology  
✅ **Attack Scenarios** - 6 different attack types for SOC training  
✅ **Professional Artifacts** - CSV, JSON, PCAP outputs for analysis tools  
✅ **Guided Learning** - Analysis worksheets with expected findings  

## 📁 Repository Structure

```
├── src/                    # Main source code
│   ├── enhanced_dnp3_soc_backend.py  # Main training system
│   └── dnp3_hex_analyzer.py          # Packet analysis tool
├── config/                 # Configuration files
├── examples/               # Usage examples
├── docs/                   # Documentation
├── training_outputs/       # Generated artifacts (gitignored)
└── legacy/                 # Previous versions
```

## 🔧 Wireshark Setup

1. Open generated PCAP file in Wireshark
2. Filter: `tcp.port == 20000`
3. Verify TCP payload starts with `64 05` (0x0564 sync bytes)
4. Right-click packet → **Decode As** → **DNP 3.0**
5. Protocol column should show "DNP 3.0"

## 🎓 Training Workflow

### Phase 1: Generate Traffic
```bash
python src/enhanced_dnp3_soc_backend.py
```

### Phase 2: Analyze Packets
```bash
python src/dnp3_hex_analyzer.py
```

### Phase 3: Import to Tools
- **Wireshark**: Open PCAP files for protocol analysis
- **Excel**: Import CSV files for pattern analysis  
- **SIEM**: Import JSON files for correlation

## 📊 Attack Scenarios

1. **Unauthorized Control** - Control commands from unauthorized sources
2. **External Access** - Internet-based attackers accessing OT network
3. **Protocol Anomalies** - Malformed or invalid DNP3 packets
4. **Device Impersonation** - Attackers spoofing legitimate devices
5. **Timing Attacks** - Operations during suspicious time windows
6. **Reconnaissance** - Network scanning and device enumeration

## 🛠 Installation

### Basic Installation
```bash
pip install PyYAML
```

### Full Installation (Recommended)
```bash
# Install build tools first:
# Windows: Visual Studio Build Tools
# Linux: sudo apt-get install cmake build-essential
# macOS: xcode-select --install

pip install pydnp3 PyYAML
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Wireshark Setup](docs/wireshark_setup.md) 
- [SOC Training Guide](docs/soc_training_guide.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🔍 Troubleshooting

### Wireshark Shows TCP Instead of DNP3
- Verify sync bytes: `tcp.payload[0:2] == 64:05`
- Use Decode As: Right-click → Decode As → DNP 3.0

### pydnp3 Installation Fails
- Install CMake and build tools
- Use fallback: System works without pydnp3

## 📄 License

MIT License - See LICENSE file for details

---

**Enhanced v2.0 Features:**
- ✅ Proper DNP3 frame structure with 0x0564 sync bytes
- ✅ Wireshark DNP3 dissector compatibility  
- ✅ Multi-device network topology simulation
- ✅ SOC analyst training focus (not operator training)
- ✅ Professional security tool integration
'''
        
        readme_path = self.repo_path / "README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        print(f"📝 Created: README.md")
    
    def create_requirements_txt(self):
        """Create requirements.txt"""
        requirements_content = '''# Core requirements
PyYAML>=6.0

# Optional for proper DNP3 frame generation
# Requires CMake and build tools (Visual Studio on Windows, build-essential on Linux)
# pydnp3>=0.1.0

# Development dependencies
pytest>=6.0

# Note: Install pydnp3 separately if you have build tools:
# pip install pydnp3
#
# The system works without pydnp3 but generates better frames with it.
'''
        
        req_path = self.repo_path / "requirements.txt"
        with open(req_path, 'w') as f:
            f.write(requirements_content)
        print(f"📦 Created: requirements.txt")
    
    def create_gitignore(self):
        """Create .gitignore"""
        gitignore_content = '''# Python
__pycache__/
*.py[cod]
*.so
*.egg-info/
dist/
build/
venv/
env/

# Training outputs (large files)
training_outputs/
*.pcap
*.log

# IDEs  
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Environment
.env

# Backup files
backup_migration/

# Temporary files
*.tmp
*.temp
'''
        
        gitignore_path = self.repo_path / ".gitignore"
        with open(gitignore_path, 'w') as f:
            f.write(gitignore_content)
        print(f"🚫 Created: .gitignore")
    
    def create_enhanced_system(self):
        """Create the main enhanced DNP3 system"""
        # This is a placeholder - you'll paste the actual artifact content
        enhanced_system_content = '''#!/usr/bin/env python3
"""
Enhanced DNP3 SOC Analyst Training System
Generates real artifacts for security analysis training using proper DNP3 library

INSTRUCTIONS FOR SETUP:
1. Copy the content from the "Enhanced Multi-Device DNP3 SOC Training System" artifact
2. Paste it here, replacing this placeholder content
3. Save the file

The artifact contains the complete implementation with:
- Proper DNP3 frame generation with 0x0564 sync bytes
- pydnp3 library support with graceful fallback
- Multi-device network topology
- 6 realistic attack scenarios
- Professional analysis artifacts
"""

def main():
    print("⚠️  SETUP REQUIRED:")
    print("1. Copy content from 'Enhanced Multi-Device DNP3 SOC Training System' artifact")
    print("2. Paste into this file: src/enhanced_dnp3_soc_backend.py")
    print("3. Save and run again")
    print()
    print("📋 Artifact contains ~500 lines of production-ready code")

if __name__ == "__main__":
    main()
'''
        
        enhanced_path = self.repo_path / "src" / "enhanced_dnp3_soc_backend.py"
        with open(enhanced_path, 'w') as f:
            f.write(enhanced_system_content)
        print(f"🏭 Created: src/enhanced_dnp3_soc_backend.py (placeholder - needs artifact content)")
    
    def create_hex_analyzer(self):
        """Create the DNP3 hex analyzer"""
        # Placeholder for the hex analyzer
        analyzer_content = '''#!/usr/bin/env python3
"""
DNP3 Packet Hex Analyzer (Wireshark Alternative)
Parse and display DNP3 packets without Wireshark

INSTRUCTIONS FOR SETUP:
1. Copy the content from the "DNP3 Packet Hex Analyzer" artifact  
2. Paste it here, replacing this placeholder content
3. Save the file

The artifact contains the complete implementation for parsing DNP3 packets.
"""

def main():
    print("⚠️  SETUP REQUIRED:")
    print("1. Copy content from 'DNP3 Packet Hex Analyzer' artifact")
    print("2. Paste into this file: src/dnp3_hex_analyzer.py")
    print("3. Save and run again")

if __name__ == "__main__":
    main()
'''
        
        analyzer_path = self.repo_path / "src" / "dnp3_hex_analyzer.py"
        with open(analyzer_path, 'w') as f:
            f.write(analyzer_content)
        print(f"🔍 Created: src/dnp3_hex_analyzer.py (placeholder - needs artifact content)")
    
    def create_basic_example(self):
        """Create basic usage example"""
        example_content = '''#!/usr/bin/env python3
"""
Basic DNP3 Training Session Example
Simple example showing how to use the training system

INSTRUCTIONS FOR SETUP:
1. Copy the content from the "Basic DNP3 PCAP MVP" or similar artifact
2. Paste it here, replacing this placeholder content  
3. Save the file
"""

def main():
    print("⚠️  SETUP REQUIRED:")
    print("1. Copy content from a basic DNP3 generator artifact")
    print("2. Paste into this file: examples/basic_session.py")
    print("3. Save and run again")

if __name__ == "__main__":
    main()
'''
        
        example_path = self.repo_path / "examples" / "basic_session.py"
        with open(example_path, 'w') as f:
            f.write(example_content)
        print(f"📝 Created: examples/basic_session.py (placeholder - needs artifact content)")
    
    def create_config_file(self):
        """Create sample configuration"""
        config_content = '''# Enhanced DNP3 SOC Training Configuration
training_environment:
  simulation_mode: true
  log_level: "INFO"

rtu_devices:
  - device_id: "RTU_001"
    description: "Main Substation RTU"
    ip_address: "10.50.1.1"
    port: 20000
    dnp3_address: 1
    vendor: "SEL"
    
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
          close_command:
            group: 12
            index: 1

# Network topology and attack scenarios defined here
# Copy full config from the main artifact for complete setup
'''
        
        config_path = self.repo_path / "config" / "enhanced_soc_training_config.yaml"
        with open(config_path, 'w') as f:
            f.write(config_content)
        print(f"⚙️  Created: config/enhanced_soc_training_config.yaml")
    
    def create_setup_instructions(self):
        """Create setup completion instructions"""
        instructions_content = '''# Setup Completion Instructions

## Files Created

The migration script has created the directory structure and placeholder files. 
You now need to copy the actual artifact content into the placeholder files.

## Required Actions

### 1. Main System File
📁 **File**: `src/enhanced_dnp3_soc_backend.py`
📋 **Source**: Copy content from "Enhanced Multi-Device DNP3 SOC Training System" artifact
🎯 **Purpose**: Main training system with proper DNP3 frames

### 2. Packet Analyzer  
📁 **File**: `src/dnp3_hex_analyzer.py`
📋 **Source**: Copy content from "DNP3 Packet Hex Analyzer" artifact
🎯 **Purpose**: Analyze packets without Wireshark

### 3. Basic Example
📁 **File**: `examples/basic_session.py`
📋 **Source**: Copy content from "Basic DNP3 PCAP MVP" artifact
🎯 **Purpose**: Simple usage example

### 4. Configuration (Optional Enhancement)
📁 **File**: `config/enhanced_soc_training_config.yaml`
📋 **Source**: Copy full config from main artifact
🎯 **Purpose**: Complete network topology

## Testing After Setup

```bash
# Test the main system
python src/enhanced_dnp3_soc_backend.py

# Test the analyzer
python src/dnp3_hex_analyzer.py

# Test basic example  
python examples/basic_session.py
```

## Git Commands for Upload

```bash
# Stage all files
git add .

# Commit with descriptive message
git commit -m "Enhanced DNP3 Training System v2.0

✅ Proper DNP3 frame structure with 0x0564 sync bytes
✅ Wireshark-compatible packet generation
✅ Multi-device network topology
✅ SOC analyst training focus
✅ Professional analysis artifacts"

# Push to GitHub
git push origin main
```

## Artifact Content Replacement

Replace the placeholder content in each file with the corresponding artifact:

1. Open the file in your editor
2. Select all content (Ctrl+A)
3. Delete existing placeholder
4. Paste artifact content
5. Save file

The artifacts contain the complete, production-ready implementations.
'''
        
        instructions_path = self.repo_path / "SETUP_INSTRUCTIONS.md"
        with open(instructions_path, 'w') as f:
            f.write(instructions_content)
        print(f"📋 Created: SETUP_INSTRUCTIONS.md")
    
    def create_src_init(self):
        """Create __init__.py for src package"""
        init_content = '''"""
Enhanced DNP3 SOC Training System
"""

__version__ = "2.0.0"
__author__ = "DNP3 Training Team"
'''
        
        init_path = self.repo_path / "src" / "__init__.py"
        with open(init_path, 'w') as f:
            f.write(init_content)
        print(f"📦 Created: src/__init__.py")
    
    def generate_migration_summary(self):
        """Generate migration summary"""
        summary = {
            "migration_timestamp": self.timestamp,
            "directory_structure": [
                "src/", "config/", "docs/", "examples/", 
                "tests/", "legacy/", "training_outputs/"
            ],
            "files_created": [
                "README.md",
                "requirements.txt", 
                ".gitignore",
                "src/enhanced_dnp3_soc_backend.py",
                "src/dnp3_hex_analyzer.py",
                "src/__init__.py",
                "examples/basic_session.py",
                "config/enhanced_soc_training_config.yaml",
                "SETUP_INSTRUCTIONS.md"
            ],
            "next_steps": [
                "Copy artifact content into placeholder files",
                "Test the system",
                "Commit to GitHub"
            ]
        }
        
        summary_path = self.repo_path / "migration_summary.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        print(f"📊 Created: migration_summary.json")
    
    def run_migration(self):
        """Run the complete migration process"""
        print(f"🎯 Starting DNP3 Training System Migration...")
        
        # Create backup
        self.backup_existing_files()
        
        # Create structure  
        self.create_directory_structure()
        
        # Create core files
        self.create_main_readme()
        self.create_requirements_txt()
        self.create_gitignore()
        
        # Create source files
        self.create_src_init()
        self.create_enhanced_system()
        self.create_hex_analyzer()
        
        # Create examples and config
        self.create_basic_example()
        self.create_config_file()
        
        # Create documentation
        self.create_setup_instructions()
        
        # Generate summary
        self.generate_migration_summary()
        
        print(f"\n🎉 Migration Complete!")
        print(f"📁 Repository structure created in: {self.repo_path.absolute()}")
        print(f"💾 Backup created in: {self.backup_dir}")
        
        print(f"\n📋 Next Steps:")
        print(f"1. Read SETUP_INSTRUCTIONS.md")
        print(f"2. Copy artifact content into placeholder files")
        print(f"3. Test: python src/enhanced_dnp3_soc_backend.py")
        print(f"4. Commit to GitHub")
        
        print(f"\n🔗 Key Files to Update:")
        print(f"   • src/enhanced_dnp3_soc_backend.py")
        print(f"   • src/dnp3_hex_analyzer.py") 
        print(f"   • examples/basic_session.py")

def main():
    """Main entry point"""
    print("🚀 DNP3 Training System GitHub Migration Script")
    print("=" * 60)
    
    # Get repository path
    repo_path = input("📁 Enter repository path (or press Enter for current directory): ").strip()
    if not repo_path:
        repo_path = "."
    
    # Confirm migration
    print(f"\n📂 Repository path: {Path(repo_path).absolute()}")
    confirm = input("🤔 Proceed with migration? (y/N): ").strip().lower()
    
    if confirm in ['y', 'yes']:
        migrator = GitHubMigrationScript(repo_path)
        migrator.run_migration()
    else:
        print("❌ Migration cancelled")

if __name__ == "__main__":
    main()
