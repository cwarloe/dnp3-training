#!/usr/bin/env python3
"""
Setup script for Enhanced DNP3 SOC Training System
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🛡️  DNP3 SOC Training System Setup")
    print("=" * 50)
    
    # Create directories
    directories = [
        "training_outputs",
        "training_outputs/pcap_files",
        "training_outputs/security_logs",
        "training_outputs/analysis_reports",
        "training_outputs/ioc_feeds",
        "training_outputs/training_scenarios"
    ]
    
    print("📁 Creating directories...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"   Created: {directory}")
    
    # Install dependencies
    print("\n📦 Installing dependencies...")
    packages = ["pyyaml>=6.0"]
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"   ✅ Installed: {package}")
        except subprocess.CalledProcessError:
            print(f"   ❌ Failed: {package} (optional)")
    
    print("\n✅ Setup complete!")
    print("\n🚀 Quick test:")
    print("python src/enhanced_dnp3_soc_backend.py")

if __name__ == "__main__":
    main()
