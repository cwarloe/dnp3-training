#!/usr/bin/env python3
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
        print("\nAvailable Commands:")
        print("  trip <breaker_id>     - Trip (open) the specified breaker")
        print("  close <breaker_id>    - Close the specified breaker")
        print("  status                - Show all breaker states")
        print("  status <breaker_id>   - Show specific breaker status")
        print("  list                  - List all configured breakers")
        print("  help                  - Show this help message")
        print("  quit                  - Exit the program")
        print("\nExample: trip CB_MAIN")
        print()
    
    def display_status(self, breaker_id=None):
        """Display breaker status"""
        if breaker_id:
            # Show specific breaker
            status = self.controller.get_breaker_status(breaker_id)
            if status:
                print(f"\nBreaker {breaker_id}:")
                print(f"  Status: {status['status']}")
                print(f"  Description: {status['description']}")
                print(f"  Bay: {status['bay']}")
                print(f"  Last Update: {status['last_update'].strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print(f"Breaker {breaker_id} not found")
        else:
            # Show all breakers
            all_status = self.controller.get_breaker_status()
            print("\nAll Breaker Status:")
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
                print("\n\nExiting...")
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
        print("\n\nShutting down...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1
    finally:
        interface.shutdown()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
