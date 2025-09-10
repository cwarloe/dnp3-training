"""
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
        print(f"\nTesting breaker: {breaker_id}")
        
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
    print("\nExample completed!")

if __name__ == "__main__":
    main()
