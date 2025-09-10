"""
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
