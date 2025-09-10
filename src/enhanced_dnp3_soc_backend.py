#!/usr/bin/env python3
"""
Enhanced DNP3 SOC Analyst Training System
Generates real artifacts for security analysis training
"""

import yaml
import time
import random
import json
import csv
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

class DNP3TrafficGenerator:
    """Enhanced DNP3 traffic generator for SOC analyst training"""
    
    def __init__(self, config_file: str = 'config/enhanced_soc_training_config.yaml'):
        self.traffic_log = []
        self.security_events = []
        self.is_running = False
        self.output_dir = Path("training_outputs")
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directories
        self.setup_output_directories()
        
        print(f"🛡️  DNP3 SOC Training System Initialized")
        print(f"📁 Output directory: {self.output_dir}")
        print(f"🆔 Session ID: {self.session_id}")
    
    def setup_output_directories(self):
        """Create output directories for training artifacts"""
        directories = [
            self.output_dir,
            self.output_dir / "pcap_files",
            self.output_dir / "security_logs", 
            self.output_dir / "analysis_reports",
            self.output_dir / "ioc_feeds",
            self.output_dir / "training_scenarios"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def generate_normal_traffic(self, duration_minutes: int = 5):
        """Generate baseline normal DNP3 traffic"""
        print(f"🟢 Generating {duration_minutes} minutes of normal traffic...")
        
        for i in range(duration_minutes * 6):  # 6 packets per minute
            # Integrity poll
            if i % 30 == 0:
                self.send_integrity_poll()
            
            # Status requests
            if i % 10 == 0:
                self.send_status_request()
            
            # Random events
            if random.random() < 0.1:
                self.send_class1_event()
            
            time.sleep(0.5)  # Faster for demo
        
        print(f"✅ Generated {len(self.traffic_log)} normal traffic packets")
    
    def generate_attack_scenario(self, attack_type: str, intensity: str = "medium"):
        """Generate specific attack scenarios"""
        print(f"🚨 Generating {attack_type} attack scenario (intensity: {intensity})")
        
        intensity_settings = {
            "low": {"count": 3, "interval": 2},
            "medium": {"count": 8, "interval": 1}, 
            "high": {"count": 15, "interval": 0.5}
        }
        
        settings = intensity_settings.get(intensity, intensity_settings["medium"])
        
        attack_methods = {
            'unauthorized_crob': self.simulate_unauthorized_crob,
            'replay_attack': self.simulate_replay_attack,
            'timing_attack': self.simulate_timing_attack,
            'protocol_fuzzing': self.simulate_protocol_fuzzing,
            'credential_stuffing': self.simulate_credential_stuffing
        }
        
        if attack_type in attack_methods:
            for i in range(settings["count"]):
                attack_methods[attack_type](attack_sequence=i+1)
                time.sleep(settings["interval"])
    
    def simulate_unauthorized_crob(self, attack_sequence: int = 1):
        """Simulate unauthorized CROB commands"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "192.168.1.50",  # Malicious IP
            'dst_ip': "10.50.1.1",
            'function_code': 5,  # Direct Operate
            'attack_type': 'Unauthorized CROB',
            'severity': 'CRITICAL',
            'data': '0C 01 41 01 64 00',
            'legitimate': False,
            'description': 'Control command from unauthorized source'
        }
        
        self.traffic_log.append(packet_info)
        self.log_security_event(packet_info)
        print(f"🔴 Unauthorized CROB from {packet_info['src_ip']}")
    
    def simulate_replay_attack(self, attack_sequence: int = 1):
        """Simulate replay attack"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "10.50.1.100",
            'dst_ip': "10.50.1.1",
            'function_code': 5,
            'attack_type': 'Replay Attack',
            'severity': 'HIGH',
            'data': '0C 01 81 01 64 00',
            'sequence_anomaly': True,
            'legitimate': False,
            'description': 'Replayed command with duplicate sequence'
        }
        
        self.traffic_log.append(packet_info)
        self.log_security_event(packet_info)
        print(f"🔴 Replay attack detected")
    
    def simulate_protocol_fuzzing(self, attack_sequence: int = 1):
        """Simulate protocol fuzzing"""
        invalid_func_code = random.choice([99, 128, 200, 255])
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "192.168.100.99",
            'dst_ip': "10.50.1.1",
            'function_code': invalid_func_code,
            'attack_type': 'Protocol Fuzzing',
            'severity': 'MEDIUM',
            'data': 'FF FF FF FF',
            'legitimate': False,
            'description': f'Invalid function code {invalid_func_code}'
        }
        
        self.traffic_log.append(packet_info)
        self.log_security_event(packet_info)
        print(f"🔴 Protocol fuzzing - invalid function code {invalid_func_code}")
    
    def simulate_timing_attack(self, attack_sequence: int = 1):
        """Simulate timing attack"""
        suspicious_time = datetime.now().replace(hour=3, minute=15)
        
        packet_info = {
            'timestamp': suspicious_time.isoformat(),
            'src_ip': "10.50.1.100",
            'dst_ip': "10.50.1.1",
            'function_code': 5,
            'attack_type': 'Timing Attack',
            'severity': 'HIGH',
            'data': '0C 01 81 01 64 00',
            'time_anomaly': True,
            'legitimate': False,
            'description': 'Control operation during off-hours'
        }
        
        self.traffic_log.append(packet_info)
        self.log_security_event(packet_info)
        print(f"🔴 Timing attack - operation at {suspicious_time.strftime('%H:%M')}")
    
    def simulate_credential_stuffing(self, attack_sequence: int = 1):
        """Simulate credential stuffing attack"""
        attacker_ips = ["192.168.1.40", "192.168.1.41", "192.168.1.42"]
        
        for ip in attacker_ips:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip,
                'dst_ip': "10.50.1.100",
                'function_code': 131,  # Authentication challenge
                'attack_type': 'Credential Stuffing',
                'severity': 'HIGH',
                'data': 'FF FF FF FF',
                'auth_failure': True,
                'legitimate': False,
                'description': f'Authentication failure from {ip}'
            }
            
            self.traffic_log.append(packet_info)
            self.log_security_event(packet_info)
            print(f"🔴 Auth failure from {ip}")
    
    def send_integrity_poll(self):
        """Send normal integrity poll"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "10.50.1.100",
            'dst_ip': "10.50.1.1",
            'function_code': 1,  # Read
            'data': '3C 02 06',
            'legitimate': True,
            'description': 'Routine integrity poll'
        }
        
        self.traffic_log.append(packet_info)
        print(f"🟢 Integrity poll")
    
    def send_status_request(self):
        """Send status request"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "10.50.1.100",
            'dst_ip': "10.50.1.1",
            'function_code': 1,
            'data': '01 02 00 00 00',
            'legitimate': True,
            'description': 'Status request'
        }
        
        self.traffic_log.append(packet_info)
        print(f"🟢 Status request")
    
    def send_class1_event(self):
        """Send Class 1 event"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': "10.50.1.1",
            'dst_ip': "10.50.1.100",
            'function_code': 129,  # Unsolicited Response
            'data': '02 01 00 00 01 81',
            'legitimate': True,
            'description': 'Class 1 event notification'
        }
        
        self.traffic_log.append(packet_info)
        print(f"🟢 Class 1 event")
    
    def log_security_event(self, packet_info):
        """Log security event"""
        event = {
            'id': len(self.security_events) + 1,
            'timestamp': packet_info['timestamp'],
            'event_type': packet_info.get('attack_type', 'Unknown'),
            'severity': packet_info.get('severity', 'INFO'),
            'source_ip': packet_info['src_ip'],
            'target_ip': packet_info['dst_ip'],
            'function_code': packet_info['function_code'],
            'description': packet_info.get('description', 'Suspicious activity'),
            'recommended_action': self.get_recommended_action(packet_info.get('attack_type', ''))
        }
        
        self.security_events.append(event)
    
    def get_recommended_action(self, attack_type: str) -> str:
        """Get recommended response action"""
        actions = {
            "Unauthorized CROB": "IMMEDIATE: Block source IP, isolate RTU, verify authentication",
            "Replay Attack": "Investigate sequence numbers, check for network compromise",  
            "Protocol Fuzzing": "Monitor for exploitation, update IDS signatures",
            "Timing Attack": "Verify maintenance schedules, check access logs",
            "Credential Stuffing": "Lock accounts, implement rate limiting, enable MFA"
        }
        return actions.get(attack_type, "Investigate and document findings")
    
    def export_training_artifacts(self):
        """Export all training artifacts"""
        print(f"\n📊 Exporting training artifacts...")
        
        # Export traffic log as CSV
        self.export_traffic_csv()
        
        # Export security events as JSON
        self.export_security_events()
        
        # Generate IOC feed
        self.generate_ioc_feed()
        
        # Create analysis worksheet
        self.create_analysis_worksheet()
        
        # Generate summary report
        self.generate_summary_report()
        
        print(f"✅ All artifacts exported to: {self.output_dir}")
    
    def export_traffic_csv(self):
        """Export traffic log as CSV"""
        csv_file = self.output_dir / "analysis_reports" / f"traffic_log_{self.session_id}.csv"
        
        if self.traffic_log:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=self.traffic_log[0].keys())
                writer.writeheader()
                writer.writerows(self.traffic_log)
            print(f"📄 CSV exported: {csv_file}")
    
    def export_security_events(self):
        """Export security events as JSON"""
        json_file = self.output_dir / "security_logs" / f"security_events_{self.session_id}.json"
        
        with open(json_file, 'w') as f:
            json.dump(self.security_events, f, indent=2)
        print(f"📄 Security events exported: {json_file}")
    
    def generate_ioc_feed(self):
        """Generate IOC feed"""
        iocs = []
        
        for packet in self.traffic_log:
            if not packet.get('legitimate', True):
                iocs.append({
                    'type': 'IP',
                    'value': packet['src_ip'],
                    'description': f"Source of {packet.get('attack_type', 'suspicious')} activity",
                    'severity': packet.get('severity', 'MEDIUM'),
                    'first_seen': packet['timestamp']
                })
        
        ioc_file = self.output_dir / "ioc_feeds" / f"ioc_feed_{self.session_id}.json"
        
        with open(ioc_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        print(f"📄 IOC feed exported: {ioc_file}")
    
    def create_analysis_worksheet(self):
        """Create analysis worksheet"""
        worksheet_content = f"""# DNP3 SOC Analysis Worksheet
Session ID: {self.session_id}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Training Objectives
1. Identify suspicious DNP3 traffic patterns
2. Correlate security events across multiple sources
3. Recommend appropriate incident response actions

## Questions for Analysis

### Traffic Analysis
1. Review the CSV file: How many total packets were captured?
2. What percentage of traffic was flagged as suspicious?
3. Which source IP addresses appear most frequently?
4. What DNP3 function codes appear? Which are concerning?

### Attack Identification  
1. How many different attack types were detected?
2. Which attack had the highest severity rating?
3. List key indicators for each attack type
4. What time-based anomalies do you observe?

### Files for Analysis
- Traffic CSV: analysis_reports/traffic_log_{self.session_id}.csv
- Security events: security_logs/security_events_{self.session_id}.json
- IOC feed: ioc_feeds/ioc_feed_{self.session_id}.json

## Analysis Steps
1. Open CSV in Excel/Google Sheets
2. Sort by 'legitimate' column to separate attacks
3. Filter by attack_type to group similar threats
4. Look for patterns in timing and source IPs
5. Cross-reference with IOC feed for threat hunting

## Expected Findings
- Unauthorized control commands from IP 192.168.1.50
- Function code 5 (Direct Operate) without authorization
- Invalid function codes >50 indicating protocol fuzzing
- Off-hours operations at 03:15 AM
- Authentication failures from multiple source IPs

## Incident Response Actions
For each attack type found, document:
1. Initial detection method
2. Impact assessment
3. Containment steps
4. Investigation findings
5. Recommended preventive measures
"""
        
        worksheet_file = self.output_dir / "training_scenarios" / f"analysis_worksheet_{self.session_id}.md"
        
        with open(worksheet_file, 'w') as f:
            f.write(worksheet_content)
        print(f"📄 Worksheet created: {worksheet_file}")
    
    def generate_summary_report(self):
        """Generate summary report"""
        total_packets = len(self.traffic_log)
        suspicious_packets = len([p for p in self.traffic_log if not p.get('legitimate', True)])
        
        report_content = f"""# Training Session Summary

**Session ID:** {self.session_id}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Statistics
- Total Packets: {total_packets}
- Suspicious Packets: {suspicious_packets}
- Attack Types: {len(set([e['event_type'] for e in self.security_events]))}
- Security Events: {len(self.security_events)}

## Generated Files
- Traffic Log: analysis_reports/traffic_log_{self.session_id}.csv
- Security Events: security_logs/security_events_{self.session_id}.json
- IOC Feed: ioc_feeds/ioc_feed_{self.session_id}.json
- Analysis Worksheet: training_scenarios/analysis_worksheet_{self.session_id}.md

## Analysis Recommendations
1. Import CSV into spreadsheet for filtering and analysis
2. Review security events for attack patterns
3. Use IOC feed for threat hunting exercises
4. Complete guided worksheet for hands-on learning

## Key Findings
- Suspicious traffic percentage: {(suspicious_packets/total_packets*100):.1f}% if total_packets > 0 else 0}%
- Most common attack types: {', '.join(set([e['event_type'] for e in self.security_events]))}
- Threat sources identified: {len(set([p['src_ip'] for p in self.traffic_log if not p.get('legitimate', True)]))} unique IPs

## Training Value
This session provides hands-on experience with:
- Real security artifact analysis (CSV, JSON)
- OT-specific attack pattern recognition
- Professional incident response workflows
- Tool integration for spreadsheet and SIEM analysis
"""
        
        report_file = self.output_dir / "analysis_reports" / f"training_summary_{self.session_id}.md"
        
        with open(report_file, 'w') as f:
            f.write(report_content)
        print(f"📄 Summary report: {report_file}")


class TrainingController:
    """Interactive training controller"""
    
    def __init__(self):
        self.generator = DNP3TrafficGenerator()
        
    def run_interactive_session(self):
        """Interactive training session"""
        print("\n🎓 DNP3 SOC Training Controller")
        print("=" * 50)
        print("Commands:")
        print("  normal <minutes>     - Generate normal traffic")
        print("  attack <type>        - Generate attack scenario")
        print("  scenario <name>      - Run predefined scenario")
        print("  export               - Export all artifacts")
        print("  status               - Show statistics")
        print("  quit                 - Exit and export")
        print()
        
        self.generator.is_running = True
        
        while True:
            try:
                command = input("training> ").strip().lower()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0]
                
                if cmd == 'quit':
                    break
                    
                elif cmd == 'normal':
                    minutes = int(parts[1]) if len(parts) > 1 else 3
                    self.generator.generate_normal_traffic(minutes)
                    
                elif cmd == 'attack':
                    if len(parts) > 1:
                        attack_type = parts[1]
                        intensity = parts[2] if len(parts) > 2 else "medium"
                        self.generator.generate_attack_scenario(attack_type, intensity)
                    else:
                        self.show_attack_types()
                        
                elif cmd == 'scenario':
                    if len(parts) > 1:
                        self.run_scenario(parts[1])
                    else:
                        self.show_scenarios()
                        
                elif cmd == 'export':
                    self.generator.export_training_artifacts()
                    
                elif cmd == 'status':
                    self.show_status()
                    
                else:
                    print(f"Unknown command: {cmd}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
        
        self.generator.is_running = False
        self.generator.export_training_artifacts()
        print("Training completed!")
    
    def show_attack_types(self):
        """Show available attacks"""
        print("Available attacks:")
        print("- unauthorized_crob   : Control commands from unauthorized sources")
        print("- replay_attack       : Replayed legitimate commands")
        print("- timing_attack       : Operations during suspicious hours")
        print("- protocol_fuzzing    : Malformed DNP3 packets")
        print("- credential_stuffing : Authentication brute force")
    
    def show_scenarios(self):
        """Show scenarios"""
        print("Available scenarios:")
        print("- basic_detection     : Mixed normal and attack traffic")
        print("- advanced_threats    : Multi-stage attack sequence")
    
    def run_scenario(self, scenario_name):
        """Run predefined scenario"""
        if scenario_name == "basic_detection":
            print("🎯 Running basic detection scenario...")
            self.generator.generate_normal_traffic(2)
            time.sleep(1)
            self.generator.generate_attack_scenario('unauthorized_crob', 'medium')
            
        elif scenario_name == "advanced_threats":
            print("🎯 Running advanced threats scenario...")
            self.generator.generate_normal_traffic(1)
            self.generator.generate_attack_scenario('credential_stuffing', 'high')
            time.sleep(1)
            self.generator.generate_attack_scenario('replay_attack', 'medium')
            
        else:
            print(f"Unknown scenario: {scenario_name}")
    
    def show_status(self):
        """Show status"""
        total = len(self.generator.traffic_log)
        suspicious = len([p for p in self.generator.traffic_log if not p.get('legitimate', True)])
        events = len(self.generator.security_events)
        
        print(f"\nSession Statistics:")
        print(f"Total packets: {total}")
        print(f"Suspicious packets: {suspicious}")
        print(f"Security events: {events}")
        print(f"Session ID: {self.generator.session_id}")


def main():
    """Main entry point"""
    print("🛡️  Enhanced DNP3 SOC Analyst Training System")
    print("=" * 60)
    print("🎯 Purpose: Train SOC analysts on OT security monitoring")
    print("📊 Generates: Traffic logs, security events, IOC feeds")
    print("🔧 Tools: CSV analysis, JSON logs, threat hunting")
    print("=" * 60)
    
    controller = TrainingController()
    controller.run_interactive_session()

if __name__ == "__main__":
    main()
