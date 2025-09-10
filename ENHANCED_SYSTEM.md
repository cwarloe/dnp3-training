# Enhanced DNP3 SOC Training System v2.0

## Overview
This enhanced system addresses the research findings by focusing on realistic SOC analyst training rather than command-line operations that don't match real utility environments.

## System Architecture
- **Traffic Generator**: Creates realistic DNP3 network patterns
- **Attack Simulator**: 6 different attack scenarios with intensity control  
- **Artifact Exporter**: Generates real files for hands-on analysis
- **Training Controller**: Interactive session management

## Usage

### Installation
```bash
python setup_training_system.py
```

### Run Interactive Training
```bash
python src/enhanced_dnp3_soc_backend.py
```

### Available Commands
```bash
training> normal 3                    # Generate 3 minutes normal traffic
training> attack unauthorized_crob    # Generate attack scenario
training> scenario basic_detection    # Run predefined scenario
training> export                      # Export all artifacts
training> status                      # Show session statistics
training> quit                        # Exit and export
```

## Attack Scenarios

| Attack Type | Description | Key Indicators |
|-------------|-------------|----------------|
| `unauthorized_crob` | Control commands from unauthorized sources | Function code 5 from non-SCADA IPs |
| `replay_attack` | Replayed legitimate commands | Duplicate sequence numbers |
| `protocol_fuzzing` | Malformed DNP3 packets | Invalid function codes >50 |
| `timing_attack` | Operations during suspicious hours | Commands at 2-5 AM |
| `credential_stuffing` | Authentication brute force | Multiple auth failures |

## Generated Training Artifacts

### CSV Traffic Logs
**Location**: `training_outputs/analysis_reports/traffic_log_*.csv`
**Purpose**: Spreadsheet-based analysis practice
**Contains**: Timestamp, source/dest IPs, function codes, attack classifications

### JSON Security Events  
**Location**: `training_outputs/security_logs/security_events_*.json`
**Purpose**: SIEM integration training
**Contains**: Event correlation, severity ratings, recommended actions

### IOC Feeds
**Location**: `training_outputs/ioc_feeds/ioc_feed_*.json`
**Purpose**: Threat hunting exercises
**Contains**: Malicious IPs, suspicious patterns, threat intelligence

### Analysis Worksheets
**Location**: `training_outputs/training_scenarios/analysis_worksheet_*.md`
**Purpose**: Guided learning exercises
**Contains**: Questions, expected findings, learning objectives

## Training Scenarios

### Basic Detection
```bash
training> scenario basic_detection
```
- 2 minutes normal traffic
- 1 unauthorized CROB attack
- Practice identifying attacks in mixed traffic

### Advanced Threats
```bash
training> scenario advanced_threats  
```
- Multi-stage attack sequence
- Credential stuffing → Replay attack
- Practice attack correlation

## Tool Integration

### Spreadsheet Analysis
1. Open CSV in Excel/Google Sheets
2. Sort by 'legitimate' column
3. Filter by attack types
4. Look for timing patterns
5. Identify threat sources

### SIEM Integration
```bash
# Import into Splunk
index=dnp3_training source="*security_events*"

# Import into QRadar (CEF format available)
# Import into Elastic (JSON format)
```

### Threat Hunting
1. Import IOC feed into threat intelligence platform
2. Cross-reference malicious IPs with other logs
3. Practice IOC development and correlation

## Learning Outcomes

### For SOC Analysts
- ✅ Identify normal vs. suspicious DNP3 traffic patterns
- ✅ Understand OT-specific attack vectors and TTPs  
- ✅ Practice incident response for control system environments
- ✅ Use professional security tools (spreadsheets, SIEM platforms)
- ✅ Develop threat hunting skills for OT networks

### Assessment Capabilities
- Guided worksheets with specific questions
- Expected findings for instructor grading
- Skill progression tracking across sessions
- Integration with existing security training programs

## Technical Details

### Dependencies
- Python 3.7+
- PyYAML (for configuration)
- Standard library only (csv, json, datetime)

### Configuration
Edit `config/enhanced_soc_training_config.yaml` to customize:
- Network topology
- Attack scenarios
- Output formats
- SIEM integration settings

### Extensibility
- Add custom attack scenarios
- Integrate with additional tools
- Customize output formats
- Scale for enterprise deployment