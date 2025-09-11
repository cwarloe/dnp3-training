# DNP3 Training System

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

---

---

## 🛡️ Enhanced SOC Training System (v2.0)

Based on the research findings above, we've developed an enhanced training system that focuses on **realistic SOC analyst workflows** rather than command-line operations.

### Quick Start
```bash
python setup_training_system.py
python src/enhanced_dnp3_soc_backend.py
```

### Key Improvements
- ✅ **Real training artifacts** - CSV logs, JSON events, IOC feeds
- ✅ **Professional workflows** - Spreadsheet analysis, SIEM integration
- ✅ **Attack scenarios** - 6 different attack types with intensity control
- ✅ **Guided exercises** - Analysis worksheets with answer keys

See [ENHANCED_SYSTEM.md](ENHANCED_SYSTEM.md) for detailed documentation.

### Generated Artifacts
- Traffic analysis: `training_outputs/analysis_reports/*.csv`
- Security events: `training_outputs/security_logs/*.json`
- Threat hunting: `training_outputs/ioc_feeds/*.json`
- Training guides: `training_outputs/training_scenarios/*.md`

## License

MIT License


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

