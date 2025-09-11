# DNP3 Network Traffic Generator

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
