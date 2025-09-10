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

## License

MIT License
