#!/bin/bash
# Raspberry Pi Setup for DNP3 Traffic Generator

echo "🥧 Setting up DNP3 Traffic Generator on Raspberry Pi"
echo "=================================================="

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
sudo apt install -y python3 python3-pip python3-venv

# Install network tools
sudo apt install -y tcpdump wireshark-tshark net-tools

# Install Python packages
pip3 install PyYAML

# Set permissions for raw sockets (needed for some advanced features)
sudo setcap cap_net_raw+ep $(which python3)

# Create systemd service
sudo tee /etc/systemd/system/dnp3-traffic.service > /dev/null <<EOF
[Unit]
Description=DNP3 Traffic Generator
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/dnp3-training/traffic_generator
ExecStart=/usr/bin/python3 dnp3_traffic_generator.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit traffic_generator/config.yaml"
echo "2. Test: python3 traffic_generator/dnp3_traffic_generator.py"
echo "3. Service: sudo systemctl start dnp3-traffic"
echo "4. Monitor: sudo tcpdump -i eth0 port 20000"
