# Windows 11 Setup Guide

## Prerequisites
- Windows 11 with admin privileges
- Anaconda installed
- Wireshark installed (with Npcap packet capture library)

## Step 1: Install Wireshark
1. Download from: https://www.wireshark.org/download/
2. Run installer
3. Check "Install Npcap" or "Install WinPcap" (packet capture backend)
4. Complete installation

## Step 2: Create Conda Environment
Open **Anaconda Prompt** (Start menu → Anaconda Prompt):

```bash
conda create -n packet-sniffer python=3.11
conda activate packet-sniffer
```

## Step 3: Clone Repository
```bash
git clone <your-repo-url>
cd windows_scanner
```

## Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

## Step 5: Run Script
**Important: Run as Administrator**

Right-click Anaconda Prompt → "Run as administrator"

```bash
conda activate packet-sniffer
python packet_capture.py
```

## Available Functions

Uncomment in `packet_capture.py`:

```python
# List interfaces and local IPs (runs by default)
list_interfaces()
list_local_ips()

# Capture LLDP packets (network topology discovery)
capture_lldp(packet_count=20)

# Capture PROFINET packets (industrial automation)
capture_profinet(packet_count=30)

# Capture TCP packets only
capture_packets(packet_count=10, packet_filter="tcp")

# ARP scan local network
scan_network("192.168.1.0/24")
```

## Troubleshooting

**"tshark not found"**
- Wireshark not installed or not in PATH
- Reinstall Wireshark, ensure Npcap is checked

**"Permission denied"**
- Run Anaconda Prompt as Administrator
- Right-click → "Run as administrator"

**"No packets captured"**
- Check interface name matches your active network adapter
- Run `list_interfaces()` to see available interfaces

**Import errors**
- Reinstall: `pip install --upgrade pyshark scapy`
