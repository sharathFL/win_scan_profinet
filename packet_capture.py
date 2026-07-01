import pyshark
import socket
import subprocess
import platform
from ipaddress import IPv4Network
import struct
import binascii
import argparse
import sys
import os

# Detect tshark path
TSHARK_PATH = "tshark"
if platform.system() == "Windows":
    wireshark_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for path in wireshark_paths:
        if os.path.exists(path):
            TSHARK_PATH = path
            break

# List network interfaces (devices)
def list_interfaces():
    print("=== Network Interfaces ===")
    if platform.system() == "Windows":
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        print(result.stdout)
    else:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        print(result.stdout)

# Get local IP addresses
def list_local_ips():
    print("\n=== Local IP Addresses ===")
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        print(f"Hostname: {hostname}")
        print(f"Primary IP: {local_ip}")
    except:
        print("Could not retrieve IP")

    # Alternative: all IPs
    try:
        all_ips = socket.gethostbyname_ex(socket.gethostname())
        print(f"All IPs: {all_ips[2]}")
    except:
        pass

# Parse LLDP packets
def parse_lldp_packet(packet):
    print(f"\n[LLDP Packet]")
    try:
        print(f"  Layers: {packet.layers}")

        if 'LLDP' in packet:
            lldp = packet['LLDP']

            # Chassis ID
            if hasattr(lldp, 'chassis_id'):
                print(f"  Chassis ID: {lldp.chassis_id}")
            if hasattr(lldp, 'chassis_subtype'):
                print(f"  Chassis Type: {lldp.chassis_subtype}")

            # Port ID
            if hasattr(lldp, 'port_id'):
                print(f"  Port ID: {lldp.port_id}")
            if hasattr(lldp, 'port_subtype'):
                print(f"  Port Type: {lldp.port_subtype}")

            # TTL
            if hasattr(lldp, 'ttl'):
                print(f"  TTL: {lldp.ttl}")

            # System Name
            if hasattr(lldp, 'system_name'):
                print(f"  System Name: {lldp.system_name}")

            # System Description
            if hasattr(lldp, 'system_description'):
                print(f"  Description: {lldp.system_description[:50]}...")

            # Capabilities
            if hasattr(lldp, 'caps_available'):
                print(f"  Capabilities: {lldp.caps_available}")
        else:
            print(f"  No LLDP layer found. Available: {list(packet.keys())[:5]}")
    except Exception as e:
        print(f"  Error parsing LLDP: {e}")

# Parse PROFINET/PN-PTCP packets
def parse_profinet_packet(packet):
    print(f"\n[PROFINET Packet]")
    try:
        # PROFINET uses specific TCP ports (34964, 34965, 2869, 34960)
        if 'TCP' in packet:
            tcp = packet['TCP']
            src_port = int(tcp.srcport)
            dst_port = int(tcp.dstport)

            # Known PROFINET ports
            pn_ports = [34964, 34965, 34960, 2869, 3702, 5353]

            if src_port in pn_ports or dst_port in pn_ports:
                print(f"  Source: {packet['IP'].src}:{src_port}")
                print(f"  Destination: {packet['IP'].dst}:{dst_port}")
                print(f"  Port: {src_port if src_port in pn_ports else dst_port} (PROFINET)")

                if 'PNIO' in packet:
                    print(f"  PNIO Layer: {packet['PNIO']}")

                if hasattr(packet, 'Raw'):
                    raw_data = packet['Raw'].payload
                    print(f"  Payload Length: {len(raw_data)} bytes")
                    print(f"  Hex: {binascii.hexlify(raw_data.encode() if isinstance(raw_data, str) else raw_data)[:64]}...")
    except Exception as e:
        print(f"  Error parsing PROFINET: {e}")

# Capture packets from interface
def capture_packets(interface=None, packet_count=10, packet_filter=None, timeout=10):
    print(f"\n=== Capturing Packets (Count: {packet_count}, Timeout: {timeout}s) ===")
    try:
        if packet_filter:
            if interface:
                cap = pyshark.LiveCapture(interface=interface, bpf_filter=packet_filter)
            else:
                cap = pyshark.LiveCapture(bpf_filter=packet_filter)
        else:
            if interface:
                cap = pyshark.LiveCapture(interface=interface)
            else:
                cap = pyshark.LiveCapture()

        cap.sniff(packet_count=packet_count, timeout=timeout)

        for packet in cap:
            print(f"\n[{packet.number}] {packet.highest_layer}")
            if 'IP' in packet:
                print(f"  SRC: {packet['IP'].src} -> DST: {packet['IP'].dst}")
            if 'TCP' in packet:
                print(f"  TCP: {packet['TCP'].srcport} -> {packet['TCP'].dstport}")
            if 'DNS' in packet:
                print(f"  DNS Query: {packet['DNS'].qry_name}")
            if 'LLDP' in packet:
                parse_lldp_packet(packet)
            if 'TCP' in packet:
                parse_profinet_packet(packet)
    except Exception as e:
        print(f"Error: {e}")

# Capture LLDP packets only
def capture_lldp(interface=None, packet_count=10, timeout=10):
    print(f"=== Capturing LLDP Packets (timeout: {timeout}s) ===")
    try:
        # LLDP uses Ethernet type 0x88cc (capture filter syntax, not display filter)
        cmd = [TSHARK_PATH, '-i', interface or '1', '-f', 'ether proto 0x88cc', '-a', f'duration:{timeout}', '-c', str(packet_count)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"tshark error: {result.stderr}")
            return

        lines = result.stdout.strip().split('\n')
        if not lines or lines[0] == '':
            print("No LLDP packets found. Check if connected to managed network switch.")
            return

        packet_count_found = 0
        for line in lines:
            if line.strip() and line[0].isdigit():
                print(f"\n{line}")
                packet_count_found += 1

        if packet_count_found == 0:
            print("No LLDP packets captured.")
    except FileNotFoundError:
        print("Error: tshark not found. Install Wireshark with tshark.")
    except Exception as e:
        print(f"Error: {e}")

# Capture PROFINET packets only (PROFINET-RT: EtherType 0x8892, 0x8891)
def capture_profinet(interface=None, packet_count=10, timeout=10):
    print(f"=== Capturing PROFINET Packets (timeout: {timeout}s) ===")
    try:
        # PROFINET-RT: EtherType 0x8892 (RT) + 0x8891 (CBA) + TCP ports
        pn_filter = "ether proto 0x8892 or ether proto 0x8891 or tcp port 34964 or tcp port 34965 or tcp port 34960"

        cmd = [TSHARK_PATH, '-i', interface or '1', '-f', pn_filter, '-a', f'duration:{timeout}', '-c', str(packet_count)]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"tshark error: {result.stderr}")
            return

        lines = result.stdout.strip().split('\n')
        if not lines or lines[0] == '':
            print("No PROFINET packets found. Check if PLC/industrial devices on network.")
            return

        packet_count_found = 0
        for line in lines:
            if line.strip() and line[0].isdigit():
                print(f"\n{line}")
                packet_count_found += 1

        if packet_count_found == 0:
            print("No PROFINET packets captured.")
    except FileNotFoundError:
        print("Error: tshark not found. Install Wireshark with tshark.")
    except Exception as e:
        print(f"Error: {e}")

# Capture all packets (no filter) with formatted output
def capture_all(interface=None, packet_count=10, timeout=10):
    print(f"=== Capturing All Packets (timeout: {timeout}s) ===\n")
    try:
        # Use tshark with formatted output fields
        cmd = [TSHARK_PATH, '-i', interface or '1', '-a', f'duration:{timeout}', '-c', str(packet_count),
               '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst',
               '-e', 'eth.src', '-e', 'eth.dst', '-e', 'frame.protocols', '-e', 'frame.len', '-e', 'info']

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            # Fallback: no field filter, just raw output
            cmd_simple = [TSHARK_PATH, '-i', interface or '1', '-a', f'duration:{timeout}', '-c', str(packet_count)]
            result = subprocess.run(cmd_simple, capture_output=True, text=True)

        lines = result.stdout.strip().split('\n')
        if not lines or lines[0] == '':
            print("No packets captured.")
            return

        print(f"{'#':<4} {'Time':<12} {'Src IP':<15} {'Dst IP':<15} {'Protocol':<20} {'Length':<8} {'Info':<50}")
        print("-" * 140)

        for i, line in enumerate(lines, 1):
            if line.strip():
                fields = line.split('\t')
                if len(fields) >= 7:
                    pkt_num = fields[0] if fields[0] else str(i)
                    timestamp = fields[1][:10] if len(fields[1]) > 10 else fields[1]
                    src_ip = fields[2][:15] if fields[2] else "N/A"
                    dst_ip = fields[3][:15] if fields[3] else "N/A"
                    protocols = fields[6][:20] if len(fields) > 6 and fields[6] else "N/A"
                    length = fields[7] if len(fields) > 7 else "0"
                    info = fields[8][:50] if len(fields) > 8 else ""

                    print(f"{pkt_num:<4} {timestamp:<12} {src_ip:<15} {dst_ip:<15} {protocols:<20} {length:<8} {info:<50}")
                else:
                    print(line)
    except FileNotFoundError:
        print("Error: tshark not found. Install Wireshark with tshark.")
    except Exception as e:
        print(f"Error: {e}")

# Scan local network (ARP scan)
def scan_network(network="192.168.1.0/24"):
    print(f"\n=== ARP Scan: {network} ===")
    try:
        from scapy.all import ARP, Ether, srp
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=False)[0]
        print(f"{'IP':<15} {'MAC':<20}")
        for sent, received in result:
            print(f"{received.psrc:<15} {received.hwsrc:<20}")
    except ImportError:
        print("Scapy not installed. Run: pip install scapy")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network packet sniffer - LLDP/PROFINET parser")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to capture on")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Capture timeout in seconds (default: 10)")
    parser.add_argument("--list-ifaces", action="store_true", help="List available network interfaces")
    parser.add_argument("--lldp", action="store_true", help="Capture LLDP packets")
    parser.add_argument("--profinet", action="store_true", help="Capture PROFINET packets")
    parser.add_argument("--tcp", action="store_true", help="Capture TCP packets")
    parser.add_argument("--arp", action="store_true", help="Perform ARP scan on network")
    parser.add_argument("--all", action="store_true", help="Capture all packets (no filter)")
    parser.add_argument("-c", "--count", type=int, default=20, help="Number of packets to capture (default: 20)")

    args = parser.parse_args()

    # List interfaces
    if args.list_ifaces:
        list_interfaces()
        list_local_ips()
        sys.exit(0)

    # Require interface for capture modes
    if not args.interface and not args.arp:
        parser.print_help()
        list_interfaces()
        list_local_ips()
        sys.exit(1)

    # Default: show info and interfaces
    if not any([args.lldp, args.profinet, args.tcp, args.arp, args.all]):
        list_interfaces()
        list_local_ips()
        sys.exit(0)

    # Execute requested mode
    if args.lldp:
        capture_lldp(interface=args.interface, packet_count=args.count, timeout=args.timeout)
    elif args.profinet:
        capture_profinet(interface=args.interface, packet_count=args.count, timeout=args.timeout)
    elif args.tcp:
        capture_packets(interface=args.interface, packet_count=args.count, packet_filter="tcp", timeout=args.timeout)
    elif args.all:
        capture_all(interface=args.interface, packet_count=args.count, timeout=args.timeout)
    elif args.arp:
        scan_network(network=args.interface if args.interface else "192.168.1.0/24")
