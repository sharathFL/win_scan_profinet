import pyshark
import socket
import subprocess
import platform
from ipaddress import IPv4Network
import struct
import binascii
import argparse
import sys

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
        if interface:
            cap = pyshark.LiveCapture(interface=interface, bpf_filter="lldp")
        else:
            cap = pyshark.LiveCapture(bpf_filter="lldp")

        cap.sniff(packet_count=packet_count, timeout=timeout)

        if len(cap) == 0:
            print("No LLDP packets found. Check if connected to managed network switch.")
        for packet in cap:
            parse_lldp_packet(packet)
    except Exception as e:
        print(f"Error: {e}")

# Capture PROFINET packets only
def capture_profinet(interface=None, packet_count=10, timeout=10):
    print(f"=== Capturing PROFINET Packets (timeout: {timeout}s) ===")
    try:
        pn_filter = "(tcp.port == 34964) || (tcp.port == 34965) || (tcp.port == 34960) || (tcp.port == 2869) || (tcp.port == 3702)"

        if interface:
            cap = pyshark.LiveCapture(interface=interface, bpf_filter=pn_filter)
        else:
            cap = pyshark.LiveCapture(bpf_filter=pn_filter)

        cap.sniff(packet_count=packet_count, timeout=timeout)

        if len(cap) == 0:
            print("No PROFINET packets found. Check if PLC/industrial devices on network.")
        for packet in cap:
            parse_profinet_packet(packet)
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
    if not any([args.lldp, args.profinet, args.tcp, args.arp]):
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
    elif args.arp:
        scan_network(network=args.interface if args.interface else "192.168.1.0/24")
