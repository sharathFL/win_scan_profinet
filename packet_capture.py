import socket
import subprocess
import platform
import argparse
import sys
import os
import json
import re

# Auto-detect tshark path on Windows
TSHARK_PATH = "tshark"
if platform.system() == "Windows":
    for path in [r"C:\Program Files\Wireshark\tshark.exe",
                 r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if os.path.exists(path):
            TSHARK_PATH = path
            break

def _tshark(args):
    return subprocess.Popen(
        [TSHARK_PATH] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

def _tshark_run(args):
    result = subprocess.run([TSHARK_PATH] + args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"tshark error: {result.stderr.strip()}")
        return None
    return result.stdout

def _find(d, key):
    if isinstance(d, dict):
        if key in d:
            return d[key]
        for v in d.values():
            r = _find(v, key)
            if r is not None:
                return r
    return None

def list_interfaces():
    print("=== Network Interfaces ===")
    if platform.system() == "Windows":
        r = subprocess.run(['ipconfig'], capture_output=True, text=True)
        print(r.stdout)
    else:
        r = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        print(r.stdout)

def list_local_ips():
    print("=== Local IPs ===")
    try:
        hostname = socket.gethostname()
        print(f"Hostname : {hostname}")
        print(f"IPs      : {socket.gethostbyname_ex(hostname)[2]}")
    except Exception as e:
        print(f"Error: {e}")

# --all: live stream all packets
def capture_all(interface, packet_count=50, timeout=30):
    print(f"=== Live Capture — all packets (timeout: {timeout}s, max: {packet_count}) ===")
    print(f"{'#':<5} {'Src':<20} {'Dst':<20} {'Protocol':<25} {'Len':<6}")
    print("-" * 90)
    proc = _tshark(['-i', interface,
                    '-a', f'duration:{timeout}', '-c', str(packet_count),
                    '-T', 'fields',
                    '-e', 'frame.number',
                    '-e', 'ip.src', '-e', 'ip.dst',
                    '-e', 'eth.src', '-e', 'eth.dst',
                    '-e', 'frame.protocols',
                    '-e', 'frame.len',
                    '-l'])
    try:
        for line in proc.stdout:
            f = line.strip().split('\t')
            if len(f) >= 6:
                num   = f[0]
                src   = f[1] or f[3] or "?"
                dst   = f[2] or f[4] or "?"
                proto = f[5][:25] if f[5] else "?"
                length = f[6] if len(f) > 6 else "?"
                print(f"{num:<5} {src:<20} {dst:<20} {proto:<25} {length:<6}")
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\nStopped.")

# --lldp: capture LLDP packets (raw summary)
def capture_lldp(interface, packet_count=10, timeout=30):
    print(f"=== LLDP Capture (timeout: {timeout}s) ===")
    out = _tshark_run(['-i', interface,
                       '-f', 'ether proto 0x88cc',
                       '-a', f'duration:{timeout}', '-c', str(packet_count)])
    if out is None:
        return
    lines = [l for l in out.strip().split('\n') if l.strip()]
    if not lines:
        print("No LLDP packets found.")
        return
    for line in lines:
        print(line)

# --profinet: capture PROFINET-RT + TCP ports
def capture_profinet(interface, packet_count=20, timeout=30):
    print(f"=== PROFINET Capture (timeout: {timeout}s) ===")
    pn_filter = ("ether proto 0x8892 or ether proto 0x8891 or "
                 "tcp port 34964 or tcp port 34965 or tcp port 34960")
    out = _tshark_run(['-i', interface,
                       '-f', pn_filter,
                       '-a', f'duration:{timeout}', '-c', str(packet_count)])
    if out is None:
        return
    lines = [l for l in out.strip().split('\n') if l.strip()]
    if not lines:
        print("No PROFINET packets found.")
        return
    for line in lines:
        print(line)

def _parse_lldp_verbose(text, debug=False):
    """Parse tshark -V verbose LLDP output into device dicts keyed by MAC."""
    if debug:
        print("=== RAW TSHARK OUTPUT ===")
        print(text[:6000])
        print("=========================\n")

    devices = {}
    current_mac = None
    dev = {}

    def flush():
        if current_mac and dev:
            if current_mac not in devices:
                devices[current_mac] = dev.copy()

    for line in text.splitlines():
        if re.match(r'^Frame \d+:', line):
            flush()
            dev = {}
            current_mac = None
            continue

        s = line.strip()
        sl = s.lower()

        # Source MAC from Ethernet line: "Ethernet II, Src: Name (aa:bb:cc:dd:ee:ff)"
        if current_mac is None and ('src:' in sl or 'source:' in sl):
            mac = re.search(r'\(([0-9a-f]{2}(?::[0-9a-f]{2}){5})\)', s, re.I)
            if mac:
                current_mac = mac.group(1).lower()

        # Chassis ID: grab human-readable from summary line
        # "Chassis Subtype = Locally assigned, Id: S7-1500..."
        m = re.match(r'chassis subtype\s*=.*?,\s*id:\s*(.+)', sl)
        if m:
            # Get original case from s using same offset
            idx = s.lower().find(', id:')
            if idx != -1:
                dev['Chassis ID'] = s[idx+5:].strip()[:30]

        # Port Id: port-001...
        elif re.match(r'port id:', sl):
            dev['Port ID'] = s.split(':', maxsplit=1)[1].strip()[:35]

        # System Name = S7-1500
        elif re.match(r'system name\s*=', sl):
            dev['System Name'] = s.split('=', maxsplit=1)[1].strip()

        # System Description = Siemens...
        elif re.match(r'system description\s*=', sl):
            dev['Description'] = s.split('=', maxsplit=1)[1].strip()[:70]

        # Management Address = 192.168.x.x  (any line containing an IP after =)
        elif 'management address' in sl and '=' in s and 'Mgmt IP' not in dev:
            m3 = re.search(r'=\s*(\d+\.\d+\.\d+\.\d+)', s)
            if m3:
                dev['Mgmt IP'] = m3.group(1)

        # Time To Live = 20 sec
        elif re.match(r'time to live\s*=', sl) and 'TTL' not in dev:
            m2 = re.search(r'=\s*(\d+)', s)
            if m2:
                dev['TTL'] = m2.group(1)

    flush()
    return devices

# --devices: parse LLDP verbose output and print device table
def scan_devices(interface, timeout=30, debug=False):
    print(f"=== Device Scan via LLDP (timeout: {timeout}s) ===\n")
    out = _tshark_run(['-i', interface,
                       '-f', 'ether proto 0x88cc',
                       '-a', f'duration:{timeout}',
                       '-V'])   # verbose: human-readable field names
    if out is None or not out.strip():
        print("No LLDP packets found.")
        return

    devices = _parse_lldp_verbose(out, debug=debug)

    if not devices:
        print("No devices parsed from LLDP.")
        return

    cols = ['MAC', 'System Name', 'Chassis ID', 'Port ID', 'Mgmt IP', 'TTL', 'Description']
    # Merge MAC into device dict + fallback System Name
    for mac, d in devices.items():
        d['MAC'] = mac
        if not d.get('System Name'):
            # Use first segment of Chassis ID as name
            d['System Name'] = d.get('Chassis ID', '').split()[0][:20]

    rows = list(devices.values())
    widths = {}
    for c in cols:
        vals = [len(str(r.get(c, ''))) for r in rows]
        widths[c] = max(len(c), max(vals) if vals else 0)

    sep = '  '
    header = sep.join(f"{c:<{widths[c]}}" for c in cols)
    print(header)
    print('-' * len(header))
    for r in rows:
        print(sep.join(f"{str(r.get(c,'')):<{widths[c]}}" for c in cols))
    print(f"\n{len(devices)} device(s) found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network sniffer — LLDP / PROFINET / General")
    parser.add_argument("-i", "--interface", type=str, help="Network interface (e.g. 'Ethernet 2')")
    parser.add_argument("-t", "--timeout",   type=int, default=30, help="Capture duration in seconds (default: 30)")
    parser.add_argument("-c", "--count",     type=int, default=50,  help="Max packet count (default: 50)")
    parser.add_argument("--list-ifaces",  action="store_true", help="List interfaces and local IPs")
    parser.add_argument("--all",          action="store_true", help="Live stream all packets")
    parser.add_argument("--lldp",         action="store_true", help="Capture LLDP packets")
    parser.add_argument("--profinet",     action="store_true", help="Capture PROFINET-RT packets")
    parser.add_argument("--devices",      action="store_true", help="Scan devices via LLDP (pretty table)")
    parser.add_argument("--arp",          type=str, metavar="SUBNET", help="ARP scan subnet e.g. 192.168.1.0/24")
    parser.add_argument("--debug",        action="store_true", help="Print raw tshark output for troubleshooting")
    args = parser.parse_args()

    if args.list_ifaces or not any([args.all, args.lldp, args.profinet, args.devices, args.arp]):
        list_interfaces()
        list_local_ips()
        sys.exit(0)

    if args.arp:
        try:
            from scapy.all import ARP, Ether, srp
            arp = ARP(pdst=args.arp)
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp, timeout=2, verbose=False)[0]
            print(f"\n{'IP':<15} {'MAC'}")
            print("-" * 35)
            for _, r in result:
                print(f"{r.psrc:<15} {r.hwsrc}")
        except ImportError:
            print("scapy not installed: pip install scapy")
        sys.exit(0)

    if not args.interface:
        print("Error: -i/--interface required for capture modes.")
        list_interfaces()
        sys.exit(1)

    if args.devices:
        scan_devices(interface=args.interface, timeout=args.timeout, debug=args.debug)
    elif args.lldp:
        capture_lldp(interface=args.interface, packet_count=args.count, timeout=args.timeout)
    elif args.profinet:
        capture_profinet(interface=args.interface, packet_count=args.count, timeout=args.timeout)
    elif args.all:
        capture_all(interface=args.interface, packet_count=args.count, timeout=args.timeout)
