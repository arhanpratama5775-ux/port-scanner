#!/usr/bin/env python3
"""
Port Scanner - Scan open ports on a target host
Simple TCP port scanner for security testing.

Usage:
    python scanner.py 192.168.1.1              # Scan common ports
    python scanner.py 192.168.1.1 -p 80,443    # Scan specific ports
    python scanner.py 192.168.1.1 -p 1-1000    # Scan port range

Disclaimer: Only use on systems you own or have permission to test.
"""

import sys
import socket
import argparse
import concurrent.futures
from datetime import datetime


# ══════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


# ══════════════════════════════════════════════════
#  COMMON PORTS & SERVICES
# ══════════════════════════════════════════════════
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPCBind',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
}


# ══════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════
class PortScanner:
    def __init__(self, host, timeout=1):
        self.host = host
        self.timeout = timeout
        self.open_ports = []

    def resolve_host(self):
        """Resolve hostname to IP"""
        try:
            ip = socket.gethostbyname(self.host)
            return ip
        except socket.gaierror:
            return None

    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            sock.close()

            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                return {'port': port, 'state': 'open', 'service': service}
            else:
                return {'port': port, 'state': 'closed', 'service': ''}
        except:
            return {'port': port, 'state': 'filtered', 'service': ''}

    def scan(self, ports, max_threads=100):
        """Scan multiple ports with threading"""
        results = []
        total = len(ports)

        print(f"\n{Colors.CYAN}Scanning {total} ports on {self.host}...{Colors.ENDC}\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}

            for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
                result = future.result()
                if result['state'] == 'open':
                    results.append(result)
                    print(f"  {Colors.GREEN}[OPEN]{Colors.ENDC}   {result['port']:5d}  {result['service']}")
                elif result['state'] == 'filtered':
                    print(f"  {Colors.YELLOW}[FILTERED]{Colors.ENDC} {result['port']:5d}")

        return sorted(results, key=lambda x: x['port'])


def parse_ports(port_str):
    """Parse port specification string"""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


# ══════════════════════════════════════════════════
#  DISPLAY
# ══════════════════════════════════════════════════
def display_banner():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*50}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}  Port Scanner{Colors.ENDC}")
    print(f"{Colors.DIM}  For authorized security testing only{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*50}{Colors.ENDC}")


def display_results(host, ip, open_ports, scan_time):
    print(f"\n{Colors.BOLD}Results for {host} ({ip}){Colors.ENDC}")
    print(f"Scanned in {scan_time:.2f}s\n")

    if open_ports:
        print(f"{Colors.GREEN}Found {len(open_ports)} open port(s):{Colors.ENDC}\n")
        print(f"  {'Port':<10} {'State':<10} {'Service'}")
        print(f"  {'-'*35}")
        for port_info in open_ports:
            print(f"  {port_info['port']:<10} {Colors.GREEN}open{Colors.ENDC}      {port_info['service']}")
    else:
        print(f"{Colors.YELLOW}No open ports found{Colors.ENDC}")

    print()


# ══════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description='Port Scanner - Scan open ports on a target host',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1                    # Scan common ports
  %(prog)s 192.168.1.1 -p 80,443,8080     # Specific ports
  %(prog)s 192.168.1.1 -p 1-1000          # Port range
  %(prog)s example.com -p 22,80,443       # Target by hostname

⚠️  Only use on systems you own or have permission to test.
        """
    )

    parser.add_argument('host', help='Target host (IP or hostname)')
    parser.add_argument('-p', '--ports', default='21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443',
                        help='Ports to scan (default: common ports)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1)')
    parser.add_argument('-w', '--workers', type=int, default=100, help='Max threads (default: 100)')

    args = parser.parse_args()

    display_banner()

    # Create scanner
    scanner = PortScanner(args.host, args.timeout)

    # Resolve host
    ip = scanner.resolve_host()
    if not ip:
        print(f"{Colors.RED}Error: Could not resolve host {args.host}{Colors.ENDC}")
        sys.exit(1)

    print(f"Target: {args.host} ({ip})")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"{Colors.RED}Error: Invalid port specification{Colors.ENDC}")
        sys.exit(1)

    # Scan
    start_time = datetime.now()
    open_ports = scanner.scan(ports, args.workers)
    scan_time = (datetime.now() - start_time).total_seconds()

    # Display results
    display_results(args.host, ip, open_ports, scan_time)


if __name__ == '__main__':
    main()
