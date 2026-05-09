#!/usr/bin/env python3
"""
nxc_credspray.py - NetExec Credential Spray Wrapper

Scans targets for open ports and automatically tests credentials
on all discovered protocols using NetExec (nxc).
"""

import argparse
import ipaddress
import os
import pty
import re
import select
import shlex
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple


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


# Protocol to port mapping
PROTOCOLS = {
    'smb': [445],
    'winrm': [5985, 5986],
    'wmi': [135],
    'rdp': [3389],
    'ldap': [389, 636],
    'mssql': [1433],
}

# Protocol colors - matching nxc's color scheme
PROTOCOL_COLORS = {
    'smb': Colors.BLUE,
    'winrm': Colors.RED,
    'wmi': Colors.YELLOW,
    'rdp': Colors.CYAN,
    'ldap': Colors.CYAN,
    'mssql': Colors.MAGENTA,
}

# Reverse mapping: port to protocol
PORT_TO_PROTOCOL = {}
for proto, ports in PROTOCOLS.items():
    for port in ports:
        PORT_TO_PROTOCOL[port] = proto

# Protocols where pass-the-hash is not meaningfully supported by nxc.
# Spraying NTLM hashes against these wastes time and generates noise.
# Override with --force-hash-all.
HASH_INCAPABLE_PROTOCOLS = {'ldap', 'rdp', 'ftp', 'ssh'}

# Cap CIDR expansion to keep memory/output sane (a /16 = 65k hosts).
MAX_CIDR_HOSTS = 65536


def expand_target(entry: str) -> List[str]:
    """Expand CIDR (10.0.0.0/24) or IP range (10.0.0.1-50, 10.0.0.1-10.0.0.50).
    Hostnames and single IPs pass through unchanged."""
    # CIDR
    if '/' in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if network.num_addresses > MAX_CIDR_HOSTS:
                print(f"{Colors.YELLOW}[!]{Colors.RESET} CIDR {entry} expands to "
                      f"{network.num_addresses} hosts (>{MAX_CIDR_HOSTS}); skipping")
                return []
            if network.num_addresses == 1:
                return [str(network.network_address)]
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            pass  # fall through; treat as literal

    # Range: 10.0.0.1-50 or 10.0.0.1-10.0.0.50
    range_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$', entry)
    if range_match:
        start_str, end_str = range_match.group(1), range_match.group(2)
        try:
            start_ip = ipaddress.IPv4Address(start_str)
            if '.' in end_str:
                end_ip = ipaddress.IPv4Address(end_str)
            else:
                base = start_str.rsplit('.', 1)[0]
                end_ip = ipaddress.IPv4Address(f"{base}.{end_str}")
            if int(end_ip) < int(start_ip):
                print(f"{Colors.YELLOW}[!]{Colors.RESET} Range {entry} has end < start; skipping")
                return []
            count = int(end_ip) - int(start_ip) + 1
            if count > MAX_CIDR_HOSTS:
                print(f"{Colors.YELLOW}[!]{Colors.RESET} Range {entry} expands to "
                      f"{count} hosts (>{MAX_CIDR_HOSTS}); skipping")
                return []
            return [str(ipaddress.IPv4Address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        except (ValueError, ipaddress.AddressValueError):
            pass

    return [entry]


def parse_targets(target_input: str) -> List[str]:
    """Parse target input - either a file of entries or a single entry.
    Supports single IPs, hostnames, CIDR, and IP ranges (in files or as the arg)."""
    raw_entries: List[str] = []

    if os.path.isfile(target_input):
        try:
            with open(target_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        raw_entries.append(line)
        except (PermissionError, IsADirectoryError, UnicodeDecodeError) as e:
            print(f"{Colors.RED}[!] Could not read target file {target_input}: {e}{Colors.RESET}")
            sys.exit(1)
    else:
        raw_entries.append(target_input)

    # Expand CIDR/ranges, dedupe while preserving order
    seen: Set[str] = set()
    targets: List[str] = []
    for entry in raw_entries:
        for t in expand_target(entry):
            if t not in seen:
                seen.add(t)
                targets.append(t)

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


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _emit_line(line: str, protocol: str, cred_type: str,
               full_output: List[str], successes: List[Dict]) -> None:
    """Print a single nxc output line and capture successes."""
    line = line.rstrip('\r')
    if not line:
        return
    full_output.append(line)
    print(line)
    clean_line = _ANSI_RE.sub('', line)
    if '[+]' in clean_line:
        entry = parse_success_line(protocol, clean_line, cred_type)
        if entry:
            successes.append(entry)


def run_nxc(protocol: str, target: str, user_arg: str, cred_arg: str,
            cred_type: str, extra_args: List[str]) -> Tuple[str, List[Dict]]:
    """Run nxc command and capture output, preserving nxc's native colors."""

    cmd = ['nxc', protocol, target, '-u', user_arg]

    if cred_type == 'password':
        cmd.extend(['-p', cred_arg])
    elif cred_type == 'hash':
        cmd.extend(['-H', cred_arg])

    cmd.extend(extra_args)

    successes: List[Dict] = []
    full_output: List[str] = []

    # shlex.join keeps empty args ('') visible and shell-quotes anything tricky
    print(f"{Colors.DIM}$ {shlex.join(cmd)}{Colors.RESET}\n")

    try:
        master_fd, slave_fd = pty.openpty()

        process = subprocess.Popen(
            cmd,
            stdout=slave_fd,
            stderr=slave_fd,
            stdin=slave_fd,
            close_fds=True,
        )

        os.close(slave_fd)

        output_buffer = ""
        try:
            while True:
                ready, _, _ = select.select([master_fd], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    output_buffer += data.decode('utf-8', errors='replace')
                    while '\n' in output_buffer:
                        line, output_buffer = output_buffer.split('\n', 1)
                        _emit_line(line, protocol, cred_type, full_output, successes)
                elif process.poll() is not None:
                    # Drain whatever is left in the PTY buffer.
                    while True:
                        try:
                            data = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        output_buffer += data.decode('utf-8', errors='replace')
                    while '\n' in output_buffer:
                        line, output_buffer = output_buffer.split('\n', 1)
                        _emit_line(line, protocol, cred_type, full_output, successes)
                    if output_buffer:
                        # Final partial line with no trailing newline.
                        _emit_line(output_buffer, protocol, cred_type, full_output, successes)
                        output_buffer = ""
                    break
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass

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
  {Colors.GREEN}%(prog)s -t 192.168.1.10 -u "" -p ""{Colors.RESET}
  {Colors.DIM}(null session: empty user, empty password — same as nxc){Colors.RESET}
  {Colors.GREEN}%(prog)s -t 192.168.1.10 -u guest --no-pass{Colors.RESET}
  {Colors.DIM}(guest-style auth: provided user, empty password){Colors.RESET}
  {Colors.GREEN}%(prog)s -t 10.0.0.0/24 -u admin -p Pass123 --protocols smb{Colors.RESET}
        '''
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target file, single IP/hostname, CIDR (10.0.0.0/24), or range (10.0.0.1-50)')
    parser.add_argument('-u', '--user', default=None,
                        help='Username file or single username (use empty string "" for null auth)')
    parser.add_argument('-p', '--password',
                        help='Password file or single password (use empty string "" for null auth)')
    parser.add_argument('-H', '--hash',
                        help='Hash file or single hash (NTLM) - can be combined with -p')
    parser.add_argument('--no-pass', action='store_true',
                        help='Send empty password with the provided -u (matches nxc --no-pass)')
    parser.add_argument('--force-hash-all', action='store_true',
                        help='Spray hashes against every open protocol, even ones where '
                             'pass-the-hash is not supported (default: skip ldap/rdp/ftp/ssh)')
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

    # Resolve auth mode and validate. Mirrors nxc's own conventions:
    #   - Standard auth:  -u <user> -p <pass>  and/or  -H <hash>
    #   - Null auth:      -u "" -p ""          (just like `nxc smb host -u "" -p ""`)
    #   - Guest-style:    -u <user> --no-pass  (matches nxc's --no-pass)
    if args.no_pass:
        if args.user is None:
            print(f"{Colors.RED}[!] Error: --no-pass requires -u/--user{Colors.RESET}")
            sys.exit(1)
        if args.hash:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} --no-pass ignores -H/--hash")
            args.hash = None
        args.password = ''
    else:
        if args.user is None:
            print(f"{Colors.RED}[!] Error: -u/--user is required "
                  f"(use -u \"\" -p \"\" for a null session){Colors.RESET}")
            sys.exit(1)
        if args.password is None and not args.hash:
            print(f"{Colors.RED}[!] Error: provide -p/--password, -H/--hash, or --no-pass "
                  f"(use -u \"\" -p \"\" for a null session){Colors.RESET}")
            parser.print_help()
            sys.exit(1)

    # Build list of credential tests to run.
    # Empty-string passwords are intentional (null/guest auth) so we check `is not None`.
    cred_tests: List[Tuple[str, str]] = []
    if args.password is not None:
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

    user_display = args.user if args.user else f"{Colors.DIM}<empty>{Colors.RESET}{Colors.CYAN}"
    print(f"\n{Colors.BLUE}[*]{Colors.RESET} User input: {Colors.CYAN}{user_display}{Colors.RESET}")
    if args.user == '' and args.password == '':
        print(f"{Colors.BLUE}[*]{Colors.RESET} Auth mode: {Colors.CYAN}null session (-u \"\" -p \"\"){Colors.RESET}")
    elif args.no_pass:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Auth mode: {Colors.CYAN}no-pass (empty password){Colors.RESET}")
    else:
        if args.password:
            print(f"{Colors.BLUE}[*]{Colors.RESET} Password input: {Colors.CYAN}{args.password}{Colors.RESET}")
        if args.hash:
            print(f"{Colors.BLUE}[*]{Colors.RESET} Hash input: {Colors.CYAN}{args.hash}{Colors.RESET}")
    if extra_args:
        print(f"{Colors.BLUE}[*]{Colors.RESET} Extra nxc options: {Colors.DIM}{shlex.join(extra_args)}{Colors.RESET}")

    # Run credential tests
    all_successes = []

    for cred_type, cred_arg in cred_tests:
        if len(cred_tests) > 1:
            print(f"\n{Colors.MAGENTA}{'═' * 62}")
            print(f" TESTING WITH {cred_type.upper()}S")
            print(f"{'═' * 62}{Colors.RESET}")

        for protocol, target in test_combinations:
            if (cred_type == 'hash'
                    and protocol in HASH_INCAPABLE_PROTOCOLS
                    and not args.force_hash_all):
                proto_color = PROTOCOL_COLORS.get(protocol, Colors.WHITE)
                print(f"\n{Colors.YELLOW}[*]{Colors.RESET} Skipping hash test on "
                      f"{proto_color}{protocol.upper()}{Colors.RESET} "
                      f"{Colors.WHITE}{target}{Colors.RESET} "
                      f"{Colors.DIM}(pass-the-hash unsupported; "
                      f"use --force-hash-all to override){Colors.RESET}")
                continue

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
