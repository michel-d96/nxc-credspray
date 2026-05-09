# NXC CredSpray

A wrapper for [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) that automatically scans targets for open ports and tests credentials on all discovered protocols.

![credspray init_image](assets/start.png)

eventually displays a summary of all successful authentications at the end of the run.
![credspray summary_image](assets/summary.png)

## Features

- **Automatic Port Scanning**: Scans targets for protocol-specific ports before testing
- **Multi-Protocol Support**: Tests credentials on all open protocols in one run
- **Combined Credentials**: Use both passwords and hashes in a single run (passwords tested first, then hashes)
- **Null & Guest Auth**: Null sessions via `-u "" -p ""` (same as nxc) and empty-password / guest-style auth via `--no-pass`
- **CIDR & Range Targets**: Accepts single IPs, hostnames, CIDR (`10.0.0.0/24`), and ranges (`10.0.0.1-50`)
- **Smart Hash Filter**: Skips pass-the-hash on protocols that don't support it (LDAP/RDP/FTP/SSH); override with `--force-hash-all`
- **Native nxc Colors**: Preserves NetExec's color output for familiar visuals
- **Real-time Output**: See nxc output as it happens
- **Success Summary**: Collects and displays all successful authentications at the end

## Supported Protocols

| Protocol | Ports |
|---------|-------|
| SMB | 445 |
| WinRM | 5985, 5986 |
| WMI | 135 |
| RDP | 3389 |
| LDAP | 389, 636 |
| MSSQL | 1433 |

## Installation

Requires Python 3 and NetExec installed:

```bash
# Install NetExec
pipx install netexec

# Clone this repo
git clone https://github.com/michel-d96/nxc-credspray.git
cd nxc-credspray

# Make executable (optional)
chmod +x nxc_cs.py
```

## Usage

```
python3 nxc_cs.py -t <target> [-u <user>] [-p <password>] [-H <hash>] [auth flag] [nxc options]
```

You must provide credentials via one of:

- `-p` / `-H` (one or both, with `-u`)
- `--no-pass` (with `-u` for guest-style empty-password auth)
- `-u "" -p ""` (null session — same as nxc)

### Required Arguments

| Argument | Description |
|----------|-------------|
| `-t, --target` | Target file (one entry per line) or single IP/hostname/CIDR/range |

### Authentication Arguments

| Argument | Description |
|----------|-------------|
| `-u, --user` | Username file or single username (use empty string `""` for null auth) |
| `-p, --password` | Password file or single password (use empty string `""` for null auth) |
| `-H, --hash` | NTLM hash file or single hash (can be combined with `-p`) |
| `--no-pass` | Send an empty password with the provided `-u` (mirrors nxc's `--no-pass`) |

> **Null sessions:** there's no separate flag — just use `-u "" -p ""`, exactly the same as `nxc <protocol> <target> -u "" -p ""`.

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `--protocols` | Comma-separated list of protocols to test (default: all open) |
| `--skip-scan` | Skip port scan and test all protocols |
| `--timeout` | Port scan timeout in seconds (default: 2.0) |
| `--force-hash-all` | Spray hashes against every open protocol (default: skip ldap/rdp/ftp/ssh, where pass-the-hash isn't supported) |

All other arguments are passed directly to nxc (e.g., `--local-auth`, `--continue-on-success`, `-d <domain>`, `-k`).

### Target Formats

The `-t` value (or any line in a target file) can be:

| Format | Example |
|--------|---------|
| Single IP | `192.168.1.10` |
| Hostname | `dc01.lab.local` |
| CIDR | `10.0.0.0/24` |
| Range (short) | `10.0.0.1-50` |
| Range (long) | `10.0.0.1-10.0.0.50` |

Lines starting with `#` are treated as comments. Expansions are deduplicated and capped at 65,536 hosts per entry.

## Examples

### Basic password spray
```bash
python3 nxc_cs.py -t targets.txt -u users.txt -p passwords.txt
```

### Single target with single credential
```bash
python3 nxc_cs.py -t 192.168.1.10 -u administrator -p Password123
```

### Hash-based authentication
```bash
python3 nxc_cs.py -t targets.txt -u users.txt -H hashes.txt
```

### Combined passwords AND hashes
```bash
# Tests all passwords first, then all hashes
python3 nxc_cs.py -t targets.txt -u users.txt -p passwords.txt -H hashes.txt
```

### Null session
```bash
# Same form as nxc itself: empty user, empty password
python3 nxc_cs.py -t 192.168.1.10 -u "" -p ""
```

### Guest / empty-password auth
```bash
# Equivalent to: nxc <proto> <target> -u guest -p ''
python3 nxc_cs.py -t 192.168.1.10 -u guest --no-pass
```

### CIDR or IP range
```bash
python3 nxc_cs.py -t 10.0.0.0/24 -u admin -p Pass123 --protocols smb
python3 nxc_cs.py -t 10.0.0.1-50 -u admin -p Pass123
```

### With local authentication
```bash
python3 nxc_cs.py -t targets.txt -u admin -p password --local-auth
```

### Test only specific protocols
```bash
python3 nxc_cs.py -t targets.txt -u users.txt -p passwords.txt --protocols smb,winrm
```

### Skip port scan (test all protocols)
```bash
python3 nxc_cs.py -t 192.168.1.10 -u admin -p pass --skip-scan
```

### Continue on success
```bash
python3 nxc_cs.py -t targets.txt -u users.txt -p passwords.txt --continue-on-success
```

### Force hash spraying on all protocols
```bash
# By default, hashes are not sprayed against ldap/rdp/ftp/ssh because
# nxc cannot perform pass-the-hash there. Use --force-hash-all to override.
python3 nxc_cs.py -t targets.txt -u admin -H hash.txt --force-hash-all
```

## Output

The tool provides:

1. **Port Scan Results**: Shows which protocols are open on each target
2. **Real-time nxc Output**: See authentication attempts as they happen
3. **Summary**: All successful authentications grouped by credential type

Example output:
```
╔══════════════════════════════════════════════════════════════╗
║          NXC CREDSPRAY - NetExec Credential Wrapper          ║
║              Scan & Spray on All Protocols                   ║
╚══════════════════════════════════════════════════════════════╝

[*] Loaded 2 target(s)

══════════════════════════════════════════════════════════════
 PORT SCAN PHASE
══════════════════════════════════════════════════════════════
[+] 192.168.1.10: smb(445), winrm(5985)
[+] 192.168.1.11: smb(445), ldap(389,636)

══════════════════════════════════════════════════════════════
 CREDENTIAL TESTING PHASE
══════════════════════════════════════════════════════════════
...

══════════════════════════════════════════════════════════════
 SUMMARY - SUCCESSFUL AUTHENTICATIONS
══════════════════════════════════════════════════════════════

Password Authentication:
  [+] SMB 192.168.1.10 445 DC01 [+] DOMAIN\admin:Password123 (Pwn3d!)

[+] Total successful: 1
[!] PWNED ACCOUNTS: 1
```
