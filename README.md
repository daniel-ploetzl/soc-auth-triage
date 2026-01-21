# soc-auth-triage

Authentication log analysis script for security inspection. Identifies failed login attempts, potential brute-force patterns, and attack timing from system authentication logs.

## Usage
```bash
# Analyze default system log
./soc-auth-triage.sh

# Analyze specific log file
./soc-auth-triage.sh <path_to_log_file>

# For systemd-only logging (no /var/log/auth.log)
sudo journalctl -u ssh --since "24 hours ago" > /tmp/ssh.log
./soc-auth-triage.sh /tmp/ssh.log
```

## What it does

- Shows top source IPs attempting failed SSH logins
- Lists targeted usernames (including invalid users)
- Displays attack timeline by hour (identifies attack patterns)
- Works with modern systemd and legacy syslog formats

## Output Example (Production VPS)
```
========== soc-auth-triage ===========
* Authentication Log Analysis Script *
======================================
Log file: /var/log/auth.log
======================================

[*] Top failed SSH source IPs:
  81.90.31.198: 149 attempts
  167.99.47.2: 149 attempts
  159.223.14.36: 87 attempts
  45.118.144.36: 86 attempts
  35.247.162.157: 86 attempts
  193.32.162.157: 83 attempts
  178.62.252.94: 75 attempts
  206.189.2.44: 74 attempts
  188.166.34.182: 74 attempts
  64.225.70.216: 73 attempts

[*] Top targeted usernames:
  root: 4975 attempts
  mysql: 195 attempts
  backup: 129 attempts
  daemon: 11 attempts
  sync: 2 attempts
  nobody: 1 attempts

[*] Attack timeline (by hour):
  2026-01-18T16:00: 234 attempts
  2026-01-19T09:00: 206 attempts
  2026-01-18T13:00: 191 attempts
  2026-01-18T11:00: 168 attempts
  2026-01-19T21:00: 154 attempts
  2026-01-18T21:00: 148 attempts
  2026-01-19T23:00: 146 attempts
  2026-01-20T11:00: 141 attempts
  2026-01-19T10:00: 128 attempts
  2026-01-19T11:00: 127 attempts

======= End of summary ========
```

## How it works

Uses grep with Perl regex to extract patterns from authentication logs. Handles both modern systemd (RFC3339 timestamps) and legacy syslog formats.

**Detection patterns:**
- **Modern (systemd):** `Connection closed by authenticating user ... [preauth]`
- **Legacy:** `Failed password for ... from ...`

**Extraction patterns:**
- **IP extraction:** `(from |user \w+ )\K[\d.]+(?= port)` - grabs IP before "port"
- **Username extraction:** `(for (?:invalid user )?|authenticating user )\K\w+` - handles both formats
- **Timestamp extraction:** `^(\d{4}-\d{2}-\d{2}T\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2})` - RFC3339 or syslog

All sections follow the same pipeline: `grep | grep -oP | sort | uniq -c | sort -nr | head`.

## System Compatibility

### Modern Linux (2015+) - Primary Target
- Ubuntu 16.04+, Debian 8+, Rocky Linux, Fedora, Arch
- Uses RFC3339 timestamps: `2026-01-18T00:00:11.966856+01:00`
- Log location: `/var/log/auth.log` or `/var/log/secure`

### Legacy Systems
- Older Ubuntu/Debian, BSD, custom rsyslog configs
- Uses syslog timestamps: `Jan 18 00:00:11`
- Script handles both formats automatically

### Systemd-only logging
Some minimal cloud/container images don't write to `/var/log/auth.log`. Export logs first:
```bash
sudo journalctl -u ssh --since "24 hours ago" > /tmp/ssh.log
./soc-auth-triage.sh /tmp/ssh.log
```

## Testing

Tested on:
- Ubuntu 24.04 LTS (RFC3339 format)
- Ubuntu 22.04 LTS (RFC3339 format)
- Debian 12 (RFC3339 format)
- Sample legacy syslog data
```bash
./soc-auth-triage.sh samples/auth.log
```

## Known limitations

- Requires GNU grep (not available on macOS/BSD by default - use `brew install grep`)
- No support for compressed logs (`.gz` files) - decompress first
- Currently focuses on SSH authentication events only
- IPv6 addresses not tested

## What I learned

- Modern Linux uses RFC3339 timestamps, not traditional syslog format
- Systemd can log to files OR journalctl-only (system-dependent)
- fail2ban blocks attempts before they log as "Failed password"
- Pattern matching must handle "Connection closed... [preauth]" for modern systems
- Perl regex `\K` and lookaheads work across different log formats
- Single grep pattern can match multiple log message types with `|`

## TODO

- [x] Extract top source IPs
- [x] Extract targeted usernames
- [x] Implement timestamp-based attack clustering
- [x] Document journalctl export workaround for systemd-only systems
- [ ] Support compressed log files (`.gz`, `.bz2`)
- [ ] Add successful login tracking (failed -> success = potential breach)
- [ ] Export results to JSON/CSV format for reporting
- [ ] Add GeoIP lookup for source IPs
- [ ] IPv6 support
- [ ] Native journalctl input mode (read directly without export)
- [ ] Expand to other auth events (sudo, su, pam)
