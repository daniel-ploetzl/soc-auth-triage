# soc-auth-triage

Authentication log analysis script for security assessment. Identifies failed login attempts, potential brute-force patterns, attack timing and potential compromises.

## Usage
```bash
# Analyze default system log
./soc-auth-triage.sh

# Analyze specific log file
./soc-auth-triage.sh <path_to_log_file>

# Compressed logs (rotated files)
./soc-auth-triage.sh /var/log/auth.log.1.gz

# Systemd-only systems
sudo journalctl -u ssh --since "24 hours ago" > /tmp/ssh.log
./soc-auth-triage.sh /tmp/ssh.log
```

## Features

- Top source IPs with failed login attempts
- Most targeted usernames (including invalid users)
- Hourly attack timeline
- Potential compromises (failed attempts -> successful login)
- Supports compressed logs (.gz, .bz2)
- Handles both RFC3339 and legacy syslog formats

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

[*] Potential compromises (failed then successful login):
  100.65.0.9: 3 failed, then SUCCESS at 2026-01-18T14:23

======= End of summary ========
```

## How it works

Extracts patterns from auth logs using `grep/cut/sed`, then correlates failed and successful logins.

- **Failed attempts (modern):** `Failed password` or `Connection closed ... [preauth]`
- **Successful logins:** `Accepted password` or `Accepted publickey`

**Correlation logic:** For each IP with successful login, check for prior failed attempts.

## System Compatibility

**Tested on:**
- Ubuntu 22.04/24.04, Debian 12 (RFC3339 timestamps)
- Legacy syslog format systems
- Compressed logs (.gz, .bz2)

**Log locations:**
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/Rocky/AlmaLinux)

## Requirements

- Bash 4.0+
- GNU grep (Perl regex support)
- Standard Linux tools: `sed, cut, awk, uniq, sort`
- gzip/bzip2 (for compressed logs - standard on all Linux systems)

## Limitations

- SSH events only (no sudo/su/pam)
- IPv6 not tested
- Assumes chronological log order

## What I learned

- Modern Linux uses RFC3339 timestamps (`2026-02-09T00:00:11+01:00`)
- fail2ban blocks before "Failed password" gets logged
- logrotate compresses with gzip, not tar
- `zcat`/`bzcat` decompress to stdout (no temp files)
- Process substitution `< <(...)` avoids subshell scope issues
- Simple sed `s/:...*/:00/` rounds timestamps for both formats

## TODO

- [x] Extract top source IPs
- [x] Extract targeted usernames
- [x] Implement timestamp-based attack clustering
- [x] Successful login correlation (failed → success = potential breach)
- [x] Document journalctl export workaround for systemd-only systems
- [x] Support compressed log files (`.gz`, `.bz2`)
- [ ] Export results to JSON/CSV format for reporting
- [ ] Add GeoIP lookup for source IPs
- [ ] IPv6 support
- [ ] Native journalctl input mode (read directly without export)
- [ ] Expand to other auth events (sudo, su, pam)
