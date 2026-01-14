# soc-auth-triage

SSH authentication log analyzer for Security Operations Center (SOC) triage workflows.

## Overview

Analyzes SSH authentication logs to identify failed login attempts, potential brute-force attacks, and credential stuffing patterns. Built as a practical tool for incident response and security monitoring.

## Features

- **Source IP analysis** - Identifies top attacking IPs
- **Username enumeration** - Shows targeted accounts (including invalid users)
- **Pattern-based detection** - Uses Perl regex for accurate log parsing
- **Flexible input** - Analyzes system logs or custom files

## Usage
```bash
# Analyze default system log
./auth-triage.sh

# Analyze specific log file
./auth-triage.sh <path_to_log_file>

# Analyze sample data
./soc-auth-triage.sh samples/auth.log
```
## How it works

**Pipeline:** `grep | grep -oP | sort | uniq -c | sort -nr | head`

**Perl Regex Patterns:**
- **IP extraction:** `from \K[\d.]+`
  - `\K` = discard "from " prefix
  - `[\d.]+` = match IPv4 address
- **Username extraction:** `for (?:invalid user )?\K\S+(?= from)`
  - `(?:invalid user )?` = optional "invalid user" prefix
  - `\K` = discard matched prefix
  - `\S+` = capture username
  - `(?= from)` = ensure " from" follows

## Testing

**Tested on:**
- Ubuntu 22.04 LTS (live system logs)
- Sample auth.log data (included in `samples/`)

**Test command:**
```bash
./soc-auth-triage.sh samples/auth.log
```
## Known limitations

- Requires GNU grep with `-P` flag (doesn't work on macOS/BSD by default)
- No support for compressed logs (`.gz` files) yet
- Assumes standard syslog format
- IPv6 addresses not tested

## What I learned

- **Bash parameter expansion:** `${1:-default}` for optional arguments with defaults
- **PCRE assertions:** `\K` for cleaner pattern extraction vs. capture groups
- **Error handling:** `set -euo pipefail` + `|| true` pattern for non-fatal grep failures
- **Regex efficiency:** Perl regex is more readable than complex awk loops for this use case

## TODO

- [ ] Add successful login tracking
- [ ] Implement timestamp-based clustering analysis
- [ ] Support compressed log files (`.gz`, `.bz2`)
- [ ] Add journalctl input mode for systemd systems
- [ ] Export results to JSON/CSV format
- [ ] Add GeoIP lookup for source IPs
