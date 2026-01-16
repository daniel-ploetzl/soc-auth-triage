# soc-auth-triage

Authentication log analysis script for security inspection. Identifies failed login attempts, potential brute-force patterns, and attack timing from system authentication logs.

## Features

- **Source IP analysis** - Identifies top attacking IPs
- **Username enumeration** - Shows targeted accounts (including invalid users)
- **Pattern-based detection** - Uses Perl regex for accurate log parsing
- **Flexible input** - Analyzes standard Linux auth logs (`/var/log/auth.log`) or custom files
- **Time-based attack clustering** - Displays attack timeline by hour (identifies attack patterns)

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

Uses grep with Perl regex to extract patterns from authentication logs.

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
- **Timeline extraction:** `^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}` - extracts Month Day Hour from syslog timestamps

Output formatted with single awk line per section for consistency.

## Testing

**Tested on:**
- Ubuntu 22.04 LTS (live system logs)
- Sample auth.log data (included in `samples/`)

## Known limitations

- Requires GNU grep with `-P` flag (doesn't work on macOS/BSD by default)
- No support for compressed logs (`.gz` files) yet
- Assumes standard syslog format
- IPv6 addresses not tested
- Currently focuses on SSH failed password events only

## What I learned

- Perl regex `\K` assertion for cleaner extraction than capture groups
- `(?:...)` non-capturing groups for optional patterns
- Positive lookahead `(?= ...)` to ensure context without consuming it
- `set -euo pipefail` + `|| printf` pattern for graceful error handling
- Consistent output formatting improves readability for security inspection
- Timestamp extraction from syslog format without external date parsing

## TODO

- [x] Extract top source IPs
- [x] Extract targeted usernames
- [x] Implement timestamp-based attack clustering
- [ ] Support compressed log files (`.gz`, `.bz2`)
- [ ] Add successful login tracking (failed -> success = potential breach)
- [ ] Export results to JSON/CSV format for reporting
- [ ] Add journalctl input mode for systemd systems
- [ ] Add GeoIP lookup for source IPs
