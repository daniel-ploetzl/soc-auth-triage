# SSH Auth Triage Script

Quick analysis of SSH authentication logs. Shows failed login attempts and potential brute-force sources.

## Usage
```bash
# Analyze default system log
./auth-triage.sh

# Analyze specific log file
./auth-triage.sh <path_to_log_file>
```

## What it does

- Extracts top source IPs attempting failed SSH logins
- Uses threshold-based detection for brute-force attempts (>10 failures)
- Outputs sorted results (highest attempt count first)

## How it works

Pipeline: `grep | grep -oP | sort | uniq -c | sort -nr | head`

Uses Perl regex (`grep -P`) for cleaner IP extraction:
- `\K` = discard matched text before this point
- `\d` = digit shorthand

## Testing

Tested on Ubuntu 22.04 with live logs and sample data.

## Known issues/limitations

- Requires GNU grep with `-P` flag (doesn't work on macOS/BSD by default)
- No support for compressed logs (`.gz` files)
- Assumes standard syslog format

## What I learned

- Bash parameter expansion: `${1:-default}` for optional arguments
- PCRE `\K` assertion
- `set -euo pipefail`: requires `|| true` for grep with no matches

## TODO

- [ ] Add username extraction
- [ ] Add timestamp analysis
- [ ] Handle compressed logs
- [ ] Support journalctl input mode
