#!/bin/bash
#
# Script to check failed SSH logins
#
# NOTE: Uses grep -P (Perl regex) for cleaner extraction.
#		Fall back to awk on BSD/macOS (see commit history).
#

set -euo pipefail

TOP_N=10
LOG_FILE="${1:-/var/log/auth.log}"		# use av[1], default to /var/log/auth.log

if [[ ! -r "$LOG_FILE" ]]; then
	echo "Error: Cannot read log file: $LOG_FILE" >&2
	exit 1
fi

echo "[*] Analysing: $LOG_FILE"

echo "[*] Top failed SSH sources:"
# Extract IPs from failed password attempts
# \K = discard everything matched before this point
# \d = digit (same as [0-9])
(
grep "Failed password" "$LOG_FILE" \
	| grep -oP 'from \K[\d.]+' \
	| sort | uniq -c | sort -nr | head -n "$TOP_N"
) || true
