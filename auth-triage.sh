#!/bin/bash
#
# Script to check failed SSH logins
#
# NOTE: Uses grep -P (Perl regex) for cleaner extraction.
#		Fall back to awk on BSD/macOS (see commit history).
#

set -euo pipefail

TOP_N=10

echo "[*] Top failed SSH sources:"
# Extract IPs from failed password attempts
# \K = discard everything matched before this point
# \d = digit (same as [0-9])
(
grep "Failed password" /var/log/auth.log \
	| grep -oP 'from \K[\d.]+' \
	| sort | uniq -c | sort -nr | head -n "$TOP_N"
) || true
