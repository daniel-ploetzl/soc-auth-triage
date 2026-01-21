#!/bin/bash
#
# soc-auth-triage.sh
#
# Purpose:
#   Authentication log analysis for security inspection. Identifies failed login
#   attempts, brute-force patterns, and attack timing from system auth logs.
#
# Usage:
#   ./soc-auth-triage.sh                  # analyzes /var/log/auth.log
#   ./soc-auth-triage.sh <path-to-log>    # analyzes specified log file
#
# Output:
#   - Top source IPs attempting failed SSH logins
#   - Top targeted usernames (including invalid users)
#   - Attack timeline by hour
#
# Technical Notes:
#   Uses grep -P (Perl regex) for pattern extraction. Requires GNU grep.
#   Handles both RFC3339 (systemd/modern) and traditional syslog timestamps.
#   For systemd-only logging: export first with 'journalctl -u ssh > ssh.log'
#
set -euo pipefail

TOP_N=10
LOG_FILE="${1:-/var/log/auth.log}"

if [[ ! -r "$LOG_FILE" ]]; then
	printf "Error: Cannot read log file: %s\n" "$LOG_FILE" >&2
	exit 1
fi

printf "\n======= soc-auth-triage =======\n"
printf "SSH Authentication Log Analysis\n"
printf "===============================\n"
printf "Log file: %s\n" "$LOG_FILE"
printf "===============================\n\n"

printf "[*] Top failed SSH source IPs:\n"
# Match both failed password attempts and preauth connection closures
# Modern (systemd): Connection closed by authenticating user root IP port [preauth]
# Legacy: Failed password for root from IP
(
	grep -E "(Failed password|Connection closed by authenticating user.*\[preauth\])" "$LOG_FILE" \
		| grep -oP '(from |user \w+ )\K[\d.]+(?= port)' \
		| sort | uniq -c | sort -nr | head -n "$TOP_N" \
		| awk '{printf "  %s: %d attempts\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Top targeted usernames:\n"
# Extract usernames from both log formats
# Modern: authenticating user USERNAME
# Legacy: for [invalid user] USERNAME from
(
	grep -E "(Failed password|Connection closed by authenticating user.*\[preauth\])" "$LOG_FILE" \
		| grep -oP '(for (?:invalid user )?|authenticating user )\K\w+(?= )' \
		| sort | uniq -c | sort -nr | head -n "$TOP_N" \
		| awk '{printf "  %s: %d attempts\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Attack timeline (by hour):\n"
# Handle both timestamp formats:
# RFC3339 (modern): 2026-01-18T00:00:11.966856+01:00
# Syslog (legacy): Jan 18 00:00:11
(
	grep -E "(Failed password|Connection closed by authenticating user.*\[preauth\])" "$LOG_FILE" \
		| grep -oP '^(\d{4}-\d{2}-\d{2}T\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2})' \
		| sed -E 's/T([0-9]{2}).*/T\1:00/; s/^([A-Z][a-z]{2}\s+[0-9]+\s+)([0-9]{2}).*/\1\2:00/' \
		| sort | uniq -c | sort -nr | head -n "$TOP_N" \
		| awk '{printf "  %s: %d attempts\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n======= End of summary ========\n"
