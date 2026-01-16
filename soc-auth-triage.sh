#!/bin/bash
#
# soc-auth-triage.sh
#
# Purpose:
#   Quick SOC-style triage of authentication logs for failed login attempts
#   and brute-force detection patterns.
#
# Usage:
#   ./soc-auth-triage.sh                  # analyzes /var/log/auth.log
#   ./soc-auth-triage.sh <path-to-log>    # analyzes specified log file
#
# Output:
#   - Top source IPs attempting failed SSH logins
#   - Top targeted usernames (including invalid users)
#   - Attack timeline
#
# Technical Notes:
#   Uses grep -P (Perl regex) for pattern extraction. Requires GNU grep.
#   For BSD/macOS compatibility, see commit history for awk-based version.
#

set -euo pipefail

TOP_N=10
LOG_FILE="${1:-/var/log/auth.log}"

if [[ ! -r "$LOG_FILE" ]]; then
	printf "Error: Cannot read log file: %s\n" "$LOG_FILE" >&2
	exit 1
fi

printf "\n========== soc-auth-triage ===========\n"
printf "* Authentication Log Analysis Script * \n"
printf "======================================\n"
printf "Log file: %s\n" "$LOG_FILE"
printf "======================================\n\n"

printf "[*] Top failed SSH source IPs:\n"
# Extract IPs from failed password attempts
# from \K - match "from " but discard it (keep what follows)
# [\d.]+ - one or more digits and dots (IPv4 address)
(
grep "Failed password" "$LOG_FILE" \
	| grep -oP 'from \K[\d.]+' \
	| sort | uniq -c | sort -nr | head -n "$TOP_N" \
	| awk '{printf "  %s: %d attempts\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Top targeted usernames:\n"
# Extract usernames from failed password attempts
# for (?:invalid user )? - match "for " optionally followed by "invalid user "
# \K - discard everything before this point
# \S+ - capture username (non-whitespace)
# (?= from) - positive lookahead: ensure " from" follows
(
grep "Failed password" "$LOG_FILE" \
	| grep -oP 'for (?:invalid user )?\K\S+(?= from)' \
	| sort | uniq -c | sort -nr | head -n "$TOP_N" \
	| awk '{printf "  %s: %d attempts\n", $2, $1}'
) || printf "      (none found)\n"

printf "\n[*] Attack timeline (by hour):\n"
# Extract timestamps: Month Day Hour
# ^[A-Z][a-z]{2} - three-letter month at start (Jan, Feb, etc.)
# \s+\d{1,2} - day (1-31)
# \s+\d{2} - hour (00-23)
(
grep "Failed password" "$LOG_FILE" \
	| grep -oP '^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}' \
	| sort | uniq -c | sort -nr | head -n "$TOP_N" \
	| awk '{printf "  %s %2s at %s:00 - %3d attempts\n", $2, $3, $4, $1}'
) || printf "      (none found)\n"


printf "\n========== End of analysis ===========\n"
