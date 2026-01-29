#!/bin/bash
#
# soc-auth-triage.sh
#
# Purpose:
#   Authentication log analysis for security inspection. Identifies failed login
#   attempts, brute-force patterns, attack timing, and potential compromises.
#
# Usage:
#   ./soc-auth-triage.sh                  # analyzes /var/log/auth.log
#   ./soc-auth-triage.sh <path-to-log>    # analyzes specified log file
#
# Output:
#   - Top source IPs attempting failed SSH logins
#   - Top targeted usernames (including invalid users)
#   - Attack timeline by hour
#   - Potential compromises (IPs with failed attempts that later succeeded)
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
		| awk '{printf "  %s: %d attempt(s)\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Top targeted usernames:\n"
# Extract usernames from both log formats
# Modern: authenticating user USERNAME
# Legacy: for [invalid user] USERNAME from
(
	grep -E "(Failed password|Connection closed by authenticating user.*\[preauth\])" "$LOG_FILE" \
		| grep -oP '(for (?:invalid user )?|authenticating user )\K\w+(?= )' \
		| sort | uniq -c | sort -nr | head -n "$TOP_N" \
		| awk '{printf "  %s: %d attempt(s)\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Attack timeline (by hour):\n"
# Extract timestamp and round to hour
(
	grep -E "(Failed password|Connection closed.*\[preauth\])" "$LOG_FILE" \
		| cut -c1-16 \
		| sed 's/:...*/:00/' \
		| sort | uniq -c | sort -nr | head -n "$TOP_N" \
		| awk '{printf "  %s: %d attempt(s)\n", $2, $1}'
) || printf "    (none found)\n"

printf "\n[*] Potential compromises (failed then successful login):\n"
# Correlate failed attempts with successful logins from same IP
# Indicates potential brute-force success or credential stuffing
(
	found=0

	while read -r ip; do
		# Count failed attempts from this IP
		failed=$(
			grep -E "(Failed password|Connection closed.*\[preauth\])" \
				"$LOG_FILE" \
				| grep -c "$ip" \
				# | grep "$ip" \
				# | wc -l
	)

	if [[ "$failed" -gt 0 ]]; then
		# Get timestamp from successful login (first 16 chars)
		time=$(grep -E "Accepted.*from $ip" "$LOG_FILE" \
			| head -1 \
			| cut -c1-16)
		printf "  %s: %d failed, then SUCCESS at %s\n" \
			"$ip" "$failed" "$time"
		found=1
	fi
done < <(
	grep -E "Accepted (password|publickey)" "$LOG_FILE" \
		| grep -oP 'from \K[\d.]+(?= port)' \
		| sort -u)

	[[ "$found" -eq 0 ]] && printf "    (none found)\n"
) || true

printf "\n======= End of summary ========\n"
