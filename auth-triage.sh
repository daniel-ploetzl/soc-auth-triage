#!/bin/bash
#
# Script to check failed SSH logins
#
# NOTE: Use grep instead of awk (see last commit), unless running on macOS/BSD.

echo "[*] Top failed SSH sources:"
grep "Failed password" /var/log/auth.log \
	| grep -oP 'from \K[\d.]+' \			# \d = [0-9]
	| sort | uniq -c | sort -nr | head -10	# uniq: omit repeated lines
