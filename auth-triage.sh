#!/bin/bash
# Quick script to check failed SSH logins
# TODO: clean this up later

echo "[*] Top failed login sources:"
grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -nr
