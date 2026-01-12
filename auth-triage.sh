#!/bin/bash
# Quick script to check failed SSH logins
# TODO: clean this up later

grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr
