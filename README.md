# Auth Triage Script

Perl regex, instead of 'awk', is cleaner:
  grep -oP 'from \K[\d.]+'

\K is a 'keep' assertion - matches 'from ' but doesn't include it.
[\d.]+ captures the IP address.

Trade-off: requires GNU grep (not portable to BSD). Acceptable for
Linux-focused SOC work."

## Portability Notes

This script assumes **Linux with GNU grep**. Known limitations:
- macOS: requires `brew install grep` and using `ggrep -P`
- OpenBSD: log path is `/var/log/authlog` not `auth.log`
- BSD systems: grep lacks `-P` flag - use awk fallback

See commit history for cross-platform branch.
