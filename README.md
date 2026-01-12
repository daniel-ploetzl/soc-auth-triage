# Auth Triage Script

## Portability Notes

This script assumes **Linux with GNU grep**. Known limitations:
- macOS: requires `brew install grep` and using `ggrep -P`
- OpenBSD: log path is `/var/log/authlog` not `auth.log`
- BSD systems: grep lacks `-P` flag - use awk fallback

See commit history for cross-platform branch.
