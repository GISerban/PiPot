#!/usr/bin/env bash
# entrypoint.sh - run the honeypot with passed args (keeps container friendly to override)
set -e

# Ensure logs folder exists and is writable
mkdir -p /app/logs
# If running as non-root user, ensure permissions are correct (container user owns it)
# (We run as honeypot user already; ownership will match container user)
exec python3 /app/httpot.py "$@"
