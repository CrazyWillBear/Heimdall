#!/bin/sh
# Load the GitHub App private key into the env var the app reads.
#
# GITHUB_APP_PRIVATE_KEY is a *string* settings field (a multiline PEM), but a
# docker-compose env_file cannot carry multiline values.  So the PEM is mounted as a
# file (a compose secret) and read into the env var here, then the real process is
# exec'd.  If the var is already set directly (e.g. in dev), the file is ignored.
set -eu

: "${GITHUB_APP_PRIVATE_KEY_FILE:=/run/secrets/github_app_private_key}"

if [ -z "${GITHUB_APP_PRIVATE_KEY:-}" ] && [ -f "$GITHUB_APP_PRIVATE_KEY_FILE" ]; then
    GITHUB_APP_PRIVATE_KEY="$(cat "$GITHUB_APP_PRIVATE_KEY_FILE")"
    export GITHUB_APP_PRIVATE_KEY
fi

exec "$@"
