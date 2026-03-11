#!/usr/bin/env bash
set -euo pipefail

# Copy from backups to apps
mkdir -p /mnt/apps/cronbox
cp -r /mnt/backups/cronbox/* /mnt/apps/cronbox/

cd /mnt/apps/cronbox

# Resolve SSH public key: argument > env var > .env file > default key path
if [[ $# -ge 1 ]]; then
    key="$1"
    if [[ -f "$key" ]]; then
        key="$(cat "$key")"
    fi
elif [[ -n "${AUTHORIZED_KEY:-}" ]]; then
    key="$AUTHORIZED_KEY"
elif [[ -f .env ]]; then
    key=""
elif [[ -f "$HOME/.ssh/id_ed25519.pub" ]]; then
    key="$(cat "$HOME/.ssh/id_ed25519.pub")"
else
    echo "Usage: ./deploy.sh <ssh-public-key-or-path>"
    echo "  or set AUTHORIZED_KEY env var"
    echo "  or create .env with AUTHORIZED_KEY=<key>"
    exit 1
fi

# Write .env only if we resolved a new key
if [[ -n "$key" ]]; then
    echo "AUTHORIZED_KEY=$key" > .env
    echo "Wrote .env with SSH key"
fi

docker compose up -d --build

echo ""
echo "Cronbox running. Connect with:"
echo "  ssh -p 2223 cron@\$(hostname -I | awk '{print \$1}')"
echo ""
echo "First time setup inside the container:"
echo "  git clone https://github.com/featurecreep-cron/roustabout.git"
echo "  cd roustabout && pip install -e '.[dev]'"
