#!/usr/bin/env bash
# setup-cloudflare-tunnel.sh
# Run ONCE after: cloudflared tunnel login
# Usage: bash scripts/setup-cloudflare-tunnel.sh <TUNNEL_UUID> [subdomain]
#   subdomain defaults to "app" → app.capslock.com
set -euo pipefail

CLOUDFLARED="${HOME}/.local/bin/cloudflared"
TUNNEL_NAME="capslock"
TUNNEL_UUID="${1:-}"
SUBDOMAIN="${2:-app}"
DOMAIN="capslock.com"
HOSTNAME="${SUBDOMAIN}.${DOMAIN}"
CONFIG="${HOME}/.cloudflared/config.yml"

if [[ -z "$TUNNEL_UUID" ]]; then
  echo "Usage: $0 <TUNNEL_UUID> [subdomain]"
  echo "Get UUID from: $CLOUDFLARED tunnel list"
  exit 1
fi

echo "→ Writing config: $CONFIG"
mkdir -p "${HOME}/.cloudflared"
cat > "$CONFIG" <<YAML
tunnel: ${TUNNEL_UUID}
credentials-file: ${HOME}/.cloudflared/${TUNNEL_UUID}.json

ingress:
  - hostname: ${HOSTNAME}
    service: http://localhost:8000
  - service: http_status:404
YAML

echo "→ Routing DNS: ${HOSTNAME} → tunnel ${TUNNEL_UUID}"
"$CLOUDFLARED" tunnel route dns "$TUNNEL_NAME" "$HOSTNAME"

echo ""
echo "✓ Done! Your permanent URL: https://${HOSTNAME}"
echo ""
echo "To start the tunnel:"
echo "  $CLOUDFLARED tunnel run ${TUNNEL_NAME}"
echo ""
echo "Or add to start.sh: $CLOUDFLARED tunnel run ${TUNNEL_NAME} &"
