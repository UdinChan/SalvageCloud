#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { printf 'Run as root to install system services.\n' >&2; exit 1; }
ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
set -a
. "$ROOT/.env.production"
set +a

[[ $SALVAGE_PUBLIC_ORIGIN == "https://$DOMAIN" ]] || {
    printf 'SALVAGE_PUBLIC_ORIGIN must exactly match https://DOMAIN\n' >&2
    exit 1
}
[[ $DOMAIN =~ ^[A-Za-z0-9.-]+$ ]] || { printf 'DOMAIN is invalid\n' >&2; exit 1; }
[[ ${#SALVAGE_SESSION_KEY} -eq 64 && $SALVAGE_SESSION_KEY =~ ^[0-9a-f]+$ ]] || {
    printf 'SALVAGE_SESSION_KEY must be 32 bytes of lowercase hex\n' >&2
    exit 1
}
[[ $TELEGRAM_API_ID =~ ^[0-9]+$ && -n $TELEGRAM_API_HASH ]] || {
    printf 'Telegram API credentials are incomplete\n' >&2
    exit 1
}
[[ -x $ROOT/target/release/salvage-server && -f $ROOT/dist/index.html ]] || {
    printf 'Build the release server and browser assets first\n' >&2
    exit 1
}
command -v caddy >/dev/null || { printf 'Install Caddy 2.10.2 first\n' >&2; exit 1; }

id -u salvage >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/salvage-cloud --shell /usr/sbin/nologin salvage
id -u caddy >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
install -d -m 0755 /opt/salvage-cloud /etc/salvage-cloud
install -d -o salvage -g salvage -m 0700 /var/lib/salvage-cloud
install -d -o caddy -g caddy -m 0700 /var/lib/caddy /var/lib/caddy/data /var/lib/caddy/config

cat > /etc/salvage-cloud/environment <<EOF
SALVAGE_BIND=127.0.0.1:3000
SALVAGE_DATA_DIR=/var/lib/salvage-cloud
SALVAGE_WEB_DIST=/opt/salvage-cloud/dist
SALVAGE_PUBLIC_ORIGIN=$SALVAGE_PUBLIC_ORIGIN
SALVAGE_COOKIE_SECURE=true
SALVAGE_TELEGRAM_TRANSPORT=grammers
SALVAGE_SESSION_KEY=$SALVAGE_SESSION_KEY
TELEGRAM_API_ID=$TELEGRAM_API_ID
TELEGRAM_API_HASH=$TELEGRAM_API_HASH
RUST_LOG=${RUST_LOG:-info}
EOF
chmod 600 /etc/salvage-cloud/environment
printf 'DOMAIN=%s\nUPSTREAM=127.0.0.1:3000\nACME_EMAIL=\n' "$DOMAIN" > /etc/salvage-cloud/caddy.env
chmod 644 /etc/salvage-cloud/caddy.env

install -m 0644 "$ROOT/deploy/caddy/Caddyfile" /etc/salvage-cloud/Caddyfile
install -m 0644 "$ROOT/deploy/salvage-cloud.service" /etc/systemd/system/salvage-cloud.service
install -m 0644 "$ROOT/deploy/salvage-caddy.service" /etc/systemd/system/salvage-caddy.service
systemctl daemon-reload
systemctl stop salvage-cloud.service 2>/dev/null || true
trap 'systemctl start salvage-cloud.service' ERR

install -m 0755 "$ROOT/target/release/salvage-server" /opt/salvage-cloud/salvage-server.new
mv -f /opt/salvage-cloud/salvage-server.new /opt/salvage-cloud/salvage-server
rm -rf /opt/salvage-cloud/dist.new
cp -a "$ROOT/dist" /opt/salvage-cloud/dist.new
if [[ -d /opt/salvage-cloud/dist ]]; then
    mv /opt/salvage-cloud/dist /opt/salvage-cloud/dist.old
fi
mv /opt/salvage-cloud/dist.new /opt/salvage-cloud/dist
rm -rf /opt/salvage-cloud/dist.old

systemctl enable salvage-cloud.service salvage-caddy.service
systemctl start salvage-cloud.service
set -a
. /etc/salvage-cloud/caddy.env
set +a
caddy validate --config /etc/salvage-cloud/Caddyfile --adapter caddyfile
if systemctl is-active --quiet salvage-caddy.service; then
    systemctl reload salvage-caddy.service
else
    systemctl start salvage-caddy.service
fi
trap - ERR
printf 'Salvage Cloud is installed at %s\n' "$SALVAGE_PUBLIC_ORIGIN"
