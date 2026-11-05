#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { printf 'Run as root for systemd and data-volume access.\n' >&2; exit 1; }
DATA_DIR=${SALVAGE_DATA_DIR:-/var/lib/salvage-cloud}
BACKUP_DIR=${1:?Usage: deploy/backup.sh /private/backup-directory}
: "${SALVAGE_BACKUP_PASSWORD:?Set SALVAGE_BACKUP_PASSWORD for this backup}"
[[ -d $DATA_DIR ]] || { printf 'Data directory not found: %s\n' "$DATA_DIR" >&2; exit 1; }

restart_services() {
    systemctl start salvage-cloud.service salvage-caddy.service
    set -a
    . /etc/salvage-cloud/caddy.env
    set +a
    for _ in {1..30}; do
        if curl --fail --silent --max-time 2 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health" >/dev/null; then
            return 0
        fi
        sleep 1
    done
    printf 'Services did not return to local HTTPS health\n' >&2
    return 1
}

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
systemctl stop salvage-cloud.service
trap 'restart_services' EXIT INT TERM
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
tar -C "$DATA_DIR" -czf - . \
    | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -pass env:SALVAGE_BACKUP_PASSWORD \
        -out "$BACKUP_DIR/salvage-cloud-$TIMESTAMP.tar.gz.enc"
chmod 600 "$BACKUP_DIR/salvage-cloud-$TIMESTAMP.tar.gz.enc"
printf 'Encrypted backup created: %s\n' "$BACKUP_DIR/salvage-cloud-$TIMESTAMP.tar.gz.enc"
