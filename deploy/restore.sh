#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { printf 'Run as root for systemd and data-volume access.\n' >&2; exit 1; }
if [[ ${1:-} != "--yes" || $# -ne 2 ]]; then
    printf 'Usage: %s --yes /private/backup.tar.gz.enc\n' "$0" >&2
    exit 2
fi
ARCHIVE=$2
DATA_DIR=${SALVAGE_DATA_DIR:-/var/lib/salvage-cloud}
: "${SALVAGE_BACKUP_PASSWORD:?Set SALVAGE_BACKUP_PASSWORD for this restore}"
[[ -f $ARCHIVE ]] || { printf 'Backup not found: %s\n' "$ARCHIVE" >&2; exit 1; }
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

TEMPORARY=$(mktemp)
trap 'rm -f "$TEMPORARY"' EXIT
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
    -pass env:SALVAGE_BACKUP_PASSWORD -in "$ARCHIVE" -out "$TEMPORARY"
gzip -t "$TEMPORARY"

systemctl stop salvage-cloud.service
trap 'rm -f "$TEMPORARY"; restart_services' EXIT INT TERM
find "$DATA_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
tar -C "$DATA_DIR" -xzf "$TEMPORARY"
chown -R salvage:salvage "$DATA_DIR"
printf 'Restore completed. Review application health before reopening traffic.\n'
