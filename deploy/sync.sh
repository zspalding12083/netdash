#!/usr/bin/env bash
# Keep this folder (the source of truth and local backup) and the Orange Pi in step.
#
#   deploy/sync.sh push     test locally, copy code to the Pi, restart, check it's up
#   deploy/sync.sh backup   copy the Pi's database and service file into backups/
#   deploy/sync.sh check    show anything that differs between here and the Pi
#
# Where to: deploy/local.env (git-ignored), e.g.  PI=pi@192.168.1.10  and, with HTTPS,
# URL=https://192.168.1.10:9180. Or set them on the command line: PI=user@host deploy/sync.sh push
# A site with its own look adds BRAND=site/brand (copied to /opt/netdash/brand; NETDASH_BRAND_DIR).
# Needs: SSH keys for $PI, /opt/netdash/netdash owned by that user,
# and /etc/sudoers.d/netdash-restart (NOPASSWD for "systemctl restart netdash").
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
[ -f "$HERE/deploy/local.env" ] && . "$HERE/deploy/local.env"
PI=${PI:?set PI=user@host in deploy/local.env or on the command line}
URL=${URL:-http://${PI#*@}:9180}          # e.g. URL=https://192.168.1.10:9180 at a site with HTTPS
BRAND=${BRAND:-}                          # e.g. BRAND=site/brand
CODE=/opt/netdash/netdash
DB=/var/lib/netdash/netdash.db
KEEP=30                                   # database snapshots to keep
RSYNC=(rsync -a --exclude __pycache__ --exclude '*.pyc')
cd "$HERE"

push() {
    python3 -m unittest discover -s tests -t . -q
    "${RSYNC[@]}" --delete netdash/ "$PI:$CODE/"
    if [ -n "$BRAND" ]; then "${RSYNC[@]}" --delete "$BRAND/" "$PI:/opt/netdash/brand/"; fi
    ssh "$PI" 'sudo -n /usr/bin/systemctl restart netdash && sleep 3 && systemctl is-active netdash'
    # /api/site needs no login, so this works with NETDASH_AUTH=on too (-k: self-signed certificates)
    curl -fsSk --max-time 10 "$URL/api/site" >/dev/null && echo "dashboard is up"
}

backup() {
    mkdir -p backups
    local stamp; stamp=$(date +%Y%m%d-%H%M)
    # sqlite's online backup: a consistent copy even while the service is writing
    ssh "$PI" "python3 -c 'import sqlite3; s=sqlite3.connect(\"file:$DB?mode=ro\", uri=True); d=sqlite3.connect(\"/tmp/netdash-backup.db\"); s.backup(d); d.close()'"
    rsync -a "$PI:/tmp/netdash-backup.db" "backups/netdash-$stamp.db"
    ssh "$PI" 'rm -f /tmp/netdash-backup.db'
    rsync -a "$PI:/etc/systemd/system/netdash.service" backups/netdash.service
    ls -1t backups/netdash-*.db | tail -n +$((KEEP + 1)) | xargs -r rm --
    echo "backed up to backups/netdash-$stamp.db ($(du -h "backups/netdash-$stamp.db" | cut -f1))"
}

check() {
    echo "code on the Pi that differs from here:"
    "${RSYNC[@]}" -nci "$PI:$CODE/" netdash/ | grep -v '^\.' || echo "  none"
    echo "service file:"
    ssh "$PI" cat /etc/systemd/system/netdash.service | diff -q - backups/netdash.service >/dev/null 2>&1 \
        && echo "  same as backups/netdash.service" || echo "  differs from backups/netdash.service (run: deploy/sync.sh backup)"
}

case "${1:-}" in
    push) push ;;
    backup) backup ;;
    check) check ;;
    *) sed -n '2,10p' "$0"; exit 1 ;;
esac
