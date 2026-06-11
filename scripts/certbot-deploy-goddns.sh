#!/bin/sh
# certbot deploy hook: mirror a renewed certificate to a location the goddns
# service user can read. /etc/letsencrypt/live and archive are root-only, so
# the daemon (User=goddns) cannot read them directly; this copies the pair to
# /etc/goddns/certs with root:goddns 0640. goddns hot-reloads the files on
# the next TLS handshake — no restart needed.
#
# Install (runs automatically after every successful renewal):
#   ln -s /usr/share/goddns/scripts/certbot-deploy-goddns.sh \
#         /etc/letsencrypt/renewal-hooks/deploy/goddns.sh
#
# Run once by hand to seed the files:
#   /usr/share/goddns/scripts/certbot-deploy-goddns.sh /etc/letsencrypt/live/myip.gr
#
# Then point goddns.conf at the mirror:
#   cert_file = "/etc/goddns/certs/fullchain.pem"
#   key_file  = "/etc/goddns/certs/privkey.pem"
#
# Multi-cert hosts: set GODDNS_LINEAGE=<live dir basename> (e.g. in the
# hook symlink's environment or edit below) so only that lineage is mirrored.
set -eu

LINEAGE="${1:-${RENEWED_LINEAGE:-}}"
[ -n "$LINEAGE" ] || { echo "usage: $0 /etc/letsencrypt/live/<name>" >&2; exit 2; }

ONLY="${GODDNS_LINEAGE:-}"
if [ -n "$ONLY" ] && [ "$(basename "$LINEAGE")" != "$ONLY" ]; then
    exit 0
fi

DST=/etc/goddns/certs
install -d -o root -g goddns -m 0750 "$DST"
install -o root -g goddns -m 0644 "$LINEAGE/fullchain.pem" "$DST/fullchain.pem"
install -o root -g goddns -m 0640 "$LINEAGE/privkey.pem"   "$DST/privkey.pem"
echo "goddns: mirrored $(basename "$LINEAGE") cert to $DST"
