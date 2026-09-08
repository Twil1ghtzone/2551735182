#!/usr/bin/env bash
# Holt den aktuellen Digest von debian:12-slim und trägt ihn in beide
# Dockerfiles ein. Regelmäßig ausführen – ein festgenagelter Digest ist
# nachvollziehbar, bekommt aber keine Sicherheitsupdates von allein.
set -euo pipefail
cd "$(dirname "$0")"

engine=""
for e in docker podman; do command -v "$e" >/dev/null 2>&1 && { engine="$e"; break; }; done
[ -n "$engine" ] || { echo "Weder docker noch podman gefunden." >&2; exit 1; }

echo "Hole aktuelles debian:12-slim ..."
"$engine" pull -q docker.io/library/debian:12-slim >/dev/null
digest=$("$engine" inspect docker.io/library/debian:12-slim \
         --format '{{index .RepoDigests 0}}' | sed 's/.*@//')
[ -n "$digest" ] || { echo "Digest nicht ermittelbar." >&2; exit 1; }

for f in Dockerfile tor/Dockerfile; do
    old=$(grep -oE 'FROM debian:12-slim@sha256:[0-9a-f]+' "$f" | head -1 || true)
    sed -i -E "s|FROM debian:12-slim@sha256:[0-9a-f]+|FROM debian:12-slim@${digest}|" "$f"
    new=$(grep -oE 'FROM debian:12-slim@sha256:[0-9a-f]+' "$f" | head -1 || true)
    if [ "$old" = "$new" ]; then echo "  $f: unverändert"; else echo "  $f: aktualisiert"; fi
done
echo
echo "Neuer Digest: $digest"
echo "Jetzt neu bauen:"
echo "  docker compose build --no-cache --build-arg BUILD_DATE=\$(date -u +%Y-%m-%d)"
