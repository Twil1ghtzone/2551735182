#!/usr/bin/env bash
# Vergleicht den festgenagelten Digest mit dem aktuellen debian:12-slim.
# Für einen Cron-Eintrag gedacht: meldet mit Rückgabe 1, wenn veraltet.
set -euo pipefail
cd "$(dirname "$0")"

engine=""
for e in docker podman; do command -v "$e" >/dev/null 2>&1 && { engine="$e"; break; }; done
[ -n "$engine" ] || { echo "Weder docker noch podman gefunden." >&2; exit 2; }

pinned=$(grep -oE 'sha256:[0-9a-f]{64}' Dockerfile | head -1)
"$engine" pull -q docker.io/library/debian:12-slim >/dev/null
current=$("$engine" inspect docker.io/library/debian:12-slim \
          --format '{{index .RepoDigests 0}}' | sed 's/.*@//')

echo "  festgenagelt: ${pinned:-keiner}"
echo "  aktuell:      ${current}"
if [ "$pinned" = "$current" ]; then
    echo "Basis-Image ist aktuell."
    exit 0
fi
echo
echo "Basis-Image ist VERALTET. Aktualisieren mit:"
echo "  ./update-base.sh && docker compose build --no-cache --build-arg BUILD_DATE=\$(date -u +%Y-%m-%d)"
exit 1
