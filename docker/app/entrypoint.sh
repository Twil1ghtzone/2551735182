#!/usr/bin/env bash
# Startet die Weboberfläche als unprivilegierter Benutzer.
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
PUID="${PUID:-1000}"; PGID="${PGID:-1000}"

if [ "$(id -u)" -eq 0 ]; then
    # UID/GID an den NAS-Benutzer anpassen, sonst gehören die Daten
    # am Ende root und man kommt über die Freigabe nicht mehr heran.
    groupmod -o -g "$PGID" dl 2>/dev/null || true
    usermod  -o -u "$PUID" -g "$PGID" dl 2>/dev/null || true
    mkdir -p "$DATA_DIR"/{downloads,quarantine,config,state}
    chown -R "$PUID:$PGID" "$DATA_DIR" 2>/dev/null || true
    # /app bewusst NICHT übereignen: der Dienst soll seinen eigenen Code
    # nicht überschreiben können. Lesen und Ausführen reicht (0755 durch root).
    echo "[entrypoint] starte als UID $PUID / GID $PGID"
    exec setpriv --reuid="$PUID" --regid="$PGID" --init-groups \
         python3 -u /app/webui.py
fi

mkdir -p "$DATA_DIR"/{downloads,quarantine,config,state}
exec python3 -u /app/webui.py
