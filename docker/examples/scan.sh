#!/bin/sh
# Beispiel für SCAN_CMD. Bekommt genau einen Parameter: den Pfad der
# heruntergeladenen Datei. Rückgabe 0 = sauber, alles andere schiebt die
# Datei in Quarantäne.
#
# Nach /data/config/scan.sh kopieren, ausführbar machen und in der
# Compose-Datei SCAN_CMD=/data/config/scan.sh setzen.
set -eu
file="$1"

# Variante A: ClamAV im Beiwagen-Container
# clamdscan --no-summary --fdpass "$file" || exit 1

# Variante B: Archive auf Plausibilität prüfen
case "$file" in
    *.zip)  command -v unzip >/dev/null && { unzip -tq "$file" >/dev/null 2>&1 || exit 1; } ;;
    *.tar.gz|*.tgz) gzip -t "$file" 2>/dev/null || exit 1 ;;
esac

exit 0
