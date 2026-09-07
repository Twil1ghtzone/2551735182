# Secure Archive Downloader

Ein gehärteter Downloader für Archivseiten, mit Terminal-Dashboard,
Docker-Fassung und Weboberfläche. Ausgelegt auf lange Läufe (TB-Bereich)
über unzuverlässige Verbindungen und optional über Tor.

## Eigenschaften

**Anonymität**
- Ohne funktionierenden SOCKS5-Proxy wird kein einziges Paket gesendet
- `socks5h` erzwungen, damit auch die DNS-Auflösung über den Proxy läuft
- Proxy-Umgebungsvariablen werden neutralisiert
- Exit-IP-Prüfung vor dem ersten Download
- Optional: keine URLs im Protokoll, Dateinamen als Hash

**Integrität**
- Prüfung gegen eine `SHA256SUMS`-Datei der Quelle, pfadgenau zugeordnet
- Unverifizierte Daten landen nie im Zielverzeichnis (getrenntes Staging)
- Magic-Byte-Prüfung: Inhalt muss zur Dateiendung passen
- Auffälliges kommt in Quarantäne statt in den Downloadordner

**Robustheit**
- Fortsetzen nach Abbruch, Neustart und tagelangen Serverausfällen
- Abbrüche zählen nur ohne Fortschritt – wachsende Dateien werden endlos fortgesetzt
- Atomares Locking über `mkdir` (auch auf NFS/SMB), mit Heartbeat
- Schnelles Überspringen fertiger Dateien ohne erneutes Hashen

**Härtung**
- Symlink-Schutz an jeder Schreibstelle
- Nur Links zum konfigurierten Host, Umleitungen auf fremde Hosts werden verworfen
- HTTPS-Pflicht (Ausnahme nur für `.onion`)
- Größen- und Speicherplatzgrenzen, Pause zwischen Anfragen gegen Aussperrung

## Schnellstart

```bash
./downloader.sh --init-config
$EDITOR ~/.config/archive-downloader.conf
./downloader.sh --tor --dry-run
```

Wichtige Optionen:

```
-d, --dir PFAD        Wurzelverzeichnis für alle Daten
    --tor             Proxy auf socks5h://127.0.0.1:9050
    --checksums URL   SHA256SUMS der Quelle (dringend empfohlen)
    --require-hash    Dateien ohne Quell-Prüfsumme ablehnen
    --delay SEKUNDEN  Pause zwischen Dateien
    --no-dashboard    Zeilenlogging statt TUI (Cron/NAS)
```

`./downloader.sh --help` zeigt alles.

## Docker mit Weboberfläche

Siehe [docker/README.md](docker/README.md).

```bash
# Aus der Repo-Wurzel bauen (Build-Kontext ist die Wurzel):
cd docker
# volumes, PUID/PGID und UI_PASSWORD in docker-compose.yml anpassen
docker compose up -d --build
```

Die Oberfläche läuft auf Port 8080 und ist absichtlich auf `127.0.0.1`
gebunden. Für den Zugriff aus dem Heimnetz die LAN-Adresse der NAS
eintragen – **nicht** im Router nach außen weiterleiten.

Der Downloader-Container hängt in einem Netz ohne Route ins Internet; der
einzige Ausgang ist der Tor-Container. Eine Verbindung an Tor vorbei ist
damit nicht bloß verboten, sondern unmöglich. Mit `ENFORCE_ANON=1` lässt
sich der Schutz auch über die Oberfläche nicht abschalten. Details in
[docker/README.md](docker/README.md).

## Voraussetzungen

`bash` ab Version 4, `curl`, `sha256sum`, GNU-Coreutils. Für Systeme mit
BusyBox (NAS-Firmware) gibt es Fallbacks für fehlendes `stat -c`,
`df -B1`, `grep -oP` und `od`. Die Docker-Fassung bringt alles mit.

## Grenzen

- Die Prüfsumme belegt nur, dass die Datei unverfälscht von der Quelle
  stammt. Ist die Quelle selbst bösartig, hilft sie nicht.
- Der Schnellabgleich erkennt lokale Manipulation an Größe und Zeitstempel.
  Wer beides exakt fälscht, kommt daran vorbei – `--verify-all` hasht alles neu.
- Der Inhalt einer Datei wird nicht auf Schadcode geprüft.
- TB-Mengen über Tor dauern realistisch Wochen.
