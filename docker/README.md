# Secure Downloader – Docker mit Weboberfläche

## Einrichten

1. `docker-compose.yml` anpassen:
   - `volumes:` auf deinen NAS-Pfad zeigen lassen, z. B. `/volume1/daten/archiv:/data`
   - `PUID`/`PGID` auf deinen NAS-Benutzer setzen (`id -u` und `id -g` auf der NAS)
   - `UI_PASSWORD` setzen. Bleibt es leer, erzeugt der Container beim Start
     ein Zufallswort und schreibt es ins Protokoll (`docker logs downloader`).

2. Starten:
   ```
   docker compose up -d --build
   ```

3. Oberfläche öffnen: `http://<NAS-IP>:8080`

## Zur Portfreigabe

In der Compose-Datei steht bewusst `127.0.0.1:8080:8080`. Damit ist die
Oberfläche nur auf der NAS selbst erreichbar. Für den Zugriff aus deinem
Heimnetz die LAN-Adresse eintragen:

```yaml
ports:
  - "192.168.1.50:8080:8080"     # feste LAN-IP deiner NAS
```

**Nicht** im Router nach außen weiterleiten. Von unterwegs gehört ein VPN
davor, kein offener Port. Wer die Seite erreicht, kann Downloads auslösen.

## Tor

Der `tor`-Dienst läuft als eigener Container; die Vorgabe
`SOCKS_PROXY=socks5h://tor:9050` zeigt schon darauf. Der SOCKS-Port ist nur
im internen Docker-Netz erreichbar, nicht auf dem Host.

Prüfen, ob es wirkt: In der Oberfläche muss unter *Anonymität* „Tor
bestätigt" mit einer fremden Exit-IP stehen. Steht dort „AUS – direkte
Verbindung", läuft nichts über Tor.

## Nach einem Neustart weiterladen

`AUTOSTART=1` setzen. Zusammen mit `restart: unless-stopped` nimmt der
Container einen unterbrochenen Auftrag nach einem NAS-Neustart von selbst
wieder auf — an der Stelle, an der er aufgehört hat.

## Verzeichnisse unter /data

```
downloads/    fertige, geprüfte Dateien (nur lesbar, 0400)
quarantine/   auffällige Dateien: Prüfsumme falsch oder Typ passt nicht
config/       downloader.conf (von der Oberfläche geschrieben)
state/        Teil-Downloads, Prüfsummen, URL-Liste, status.json
download.log  Protokoll des Downloaders
```

## Ohne Oberfläche

Das Skript funktioniert unverändert direkt:

```
docker compose exec downloader /app/downloader.sh --help
```

## Sicherheitsentscheidungen

- Der Container läuft unprivilegiert, ohne zusätzliche Rechte
  (`no-new-privileges`, `cap_drop: ALL`).
- Die Oberfläche nutzt nur die Python-Standardbibliothek – keine
  Fremdpakete, deren Herkunft man prüfen müsste.
- Eingaben aus dem Browser landen ausschließlich als geprüfte KEY=WERT-Zeilen
  in einer Konfigurationsdatei. Es wird nie eine Zeichenkette an eine Shell
  übergeben.
- Anmeldung mit Sitzungscookie (HttpOnly, SameSite=Strict), CSRF-Token für
  jede schreibende Anfrage, Bremse nach mehreren Fehlversuchen.
