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

## Das Sicherheitsmodell

### Kein Weg an Tor vorbei

Der Downloader-Container hängt **ausschließlich** im Netz `tornet`, das als
`internal: true` deklariert ist. Es existiert keine Route ins Internet. Der
Tor-Container hängt in beiden Netzen und ist damit der einzige Ausgang.

Das ist der Unterschied zwischen einer Zusage in Software und einer im
Netzaufbau: selbst wenn die Konfiguration falsch wäre, *kann* keine
Verbindung an Tor vorbei entstehen — es gibt keine.

Nachgemessen im laufenden Aufbau:

| Prüfung | Ergebnis |
|---|---|
| Über Tor nach draußen | `{"IsTor":true,"IP":"192.42.116.92"}` |
| Direkt per Hostname | keine Verbindung |
| Direkt per roher IP | keine Verbindung |
| DNS-Auflösung nach draußen | nicht möglich |
| Oberfläche vom Host | erreichbar |

### Der Schutz lässt sich im Browser nicht abschalten

Mit `ENFORCE_ANON=1` sind `ANON_MODE`, `LEAK_CHECK`, `REQUIRE_HTTPS` und
`SOCKS_PROXY` festgezurrt. In der Oberfläche erscheinen sie mit Schloss und
sind nicht bedienbar; ein Versuch über die Schnittstelle wird abgewiesen.
Ohne diese Sperre könnte jeder mit Zugriff auf die Oberfläche den Schutz
ausschalten und die echte IP preisgeben.

Zum Prüfen: `docker logs downloader` zeigt beim Start, was gesperrt ist.

### Eigener Tor-Container

Tor wird aus den signierten Debian-Paketquellen im eigenen Image gebaut
(`docker/tor/`). So hängt kein unversioniertes `:latest` eines Dritten in
der Kette.

### Verschlüsselung der Oberfläche

Ohne TLS geht das Zugangswort im Klartext durchs Netz — im eigenen LAN
meist hinnehmbar, aber kein guter Zustand. Eigene Zertifikate einhängen und
setzen:

```yaml
- UI_TLS_CERT=/data/config/ui.crt
- UI_TLS_KEY=/data/config/ui.key
```

Dann wird auch das Sitzungscookie mit `Secure` ausgeliefert. Alternativ den
Reverse-Proxy der NAS mit HTTPS davorstellen.

### Weitere Härtung

- Der Dienst kann seinen **eigenen Code nicht überschreiben**: `/app` gehört
  root, der Dienst darf nur lesen und ausführen. `read_only: true` macht
  zusätzlich das gesamte Wurzeldateisystem unbeschreibbar; nur `/data` und
  `/tmp` sind beschreibbar.
- Das Zugangswort muss mindestens 12 Zeichen haben, sonst startet der
  Container nicht (`UI_MIN_PASSWORD_LEN` senkt die Grenze bewusst).
- Text aus der Fremdquelle (Dateinamen, URLs) wird in der Oberfläche
  escaped. Geprüft mit einer Archivseite, die `<script>`- und
  `onerror`-Nutzlasten in Dateinamen unterbringt: nichts wird ausgeführt,
  und die Dateinamen selbst werden ohnehin auf harmlose Zeichen reduziert.

### Was weiterhin gilt

- Wer die Oberfläche erreicht, kann Downloads auslösen und Dateinamen sehen.
  Der Port gehört ins LAN, nicht ins Internet.
- `PIN_REQUIRE_HTTPS=0` ist nur nötig, wenn dein Ziel eine `.onion`-Adresse
  ist — dort verschlüsselt Tor selbst.
- Tor liefert wenige MB/s. Sehr große Bestände dauern entsprechend.

### Signaturprüfung einrichten

1. Öffentlichen Schlüssel des Herausgebers besorgen – **nicht** vom selben
   Server wie die Dateien, sonst ist der Anker wertlos.
2. Nach `/data/config/trusted.asc` legen.
3. In der Oberfläche unter *Signatur*: Modus `sums` oder `perfile`,
   Schlüsseldatei eintragen und **den Fingerabdruck festnageln**.

Ohne Fingerabdruck warnt das Protokoll: eine ausgetauschte Schlüsseldatei
fiele sonst nicht auf. Mit Fingerabdruck bricht der Lauf ab, bevor
irgendetwas heruntergeladen wird.

### Eigene Inhaltsprüfung

`SCAN_CMD` zeigt auf ein ausführbares Skript, das den Dateipfad bekommt.
Rückgabe ungleich 0 schiebt die Datei in Quarantäne. Ein Beispiel liegt
unter `docker/examples/scan.sh`.

Das ist **absichtlich nicht in der Oberfläche einstellbar** – ein Eingabefeld
für ein auszuführendes Programm wäre eine Fernausführungslücke. Es geht nur
über die Compose-Umgebung.

### Basis-Image aktualisieren

Beide Dockerfiles sind auf einen Digest festgenagelt. Das ist
nachvollziehbar, bekommt aber keine Sicherheitsupdates von allein:

```bash
./docker/update-base.sh && docker compose build --no-cache
```

Etwa monatlich ausführen.

### Offene Punkte

Ehrlich benannt, was **nicht** abgesichert ist:

- **Das selbst erzeugte TLS-Zertifikat schützt vor Mitlesen, nicht vor einem
  Angreifer, der sich aktiv dazwischenschaltet.** Für echten Schutz ein
  eigenes Zertifikat einhängen oder den Reverse-Proxy der NAS nutzen.
- **Wer die Oberfläche erreicht, kann Downloads auslösen und Dateinamen
  sehen.** Der Port gehört ins LAN, nicht ins Internet.
- **Die Inhaltsprüfung ist nur so gut wie das hinterlegte Skript.** Ohne
  `SCAN_CMD` findet keine statt.
- **Der festgenagelte Digest veraltet**, wenn `update-base.sh` nie läuft.

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
