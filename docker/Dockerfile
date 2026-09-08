# Bewusst debian-slim statt alpine: Alpine bringt BusyBox mit, damit hätte
# man sich die fehlenden GNU-Werkzeuge in den Container zurückgeholt.
# Auf einen Digest festgenagelt: das Basis-Image kann sich sonst unter
# einem ändern. "docker/update-base.sh" holt den aktuellen Digest –
# etwa monatlich ausführen, sonst frierst du Sicherheitslücken ein.
FROM debian:12-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl ca-certificates coreutils grep sed gawk findutils \
        python3 tzdata \
    && rm -rf /var/lib/apt/lists/*

# Unprivilegierter Benutzer; UID/GID werden beim Start an die des NAS angepasst.
RUN groupadd -g 1000 dl && useradd -u 1000 -g dl -d /app -s /usr/sbin/nologin dl

WORKDIR /app
COPY docker/app/webui.py       /app/webui.py
COPY docker/app/ui/index.html  /app/ui/index.html
COPY docker/app/entrypoint.sh  /app/entrypoint.sh
COPY downloader.sh             /app/downloader.sh
RUN chmod 0755 /app/downloader.sh /app/entrypoint.sh /app/webui.py

ENV DATA_DIR=/data \
    DOWNLOADER_BIN=/app/downloader.sh \
    UI_BIND=0.0.0.0 \
    UI_PORT=8080 \
    PUID=1000 \
    PGID=1000 \
    AUTOSTART=0 \
    TZ=Europe/Berlin

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/session',timeout=3).status==200 else 1)"

ENTRYPOINT ["/app/entrypoint.sh"]
