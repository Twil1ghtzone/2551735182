# Eigener Tor-Container statt eines fremden Images: die Herkunft ist
# damit nachvollziehbar (Debian-Paketquellen, signiert) und es hängt
# kein unversioniertes :latest von Dritten in der Kette.
# Auf einen Digest festgenagelt: das Basis-Image kann sich sonst unter
# einem ändern. "docker/update-base.sh" holt den aktuellen Digest –
# etwa monatlich ausführen, sonst frierst du Sicherheitslücken ein.
FROM debian:12-slim@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867

RUN apt-get update && apt-get install -y --no-install-recommends \
        tor curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY docker/tor/torrc /etc/tor/torrc
RUN chown -R debian-tor:debian-tor /etc/tor

USER debian-tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
