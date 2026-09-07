# Eigener Tor-Container statt eines fremden Images: die Herkunft ist
# damit nachvollziehbar (Debian-Paketquellen, signiert) und es hängt
# kein unversioniertes :latest von Dritten in der Kette.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tor curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY docker/tor/torrc /etc/tor/torrc
RUN chown -R debian-tor:debian-tor /etc/tor

USER debian-tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
