#!/usr/bin/env python3
"""
Weboberfläche für den Secure Archive Downloader.

Bewusste Entscheidungen:
  - Nur Python-Standardbibliothek. Keine Fremdpakete = keine Lieferkette,
    die man im Auge behalten muss.
  - Die UI schreibt ausschließlich eine KEY=WERT-Datei, die das Skript
    ohnehin schon streng geparst einliest. Es wird niemals eine Zeichenkette
    aus dem Browser an eine Shell übergeben.
  - Jeder Konfigurationswert wird gegen ein Schema geprüft; unbekannte
    Schlüssel werden verworfen.
"""

import hmac, html, json, os, re, secrets, signal, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

APP_DIR      = os.path.dirname(os.path.abspath(__file__))
UI_DIR       = os.path.join(APP_DIR, "ui")
DOWNLOADER   = os.environ.get("DOWNLOADER_BIN", "/app/downloader.sh")
DATA_DIR     = os.environ.get("DATA_DIR", "/data")
CONFIG_DIR   = os.path.join(DATA_DIR, "config")
CONFIG_FILE  = os.path.join(CONFIG_DIR, "downloader.conf")
STATUS_FILE  = os.path.join(DATA_DIR, "state", "status.json")
LOG_FILE     = os.path.join(DATA_DIR, "download.log")
RUN_LOG      = os.path.join(DATA_DIR, "state", "runner.log")
BIND_HOST    = os.environ.get("UI_BIND", "0.0.0.0")
BIND_PORT    = int(os.environ.get("UI_PORT", "8080"))
SESSION_TTL  = int(os.environ.get("UI_SESSION_TTL", "43200"))   # 12 h
MAX_BODY     = 64 * 1024
UI_TLS_CERT  = os.environ.get("UI_TLS_CERT", "").strip()
UI_TLS_KEY   = os.environ.get("UI_TLS_KEY", "").strip()

# ─── Erzwungene Sicherheitseinstellungen ─────────────────────
# Ohne diese Sperre könnte jeder mit Zugriff auf die Oberfläche den
# Anonymitätsschutz abschalten und damit die echte IP preisgeben.
# Was hier eingetragen ist, lässt sich im Browser nicht mehr ändern.
ENFORCE_ANON = os.environ.get("ENFORCE_ANON", "1") == "1"
PINNED = {}
if ENFORCE_ANON:
    PINNED = {
        "ANON_MODE": "1",
        "LEAK_CHECK": "1",
        "REQUIRE_HTTPS": os.environ.get("PIN_REQUIRE_HTTPS", "1"),
        "SOCKS_PROXY": os.environ.get("PIN_SOCKS_PROXY", "socks5h://tor:9050"),
    }

# ─── Konfigurationsschema ────────────────────────────────────
# (typ, vorgabe, gruppe, beschriftung, hilfetext, extra)
RE_URL   = re.compile(r"^https?://[A-Za-z0-9._\-]+(:\d{1,5})?(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]*)?$")
RE_PROXY = re.compile(r"^socks5h?://[A-Za-z0-9._\-]+:\d{1,5}$")
RE_PATH  = re.compile(r"^/[A-Za-z0-9 ._\-/]*$")

SCHEMA = {
    "DATA_DIR":       ("path",  "/data",  "Ablage",      "Datenverzeichnis",
                       "Wurzel für Downloads, Protokoll und Status.", {}),
    "BASE_URL":       ("url",   "",       "Quelle",      "Basis-URL",
                       "Der Host, von dem geladen wird.", {}),
    "ARCHIVE_URL":    ("url",   "",       "Quelle",      "Archivseite",
                       "Die Seite, aus der die Download-Links gelesen werden.", {}),
    "CHECKSUM_URL":   ("url_opt","",      "Quelle",      "SHA256SUMS-URL",
                       "Ohne sie ist keine echte Integritätsprüfung möglich.", {}),
    "SOCKS_PROXY":    ("proxy", "socks5h://tor:9050", "Anonymität", "SOCKS5-Proxy",
                       "socks5h leitet auch die DNS-Auflösung über den Proxy.", {}),
    "ANON_MODE":      ("bool",  "1",      "Anonymität",  "Ohne Proxy nichts senden",
                       "Bricht ab, statt ungeschützt zu verbinden.", {}),
    "LEAK_CHECK":     ("bool",  "1",      "Anonymität",  "Exit-IP prüfen",
                       "Ermittelt vor dem ersten Download die sichtbare IP.", {}),
    "LOG_URLS":       ("bool",  "1",      "Anonymität",  "URLs protokollieren",
                       "Aus: es landen keine URLs in der Protokolldatei.", {}),
    "OBFUSCATE_NAMES":("bool",  "0",      "Anonymität",  "Dateinamen verschleiern",
                       "Speichert unter Hash-Namen statt Klarnamen.", {}),
    "REQUIRE_HTTPS":  ("bool",  "1",      "Sicherheit",  "HTTPS erzwingen",
                       "Aus nur für .onion-Adressen nötig.", {}),
    "REQUIRE_HASH":   ("bool",  "0",      "Sicherheit",  "Nur mit Quell-Prüfsumme",
                       "Dateien ohne Eintrag kommen in Quarantäne.", {}),
    "STRICT_TYPE":    ("bool",  "1",      "Sicherheit",  "Dateityp prüfen",
                       "Vergleicht den Inhalt mit der Dateiendung.", {}),
    "VERIFY_ALL":     ("bool",  "0",      "Sicherheit",  "Immer neu durchhashen",
                       "Gründlich, bei großen Beständen sehr langsam.", {}),
    "MAX_FILESIZE":   ("int",   "0",      "Grenzen",     "Max. Größe je Datei",
                       "0 = keine Obergrenze. Angabe in Bytes.", {"min":0}),
    "MIN_FREE_BYTES": ("int",   "1073741824", "Grenzen", "Freizuhaltender Speicher",
                       "Reserve, die auf dem Datenträger bleiben muss.", {"min":0}),
    "MAX_DOWNLOAD_SPEED":("int","0",      "Grenzen",     "Bandbreite",
                       "Bytes pro Sekunde, 0 = unbegrenzt.", {"min":0}),
    "REQUEST_DELAY":  ("int",   "1",      "Grenzen",     "Pause zwischen Dateien",
                       "Sekunden. Schützt vor Aussperrung durch den Server.", {"min":0,"max":3600}),
    "MAX_ATTEMPTS":   ("int",   "3",      "Verhalten",   "Versuche ohne Fortschritt",
                       "Danach gilt eine Datei als gescheitert.", {"min":1,"max":100}),
    "RETRY_BACKOFF":  ("int",   "30",     "Verhalten",   "Pause nach Fehlversuch",
                       "Sekunden.", {"min":1,"max":3600}),
    "CHECK_INTERVAL": ("int",   "60",     "Verhalten",   "Erster Wartezeitschritt",
                       "Sekunden; verdoppelt sich bei anhaltendem Ausfall.", {"min":5,"max":3600}),
    "MAX_WAIT_CYCLES":("int",   "0",      "Verhalten",   "Max. Warteversuche",
                       "0 = unbegrenzt warten, auch tagelang.", {"min":0}),
    "URL_LIST_TTL":   ("int",   "21600",  "Verhalten",   "Gültigkeit der URL-Liste",
                       "Sekunden, bis die Archivseite neu gelesen wird.", {"min":0}),
    "STALL_SECONDS":  ("int",   "300",    "Verhalten",   "Stillstandserkennung",
                       "Sekunden ohne nennenswerten Durchsatz.", {"min":10,"max":86400}),
}
GROUPS = ["Quelle", "Anonymität", "Sicherheit", "Grenzen", "Verhalten", "Ablage"]


def validate(key, raw):
    """Gibt (wert, fehler) zurück. Wert ist immer eine harmlose Zeichenkette."""
    if key not in SCHEMA:
        return None, "unbekannter Schlüssel"
    kind, default, _g, label, _h, extra = SCHEMA[key]
    v = ("" if raw is None else str(raw)).strip()
    if kind == "bool":
        return ("1" if v in ("1", "true", "on", "yes") else "0"), None
    if kind == "int":
        if not re.fullmatch(r"\d{1,19}", v):
            return None, f"{label}: nur ganze Zahlen"
        n = int(v)
        if "min" in extra and n < extra["min"]:
            return None, f"{label}: mindestens {extra['min']}"
        if "max" in extra and n > extra["max"]:
            return None, f"{label}: höchstens {extra['max']}"
        return str(n), None
    if kind in ("url", "url_opt"):
        if not v:
            return ("", None) if kind == "url_opt" else (None, f"{label}: darf nicht leer sein")
        if len(v) > 2000 or not RE_URL.fullmatch(v):
            return None, f"{label}: keine gültige http(s)-Adresse"
        return v, None
    if kind == "proxy":
        if not v:
            return "", None
        if not RE_PROXY.fullmatch(v):
            return None, f"{label}: Format socks5h://host:port"
        return v, None
    if kind == "path":
        if not RE_PATH.fullmatch(v) or ".." in v:
            return None, f"{label}: absoluter Pfad ohne Sonderzeichen"
        return v, None
    return None, "unbekannter Typ"


def read_config():
    cfg = {k: v[1] for k, v in SCHEMA.items()}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if "=" not in line:
                    continue
                k, _, val = line.partition("=")
                k = k.strip(); val = val.strip().strip('"').strip("'")
                if k in SCHEMA:
                    ok, _err = validate(k, val)
                    if ok is not None:
                        cfg[k] = ok
    except FileNotFoundError:
        pass
    cfg.update(PINNED)          # festgezurrte Werte gewinnen immer
    return cfg


def write_config(cfg):
    cfg = dict(cfg); cfg.update(PINNED)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("# Von der Weboberfläche geschrieben – nur KEY=WERT.\n")
        for group in GROUPS:
            keys = [k for k in SCHEMA if SCHEMA[k][2] == group]
            if not keys:
                continue
            fh.write(f"\n# {group}\n")
            for k in keys:
                fh.write(f"{k}={cfg.get(k, SCHEMA[k][1])}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


# ─── Prozessverwaltung ───────────────────────────────────────
class Runner:
    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self.started_at = None

    def running(self):
        with self.lock:
            return self.proc is not None and self.proc.poll() is None

    def start(self):
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return False, "läuft bereits"
            cfg = read_config()
            if not cfg.get("BASE_URL") or not cfg.get("ARCHIVE_URL"):
                return False, "Basis-URL und Archivseite müssen gesetzt sein"
            os.makedirs(os.path.dirname(RUN_LOG), exist_ok=True)
            logfh = open(RUN_LOG, "ab", buffering=0)
            # Feste Argumentliste, keine Shell: aus der UI kann nichts
            # als Befehl interpretiert werden.
            argv = [DOWNLOADER, "--config", CONFIG_FILE, "--no-dashboard"]
            try:
                self.proc = subprocess.Popen(
                    argv, stdout=logfh, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                    env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                         "HOME": os.environ.get("HOME", "/tmp"),
                         # TZ durchreichen, sonst stünden im Protokoll des
                         # Downloaders UTC-Zeiten, während die UI lokale zeigt.
                         "TZ": os.environ.get("TZ", "UTC"),
                         "LC_ALL": "C.UTF-8", "TERM": "dumb"})
            except OSError as exc:
                return False, f"Start fehlgeschlagen: {exc}"
            self.started_at = time.time()
            return True, "gestartet"

    def stop(self):
        with self.lock:
            if self.proc is None or self.proc.poll() is not None:
                return False, "läuft nicht"
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            except OSError:
                self.proc.terminate()
            return True, "wird beendet"


RUNNER = Runner()

# ─── Anmeldung ───────────────────────────────────────────────
PASSWORD = os.environ.get("UI_PASSWORD", "").strip()
if not PASSWORD:
    PASSWORD = secrets.token_urlsafe(12)
    print(f"[webui] Kein UI_PASSWORD gesetzt. Zugangswort für diese Sitzung: {PASSWORD}",
          flush=True)

SESSIONS = {}          # token -> (ablauf, csrf)
FAILS = {}             # ip -> (anzahl, sperre_bis)
SESS_LOCK = threading.Lock()


def new_session():
    tok, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with SESS_LOCK:
        SESSIONS[tok] = (time.time() + SESSION_TTL, csrf)
    return tok, csrf


def session_of(tok):
    if not tok:
        return None
    with SESS_LOCK:
        item = SESSIONS.get(tok)
        if not item:
            return None
        if item[0] < time.time():
            SESSIONS.pop(tok, None)
            return None
        return item


def note_fail(ip):
    with SESS_LOCK:
        n, _until = FAILS.get(ip, (0, 0))
        n += 1
        FAILS[ip] = (n, time.time() + min(300, 5 * n) if n >= 3 else 0)


def locked_out(ip):
    with SESS_LOCK:
        n, until = FAILS.get(ip, (0, 0))
        return until > time.time()


# ─── HTTP ────────────────────────────────────────────────────
def tail_lines(path, n):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, max(4096, n * 200))
            fh.seek(size - block)
            data = fh.read().decode("utf-8", "replace")
        return data.splitlines()[-n:]
    except OSError:
        return []


def dir_listing(path, limit=200):
    out = []
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.is_file():
                    st = e.stat()
                    out.append({"name": e.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    except OSError:
        return []
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out[:limit]


class Handler(BaseHTTPRequestHandler):
    server_version = "downloader-ui"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)

    # -- Hilfen ------------------------------------------------
    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), extra=extra)

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return ""

    def _auth(self):
        return session_of(self._cookie())

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    # -- GET ---------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(UI_DIR, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, b"UI fehlt", "text/plain; charset=utf-8")
        if path == "/api/session":
            return self._json(200, {"authenticated": self._auth() is not None})
        if not path.startswith("/api/"):
            return self._send(404, b"nicht gefunden", "text/plain; charset=utf-8")

        sess = self._auth()
        if sess is None:
            return self._json(401, {"error": "nicht angemeldet"})

        if path == "/api/state":
            status = {}
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as fh:
                    status = json.load(fh)
            except (OSError, ValueError):
                status = {}
            cfg = read_config()
            return self._json(200, {
                "running": RUNNER.running(),
                "status": status,
                "config": cfg,
                "csrf": sess[1],
                "schema": [
                    {"key": k, "type": SCHEMA[k][0], "default": SCHEMA[k][1],
                     "group": SCHEMA[k][2], "label": SCHEMA[k][3], "help": SCHEMA[k][4],
                     "locked": k in PINNED, **SCHEMA[k][5]}
                    for k in SCHEMA
                ],
                "groups": GROUPS,
                "enforce_anon": ENFORCE_ANON,
                "tls": bool(UI_TLS_CERT and UI_TLS_KEY),
            })
        if path == "/api/log":
            q = parse_qs(urlparse(self.path).query)
            n = min(500, max(10, int(q.get("n", ["150"])[0] or 150)))
            which = q.get("src", ["download"])[0]
            src = RUN_LOG if which == "runner" else LOG_FILE
            return self._json(200, {"lines": tail_lines(src, n)})
        if path == "/api/files":
            data = read_config().get("DATA_DIR", DATA_DIR)
            return self._json(200, {
                "downloads": dir_listing(os.path.join(data, "downloads")),
                "quarantine": dir_listing(os.path.join(data, "quarantine")),
            })
        return self._json(404, {"error": "unbekannter Endpunkt"})

    # -- POST --------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        ip = self.client_address[0]

        if path == "/api/login":
            if locked_out(ip):
                return self._json(429, {"error": "zu viele Fehlversuche – kurz warten"})
            body = self._body() or {}
            given = str(body.get("password", ""))
            if hmac.compare_digest(given, PASSWORD):
                tok, csrf = new_session()
                with SESS_LOCK:
                    FAILS.pop(ip, None)
                secure = "; Secure" if (UI_TLS_CERT and UI_TLS_KEY) else ""
                return self._json(200, {"ok": True, "csrf": csrf}, extra=[
                    ("Set-Cookie",
                     f"sid={tok}; HttpOnly; SameSite=Strict{secure}; Path=/; Max-Age={SESSION_TTL}")])
            note_fail(ip)
            time.sleep(0.5)
            return self._json(401, {"error": "falsches Zugangswort"})

        sess = self._auth()
        if sess is None:
            return self._json(401, {"error": "nicht angemeldet"})
        # CSRF: der Token steckt nur im Speicher der Seite, nicht im Cookie.
        if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), sess[1]):
            return self._json(403, {"error": "CSRF-Token fehlt oder passt nicht"})

        if path == "/api/logout":
            with SESS_LOCK:
                SESSIONS.pop(self._cookie(), None)
            return self._json(200, {"ok": True}, extra=[
                ("Set-Cookie", "sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")])

        if path == "/api/config":
            if RUNNER.running():
                return self._json(409, {"error": "läuft gerade – erst anhalten"})
            body = self._body()
            if not isinstance(body, dict):
                return self._json(400, {"error": "ungültige Daten"})
            cfg, errors = read_config(), []
            for k, raw in body.items():
                if k not in SCHEMA:
                    continue          # unbekannte Schlüssel still verwerfen
                if k in PINNED and str(raw) != PINNED[k]:
                    errors.append(f"{SCHEMA[k][3]}: durch ENFORCE_ANON gesperrt")
                    continue
                val, err = validate(k, raw)
                if err:
                    errors.append(err)
                else:
                    cfg[k] = val
            if errors:
                return self._json(400, {"error": "; ".join(errors[:5])})
            try:
                write_config(cfg)
            except OSError as exc:
                return self._json(500, {"error": f"Speichern fehlgeschlagen: {exc}"})
            return self._json(200, {"ok": True, "config": cfg})

        if path == "/api/control":
            body = self._body() or {}
            action = str(body.get("action", ""))
            if action == "start":
                ok, msg = RUNNER.start()
            elif action == "stop":
                ok, msg = RUNNER.stop()
            else:
                ok, msg = False, "unbekannte Aktion"
            return self._json(200 if ok else 400, {"ok": ok, "message": msg})

        return self._json(404, {"error": "unbekannter Endpunkt"})


def main():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "state"), exist_ok=True)
    if not os.path.exists(CONFIG_FILE):
        write_config({k: v[1] for k, v in SCHEMA.items()})
    if os.environ.get("AUTOSTART", "0") == "1":
        ok, msg = RUNNER.start()
        print(f"[webui] Autostart: {msg}", flush=True)
    if ENFORCE_ANON:
        print(f"[webui] Anonymitätsschutz gesperrt (nicht im Browser abschaltbar): "
              f"{', '.join(f'{k}={v}' for k, v in sorted(PINNED.items()))}", flush=True)
    else:
        print("[webui] WARNUNG: ENFORCE_ANON=0 – der Schutz lässt sich "
              "über die Oberfläche abschalten.", flush=True)
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    srv.daemon_threads = True
    scheme = "http"
    if UI_TLS_CERT and UI_TLS_KEY:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(UI_TLS_CERT, UI_TLS_KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    else:
        print("[webui] Hinweis: ohne TLS wird das Zugangswort im Klartext "
              "durchs Netz geschickt. UI_TLS_CERT/UI_TLS_KEY setzen oder "
              "einen HTTPS-Reverse-Proxy davorstellen.", flush=True)
    print(f"[webui] bereit auf {scheme}://{BIND_HOST}:{BIND_PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
