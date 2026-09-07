#!/usr/bin/env bash
# ============================================================
# Secure Archive Downloader v3
# ============================================================
# Schwerpunkte:
#   - Anonymität: erzwungener SOCKS5h-Proxy, kein DNS-Leck,
#     Neutralisierung von Proxy-Umgebungsvariablen, Leak-Test
#   - Sicherheit: Symlink-Schutz, isoliertes Staging, echte
#     Prüfsummen, Typprüfung, restriktive Rechte, kein exec-Bit
#   - NAS-tauglich: portable Fallbacks (BusyBox), freier Pfad,
#     Konfigurationsdatei, sauberer Nicht-TTY-Modus
#
# Nutzung:  ./downloader.sh --help
# ============================================================

set -euo pipefail
umask 077
export LC_ALL=C

VERSION="3.3"
SELF="${0##*/}"

# ─── Vorgaben (überschreibbar per Konfig-Datei und CLI) ──────
BASE_URL=""
ARCHIVE_URL=""
CHECKSUM_URL=""
DATA_DIR=""                     # Wurzel für ALLE Daten (NAS-Pfad)
SOCKS_PROXY=""
ANON_MODE=1                     # 1 = ohne funktionierenden Proxy kein Traffic
REQUIRE_HTTPS=1                 # 0 nötig für .onion über http
ALLOW_ONION=1
LOG_URLS=1                      # 0 = URLs/Dateinamen nicht auf Platte loggen
OBFUSCATE_NAMES=0               # 1 = Dateinamen auf Platte durch Hash ersetzen
STRICT_TYPE=1                   # 1 = Dateityp muss zur Endung passen
LEAK_CHECK=1                    # Exit-IP vor dem ersten Download prüfen
VERIFY_ALL=0                    # 1 = fertige Dateien bei jedem Lauf neu hashen
REQUIRE_HASH=0                  # 1 = Dateien ohne Quell-Prüfsumme ablehnen
URL_LIST_TTL=21600              # URL-Liste nach 6 h neu einlesen (0 = immer)
LOCK_MAX_AGE=86400              # fremder Lock gilt danach als verwaist

CHECK_INTERVAL=60
MAX_WAIT_CYCLES=0               # 0 = unbegrenzt warten (Server tage-/wochenlang aus)
MAX_WAIT_INTERVAL=900           # Wartezeit wächst bis höchstens 15 min
MAX_DOWNLOAD_SPEED=0            # 0 = keine Drosselung (5000000 = 5 MB/s)
MAX_FILESIZE=0                  # 0 = keine Obergrenze pro Datei
MIN_FREE_BYTES=1073741824
DOWNLOAD_TIMEOUT=0              # 0 = kein Zeitlimit pro Versuch (TB-Dateien)
STALL_BYTES=1024                # unter dieser Rate gilt die Übertragung als
STALL_SECONDS=300               # eingeschlafen und wird neu aufgesetzt
MAX_RESUMES=10000               # Sicherheitsnetz gegen Endlosschleifen
MAX_REDIRS=5
MAX_ATTEMPTS=3
RETRY_BACKOFF=30
REQUEST_DELAY=1                 # Pause zwischen Dateien: schützt davor, dass
                                # der Mirror einen als Bot aussperrt
DASHBOARD="auto"
DRY_RUN=0
# Generischer UA: ein eigener Name wäre ein eindeutiger Fingerabdruck.
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

CONFIG_FILE=""
DEFAULT_CONFIG="${HOME}/.config/archive-downloader.conf"

# ─── Hilfe ───────────────────────────────────────────────────
usage() {
    cat <<USAGE
${SELF} v${VERSION} — sicherer, anonymer Archiv-Downloader

  ${SELF} --dir /volume1/daten/archiv --base-url https://… --archive-url https://…/index

Pfade & Konfiguration
  -d, --dir PFAD          Wurzelverzeichnis für ALLE Daten (Downloads, Logs,
                          Status, Lock). Pflichtangabe oder via Konfig.
  -c, --config DATEI      Konfigurationsdatei (Vorgabe: ${DEFAULT_CONFIG})
      --init-config       Kommentierte Beispielkonfiguration schreiben
      --print-config      Effektive Einstellungen zeigen und beenden

Quelle
      --base-url URL      Basis-URL des Hosts
      --archive-url URL   Seite, von der Links extrahiert werden
      --checksums URL     SHA256SUMS-Datei der Quelle (dringend empfohlen)

Anonymität
      --proxy URL         SOCKS5-Proxy, z. B. socks5h://127.0.0.1:9050
      --tor               Kurzform für --proxy socks5h://127.0.0.1:9050
      --no-anon           Anonymitätszwang AUS (Klartext-Verbindung erlauben)
      --no-leak-check     Exit-IP-Prüfung überspringen
      --no-url-log        URLs und Dateinamen nicht in die Logdatei schreiben
      --obfuscate-names   Dateien unter Hash-Namen speichern

Sicherheit
      --allow-http        HTTP ohne TLS zulassen (für .onion nötig)
      --no-type-check     Dateityp-Prüfung (Magic Bytes) abschalten
      --require-hash      Dateien ohne Quell-Prüfsumme ablehnen
      --max-size BYTES    Obergrenze pro Datei in Bytes (0 = keine)
      --speed BYTES/s     Bandbreite drosseln (0 = unbegrenzt)
      --delay SEKUNDEN    Pause zwischen Dateien (gegen Aussperrung)
      --min-free BYTES    Reserve, die auf dem Datenträger frei bleibt

Betrieb
      --refresh           URL-Liste neu einlesen (neue Dateien erkennen)
      --verify-all        Alle fertigen Dateien neu durchhashen (langsam)
      --dry-run           Nur auflisten, nichts herunterladen
      --no-dashboard      Zeilenlogging statt TUI (für Cron/NAS-Scheduler)
  -h, --help              Diese Hilfe
USAGE
}

write_config_template() {
    local target="${1:-$DEFAULT_CONFIG}"
    local dir="${target%/*}"
    [ "$dir" != "$target" ] && mkdir -p "$dir"
    if [ -e "$target" ]; then
        echo "Abbruch: $target existiert bereits." >&2; exit 1
    fi
    cat > "$target" <<'CONF'
# ── Secure Archive Downloader – Konfiguration ────────────────
# Nur KEY=WERT. Die Datei wird NICHT als Shell ausgeführt.

# Wurzelverzeichnis für alle Daten. Auf dem NAS z. B.:
#DATA_DIR=/volume1/daten/archiv
DATA_DIR=

BASE_URL=
ARCHIVE_URL=
# SHA256SUMS-Datei der Quelle – ohne sie ist keine echte
# Integritätsprüfung möglich.
CHECKSUM_URL=

# Anonymität: socks5h leitet auch die DNS-Auflösung über den
# Proxy. Mit socks5 (ohne h) würde dein Router die Domains sehen.
SOCKS_PROXY=socks5h://127.0.0.1:9050
ANON_MODE=1
LEAK_CHECK=1
LOG_URLS=1
OBFUSCATE_NAMES=0

# Sicherheit
REQUIRE_HTTPS=1
STRICT_TYPE=1
# 0 = keine Obergrenze pro Datei. Der Schutz vor endlosen Downloads
# läuft dann über MIN_FREE_BYTES (Rest, der frei bleiben muss).
MAX_FILESIZE=0
MIN_FREE_BYTES=1073741824

# Tempo und Wiederholungen
# 0 = keine Drosselung. Rechenbeispiel: 5000000 (5 MB/s) bedeutet für
# 6 TB rund 14 Tage Laufzeit.
MAX_DOWNLOAD_SPEED=0
REQUEST_DELAY=1
MAX_ATTEMPTS=3
CHECK_INTERVAL=60
DASHBOARD=auto
CONF
    chmod 600 "$target"
    echo "Konfiguration angelegt: $target"
    exit 0
}

# ─── Konfiguration einlesen (parsen, NICHT sourcen) ──────────
# 'source' würde beliebigen Code aus der Datei ausführen.
ALLOWED_KEYS=" BASE_URL ARCHIVE_URL CHECKSUM_URL DATA_DIR SOCKS_PROXY ANON_MODE REQUIRE_HTTPS ALLOW_ONION LOG_URLS OBFUSCATE_NAMES STRICT_TYPE LEAK_CHECK CHECK_INTERVAL MAX_WAIT_CYCLES MAX_DOWNLOAD_SPEED MAX_FILESIZE MIN_FREE_BYTES DOWNLOAD_TIMEOUT MAX_REDIRS MAX_ATTEMPTS RETRY_BACKOFF DASHBOARD USER_AGENT REQUIRE_HASH URL_LIST_TTL LOCK_MAX_AGE MAX_WAIT_INTERVAL STALL_BYTES STALL_SECONDS MAX_RESUMES VERIFY_ALL REQUEST_DELAY "

load_config() {
    local file="$1"
    [ -f "$file" ] || return 0
    if [ -L "$file" ]; then
        echo "Abbruch: Konfigurationsdatei ist ein Symlink: $file" >&2; exit 1
    fi
    local perms
    perms=$(ls -l "$file" | cut -c1-10)
    case "$perms" in
        *w*w*|???????w*) : ;;
    esac
    if [ -w "$file" ] && [ "$(ls -ld "$file" | cut -c6,9)" != "--" ]; then
        echo "Warnung: $file ist für Gruppe/Andere beschreibbar – bitte chmod 600." >&2
    fi
    local line key val
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -n "$line" ] || continue
        case "$line" in *=*) ;; *) continue ;; esac
        key="${line%%=*}"; val="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"
        val="${val#"${val%%[![:space:]]*}"}"
        val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
        case "$ALLOWED_KEYS" in
            *" $key "*) printf -v "$key" '%s' "$val" ;;
            *) echo "Warnung: unbekannter Konfigurationsschlüssel '$key' – ignoriert." >&2 ;;
        esac
    done < "$file"
    return 0
}

# ─── CLI ─────────────────────────────────────────────────────
CLI_ARGS=("$@")
# Erster Durchlauf: nur --config/--init-config/--help
i=0
while [ $i -lt ${#CLI_ARGS[@]} ]; do
    case "${CLI_ARGS[$i]}" in
        -h|--help) usage; exit 0 ;;
        --init-config)
            n=$((i+1))
            write_config_template "${CLI_ARGS[$n]:-$DEFAULT_CONFIG}" ;;
        -c|--config) n=$((i+1)); CONFIG_FILE="${CLI_ARGS[$n]:-}" ;;
    esac
    i=$((i+1))
done

load_config "${CONFIG_FILE:-$DEFAULT_CONFIG}"

PRINT_CONFIG=0
FORCE_REFRESH=0
while [ $# -gt 0 ]; do
    case "$1" in
        -d|--dir)          DATA_DIR="${2:?Pfad fehlt}"; shift 2 ;;
        -c|--config)       shift 2 ;;
        --base-url)        BASE_URL="${2:?}"; shift 2 ;;
        --archive-url)     ARCHIVE_URL="${2:?}"; shift 2 ;;
        --checksums)       CHECKSUM_URL="${2:?}"; shift 2 ;;
        --proxy)           SOCKS_PROXY="${2:?}"; shift 2 ;;
        --tor)             SOCKS_PROXY="socks5h://127.0.0.1:9050"; shift ;;
        --no-anon)         ANON_MODE=0; shift ;;
        --no-leak-check)   LEAK_CHECK=0; shift ;;
        --no-url-log)      LOG_URLS=0; shift ;;
        --obfuscate-names) OBFUSCATE_NAMES=1; shift ;;
        --allow-http)      REQUIRE_HTTPS=0; shift ;;
        --no-type-check)   STRICT_TYPE=0; shift ;;
        --require-hash)    REQUIRE_HASH=1; shift ;;
        --refresh)         FORCE_REFRESH=1; shift ;;
        --verify-all)      VERIFY_ALL=1; shift ;;
        --max-size)        MAX_FILESIZE="${2:?}"; shift 2 ;;
        --speed)           MAX_DOWNLOAD_SPEED="${2:?}"; shift 2 ;;
        --delay)           REQUEST_DELAY="${2:?}"; shift 2 ;;
        --min-free)        MIN_FREE_BYTES="${2:?}"; shift 2 ;;
        --dry-run)         DRY_RUN=1; shift ;;
        --no-dashboard)    DASHBOARD="off"; shift ;;
        --print-config)    PRINT_CONFIG=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        --init-config)     shift; [ $# -gt 0 ] && shift ;;
        *) echo "Unbekannte Option: $1 (--help für Hilfe)" >&2; exit 2 ;;
    esac
done

# ─── Portabilität: BusyBox/NAS-Fallbacks ─────────────────────
HAVE_PCRE=0; HAVE_TPUT=0; HAVE_FILE=0; HAVE_OD=0; STAT_MODE="none"
detect_capabilities() {
    printf 'x' | grep -qoP 'x' 2>/dev/null && HAVE_PCRE=1
    command -v tput >/dev/null 2>&1 && HAVE_TPUT=1
    command -v file >/dev/null 2>&1 && HAVE_FILE=1
    command -v od >/dev/null 2>&1 && HAVE_OD=1
    if stat -c %s /dev/null >/dev/null 2>&1; then STAT_MODE="gnu"
    elif stat -f %z /dev/null >/dev/null 2>&1; then STAT_MODE="bsd"
    fi
    return 0
}
detect_capabilities

file_size() {
    local f="$1"
    [ -f "$f" ] || { printf '0'; return 0; }
    case "$STAT_MODE" in
        gnu) stat -c %s "$f" 2>/dev/null || printf '0' ;;
        bsd) stat -f %z "$f" 2>/dev/null || printf '0' ;;
        *)   wc -c < "$f" 2>/dev/null | tr -cd '0-9' || printf '0' ;;
    esac
}

file_mtime() {
    local f="$1"
    [ -f "$f" ] || { printf '0'; return 0; }
    case "$STAT_MODE" in
        gnu) stat -c %Y "$f" 2>/dev/null || printf '0' ;;
        bsd) stat -f %m "$f" 2>/dev/null || printf '0' ;;
        *)   printf '0' ;;
    esac
}

free_bytes() {
    # -P (POSIX) kann BusyBox; -B1 kann es nicht -> in 1K-Blöcken rechnen
    local kb
    kb=$(df -Pk "$1" 2>/dev/null | awk 'NR==2{print $4}' | tr -cd '0-9')
    [ -n "$kb" ] || { printf ''; return 1; }
    printf '%s' $((kb * 1024))
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}
sha256_str() { printf '%s' "$1" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } | awk '{print $1}'; }

# ─── Terminal ────────────────────────────────────────────────
TUI=0
if [ -t 1 ] && [ "$DASHBOARD" != "off" ] && [ "$HAVE_TPUT" -eq 1 ]; then TUI=1; fi
if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_B=$'\033[1m'
    C_RED=$'\033[38;5;203m'; C_GRN=$'\033[38;5;114m'; C_YEL=$'\033[38;5;221m'
    C_BLU=$'\033[38;5;110m'; C_MAG=$'\033[38;5;176m'; C_GRY=$'\033[38;5;245m'
else
    C_RESET=''; C_DIM=''; C_B=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_MAG=''; C_GRY=''
fi

# ─── Laufzeitstatus ──────────────────────────────────────────
LOCK_ACQUIRED=0; CURL_PID=""
START_TS=$(date +%s)
ST_PHASE="Start"; ST_HOST="unbekannt"; ST_ARCHIVE="unbekannt"
ST_HOST_CODE="-"; ST_ARCHIVE_CODE="-"; ST_FILE="-"
ST_ATTEMPT=0; ST_DONE=0; ST_SKIPPED=0; ST_FAILED=0
ST_TOTAL=0; ST_INDEX=0; ST_BYTES_SESSION=0
ST_CUR_BYTES=0; ST_CUR_SIZE=0; ST_SPEED=0
ST_CHECKSUM_MODE="nur lokaler Fingerabdruck"
ST_ANON="ungeprüft"; ST_EXIT_IP="-"
declare -a LOG_TAIL=()

redact() {   # Ausgabe entschärfen, wenn URLs nicht protokolliert werden sollen
    if [ "$LOG_URLS" -eq 1 ]; then printf '%s' "$1"; else printf '%s' "[redigiert]"; fi
}

log() {
    local level="$1"; shift
    local ts msg
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    msg="${ts} [${level}] $*"
    if [ -n "${LOG_FILE:-}" ] && [ -w "${LOG_FILE:-/nonexistent}" ]; then
        printf '%s\n' "$msg" >> "$LOG_FILE"
    fi
    LOG_TAIL+=("${level}|$(date '+%H:%M:%S')|$*")
    if [ "${#LOG_TAIL[@]}" -gt 40 ]; then LOG_TAIL=("${LOG_TAIL[@]:${#LOG_TAIL[@]}-40}"); fi
    if [ "$TUI" -eq 1 ]; then render; else printf '%s\n' "$msg"; fi
    write_status
    return 0
}
die() { log "ERROR" "$*"; exit 1; }
fail_early() { echo "Abbruch: $*" >&2; exit 1; }

cleanup() {
    local rc=$?
    if [ -n "$CURL_PID" ]; then kill "$CURL_PID" 2>/dev/null || true; fi
    if [ "$TUI" -eq 1 ]; then
        tput cnorm 2>/dev/null || true
        tput rmcup 2>/dev/null || true
    fi
    if [ "$LOCK_ACQUIRED" -eq 1 ] && [ -n "${LOCK_DIR:-}" ]; then
        rm -f "${LOCK_INFO}" 2>/dev/null || true
        rmdir "${LOCK_DIR}" 2>/dev/null || true
    fi
    return $rc
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ─── Proxy-Umgebung neutralisieren ───────────────────────────
# curl übernimmt sonst http_proxy/all_proxy aus der Umgebung – der
# Traffic ginge unbemerkt woanders hin als beabsichtigt.
unset http_proxy https_proxy ftp_proxy all_proxy HTTP_PROXY HTTPS_PROXY \
      FTP_PROXY ALL_PROXY no_proxy NO_PROXY 2>/dev/null || true

# ─── Validierung ─────────────────────────────────────────────
# Nur den HOST prüfen. Ein Pfad wie /abc.onion/x auf einem Klartext-Server
# darf die HTTPS-Pflicht nicht aushebeln.
is_onion() {
    local h="${1#*://}"; h="${h%%/*}"; h="${h%%\?*}"; h="${h%%:*}"
    case "$h" in *.onion) return 0 ;; *) return 1 ;; esac
}

validate_url() {
    local url="$1" label="$2"
    case "$url" in
        https://*) return 0 ;;
        http://*)
            if is_onion "$url" && [ "$ALLOW_ONION" -eq 1 ]; then return 0; fi
            if [ "$REQUIRE_HTTPS" -eq 1 ]; then
                fail_early "$label nutzt unverschlüsseltes HTTP: $url
  Mit HTTP kann jeder auf dem Weg mitlesen und Dateien austauschen.
  Wenn du das wirklich willst: --allow-http"
            fi
            return 0 ;;
        *) fail_early "$label muss http(s) sein: $url" ;;
    esac
}

for bin in curl awk sed grep df; do
    command -v "$bin" >/dev/null 2>&1 || fail_early "'$bin' nicht gefunden."
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail_early "Weder sha256sum noch shasum vorhanden – Integritätsprüfung unmöglich."
fi
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    fail_early "bash >= 4 erforderlich (gefunden: ${BASH_VERSION:-unbekannt})."
fi

[ -n "$DATA_DIR" ] || fail_early "Kein Datenverzeichnis. Nutze --dir /pfad oder trage DATA_DIR in die Konfiguration ein."
case "$DATA_DIR" in /*) ;; *) DATA_DIR="$(pwd)/$DATA_DIR" ;; esac

if [ "$PRINT_CONFIG" -eq 0 ]; then
    [ -n "$BASE_URL" ] || fail_early "BASE_URL fehlt."
    [ -n "$ARCHIVE_URL" ] || fail_early "ARCHIVE_URL fehlt."
    validate_url "$BASE_URL" "BASE_URL"
    validate_url "$ARCHIVE_URL" "ARCHIVE_URL"
    [ -n "$CHECKSUM_URL" ] && validate_url "$CHECKSUM_URL" "CHECKSUM_URL"
fi
BASE_URL="${BASE_URL%/}"

# ─── Anonymitätszwang ────────────────────────────────────────
if [ -n "$SOCKS_PROXY" ]; then
    case "$SOCKS_PROXY" in
        socks5h://*) ;;
        socks5://*)
            SOCKS_PROXY="socks5h://${SOCKS_PROXY#socks5://}"
            echo "Hinweis: socks5:// auf socks5h:// korrigiert – sonst würden DNS-Anfragen an deinem Proxy vorbei laufen." >&2 ;;
        socks4*|socks://*) fail_early "SOCKS4 leitet kein DNS weiter. Nutze socks5h://." ;;
        http://*|https://*) fail_early "HTTP-Proxy bietet hier keine Anonymität. Nutze socks5h://." ;;
        *) fail_early "Proxy muss socks5h://HOST:PORT sein." ;;
    esac
fi
if [ "$ANON_MODE" -eq 1 ] && [ -z "$SOCKS_PROXY" ] && [ "$PRINT_CONFIG" -eq 0 ]; then
    fail_early "Anonymitätsmodus aktiv, aber kein Proxy gesetzt.
  Ohne Proxy sieht dein Provider jede Anfrage und der Zielserver deine IP.
  Entweder:  --tor            (Tor auf 127.0.0.1:9050)
  oder:      --proxy socks5h://HOST:PORT
  oder bewusst abschalten:  --no-anon"
fi

if [ "$PRINT_CONFIG" -eq 1 ]; then
    printf 'DATA_DIR=%s\nBASE_URL=%s\nARCHIVE_URL=%s\nCHECKSUM_URL=%s\n' \
        "$DATA_DIR" "$BASE_URL" "$ARCHIVE_URL" "$CHECKSUM_URL"
    printf 'SOCKS_PROXY=%s\nANON_MODE=%s\nREQUIRE_HTTPS=%s\nSTRICT_TYPE=%s\n' \
        "${SOCKS_PROXY:-<keiner>}" "$ANON_MODE" "$REQUIRE_HTTPS" "$STRICT_TYPE"
    printf 'LOG_URLS=%s\nOBFUSCATE_NAMES=%s\nMAX_FILESIZE=%s\n' \
        "$LOG_URLS" "$OBFUSCATE_NAMES" "$MAX_FILESIZE"
    printf 'Fähigkeiten: PCRE=%s tput=%s file=%s stat=%s\n' "$HAVE_PCRE" "$HAVE_TPUT" "$HAVE_FILE" "$STAT_MODE"
    exit 0
fi

# ─── Verzeichnisse anlegen und absichern ─────────────────────
DOWNLOAD_DIR="${DATA_DIR}/downloads"
STATE_DIR="${DATA_DIR}/state"
STAGING_DIR="${DATA_DIR}/state/staging"
CHECKSUM_DIR="${DATA_DIR}/state/checksums"
QUARANTINE_DIR="${DATA_DIR}/quarantine"
DONE_DIR="${DATA_DIR}/state/done"
STATUS_FILE="${DATA_DIR}/state/status.json"
LOG_FILE="${DATA_DIR}/download.log"
LOCK_DIR="${DATA_DIR}/.lock.d"
LOCK_INFO="${LOCK_DIR}/owner"

assert_no_symlink() {
    if [ -L "$1" ]; then
        fail_early "Symlink an sicherheitsrelevanter Stelle: $1
  Ein Angreifer könnte damit Schreibzugriffe auf fremde Dateien umlenken."
    fi
    return 0
}

if [ -e "$DATA_DIR" ] && [ ! -d "$DATA_DIR" ]; then
    fail_early "$DATA_DIR existiert, ist aber kein Verzeichnis."
fi
assert_no_symlink "$DATA_DIR"
mkdir -p "$DATA_DIR" || fail_early "Kann $DATA_DIR nicht anlegen (Rechte? NAS-Share gemountet?)"
[ -w "$DATA_DIR" ] || fail_early "$DATA_DIR ist nicht beschreibbar."

for d in "$DOWNLOAD_DIR" "$STATE_DIR" "$STAGING_DIR" "$CHECKSUM_DIR" "$QUARANTINE_DIR" "$DONE_DIR"; do
    assert_no_symlink "$d"
    mkdir -p "$d" || fail_early "Kann $d nicht anlegen."
done
# Staging ist ausschließlich für uns – dort landen unverifizierte Daten.
chmod 700 "$STATE_DIR" "$STAGING_DIR" 2>/dev/null || true

# Warnen, wenn das Zielverzeichnis für andere beschreibbar ist (NAS-Shares!)
dir_perm_warning() {
    local d="$1" mode=""
    case "$STAT_MODE" in
        gnu) mode=$(stat -c %a "$d" 2>/dev/null || true) ;;
        bsd) mode=$(stat -f %Lp "$d" 2>/dev/null || true) ;;
    esac
    [ -n "$mode" ] || return 0
    local other="${mode: -1}" group="${mode: -2:1}"
    if [ "$((other & 2))" -ne 0 ] || [ "$((group & 2))" -ne 0 ]; then
        echo "Warnung: $d ist für Gruppe/Andere beschreibbar (Modus $mode)." >&2
        echo "         Auf einem geteilten NAS-Share können andere Konten dort Dateien unterschieben." >&2
    fi
    return 0
}
dir_perm_warning "$DOWNLOAD_DIR"

if [ "$(id -u)" -eq 0 ]; then
    echo "Warnung: Ausführung als root. Besser ein eigenes, unprivilegiertes Konto verwenden." >&2
fi

assert_no_symlink "$LOG_FILE"
touch "$LOG_FILE" 2>/dev/null || true
chmod 600 "$LOG_FILE" 2>/dev/null || true
# Anhängen, nicht überschreiben – aber nicht unbegrenzt wachsen lassen.
if [ -f "$LOG_FILE" ]; then
    _lsz=$(wc -c < "$LOG_FILE" 2>/dev/null | tr -cd '0-9')
    if [ -n "$_lsz" ] && [ "$_lsz" -gt 5242880 ]; then
        mv -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
        touch "$LOG_FILE"; chmod 600 "$LOG_FILE" 2>/dev/null || true
    fi
    unset _lsz
fi

# ─── Atomares Locking mit Stale-Erkennung ────────────────────
# mkdir ist auch auf NFS-/SMB-Freigaben atomar; das Anlegen einer Datei
# mit noclobber ist es dort NICHT. Auf dem NAS ist das der Unterschied
# zwischen echtem und scheinbarem Schutz.
acquire_lock() {
    local me_host me_pid now tries=0
    me_host=$(hostname 2>/dev/null || echo unbekannt)
    me_pid=$$
    while :; do
        if mkdir "$LOCK_DIR" 2>/dev/null; then
            now=$(date +%s)
            printf '%s %s %s\n' "$me_host" "$me_pid" "$now" > "$LOCK_INFO" 2>/dev/null || true
            LOCK_ACQUIRED=1
            return 0
        fi
        local o_host o_pid o_ts age
        read -r o_host o_pid o_ts < "$LOCK_INFO" 2>/dev/null || true
        o_host="${o_host:-}"; o_pid="${o_pid:-}"; o_ts="${o_ts:-0}"
        case "$o_ts" in *[!0-9]*|'') o_ts=0 ;; esac
        age=$(( $(date +%s) - o_ts ))

        if [ "$o_host" = "$me_host" ] && [ -n "$o_pid" ] && [[ "$o_pid" =~ ^[0-9]+$ ]]; then
            # Gleicher Rechner: PID-Prüfung ist aussagekräftig.
            if kill -0 "$o_pid" 2>/dev/null; then
                fail_early "Eine Instanz läuft bereits (PID $o_pid auf $o_host)."
            fi
        elif [ -n "$o_host" ] && [ "$o_ts" -gt 0 ] && [ "$age" -lt "$LOCK_MAX_AGE" ]; then
            # Anderer Rechner: dessen PID sagt hier nichts aus, also Alter prüfen.
            fail_early "Gesperrt durch '$o_host' (seit ${age}s).
  Läuft dort noch eine Instanz? Sonst: rm -rf '$LOCK_DIR'"
        fi

        tries=$((tries + 1))
        [ "$tries" -gt 2 ] && fail_early "Lock nicht übernehmbar: $LOCK_DIR"
        rm -f "$LOCK_INFO" 2>/dev/null || true
        rmdir "$LOCK_DIR" 2>/dev/null || fail_early "Lock-Verzeichnis nicht entfernbar: $LOCK_DIR"
    done
}
acquire_lock

if [ "$TUI" -eq 1 ]; then
    tput smcup 2>/dev/null || true
    tput civis 2>/dev/null || true
    clear
fi

# ─── curl-Basisargumente ─────────────────────────────────────
CURL_ARGS=(
    --silent --show-error
    --proto '=http,https'
    --proto-redir '=http,https'
    --proto-default https
    --max-redirs "$MAX_REDIRS"
    --connect-timeout 45
    --tlsv1.2
    --no-sessionid
    --cookie ''            # niemals Cookies senden oder speichern
    -A "$USER_AGENT"
    -L
)
if [ -n "$SOCKS_PROXY" ]; then CURL_ARGS+=(-x "$SOCKS_PROXY"); fi

# Selbsttest der curl-Optionen, rein lokal: curl prüft die Optionen auch
# bei --help. Ohne diesen Test würde eine vom vorhandenen curl nicht
# unterstützte Option jeden Request mit Exit 2 scheitern lassen – und das
# Skript würde fälschlich "Ziel offline" melden, statt das Problem zu nennen.
if ! curl "${CURL_ARGS[@]}" --help >/dev/null 2>&1; then
    _bad=$(curl "${CURL_ARGS[@]}" --help 2>&1 >/dev/null | head -2)
    fail_early "Dein curl akzeptiert die verwendeten Optionen nicht:
  ${_bad}
  curl-Version: $(curl --version 2>/dev/null | head -1)"
fi

# ─── Anonymitätsprüfung ──────────────────────────────────────
verify_anonymity() {
    if [ -z "$SOCKS_PROXY" ]; then
        ST_ANON="AUS – direkte Verbindung"; ST_EXIT_IP="deine eigene IP"
        log "WARN" "Kein Proxy: Zielserver und Provider sehen deine echte IP."
        return 0
    fi
    # 1) Proxy überhaupt erreichbar? /dev/tcp fehlt in manchen bash-Builds
    #    (NAS-Firmware), deshalb ist ein Fehlschlag hier kein Beweis.
    local host_port="${SOCKS_PROXY#socks5h://}"
    local phost="${host_port%%:*}" pport="${host_port##*:}"
    if (exec 3<>"/dev/tcp/${phost}/${pport}") 2>/dev/null; then
        exec 3<&- 2>/dev/null || true
    else
        # Gegenprobe über curl. Ein Fehlschlag hier bedeutet: es kam KEINE
        # Verbindung zustande – curl weicht niemals am Proxy vorbei aus.
        local rc=0
        curl "${CURL_ARGS[@]}" -o /dev/null --max-time 25 "$BASE_URL" 2>/dev/null || rc=$?
        case "$rc" in
            2)
                die "curl lehnt die Aufrufoptionen ab (Exit 2) – kein Verbindungsproblem." ;;
            7|97|5|56)
                die "SOCKS-Proxy ${phost}:${pport} nicht erreichbar (curl $rc). Läuft Tor?
  Es wurde KEINE Verbindung nach außen aufgebaut." ;;
        esac
    fi

    if [ "$LEAK_CHECK" -eq 0 ]; then
        ST_ANON="Proxy aktiv (ungeprüft)"
        log "INFO" "Proxy erreichbar; Leak-Test übersprungen."
        return 0
    fi

    ST_PHASE="prüfe Anonymität"
    # 2) Exit-IP über den Proxy ermitteln
    local via_proxy
    via_proxy=$(curl "${CURL_ARGS[@]}" --fail --max-time 45 "https://check.torproject.org/api/ip" 2>/dev/null || true)
    if [ -z "$via_proxy" ]; then
        via_proxy=$(curl "${CURL_ARGS[@]}" --fail --max-time 45 "https://api.ipify.org" 2>/dev/null || true)
    fi
    if [ -z "$via_proxy" ]; then
        ST_ANON="Proxy aktiv, Test fehlgeschlagen"
        log "WARN" "Exit-IP nicht ermittelbar (Testdienst blockiert?). Proxy ist aber erreichbar."
        return 0
    fi
    local exit_ip is_tor
    exit_ip=$(printf '%s' "$via_proxy" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    is_tor=$(printf '%s' "$via_proxy" | grep -o '"IsTor":[a-z]*' | cut -d: -f2 || true)
    ST_EXIT_IP="${exit_ip:-unbekannt}"

    # 3) Gegenprobe: Direktverbindung nur, wenn ausdrücklich erlaubt.
    #    Im Anonymitätsmodus wird bewusst KEIN Direkt-Request gesendet.
    if [ "$is_tor" = "true" ]; then
        ST_ANON="Tor bestätigt"
        log "OK" "Tor bestätigt. Exit-IP: ${ST_EXIT_IP}"
    else
        ST_ANON="Proxy aktiv (kein Tor)"
        log "INFO" "Verbindung läuft über Proxy. Exit-IP: ${ST_EXIT_IP}"
    fi
    return 0
}

# ─── Verbindungsprüfungen ────────────────────────────────────
# curl-Ausgabe und Exit-Status getrennt auswerten: ein "|| echo 000"
# würde die bereits ausgegebenen Ziffern ergänzen statt ersetzen
# (aus 302 würde 302000).
http_status() {
    local url="$1" tmo="$2" out rc=0
    out=$(curl "${CURL_ARGS[@]}" -o /dev/null -w '%{http_code}' --max-time "$tmo" "$url" 2>/dev/null) || rc=$?
    if [ "$rc" -eq 2 ]; then die "curl lehnt die Aufrufoptionen ab (Exit 2) – kein Verbindungsproblem."; fi
    if [ "$rc" -ne 0 ]; then printf '000'; return 0; fi
    case "$out" in
        [0-9][0-9][0-9]) printf '%s' "$out" ;;
        *)               printf '000' ;;
    esac
    return 0
}
check_connection() {
    ST_HOST_CODE=$(http_status "$BASE_URL" 20)
    case "$ST_HOST_CODE" in 2*) ST_HOST="up"; return 0 ;; esac
    ST_HOST="down"; return 1
}
check_archive() {
    ST_ARCHIVE_CODE=$(http_status "$ARCHIVE_URL" 25)
    case "$ST_ARCHIVE_CODE" in 2*) ST_ARCHIVE="up"; return 0 ;; esac
    ST_ARCHIVE="down"; return 1
}
interruptible_sleep() {
    local n="$1" i=0
    while [ "$i" -lt "$n" ]; do sleep 1; i=$((i+1)); render; done
    return 0
}
# Wartet, bis das Ziel wieder da ist. Mit MAX_WAIT_CYCLES=0 unbegrenzt –
# der Ausfall darf Stunden oder Tage dauern, der Fortschritt bleibt erhalten.
wait_for_host() {
    local cycles=0 iv="$CHECK_INTERVAL" total=0
    while ! { check_connection && check_archive; }; do
        cycles=$((cycles + 1))
        if [ "$MAX_WAIT_CYCLES" -gt 0 ] && [ "$cycles" -ge "$MAX_WAIT_CYCLES" ]; then
            die "Ziel nach $cycles Versuchen nicht erreichbar."
        fi
        if [ "$MAX_WAIT_CYCLES" -gt 0 ]; then
            ST_PHASE="warte auf Verbindung (${cycles}/${MAX_WAIT_CYCLES})"
        else
            ST_PHASE="warte auf Server ($(human_time "$total"))"
        fi
        log "WARN" "Nicht erreichbar (Host $ST_HOST_CODE / Archiv $ST_ARCHIVE_CODE). Nächster Versuch in ${iv}s."
        interruptible_sleep "$iv"
        total=$((total + iv))
        lock_heartbeat
        # Abstand verdoppeln, damit ein tagelanger Ausfall den Server
        # nicht unnötig anklopft – gedeckelt auf MAX_WAIT_INTERVAL.
        iv=$((iv * 2))
        [ "$iv" -gt "$MAX_WAIT_INTERVAL" ] && iv="$MAX_WAIT_INTERVAL"
    done
    [ "$cycles" -gt 0 ] && log "OK" "Server wieder erreichbar nach $(human_time "$total")."
    ST_PHASE="verbunden"
    return 0
}

# Ein Download über Tage würde sonst von einem anderen Rechner nach
# LOCK_MAX_AGE für verwaist gehalten und überrannt.
lock_heartbeat() {
    [ "$LOCK_ACQUIRED" -eq 1 ] || return 0
    printf '%s %s %s\n' "$(hostname 2>/dev/null || echo unbekannt)" "$$" "$(date +%s)" \
        > "$LOCK_INFO" 2>/dev/null || true
    return 0
}

# ─── Erwartete Prüfsummen ────────────────────────────────────
declare -A EXPECTED_HASH=()
load_expected_hashes() {
    [ -n "$CHECKSUM_URL" ] || {
        log "WARN" "Keine CHECKSUM_URL: Downloads sind nicht gegen Manipulation prüfbar."
        return 0
    }
    ST_PHASE="lade Prüfsummen"
    local sums="${STATE_DIR}/SHA256SUMS"
    assert_no_symlink "$sums"
    curl "${CURL_ARGS[@]}" --fail --max-time 60 --max-filesize 5242880 -o "$sums" "$CHECKSUM_URL" \
        || die "Prüfsummendatei nicht ladbar: $(redact "$CHECKSUM_URL")"
    local hash name count=0
    while read -r hash name; do
        [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] || continue
        name="${name#\*}"; name="${name#./}"
        EXPECTED_HASH["$name"]=$(printf '%s' "$hash" | tr 'A-F' 'a-f')
        count=$((count + 1))
    done < "$sums"
    [ "$count" -gt 0 ] || die "Prüfsummendatei enthält keine gültigen SHA256-Einträge."
    ST_CHECKSUM_MODE="SHA256 gegen Quelle (${count})"
    log "INFO" "$count erwartete Prüfsummen geladen."
    return 0
}
lookup_expected() {
    local probe="${1#/}"
    while :; do
        if [ -n "${EXPECTED_HASH[$probe]:-}" ]; then printf '%s' "${EXPECTED_HASH[$probe]}"; return 0; fi
        case "$probe" in */*) probe="${probe#*/}" ;; *) return 1 ;; esac
    done
}

# ─── URL-Liste ───────────────────────────────────────────────
EXT_RE='zip|rar|7z|tar\.gz|tgz|pdf|docx?|xlsx?|csv|txt'
extract_hrefs() {
    if [ "$HAVE_PCRE" -eq 1 ]; then
        grep -oPi "href\\s*=\\s*[\"'][^\"']+\\.(${EXT_RE})(\\?[^\"']*)?[\"']" \
            | sed -E "s/^href[[:space:]]*=[[:space:]]*[\"']//I; s/[\"']\$//"
    else
        # BusyBox-Fallback ohne PCRE
        tr '<' '\n' | sed -n "s/.*[hH][rR][eE][fF][[:space:]]*=[[:space:]]*[\"']\\([^\"']*\\)[\"'].*/\\1/p" \
            | grep -Ei "\\.(${EXT_RE})(\\?|\$)"
    fi
}

build_url_list() {
    local url_file="${STATE_DIR}/urls.txt"
    assert_no_symlink "$url_file"
    local stamp="${STATE_DIR}/urls.stamp"
    if [ -s "$url_file" ] && [ "$FORCE_REFRESH" -eq 0 ]; then
        # Zwischengespeicherte Liste nur nutzen, solange sie frisch ist – sonst
        # würden neu hinzugekommene Dateien nie bemerkt.
        local age=999999999 written="" cached_url=""
        # Der Stempel enthält Zeitpunkt UND Quelle: wird die Archivseite
        # geändert, darf die alte Liste nicht weiterverwendet werden.
        IFS='|' read -r written cached_url < "$stamp" 2>/dev/null || true
        written=$(printf '%s' "${written:-}" | tr -cd '0-9')
        if [ -n "$written" ]; then age=$(( $(date +%s) - written )); fi
        if [ -n "$cached_url" ] && [ "$cached_url" != "$ARCHIVE_URL" ]; then
            log "INFO" "Quelle geändert – URL-Liste wird neu eingelesen."
            age=999999999
        fi
        if [ "$URL_LIST_TTL" -gt 0 ] && [ "$age" -lt "$URL_LIST_TTL" ]; then
            log "INFO" "URL-Liste weiterverwendet ($(grep -c . "$url_file") Einträge, ${age}s alt)."
            return 0
        fi
        log "INFO" "URL-Liste veraltet – lese neu ein."
    fi
    ST_PHASE="extrahiere URLs"
    log "INFO" "Extrahiere URLs von der Archiv-Seite..."
    local raw_html
    raw_html=$(curl "${CURL_ARGS[@]}" --fail --max-time 90 --max-filesize 52428800 "$ARCHIVE_URL" || true)
    [ -n "$raw_html" ] || { log "ERROR" "Kein Inhalt von der Quellseite."; return 1; }

    local base_host="${BASE_URL#*://}"; base_host="${base_host%%/*}"
    base_host="${base_host%%:*}"      # Port abschneiden – h unten hat auch keinen

    # Relative Links gehören gegen das VERZEICHNIS der Archivseite aufgelöst,
    # nicht gegen die Site-Wurzel: auf https://host/gnu/hello/ meint
    # "datei.tar.gz" eben https://host/gnu/hello/datei.tar.gz.
    local page_dir="${ARCHIVE_URL%%\?*}"; page_dir="${page_dir%%#*}"
    case "$page_dir" in
        */) ;;
        *)  page_dir="${page_dir%/*}/" ;;
    esac

    printf '%s' "$raw_html" | extract_hrefs \
        | sed -e 's/&amp;/\&/g' -e 's/&#38;/\&/g' -e 's/&quot;/"/g' -e 's/&#x2F;/\//g' \
        | while IFS= read -r line; do
            [ -n "$line" ] || continue
            local abs=""
            case "$line" in
                https://*|http://*) abs="$line" ;;
                //*)                abs="https:${line}" ;;
                /*)                 abs="${BASE_URL}${line}" ;;
                *:*)                continue ;;   # javascript:, data:, file: verwerfen
                ./*)                abs="${page_dir}${line#./}" ;;
                *)                  abs="${page_dir}${line}" ;;
            esac
            # ../ auflösen, damit keine Pfade mit ".." zum Server gehen
            while case "$abs" in *"/../"*) true ;; *) false ;; esac; do
                local head="${abs%%/../*}" tail="${abs#*/../}"
                abs="${head%/*}/${tail}"
            done
            # Nur Links zum konfigurierten Host akzeptieren – eine
            # manipulierte Archivseite soll uns nicht auf fremde
            # Server (oder ins lokale Netz) schicken.
            local h="${abs#*://}"; h="${h%%/*}"; h="${h%%:*}"
            [ "$h" = "$base_host" ] || continue
            case "$abs" in
                *[[:space:]]*|*'"'*|*"'"*|*'`'*|*'$'*) continue ;;
            esac
            printf '%s\n' "$abs"
          done | sort -u > "$url_file"

    printf '%s|%s\n' "$(date +%s)" "$ARCHIVE_URL" > "$stamp"
    local n; n=$(grep -c . "$url_file" 2>/dev/null) || n=0
    log "INFO" "$n URLs verarbeitet."
    return 0
}

# ─── Dateinamen ──────────────────────────────────────────────
sanitize_filename() {
    local url="$1"
    local name="${url%%\?*}"; name="${name%%#*}"
    name=$(basename -- "$name")
    name="${name//%2F/_}"; name="${name//%2f/_}"; name="${name//%00/_}"
    name=$(printf '%s' "$name" | tr -cd 'a-zA-Z0-9._-')
    name="${name#"${name%%[!.]*}"}"
    case "$name" in ''|.|..) name="" ;; esac
    [ "${#name}" -gt 120 ] && name="${name: -120}"
    local tag
    tag=$(sha256_str "$url"); tag="${tag:0:8}"
    if [ "$OBFUSCATE_NAMES" -eq 1 ]; then
        local ext=""
        case "$name" in *.*) ext=".${name##*.}" ;; esac
        printf '%s%s' "$tag$(sha256_str "$url" | cut -c9-24)" "$ext"
        return 0
    fi
    if [ -z "$name" ]; then
        printf 'file_%s.dat' "$tag"
    else
        # Doppelendungen zusammenhalten, sonst entstünde "x.tar_ab12.gz"
        local stem ext=""
        case "$name" in
            *.tar.gz|*.tar.bz2|*.tar.xz|*.tar.zst)
                ext=".${name#*.}"; ext=".tar.${name##*.}"; stem="${name%.tar.*}" ;;
            *.*) ext=".${name##*.}"; stem="${name%.*}" ;;
            *)   stem="$name" ;;
        esac
        printf '%s_%s%s' "$stem" "$tag" "$ext"
    fi
    return 0
}

# ─── Typprüfung (Magic Bytes) ────────────────────────────────
magic_ok() {
    local f="$1" name="$2"
    [ "$STRICT_TYPE" -eq 1 ] || return 0
    local ext="${name##*.}"
    ext=$(printf '%s' "$ext" | tr 'A-Z' 'a-z')
    local head4=""
    if [ "$HAVE_OD" -eq 1 ]; then
        head4=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n' || true)
    fi
    if [ -z "$head4" ]; then
        # Fallback ohne od: Präfix direkt vergleichen
        local raw; raw=$(head -c 4 "$f" 2>/dev/null || true)
        case "$raw" in
            PK*)            head4="504b0304" ;;
            '%PDF')         head4="25504446" ;;
            $'\x1f\x8b'*)   head4="1f8b0000" ;;
            '7z'*)          head4="377abcaf" ;;
            'Rar!')         head4="52617221" ;;
            *)              return 0 ;;   # unbekannt -> nicht blockieren
        esac
    fi
    case "$ext" in
        zip|docx|xlsx) case "$head4" in 504b0304|504b0506|504b0708) return 0 ;; *) return 1 ;; esac ;;
        pdf)           case "$head4" in 25504446) return 0 ;; *) return 1 ;; esac ;;
        gz|tgz)        case "$head4" in 1f8b*) return 0 ;; *) return 1 ;; esac ;;
        7z)            case "$head4" in 377abcaf) return 0 ;; *) return 1 ;; esac ;;
        rar)           case "$head4" in 52617221) return 0 ;; *) return 1 ;; esac ;;
        doc|xls)       case "$head4" in d0cf11e0) return 0 ;; *) return 1 ;; esac ;;
        txt|csv)
            # HTML-Fehlerseite als .txt ausgeliefert?
            case "$(head -c 512 "$f" | tr 'A-Z' 'a-z')" in
                *"<html"*|*"<!doctype html"*) return 1 ;;
            esac
            return 0 ;;
        *) return 0 ;;
    esac
}

# ─── Remote-Metadaten ────────────────────────────────────────
probe_remote() {
    R_SIZE=0; R_ETAG=""
    local hdrs
    hdrs=$(curl "${CURL_ARGS[@]}" --head --fail --max-time 30 "$1" 2>/dev/null || true)
    [ -n "$hdrs" ] || return 1
    R_SIZE=$(printf '%s' "$hdrs" | grep -i '^content-length:' | tail -1 | tr -cd '0-9')
    [ -n "$R_SIZE" ] || R_SIZE=0
    R_ETAG=$(printf '%s' "$hdrs" | grep -i '^etag:' | tail -1 | tr -d '\r' | cut -d' ' -f2- || true)
    return 0
}
free_space_ok() {
    local need="$1" avail
    avail=$(free_bytes "$DATA_DIR") || return 0
    [ "$avail" -gt $(( need + MIN_FREE_BYTES )) ]
}

verify_file() {
    local path="$1" url_path="$2"
    local actual expected
    actual=$(sha256_of "$path")
    if [ ${#EXPECTED_HASH[@]} -gt 0 ]; then
        expected=$(lookup_expected "$url_path" || true)
        if [ -z "$expected" ]; then printf '%s' "$actual"; return 2; fi
        if [ "$actual" != "$expected" ]; then printf '%s' "$actual"; return 1; fi
    fi
    printf '%s' "$actual"
    return 0
}

quarantine() {
    local f="$1" name="$2" why="$3"
    local dest="${QUARANTINE_DIR}/${name}.$(date +%s)"
    mv -f "$f" "$dest" 2>/dev/null && chmod 400 "$dest" 2>/dev/null || rm -f "$f"
    log "WARN" "In Quarantäne: $name ($why)"
    return 0
}

# ─── Download ────────────────────────────────────────────────
download_file() {
    local url="$1"
    local url_path="${url%%\?*}"; url_path="${url_path#*://*/}"
    local filename; filename=$(sanitize_filename "$url")

    local final="${DOWNLOAD_DIR}/${filename}"
    # Unverifizierte Daten landen NIE direkt im Zielverzeichnis.
    local part="${STAGING_DIR}/${filename}.part"
    local metafile="${STAGING_DIR}/${filename}.meta"
    local checksum="${CHECKSUM_DIR}/${filename}.sha256"

    ST_FILE="$filename"; ST_CUR_BYTES=0; ST_CUR_SIZE=0; ST_SPEED=0; ST_ATTEMPT=0

    # Symlink-Schutz an jeder Schreibstelle
    for p in "$final" "$part" "$metafile" "$checksum"; do
        if [ -L "$p" ]; then
            log "ERROR" "Symlink entdeckt statt Datei: $p – übersprungen."
            ST_FAILED=$((ST_FAILED + 1)); return 1
        fi
    done

    if [ -f "$final" ] && [ -f "$checksum" ]; then
        # Bei 6 TB Bestand würde ein vollständiges Neu-Hashen jedes Laufs
        # Stunden kosten. Deshalb zuerst der schnelle Abgleich über Größe
        # und Änderungszeit; erst bei Abweichung (oder --verify-all) wird
        # wirklich gehasht.
        local done_rec="${DONE_DIR}/${filename}.done"
        local cur_size cur_mtime rec_size rec_mtime
        cur_size=$(file_size "$final"); cur_mtime=$(file_mtime "$final")
        rec_size=""; rec_mtime=""
        if [ "$VERIFY_ALL" -eq 0 ] && [ -f "$done_rec" ]; then
            read -r rec_size rec_mtime _ < "$done_rec" 2>/dev/null || true
        fi
        if [ -n "$rec_size" ] && [ "$rec_size" = "$cur_size" ] && \
           [ -n "$rec_mtime" ] && [ "$rec_mtime" = "$cur_mtime" ] && [ "$cur_mtime" != "0" ]; then
            ST_SKIPPED=$((ST_SKIPPED + 1))
            log "SKIP" "$filename (unverändert seit dem Download)"
            return 0
        fi
        if [ "$(sha256_of "$final")" = "$(cat "$checksum")" ]; then
            printf '%s %s %s\n' "$cur_size" "$cur_mtime" "verifiziert" > "$done_rec" 2>/dev/null || true
            ST_SKIPPED=$((ST_SKIPPED + 1))
            log "SKIP" "$filename (vorhanden, Prüfsumme stimmt)"
            return 0
        fi
        log "WARN" "$filename lokal verändert – lade neu."
        rm -f "$final" "$done_rec"
    fi

    if probe_remote "$url"; then
        ST_CUR_SIZE="$R_SIZE"
        local sig="${R_SIZE}|${R_ETAG}"
        if [ -f "$part" ] && [ "$(cat "$metafile" 2>/dev/null || true)" != "$sig" ]; then
            log "WARN" "Remote-Datei geändert – Teil-Download verworfen."
            rm -f "$part"
        fi
        printf '%s' "$sig" > "$metafile"
        if [ "$MAX_FILESIZE" -gt 0 ] && [ "$R_SIZE" -gt "$MAX_FILESIZE" ]; then
            ST_FAILED=$((ST_FAILED + 1))
            log "ERROR" "$filename überschreitet Größenlimit – übersprungen."
            rm -f "$part" "$metafile"; return 1
        fi
        free_space_ok "$R_SIZE" || die "Zu wenig freier Speicher in $DATA_DIR."
    else
        rm -f "$part" "$metafile"
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        log "INFO" "[dry-run] würde laden: $filename ($(human_bytes "${R_SIZE:-0}"))"
        return 0
    fi

    log "START" "Lade: $filename"
    local success=false stalled=0 rounds=0 before_bytes after_bytes
    local errfile="${STATE_DIR}/curl.err" effurl="${STATE_DIR}/curl.url"
    # Abbrüche zählen nur, wenn KEIN Fortschritt entstanden ist. Eine
    # 500-GB-Datei über eine wackelige Leitung wird so beliebig oft
    # fortgesetzt, solange sie tatsächlich wächst.
    while [ "$stalled" -lt "$MAX_ATTEMPTS" ]; do
        rounds=$((rounds + 1))
        if [ "$rounds" -gt "$MAX_RESUMES" ]; then
            log "ERROR" "$filename: $MAX_RESUMES Fortsetzungen ohne Abschluss – Abbruch."
            break
        fi
        before_bytes=$(file_size "$part")
        ST_ATTEMPT=$((stalled + 1))
        ST_PHASE="Download ${ST_INDEX}/${ST_TOTAL}"
        local dl_args=(--fail
                       --speed-limit "$STALL_BYTES" --speed-time "$STALL_SECONDS"
                       --retry 2 --retry-delay 10 -C -
                       -w '%{url_effective}')
        # Ein hartes --max-time würde große Dateien mitten im Transfer
        # abschneiden; stattdessen bricht curl nur bei echtem Stillstand ab.
        [ "$MAX_DOWNLOAD_SPEED" -gt 0 ] && dl_args+=(--limit-rate "$MAX_DOWNLOAD_SPEED")
        [ "$DOWNLOAD_TIMEOUT" -gt 0 ] && dl_args+=(--max-time "$DOWNLOAD_TIMEOUT")
        [ "$MAX_FILESIZE" -gt 0 ] && dl_args+=(--max-filesize "$MAX_FILESIZE")
        curl "${CURL_ARGS[@]}" "${dl_args[@]}" \
            -o "$part" "$url" >"$effurl" 2>"$errfile" &
        CURL_PID=$!
        local last_bytes=0 last_ts now ticks=0 aborted=""
        last_ts=$(date +%s)
        while kill -0 "$CURL_PID" 2>/dev/null; do
            ST_CUR_BYTES=$(file_size "$part")
            now=$(date +%s)
            if [ "$now" -gt "$last_ts" ]; then
                ST_SPEED=$(( (ST_CUR_BYTES - last_bytes) / (now - last_ts) ))
                [ "$ST_SPEED" -lt 0 ] && ST_SPEED=0
                last_bytes=$ST_CUR_BYTES; last_ts=$now
            fi
            # Eigener Wächter: ältere curl-Versionen erzwingen --max-filesize
            # nicht, wenn der Server keine Länge ankündigt (chunked).
            if [ "$MAX_FILESIZE" -gt 0 ] && [ "$ST_CUR_BYTES" -gt "$MAX_FILESIZE" ]; then
                aborted="groesse"; kill "$CURL_PID" 2>/dev/null || true; break
            fi
            ticks=$((ticks + 1))
            [ $((ticks % 300)) -eq 0 ] && lock_heartbeat
            if [ $((ticks % 50)) -eq 0 ]; then
                local fb; fb=$(free_bytes "$DATA_DIR" 2>/dev/null || true)
                if [ -n "$fb" ] && [ "$fb" -lt "$MIN_FREE_BYTES" ]; then
                    aborted="platz"; kill "$CURL_PID" 2>/dev/null || true; break
                fi
            fi
            render
            [ $((ticks % 5)) -eq 0 ] && write_status
            sleep 0.2
        done
        if [ -n "$aborted" ]; then
            wait "$CURL_PID" 2>/dev/null || true; CURL_PID=""
            rm -f "$part" "$metafile"
            ST_FAILED=$((ST_FAILED + 1))
            case "$aborted" in
                groesse) log "ERROR" "$filename überschreitet das Größenlimit – abgebrochen." ;;
                platz)   die "Freier Speicher unter dem Mindestwert – Abbruch." ;;
            esac
            return 1
        fi
        local rc=0; wait "$CURL_PID" || rc=$?; CURL_PID=""
        [ "$rc" -eq 0 ] && { success=true; break; }
        [ "$rc" -eq 2 ] && die "curl lehnt die Aufrufoptionen ab (Exit 2)."

        after_bytes=$(file_size "$part")
        if [ "$after_bytes" -gt "$before_bytes" ]; then
            stalled=0
            log "WARN" "Verbindung abgerissen bei $(human_bytes "$after_bytes") – setze fort."
        else
            stalled=$((stalled + 1))
            log "WARN" "Versuch $stalled/$MAX_ATTEMPTS ohne Fortschritt (curl $rc): $(tr -d '\r' < "$errfile" 2>/dev/null | tail -1)"
        fi
        case "$rc" in 33|36) rm -f "$part" ;; esac

        # Ist der Server ganz weg, wird gewartet statt Versuche zu verbrennen.
        if ! check_archive; then
            ST_PHASE="Server offline – warte"
            log "WARN" "Server nicht erreichbar – warte auf Rückkehr."
            wait_for_host
            stalled=0
        elif [ "$stalled" -lt "$MAX_ATTEMPTS" ]; then
            interruptible_sleep "$RETRY_BACKOFF"
        fi
    done
    rm -f "$errfile"

    if [ "$success" != true ]; then
        ST_FAILED=$((ST_FAILED + 1))
        log "ERROR" "Endgültig fehlgeschlagen: $filename"
        return 1
    fi

    # Eine Umleitung darf uns nicht unbemerkt auf einen fremden Server führen.
    local eff eff_host base_host
    eff=$(cat "$effurl" 2>/dev/null || true); rm -f "$effurl"
    if [ -n "$eff" ]; then
        eff_host="${eff#*://}"; eff_host="${eff_host%%/*}"; eff_host="${eff_host%%:*}"
        base_host="${BASE_URL#*://}"; base_host="${base_host%%/*}"; base_host="${base_host%%:*}"
        if [ "$eff_host" != "$base_host" ]; then
            ST_FAILED=$((ST_FAILED + 1))
            log "ERROR" "Umleitung auf fremden Host ($eff_host) – verworfen."
            rm -f "$part" "$metafile"; return 1
        fi
    fi

    local got; got=$(file_size "$part")
    if [ "$ST_CUR_SIZE" -gt 0 ] && [ "$got" -ne "$ST_CUR_SIZE" ]; then
        ST_FAILED=$((ST_FAILED + 1))
        log "ERROR" "$filename unvollständig ($got/$ST_CUR_SIZE Bytes) – verworfen."
        rm -f "$part"; return 1
    fi

    local hash vrc=0
    hash=$(verify_file "$part" "$url_path") || vrc=$?
    if [ "$vrc" -eq 1 ]; then
        ST_FAILED=$((ST_FAILED + 1))
        log "ERROR" "PRÜFSUMME FALSCH: $filename"
        quarantine "$part" "$filename" "Hash weicht ab"
        rm -f "$metafile"; return 1
    fi

    if [ "$vrc" -eq 2 ] && [ "$REQUIRE_HASH" -eq 1 ]; then
        ST_FAILED=$((ST_FAILED + 1))
        log "ERROR" "$filename: keine Quell-Prüfsumme vorhanden (--require-hash)."
        quarantine "$part" "$filename" "nicht verifizierbar"
        rm -f "$metafile"; return 1
    fi

    if ! magic_ok "$part" "$filename"; then
        ST_FAILED=$((ST_FAILED + 1))
        log "ERROR" "$filename: Inhalt passt nicht zur Endung (getarnte Datei?)"
        quarantine "$part" "$filename" "Typ passt nicht zur Endung"
        rm -f "$metafile"; return 1
    fi

    chmod 400 "$part" 2>/dev/null || true
    mv -f "$part" "$final"
    printf '%s' "$hash" > "$checksum"
    chmod 400 "$final" 2>/dev/null || true
    printf '%s %s %s\n' "$(file_size "$final")" "$(file_mtime "$final")" "verifiziert" \
        > "${DONE_DIR}/${filename}.done" 2>/dev/null || true
    rm -f "$metafile"

    ST_DONE=$((ST_DONE + 1)); ST_BYTES_SESSION=$((ST_BYTES_SESSION + got))
    if [ "$vrc" -eq 0 ] && [ ${#EXPECTED_HASH[@]} -gt 0 ]; then
        log "OK" "$filename – Prüfsumme der Quelle bestätigt."
    elif [ "$vrc" -eq 2 ]; then
        log "OK" "$filename gespeichert ($(human_bytes "$got")) – ohne Quell-Prüfsumme."
    else
        log "OK" "$filename gespeichert ($(human_bytes "$got"))."
    fi
    ST_CUR_BYTES=0; ST_CUR_SIZE=0; ST_SPEED=0
    return 0
}

# ─── Statusdatei für die Web-Oberfläche ──────────────────────
# Wird atomar geschrieben (temporär + umbenennen), damit die UI nie
# eine halb geschriebene Datei liest.
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    str="${str//$'\t'/\\t}"
    printf '%s' "$str"
}

write_status() {
    [ -n "${STATUS_FILE:-}" ] || return 0
    local tmp="${STATUS_FILE}.tmp.$$"
    local now; now=$(date +%s)
    {
        printf '{\n'
        printf '  "version": "%s",\n' "$VERSION"
        printf '  "pid": %s,\n' "$$"
        printf '  "started": %s,\n' "$START_TS"
        printf '  "now": %s,\n' "$now"
        printf '  "elapsed": %s,\n' "$((now - START_TS))"
        printf '  "phase": "%s",\n' "$(json_escape "$ST_PHASE")"
        printf '  "anon": {"status": "%s", "proxy": "%s", "exit_ip": "%s"},\n' \
            "$(json_escape "$ST_ANON")" "$(json_escape "${SOCKS_PROXY:-}")" "$(json_escape "$ST_EXIT_IP")"
        printf '  "connection": {"host": "%s", "host_code": "%s", "archive": "%s", "archive_code": "%s", "checksums": "%s", "data_dir": "%s"},\n' \
            "$ST_HOST" "$ST_HOST_CODE" "$ST_ARCHIVE" "$ST_ARCHIVE_CODE" \
            "$(json_escape "$ST_CHECKSUM_MODE")" "$(json_escape "$DATA_DIR")"
        printf '  "progress": {"index": %s, "total": %s, "done": %s, "skipped": %s, "failed": %s, "bytes": %s},\n' \
            "$ST_INDEX" "$ST_TOTAL" "$ST_DONE" "$ST_SKIPPED" "$ST_FAILED" "$ST_BYTES_SESSION"
        printf '  "current": {"file": "%s", "bytes": %s, "size": %s, "speed": %s, "attempt": %s, "max_attempts": %s},\n' \
            "$(json_escape "$ST_FILE")" "$ST_CUR_BYTES" "$ST_CUR_SIZE" "$ST_SPEED" "$ST_ATTEMPT" "$MAX_ATTEMPTS"
        printf '  "events": ['
        local n=${#LOG_TAIL[@]} start=$(( ${#LOG_TAIL[@]} - 25 )) i first=1
        [ "$start" -lt 0 ] && start=0
        for (( i = start; i < n; i++ )); do
            local e="${LOG_TAIL[$i]}" lvl rest tm txt
            lvl="${e%%|*}"; rest="${e#*|}"; tm="${rest%%|*}"; txt="${rest#*|}"
            [ "$first" -eq 1 ] || printf ','
            first=0
            printf '\n    {"level": "%s", "time": "%s", "text": "%s"}' \
                "$(json_escape "$lvl")" "$(json_escape "$tm")" "$(json_escape "$txt")"
        done
        printf '\n  ]\n}\n'
    } > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
    mv -f "$tmp" "$STATUS_FILE" 2>/dev/null || rm -f "$tmp"
    return 0
}

# ─── Formatierung ────────────────────────────────────────────
human_bytes() {
    local b=${1:-0}
    if   [ "$b" -ge 1099511627776 ]; then awk "BEGIN{printf \"%.2f TB\", $b/1099511627776}"
    elif [ "$b" -ge 1073741824 ]; then awk "BEGIN{printf \"%.2f GB\", $b/1073741824}"
    elif [ "$b" -ge 1048576 ];   then awk "BEGIN{printf \"%.1f MB\", $b/1048576}"
    elif [ "$b" -ge 1024 ];      then awk "BEGIN{printf \"%.1f KB\", $b/1024}"
    else printf '%s B' "$b"; fi
}
human_time() { local s=${1:-0}; printf '%02d:%02d:%02d' $((s/3600)) $(((s%3600)/60)) $((s%60)); }
truncate_mid() {
    local s="$1" max="$2"
    [ "$max" -lt 8 ] && max=8
    if [ "${#s}" -le "$max" ]; then printf '%s' "$s"; return 0; fi
    local keep=$(( (max - 1) / 2 ))
    printf '%s…%s' "${s:0:keep}" "${s: -keep}"
}

# ─── Dashboard ───────────────────────────────────────────────
SPIN_FRAMES='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; SPIN_I=0
dot() {
    case "$1" in
        up)   printf '%s●%s %s%-10s%s' "$C_GRN" "$C_RESET" "$C_GRN" "online"    "$C_RESET" ;;
        down) printf '%s●%s %s%-10s%s' "$C_RED" "$C_RESET" "$C_RED" "offline"   "$C_RESET" ;;
        *)    printf '%s●%s %s%-10s%s' "$C_GRY" "$C_RESET" "$C_GRY" "unbekannt" "$C_RESET" ;;
    esac
}
anon_dot() {
    case "$ST_ANON" in
        "Tor bestätigt")   printf '%s●%s %s%s%s' "$C_GRN" "$C_RESET" "$C_GRN" "$ST_ANON" "$C_RESET" ;;
        AUS*)              printf '%s●%s %s%s%s' "$C_RED" "$C_RESET" "$C_RED" "$ST_ANON" "$C_RESET" ;;
        ungeprüft)         printf '%s●%s %s%s%s' "$C_GRY" "$C_RESET" "$C_GRY" "$ST_ANON" "$C_RESET" ;;
        *)                 printf '%s●%s %s%s%s' "$C_YEL" "$C_RESET" "$C_YEL" "$ST_ANON" "$C_RESET" ;;
    esac
}
bar() {
    local cur=$1 total=$2 width=$3 filled=0
    if [ "$total" -gt 0 ]; then
        filled=$(( cur * width / total )); [ "$filled" -gt "$width" ] && filled=$width
    fi
    local empty=$(( width - filled )) i
    printf '%s' "$C_BLU"; i=0; while [ $i -lt $filled ]; do printf '█'; i=$((i+1)); done
    printf '%s%s' "$C_RESET" "$C_DIM"; i=0; while [ $i -lt $empty ]; do printf '░'; i=$((i+1)); done
    printf '%s' "$C_RESET"
}
hr() { local i=0; printf '%s' "$C_DIM"; while [ $i -lt "$1" ]; do printf '─'; i=$((i+1)); done; printf '%s' "$C_RESET"; }

render() {
    [ "$TUI" -eq 1 ] || return 0
    local cols rows
    cols=$(tput cols 2>/dev/null || echo 80); rows=$(tput lines 2>/dev/null || echo 24)
    [ "$cols" -gt 110 ] && cols=110; [ "$cols" -lt 62 ] && cols=62
    local w=$((cols - 4))
    SPIN_I=$(( (SPIN_I + 1) % 10 )); local spin="${SPIN_FRAMES:$SPIN_I:1}"
    local now elapsed; now=$(date +%s); elapsed=$((now - START_TS))

    tput cup 0 0 2>/dev/null || true

    printf '%s%s  SECURE DOWNLOADER%s %sv%s%s' "$C_B" "$C_MAG" "$C_RESET" "$C_DIM" "$VERSION" "$C_RESET"
    local pad=$((cols - 24 - ${#ST_PHASE} - 2)); [ "$pad" -lt 1 ] && pad=1
    printf '%*s%s%s %s%s\n' "$pad" '' "$C_YEL" "$spin" "$ST_PHASE" "$C_RESET"
    printf '  '; hr "$w"; printf '\n'

    printf '  %sANONYMITÄT%s\n' "$C_B" "$C_RESET"
    printf '    Status         %s\n' "$(anon_dot)"
    if [ -n "$SOCKS_PROXY" ]; then
        printf '    Proxy          %s%s%s  %sDNS über Proxy%s\n' "$C_MAG" "$SOCKS_PROXY" "$C_RESET" "$C_DIM" "$C_RESET"
    else
        printf '    Proxy          %skeiner – direkte Verbindung%s\n' "$C_RED" "$C_RESET"
    fi
    printf '    Sichtbare IP   %s%s%s\n' "$C_DIM" "$ST_EXIT_IP" "$C_RESET"
    printf '\n'

    printf '  %sVERBINDUNG%s\n' "$C_B" "$C_RESET"
    printf '    Ziel-Host      %s %sHTTP %s%s\n' "$(dot "$ST_HOST")"    "$C_DIM" "$ST_HOST_CODE" "$C_RESET"
    printf '    Archiv-Seite   %s %sHTTP %s%s\n' "$(dot "$ST_ARCHIVE")" "$C_DIM" "$ST_ARCHIVE_CODE" "$C_RESET"
    printf '    Integrität     %s%s%s\n' "$C_DIM" "$ST_CHECKSUM_MODE" "$C_RESET"
    printf '    Ablage         %s%s%s\n' "$C_DIM" "$(truncate_mid "$DATA_DIR" $((w - 19)))" "$C_RESET"
    printf '\n'

    printf '  %sFORTSCHRITT%s   %s%d/%d%s   Laufzeit %s%s%s\n' \
        "$C_B" "$C_RESET" "$C_B" "$ST_INDEX" "$ST_TOTAL" "$C_RESET" "$C_DIM" "$(human_time "$elapsed")" "$C_RESET"
    printf '    '; bar "$ST_INDEX" "$ST_TOTAL" $((w - 12))
    local pct=0; [ "$ST_TOTAL" -gt 0 ] && pct=$(( ST_INDEX * 100 / ST_TOTAL ))
    printf ' %s%3d%%%s\n' "$C_B" "$pct" "$C_RESET"
    printf '    %sok%s %-5d %sskip%s %-5d %sfehler%s %-5d %sgeladen%s %s\n' \
        "$C_GRN" "$C_RESET" "$ST_DONE" "$C_BLU" "$C_RESET" "$ST_SKIPPED" \
        "$C_RED" "$C_RESET" "$ST_FAILED" "$C_DIM" "$C_RESET" "$(human_bytes "$ST_BYTES_SESSION")"
    printf '\n'

    printf '  %sAKTUELL%s\n' "$C_B" "$C_RESET"
    printf '    %s%s%s' "$C_YEL" "$(truncate_mid "$ST_FILE" $((w - 4)))" "$C_RESET"
    tput el 2>/dev/null || true; printf '\n'
    if [ "$ST_CUR_SIZE" -gt 0 ]; then
        printf '    '; bar "$ST_CUR_BYTES" "$ST_CUR_SIZE" $((w - 12))
        printf ' %s%3d%%%s\n' "$C_B" $(( ST_CUR_BYTES * 100 / ST_CUR_SIZE )) "$C_RESET"
        printf '    %s%s / %s  •  %s/s  •  Versuch %d/%d%s' "$C_DIM" \
            "$(human_bytes "$ST_CUR_BYTES")" "$(human_bytes "$ST_CUR_SIZE")" \
            "$(human_bytes "$ST_SPEED")" "$ST_ATTEMPT" "$MAX_ATTEMPTS" "$C_RESET"
    else
        printf '%*s\n' "$((cols-1))" ''
        printf '    %s%s  •  %s/s%s' "$C_DIM" "$(human_bytes "$ST_CUR_BYTES")" "$(human_bytes "$ST_SPEED")" "$C_RESET"
    fi
    tput el 2>/dev/null || true; printf '\n\n'

    printf '  %sEREIGNISSE%s\n' "$C_B" "$C_RESET"
    local avail=$(( rows - 26 ))
    [ "$avail" -lt 3 ] && avail=3; [ "$avail" -gt 10 ] && avail=10
    local n=${#LOG_TAIL[@]} start=$(( ${#LOG_TAIL[@]} - avail )) i
    [ "$start" -lt 0 ] && start=0
    for (( i = start; i < n; i++ )); do
        local entry="${LOG_TAIL[$i]}" lvl rest tm txt col
        lvl="${entry%%|*}"; rest="${entry#*|}"; tm="${rest%%|*}"; txt="${rest#*|}"
        case "$lvl" in
            OK)    col="$C_GRN" ;; INFO) col="$C_GRN" ;; WARN) col="$C_YEL" ;;
            ERROR) col="$C_RED" ;; SKIP) col="$C_BLU" ;; START) col="$C_MAG" ;; *) col="$C_GRY" ;;
        esac
        printf '    %s%s%s %s%-5s%s %s' "$C_DIM" "$tm" "$C_RESET" "$col" "$lvl" "$C_RESET" \
            "$(truncate_mid "$txt" $((w - 18)))"
        tput el 2>/dev/null || true; printf '\n'
    done
    for (( i = n - start; i < avail; i++ )); do tput el 2>/dev/null || true; printf '\n'; done
    tput ed 2>/dev/null || true
    return 0
}

# ─── Hauptablauf ─────────────────────────────────────────────
main() {
    log "INFO" "Start v${VERSION} – Ablage: $DATA_DIR"
    [ "$HAVE_PCRE" -eq 0 ] && log "INFO" "Ohne PCRE-grep: nutze BusyBox-kompatiblen Parser."
    ST_PHASE="prüfe Anonymität"; render

    verify_anonymity
    wait_for_host
    log "INFO" "Verbunden (Host $ST_HOST_CODE / Archiv $ST_ARCHIVE_CODE)."

    load_expected_hashes
    build_url_list || die "URL-Liste nicht erstellbar."

    local url_file="${STATE_DIR}/urls.txt"
    if [ ! -s "$url_file" ]; then
        ST_PHASE="nichts zu tun"; log "WARN" "Keine URLs gefunden."; render; return 0
    fi
    ST_TOTAL=$(grep -c . "$url_file")

    while IFS= read -r target_url || [ -n "$target_url" ]; do
        [ -n "$target_url" ] || continue
        ST_INDEX=$((ST_INDEX + 1))
        log "INFO" "[$ST_INDEX/$ST_TOTAL] $(redact "$target_url")"
        if ! check_archive; then
            ST_PHASE="Ziel offline – pausiert"
            log "WARN" "Ziel nicht erreichbar. Pausiere..."
            wait_for_host
        fi
        download_file "$target_url" || true
        render
        # Kurze Pause, damit ein Lauf über tausende Dateien nicht als
        # Angriff gewertet wird. Getestet: ein öffentlicher Mirror hat uns
        # ohne diese Pause nach ~25 Anfragen ausgesperrt.
        [ "$REQUEST_DELAY" -gt 0 ] && interruptible_sleep "$REQUEST_DELAY"
    done < "$url_file"

    ST_PHASE="abgeschlossen"; ST_FILE="-"
    log "INFO" "Fertig: $ST_DONE geladen, $ST_SKIPPED übersprungen, $ST_FAILED fehlgeschlagen."
    render
    if [ "$TUI" -eq 1 ] && [ -t 0 ]; then
        printf '\n  %sTaste drücken zum Beenden...%s' "$C_DIM" "$C_RESET"
        read -r -n 1 -s || true
    fi
    return 0
}

main
