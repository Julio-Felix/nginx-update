#!/usr/bin/env bash
# NGINX2Root (CVE-2026-123007 and related): log status, upgrade, restart and verify.
#
# A host counts as patched when EITHER:
#   - upstream version >= 1.30.7 (stable) / 1.31.9 (mainline), OR
#   - the distro package changelog lists the backported CVE fixes
#     (Ubuntu/Debian/RHEL keep the old version number, e.g. 1.24.0).
# It must also be running the new binary (a reload is not enough, a restart is).
#
# Usage: sudo bash nginx-update.sh      Log: /var/log/nginx-update.log
set -u

LOG="${LOG:-/var/log/nginx-update.log}"
CVES="CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

if ! command -v nginx >/dev/null 2>&1; then
  log "nginx not found on $(hostname); nothing to do."
  exit 0
fi

nginx_ver() { nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p'; }

# vge A B: true if version A >= version B
vge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

upstream_fixed() {
  local v="$1"
  [ -n "$v" ] || return 1
  if vge "$v" "1.31.0"; then vge "$v" "1.31.9"
  elif vge "$v" "1.30.0"; then vge "$v" "1.30.7"
  else return 1; fi
}

pkg_changelog() {
  if command -v dpkg >/dev/null 2>&1 && dpkg -s nginx >/dev/null 2>&1; then
    { zcat -f /usr/share/doc/nginx*/changelog.Debian.gz 2>/dev/null
      apt-get changelog nginx 2>/dev/null; }
  elif command -v rpm >/dev/null 2>&1; then
    rpm -q --changelog nginx 2>/dev/null
  fi
}

# Prints CVEs missing from the package changelog; empty output means all present.
missing_cves() {
  local cl c out=""
  cl="$(pkg_changelog)"
  for c in $CVES; do
    echo "$cl" | grep -q "$c" || out="$out $c"
  done
  echo "${out# }"
}

# Returns 0 if the running master process uses the current binary.
running_current() {
  local pid bin start mtime
  pid="$(cat /run/nginx.pid 2>/dev/null)"
  if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
    log "nginx master process not running"
    return 1
  fi
  if readlink "/proc/$pid/exe" 2>/dev/null | grep -q '(deleted)'; then
    return 1
  fi
  bin="$(readlink -f "$(command -v nginx)")"
  start="$(date -d "$(ps -o lstart= -p "$pid")" +%s 2>/dev/null || echo 0)"
  mtime="$(stat -c %Y "$bin" 2>/dev/null || echo 0)"
  [ "$start" -ge "$mtime" ]
}

report() {
  local v pkg
  v="$(nginx_ver)"
  pkg="$(dpkg-query -W -f='${Version}' nginx 2>/dev/null || rpm -q nginx 2>/dev/null || echo n/a)"
  log "$1: nginx $v | package $pkg"
  if running_current; then log "$1: running process uses the current binary"
  else log "$1: running process is OLD (needs restart)"; fi
}

log "===== $(hostname) ====="
report "BEFORE"

if command -v apt-get >/dev/null 2>&1; then
  log "Using apt"
  apt-get update 2>&1 | tee -a "$LOG"
  DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y nginx 2>&1 | tee -a "$LOG"
elif command -v dnf >/dev/null 2>&1; then
  log "Using dnf"
  dnf upgrade -y nginx 2>&1 | tee -a "$LOG"
elif command -v yum >/dev/null 2>&1; then
  log "Using yum"
  yum update -y nginx 2>&1 | tee -a "$LOG"
elif command -v apk >/dev/null 2>&1; then
  log "Using apk"
  apk update 2>&1 | tee -a "$LOG"
  apk upgrade nginx 2>&1 | tee -a "$LOG"
elif command -v zypper >/dev/null 2>&1; then
  log "Using zypper"
  zypper --non-interactive update nginx 2>&1 | tee -a "$LOG"
else
  log "No supported package manager found; upgrade manually."
fi

# Restart only if the config is valid; a reload does not replace the binary.
if nginx -t >>"$LOG" 2>&1; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart nginx 2>&1 | tee -a "$LOG"
  else
    service nginx restart 2>&1 | tee -a "$LOG"
  fi
  log "nginx restarted"
else
  log "nginx -t FAILED; not restarting. Fix the config first."
fi

report "AFTER"

VER="$(nginx_ver)"
MISSING="$(missing_cves)"
if upstream_fixed "$VER"; then
  CODE_OK=1; WHY="upstream version $VER is fixed"
elif [ -z "$MISSING" ]; then
  CODE_OK=1; WHY="distro package has the backported fixes"
else
  CODE_OK=0; WHY="version $VER is not fixed upstream and package changelog lacks: $MISSING"
fi

if [ "$CODE_OK" -eq 1 ] && running_current; then
  log "RESULT: OK - patched ($WHY) and running the new binary"
  RC=0
elif [ "$CODE_OK" -eq 1 ]; then
  log "RESULT: PATCHED BUT NOT RUNNING - restart nginx manually (systemctl restart nginx)"
  RC=3
else
  log "RESULT: VULNERABLE - $WHY. Wait for the distro patch, use the nginx.org repo (1.30.7+), or disable HTTP/2 as a stopgap."
  RC=4
fi

# Kernel SCTP flaw chained with NGINX2Root (no kernel patch yet)
if lsmod 2>/dev/null | grep -q '^sctp'; then
  log "WARNING: sctp kernel module is loaded. If unused: printf 'install sctp /bin/true\nblacklist sctp\n' > /etc/modprobe.d/disable-sctp.conf; modprobe -r sctp"
fi

exit "$RC"
