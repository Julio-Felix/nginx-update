#!/usr/bin/env bash
# Logs the NGINX version and tries to upgrade it (NGINX2Root, CVE-2026-123007 and related).
# Fixed versions: 1.30.7 (stable) / 1.31.9 (mainline). Run as root.
set -u

LOG="${LOG:-/var/log/nginx-update.log}"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

if ! command -v nginx >/dev/null 2>&1; then
  log "nginx not found on $(hostname); nothing to do."
  exit 0
fi

ver() { nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9.]*\).*#\1#p'; }

BEFORE="$(ver)"
log "Host: $(hostname) | nginx version BEFORE: ${BEFORE:-unknown}"

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
  exit 2
fi

# A reload does not replace the running binary, so restart is required.
if nginx -t >>"$LOG" 2>&1; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart nginx 2>&1 | tee -a "$LOG"
  else
    service nginx restart 2>&1 | tee -a "$LOG"
  fi
  log "nginx restarted"
else
  log "nginx -t FAILED; not restarting. Check config."
fi

AFTER="$(ver)"
log "nginx version AFTER: ${AFTER:-unknown}"

# Pass if AFTER >= 1.30.7 on stable (1.30.x) or >= 1.31.9 on mainline (1.31+).
ok=0
if [ -n "$AFTER" ]; then
  if [ "$(printf '%s\n%s\n' "1.30.7" "$AFTER" | sort -V | head -n1)" = "1.30.7" ] &&
     [ "${AFTER%.*}" != "1.31" ]; then ok=1; fi
  if [ "$(printf '%s\n%s\n' "1.31.9" "$AFTER" | sort -V | head -n1)" = "1.31.9" ]; then ok=1; fi
fi
if [ "$ok" -eq 1 ]; then
  log "RESULT: patched version"
else
  log "RESULT: STILL VULNERABLE (need 1.30.7 stable / 1.31.9 mainline). Repo may not have the fix yet; consider nginx.org repo or HTTP/2 mitigation."
fi
