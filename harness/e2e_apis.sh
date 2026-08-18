#!/usr/bin/env bash
# WebGoat runtime regression — assert core APIs keep working after remedia.
# Usage: BASE_URL=http://127.0.0.1:8080/WebGoat ./e2e_apis.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080/WebGoat}"
BASE_URL="${BASE_URL%/}"
COOKIE="$(mktemp)"
HDR="$(mktemp)"
trap 'rm -f "$COOKIE" "$HDR"' EXIT INT TERM

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*"; exit 1; }

http_code() {
  # args: curl args...  -> prints status code only; body on stdout of caller via -o
  curl -sS "$@" -o /tmp/wg-e2e-body -w '%{http_code}'
}

wait_health() {
  say "==> Wait actuator health at $BASE_URL/actuator/health"
  i=0
  while [ "$i" -lt 90 ]; do
    code="$(curl -sS -o /tmp/wg-health.json -w '%{http_code}' "$BASE_URL/actuator/health" || true)"
    if [ "$code" = "200" ] && grep -q '"status"[[:space:]]*:[[:space:]]*"UP"' /tmp/wg-health.json 2>/dev/null; then
      say "health_ok"
      return 0
    fi
    i=$((i + 1))
    sleep 2
  done
  fail "health not UP after wait"
}

assert_code() {
  got="$1"
  want="$2"
  what="$3"
  case ",$want," in
    *",$got,"*) say "ok $what -> $got" ;;
    *) fail "$what expected one of [$want], got $got" ;;
  esac
}

wait_health

say "==> Public pages"
code="$(http_code "$BASE_URL/login")"
assert_code "$code" "200" "GET /login"

code="$(http_code "$BASE_URL/registration")"
assert_code "$code" "200" "GET /registration"

USER="e2e$(date +%s | tail -c 7)"
PASS='test1234'
say "==> Register $USER"
code="$(curl -sS -c "$COOKIE" -b "$COOKIE" -o /tmp/wg-e2e-body -w '%{http_code}' \
  -X POST "$BASE_URL/register.mvc" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "matchingPassword=$PASS" \
  --data-urlencode "agree=true" \
  -D "$HDR")"
assert_code "$code" "302" "POST /register.mvc"
grep -qi '^Location:.*attack' "$HDR" || fail "register Location should include /attack"
say "register_redirect_ok"

say "==> Lesson menu after register (session)"
code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "200" "GET /service/lessonmenu.mvc (authed)"
python3 - <<'PY'
import json,sys
d=json.load(open("/tmp/wg-e2e-body"))
assert isinstance(d, list) and len(d) >= 5, (type(d), d[:1] if isinstance(d,list) else d)
print(f"menu_categories={len(d)}")
PY

say "==> start.mvc"
code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/start.mvc")"
assert_code "$code" "200" "GET /start.mvc"

say "==> Logout + form login (same credentials must still work)"
curl -sS -c "$COOKIE" -b "$COOKIE" -o /dev/null "$BASE_URL/logout" || true
rm -f "$COOKIE"
: > "$COOKIE"
code="$(curl -sS -c "$COOKIE" -b "$COOKIE" -o /tmp/wg-e2e-body -w '%{http_code}' \
  -X POST "$BASE_URL/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  -D "$HDR")"
assert_code "$code" "302" "POST /login"
grep -qi '^Location:.*welcome\.mvc' "$HDR" || fail "login Location should be welcome.mvc"

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "200" "GET /service/lessonmenu.mvc after re-login"
python3 - <<'PY'
import json
d=json.load(open("/tmp/wg-e2e-body"))
assert isinstance(d, list) and len(d) >= 5
print(f"relogin_menu_categories={len(d)}")
PY

say "==> Unauthenticated menu must not return lesson JSON"
code="$(http_code "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "302,401,403" "GET /service/lessonmenu.mvc (anon)"

say "==> Runtime API regression PASSED"
