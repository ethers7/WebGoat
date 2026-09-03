#!/usr/bin/env bash
# WebGoat runtime regression — platform shell only, not lesson exploits.
# Usage: BASE_URL=http://127.0.0.1:8080/WebGoat ./e2e_apis.sh
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080/WebGoat}"
BASE_URL="${BASE_URL%/}"
OUT_DIR="${E2E_JUNIT_DIR:-test-results}"
COOKIE="$(mktemp)"
HDR="$(mktemp)"
BODY="$(mktemp)"
CASES="$(mktemp)"
export BODY
trap 'rm -f "$COOKIE" "$HDR" "$BODY" "$CASES"' EXIT INT TERM

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*"; exit 1; }

record() {
  name="$1"
  ok="$2"
  detail="${3:-}"
  printf '%s\t%s\t%s\n' "$name" "$ok" "$detail" >>"$CASES"
  if [ "$ok" = "1" ]; then
    say "ok $name${detail:+ -> $detail}"
  else
    say "FAIL $name${detail:+ -> $detail}"
  fi
}

http_code() {
  curl -sS "$@" -o "$BODY" -w '%{http_code}'
}

assert_code() {
  got="$1"
  want="$2"
  what="$3"
  case ",$want," in
    *",$got,"*) record "$what" 1 "$got" ;;
    *)
      say "body preview:"
      head -c 400 "$BODY"; echo
      record "$what" 0 "expected [$want] got $got"
      ;;
  esac
}

json_ok() {
  python3 -c "$1"
}

write_junit() {
  mkdir -p "$OUT_DIR"
  python3 - "$CASES" "$OUT_DIR/e2e-apis.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
cases_path, out_path = sys.argv[1], sys.argv[2]
rows = []
with open(cases_path) as f:
    for line in f:
        name, ok, detail = line.rstrip("\n").split("\t", 2)
        rows.append((name, ok == "1", detail))
fail_n = sum(1 for _, ok, _ in rows if not ok)
ts = ET.Element("testsuite", name="webgoat-e2e-apis", tests=str(len(rows)), failures=str(fail_n))
for name, ok, detail in rows:
    tc = ET.SubElement(ts, "testcase", name=name, classname="harness.e2e_apis")
    if not ok:
        ET.SubElement(tc, "failure", message=escape(detail or "failed")).text = detail
ET.ElementTree(ts).write(out_path, encoding="utf-8", xml_declaration=True)
print(f"junit {out_path} tests={len(rows)} failures={fail_n}")
sys.exit(1 if fail_n else 0)
PY
}

say "==> Actuator health"
code="$(http_code "$BASE_URL/actuator/health")"
assert_code "$code" "200" "GET /actuator/health"
if grep -q '"status"[[:space:]]*:[[:space:]]*"UP"' "$BODY"; then
  record "actuator_health_UP" 1
else
  record "actuator_health_UP" 0 "status not UP"
fi

say "==> Public pages"
code="$(http_code "$BASE_URL/login")"
assert_code "$code" "200" "GET /login"
if grep -qi 'username' "$BODY"; then
  record "login_form" 1
else
  record "login_form" 0 "login page missing username field"
fi

code="$(http_code "$BASE_URL/registration")"
assert_code "$code" "200" "GET /registration"

# UserForm: username [a-z0-9-] 6-45; password 6-10
USER="e2e$(date +%s | tr -cd '0-9' | tail -c 8)"
PASS='test1234'
say "==> Register $USER"
: > "$COOKIE"
code="$(curl -sS -c "$COOKIE" -b "$COOKIE" -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE_URL/register.mvc" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "matchingPassword=$PASS" \
  --data-urlencode "agree=true" \
  -D "$HDR")"
assert_code "$code" "302" "POST /register.mvc"
if grep -qi '^Location:.*attack' "$HDR"; then
  record "register_redirect_attack" 1
else
  record "register_redirect_attack" 0 "Location missing /attack"
  cat "$HDR" | head -20
fi

say "==> Authenticated platform APIs"
code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "200" "GET /service/lessonmenu.mvc (authed)"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d, list) and len(d) >= 5; print("menu_categories", len(d))'; then
  record "lessonmenu_shape" 1
else
  record "lessonmenu_shape" 0
fi

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/start.mvc")"
assert_code "$code" "200" "GET /start.mvc"

code="$(http_code -c "$COOKIE" -b "$COOKIE" -D "$HDR" "$BASE_URL/welcome.mvc")"
assert_code "$code" "200,302" "GET /welcome.mvc"

code="$(http_code -c "$COOKIE" -b "$COOKIE" -D "$HDR" "$BASE_URL/attack")"
assert_code "$code" "200,302" "GET /attack"

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/labels.mvc")"
assert_code "$code" "200" "GET /service/labels.mvc"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d, dict) and len(d) >= 20; print("labels", len(d))'; then
  record "labels_shape" 1
else
  record "labels_shape" 0
fi

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/reportcard.mvc")"
assert_code "$code" "200" "GET /service/reportcard.mvc"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert d.get("totalNumberOfLessons",0) >= 5; print("lessons", d["totalNumberOfLessons"])'; then
  record "reportcard_shape" 1
else
  record "reportcard_shape" 0
fi

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/hint.mvc")"
assert_code "$code" "200" "GET /service/hint.mvc"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d, list) and len(d) >= 1; print("hints", len(d))'; then
  record "hints_shape" 1
else
  record "hints_shape" 0
fi

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/lessoninfo.mvc/WebGoatIntroduction")"
assert_code "$code" "200" "GET /service/lessoninfo.mvc/WebGoatIntroduction"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert "lessonTitle" in d or "title" in d or d; print(list(d)[:6] if isinstance(d,dict) else type(d))'; then
  record "lessoninfo_shape" 1
else
  record "lessoninfo_shape" 0
fi

say "==> Logout + form login"
curl -sS -c "$COOKIE" -b "$COOKIE" -o /dev/null "$BASE_URL/logout" || true
rm -f "$COOKIE"
: > "$COOKIE"
code="$(curl -sS -c "$COOKIE" -b "$COOKIE" -o "$BODY" -w '%{http_code}' \
  -X POST "$BASE_URL/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  -D "$HDR")"
assert_code "$code" "302" "POST /login"
if grep -qi '^Location:.*welcome\.mvc' "$HDR"; then
  record "login_redirect_welcome" 1
else
  record "login_redirect_welcome" 0 "Location missing welcome.mvc"
fi

code="$(http_code -c "$COOKIE" -b "$COOKIE" "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "200" "GET /service/lessonmenu.mvc after re-login"
if json_ok 'import json,os; d=json.load(open(os.environ["BODY"])); assert isinstance(d, list) and len(d) >= 5'; then
  record "relogin_menu_shape" 1
else
  record "relogin_menu_shape" 0
fi

say "==> Unauthenticated menu must not return lesson JSON"
code="$(http_code "$BASE_URL/service/lessonmenu.mvc")"
assert_code "$code" "302,401,403" "GET /service/lessonmenu.mvc (anon)"

say "==> Write JUnit"
write_junit
say "==> Runtime API regression PASSED"
