#!/usr/bin/env bash
# ==============================================================================
# SmartNest D3 - Web Hardening Verification Helper
# ==============================================================================
# This script validates the hardened web panel after D3 changes:
#   1. SQL injection bypass attempt fails
#   2. Password-only login redirects to TOTP instead of the dashboard
#   3. CSRF-protected endpoints reject missing tokens
#   4. Passwords in SQLite are stored as bcrypt hashes
#
# Usage:
#   chmod +x attacks/verify_web_hardening.sh
#   ./attacks/verify_web_hardening.sh
#
# Optional environment variables:
#   BASE_URL=http://localhost:5001
#   APP_CONTAINER=smartnest-web
# ==============================================================================

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:5001}"
APP_CONTAINER="${APP_CONTAINER:-smartnest-web}"
DB_PATH="${DB_PATH:-/tmp/smartnest.db}"
COOKIE_JAR="$(mktemp)"
TMP_HEADERS="$(mktemp)"
TMP_BODY="$(mktemp)"

cleanup() {
    rm -f "${COOKIE_JAR}" "${TMP_HEADERS}" "${TMP_BODY}"
}
trap cleanup EXIT

print_step() {
    echo ""
    echo "=============================================="
    echo "  $1"
    echo "=============================================="
}

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

fetch_login_page() {
    curl -fsSL -c "${COOKIE_JAR}" "${BASE_URL}/login"
}

extract_csrf_token() {
    sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -n 1
}

require_app() {
    print_step "Checking that the hardened web panel is reachable"
    fetch_login_page >/dev/null || fail "Could not reach ${BASE_URL}/login. Start the stack first."
    pass "Web panel is reachable at ${BASE_URL}"
}

test_sql_injection_bypass() {
    print_step "Checking that admin' -- no longer bypasses login"

    local token response
    token="$(fetch_login_page | extract_csrf_token)"
    [ -n "${token}" ] || fail "Could not extract login CSRF token."

    response="$(curl -fsSL -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" \
        --data-urlencode "username=admin' --" \
        --data-urlencode "password=irrelevant" \
        --data-urlencode "csrf_token=${token}" \
        "${BASE_URL}/login")"

    echo "${response}" | grep -q "Invalid credentials" \
        || fail "Injection payload did not return the expected invalid-credentials page."

    pass "SQL injection bypass attempt failed as expected"
}

test_totp_redirect() {
    print_step "Checking that password-only login now requires TOTP"

    local token location
    token="$(fetch_login_page | extract_csrf_token)"
    [ -n "${token}" ] || fail "Could not extract login CSRF token."

    curl -sS -D "${TMP_HEADERS}" -o "${TMP_BODY}" -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" \
        --data-urlencode "username=admin" \
        --data-urlencode "password=admin" \
        --data-urlencode "csrf_token=${token}" \
        "${BASE_URL}/login" >/dev/null

    location="$(awk 'BEGIN{IGNORECASE=1} /^Location:/ {print $2}' "${TMP_HEADERS}" | tr -d '\r' | tail -n 1)"
    [ "${location}" = "/verify-totp" ] \
        || fail "Expected login to redirect to /verify-totp, got '${location:-<none>}' instead."

    pass "Password-only login is redirected to /verify-totp"
}

test_command_csrf() {
    print_step "Checking that /command rejects requests without a CSRF token"

    local status_code
    status_code="$(curl -sS -o "${TMP_BODY}" -w '%{http_code}' \
        --data-urlencode "device=lock" \
        --data-urlencode "action=UNLOCK" \
        "${BASE_URL}/command")"

    [ "${status_code}" = "400" ] || fail "Expected HTTP 400 from /command without CSRF token, got ${status_code}."
    grep -q "Request Blocked" "${TMP_BODY}" || fail "Expected CSRF error page content was not returned."

    pass "CSRF protection blocked a forged /command request"
}

test_password_hash_storage() {
    print_step "Checking that passwords are stored as bcrypt hashes"

    command -v docker >/dev/null 2>&1 || {
        echo "[SKIP] docker not found, skipping DB hash inspection"
        return
    }

    local db_row
    db_row="$(docker exec "${APP_CONTAINER}" python -c "import sqlite3; conn = sqlite3.connect('${DB_PATH}'); row = conn.execute(\"SELECT username, password FROM users WHERE username='admin'\").fetchone(); print('|'.join(row) if row else ''); conn.close()")" \
        || fail "Could not inspect the database in container ${APP_CONTAINER}."

    [ -n "${db_row}" ] || fail "Could not find the admin user in the database."
    local stored_hash="${db_row#*|}"
    [[ "${stored_hash}" == \$2* ]] || fail "Admin password is not stored as a bcrypt hash."

    pass "Database stores the admin password as a bcrypt hash"
}

print_sqlmap_hint() {
    print_step "Suggested sqlmap command for your evidence screenshot"
    cat <<EOF
sqlmap -u "${BASE_URL}/login" \\
  --method POST \\
  --data="username=test&password=test&csrf_token=*" \\
  --csrf-token="csrf_token" \\
  --batch --flush-session --level=2 --risk=1

Expected outcome:
- sqlmap refreshes the CSRF token automatically
- it should report that the tested parameters do not appear injectable
EOF
}

print_totp_demo_hint() {
    print_step "Manual TOTP demo checkpoint"
    cat <<EOF
1. Open ${BASE_URL}/login
2. Sign in with admin / admin
3. On first login, scan the QR code in Google Authenticator / Microsoft Authenticator / Authy
4. Enter the 6-digit code to finish setup
5. Log out and sign in again
6. Capture the page that now asks for the 6-digit verification code
EOF
}

main() {
    require_app
    test_sql_injection_bypass
    test_totp_redirect
    test_command_csrf
    test_password_hash_storage
    print_sqlmap_hint
    print_totp_demo_hint

    echo ""
    echo "[DONE] Automated D3 checks completed."
}

main "$@"
