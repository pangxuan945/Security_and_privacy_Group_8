"""
SmartNest Web Management Panel
!! INTENTIONALLY VULNERABLE - for security coursework attack demonstration !!

Vulnerabilities planted:
1. SQL Injection on login form
2. Default credentials (admin/admin)
3. No CSRF protection
4. No rate limiting
5. Sensitive data in plain HTML comments
"""

import json
import os
import sqlite3
import time
import threading
import base64
import io
from datetime import datetime
import ssl

import bcrypt
from flask import Flask, render_template_string, request, redirect, session, jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError
import paho.mqtt.client as mqtt
import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Intentionally weak
csrf = CSRFProtect(app)

BROKER_HOST = os.getenv("MQTT_BROKER", "broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", 8883))

CA_CERT     = os.getenv("CA_CERT",     "/certs/ca.crt")
CLIENT_CERT = os.getenv("CLIENT_CERT", "/certs/web_panel.crt")
CLIENT_KEY  = os.getenv("CLIENT_KEY",  "/certs/web_panel.key")

# ──────────────────────────────────────────────
# In-memory device state (updated via MQTT)
# ──────────────────────────────────────────────

device_states = {}
event_log = []
alert_log = []
MAX_ALERTS = 20
MAX_EVENTS = 100

# ──────────────────────────────────────────────
# SQLite Setup (INTENTIONALLY VULNERABLE)
# ──────────────────────────────────────────────

DB_PATH = "/tmp/smartnest.db"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def is_bcrypt_hash(password: str) -> bool:
    return isinstance(password, str) and password.startswith("$2")


def verify_password(password: str, stored_password: str) -> bool:
    if not stored_password or not is_bcrypt_hash(stored_password):
        return False

    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8"))
    except ValueError:
        return False


def build_totp_qr_data_uri(username: str, secret: str) -> str:
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="SmartNest",
    )
    qr_image = qrcode.make(provisioning_uri, image_factory=SvgPathImage)
    buffer = io.BytesIO()
    qr_image.save(buffer)
    encoded_svg = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded_svg}"


def clear_pending_login():
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("pending_role", None)
    session.pop("pending_totp_secret", None)
    session.pop("pending_totp_setup", None)


def render_totp_page(error=None):
    pending_username = session.get("pending_username", "")
    pending_secret = session.get("pending_totp_secret", "")
    is_setup = bool(session.get("pending_totp_setup"))
    qr_code_data_uri = None

    if is_setup and pending_username and pending_secret:
        qr_code_data_uri = build_totp_qr_data_uri(pending_username, pending_secret)

    title = "Set Up Two-Factor Authentication" if is_setup else "Two-Factor Verification"
    subtitle = (
        "Scan the QR code in your authenticator app, then enter the current 6-digit code."
        if is_setup else
        "Enter the current 6-digit code from your authenticator app to finish signing in."
    )

    return render_template_string(
        TOTP_PAGE,
        error=error,
        title=title,
        subtitle=subtitle,
        username=pending_username,
        qr_code_data_uri=qr_code_data_uri,
        manual_secret=pending_secret if is_setup else None,
        is_setup=is_setup,
    )


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    """)

    c.execute("PRAGMA table_info(users)")
    existing_columns = {row[1] for row in c.fetchall()}
    if "totp_secret" not in existing_columns:
        c.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")

    # Migrate any legacy plaintext passwords to bcrypt hashes.
    c.execute("SELECT id, password FROM users")
    for user_id, stored_password in c.fetchall():
        if stored_password and not is_bcrypt_hash(stored_password):
            c.execute(
                "UPDATE users SET password=? WHERE id=?",
                (hash_password(stored_password), user_id),
            )

    default_users = [
        ("admin", "admin", "admin"),
        ("guest", "guest123", "viewer"),
    ]
    for username, plain_password, role in default_users:
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        if c.fetchone() is None:
            c.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(plain_password), role),
            )

    conn.commit()
    conn.close()


init_db()


# ──────────────────────────────────────────────
# MQTT Client for Web Panel
# ──────────────────────────────────────────────

mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="web_panel")


def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[WEB-MQTT] Connected to broker")
        client.subscribe("home/#")  # Subscribe to everything
    else:
        print(f"[WEB-MQTT] Connection failed: {rc}")


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        topic = msg.topic

        # Update device state
        if "/status" in topic:
            device_id = payload.get("device_id", "unknown")
            device_states[device_id] = {
                "topic": topic,
                "data": payload,
                "last_seen": datetime.now().strftime("%H:%M:%S"),
            }

        # Capture IDS alerts
        if topic == "home/alert":
            alert_log.insert(0, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "data": payload,
            })
            if len(alert_log) > MAX_ALERTS:
                 alert_log.pop()

        # Log events
        if "/event" in topic:
            event_log.insert(0, {
                "time": datetime.now().strftime("%H:%M:%S"),
                "topic": topic,
                "data": payload,
            })
            if len(event_log) > MAX_EVENTS:
                event_log.pop()

    except json.JSONDecodeError:
        pass


mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message


def mqtt_connect():
    mqtt_client.tls_set(
        ca_certs=CA_CERT,
        certfile=CLIENT_CERT,
        keyfile=CLIENT_KEY,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )
    mqtt_client.tls_insecure_set(False)

    while True:
        try:
            mqtt_client.connect(BROKER_HOST, BROKER_PORT, 60)
            mqtt_client.loop_start()
            print("[WEB-MQTT] Connected to broker over TLS")
            return
        except Exception as e:
            print(f"[WEB-MQTT] Waiting for broker... ({e})")
            time.sleep(3)


# ──────────────────────────────────────────────
# HTML Templates (inline for simplicity)
# ──────────────────────────────────────────────

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SmartNest - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-box { background: #1e293b; padding: 2.5rem; border-radius: 12px; width: 360px;
                     box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
        .login-box h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #38bdf8; }
        .login-box p.sub { color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }
        input { width: 100%; padding: 0.7rem 1rem; margin-bottom: 1rem; border: 1px solid #334155;
                border-radius: 8px; background: #0f172a; color: #e2e8f0; font-size: 0.95rem; }
        input:focus { outline: none; border-color: #38bdf8; }
        button { width: 100%; padding: 0.75rem; background: #38bdf8; color: #0f172a; border: none;
                 border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
        button:hover { background: #7dd3fc; }
        .error { color: #f87171; font-size: 0.85rem; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <!-- TODO: remove default creds before production - admin/admin -->
    <div class="login-box">
        <h1>SmartNest</h1>
        <p class="sub">Smart Home Management Panel</p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

TOTP_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SmartNest - Two-Factor Authentication</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .auth-box { background: #1e293b; padding: 2.5rem; border-radius: 12px; width: 420px;
                    box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
        h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #38bdf8; }
        .sub { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; margin-bottom: 1.5rem; }
        .error { color: #f87171; font-size: 0.85rem; margin-bottom: 1rem; }
        .hint { color: #cbd5e1; font-size: 0.85rem; line-height: 1.5; margin-top: 1rem; }
        .qr-box { display: flex; justify-content: center; background: #f8fafc; border-radius: 12px;
                  padding: 1rem; margin-bottom: 1rem; }
        .qr-box img { width: 220px; height: 220px; }
        .secret { display: block; margin-top: 0.75rem; background: #0f172a; border: 1px solid #334155;
                  padding: 0.8rem; border-radius: 8px; color: #7dd3fc; font-size: 0.9rem;
                  word-break: break-all; }
        input { width: 100%; padding: 0.7rem 1rem; margin: 1rem 0; border: 1px solid #334155;
                border-radius: 8px; background: #0f172a; color: #e2e8f0; font-size: 0.95rem; }
        input:focus { outline: none; border-color: #38bdf8; }
        button { width: 100%; padding: 0.75rem; background: #38bdf8; color: #0f172a; border: none;
                 border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
        button:hover { background: #7dd3fc; }
    </style>
</head>
<body>
    <div class="auth-box">
        <h1>{{ title }}</h1>
        <p class="sub">{{ subtitle }}</p>
        <p class="sub">Account: {{ username }}</p>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}

        {% if qr_code_data_uri %}
        <div class="qr-box">
            <img src="{{ qr_code_data_uri }}" alt="TOTP QR code">
        </div>
        <p class="hint">If scanning is unavailable, enter this secret manually in your authenticator app:</p>
        <code class="secret">{{ manual_secret }}</code>
        {% endif %}

        <form method="POST" action="/verify-totp">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="text" name="code" placeholder="Enter 6-digit code" inputmode="numeric"
                   pattern="[0-9]{6}" maxlength="6" required>
            <button type="submit">{% if is_setup %}Verify and Enable{% else %}Verify and Sign In{% endif %}</button>
        </form>
    </div>
</body>
</html>
"""

CSRF_ERROR_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SmartNest - Request Blocked</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
               display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .error-box { background: #1e293b; padding: 2.5rem; border-radius: 12px; width: 420px;
                     box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
        h1 { font-size: 1.5rem; margin-bottom: 0.75rem; color: #f87171; }
        p { color: #cbd5e1; line-height: 1.6; margin-bottom: 0.75rem; }
        a { color: #38bdf8; text-decoration: none; }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>Request Blocked</h1>
        <p>{{ reason }}</p>
        <p>Please go back to the SmartNest page and try again.</p>
        <p><a href="/login">Return to login</a></p>
    </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SmartNest Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; }
        .topbar { background: #1e293b; padding: 1rem 2rem; display: flex; justify-content: space-between;
                  align-items: center; border-bottom: 1px solid #334155; }
        .topbar h1 { font-size: 1.25rem; color: #38bdf8; }
        .topbar .user { color: #94a3b8; font-size: 0.85rem; }
        .topbar a { color: #f87171; text-decoration: none; margin-left: 1rem; font-size: 0.85rem; }
        .container { max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; }
        .card { background: #1e293b; border-radius: 12px; padding: 1.5rem; border: 1px solid #334155; }
        .card h2 { font-size: 1.1rem; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .card .indicator { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .card .indicator.on { background: #4ade80; }
        .card .indicator.off { background: #64748b; }

        .status-row { display: flex; justify-content: space-between; padding: 0.4rem 0;
                      border-bottom: 1px solid #1e293b; font-size: 0.9rem; }
        .status-row .label { color: #94a3b8; }
        .status-row .value { color: #e2e8f0; font-weight: 500; }

        .actions { margin-top: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .btn { padding: 0.5rem 1rem; border: none; border-radius: 6px; cursor: pointer;
               font-size: 0.85rem; font-weight: 500; }
        .btn-primary { background: #38bdf8; color: #0f172a; }
        .btn-danger { background: #f87171; color: #0f172a; }
        .btn-secondary { background: #334155; color: #e2e8f0; }
        .btn:hover { opacity: 0.85; }

        .event-log { margin-top: 2rem; }
        .event-log h2 { margin-bottom: 1rem; }
        .event-item { background: #1e293b; padding: 0.75rem 1rem; border-radius: 8px;
                      margin-bottom: 0.5rem; font-size: 0.85rem; border-left: 3px solid #334155; }
        .event-item.high { border-left-color: #f87171; }
        .event-item.medium { border-left-color: #fbbf24; }
        .event-item.low { border-left-color: #4ade80; }
        .event-time { color: #64748b; font-size: 0.8rem; }

        .slider-group { margin-top: 0.5rem; display: flex; align-items: center; gap: 0.75rem; }
        .slider-group input[type=range] { flex: 1; }
        .slider-group span { min-width: 36px; text-align: right; font-size: 0.85rem; }

        .refresh-note { text-align: center; color: #475569; font-size: 0.8rem; margin-top: 2rem; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>SmartNest Dashboard</h1>
        <div>
            <span class="user">Logged in as: {{ username }} ({{ role }})</span>
            <a href="/logout">Logout</a>
        </div>
    </div>

    <div class="container">
        {% if alerts %}
        <div style="background: #991b1b; border: 1px solid #f87171; border-radius: 8px;
                    padding: 1rem 1.5rem; margin-bottom: 1.5rem;">
            <h3 style="color: #fca5a5; margin-bottom: 0.5rem; font-size: 1rem;">
                IDS Alert — Anomaly Detected
            </h3>
            {% for alert in alerts %}
            <div style="color: #fecaca; font-size: 0.85rem; padding: 0.3rem 0;
                        border-bottom: 1px solid rgba(248,113,113,0.2);">
                <span style="color: #f87171; font-weight: 600;">[{{ alert.data.type }}]</span>
                {{ alert.data.detail }}
                <span style="color: #fb923c; font-size: 0.8rem; margin-left: 0.5rem;">
                    {{ alert.time }}
                </span>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        <div class="grid">

            <!-- Smart Lock Card -->
            <div class="card">
                <h2>
                    <span class="indicator {{ 'on' if lock.state == 'LOCKED' else 'off' }}"></span>
                    Smart Lock
                </h2>
                <div class="status-row"><span class="label">State</span>
                    <span class="value">{{ lock.state }}</span></div>
                <div class="status-row"><span class="label">Battery</span>
                    <span class="value">{{ lock.battery }}%</span></div>
                <div class="status-row"><span class="label">Last user</span>
                    <span class="value">{{ lock.last_user }}</span></div>
                <div class="status-row"><span class="label">Method</span>
                    <span class="value">{{ lock.method }}</span></div>
                <div class="actions">
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="lock">
                        <input type="hidden" name="action" value="UNLOCK">
                        <button class="btn btn-danger" type="submit">Unlock</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="lock">
                        <input type="hidden" name="action" value="LOCK">
                        <button class="btn btn-primary" type="submit">Lock</button>
                    </form>
                </div>
            </div>

            <!-- Smart Light Card -->
            <div class="card">
                <h2>
                    <span class="indicator {{ 'on' if light.power == 'ON' else 'off' }}"></span>
                    Smart Light
                </h2>
                <div class="status-row"><span class="label">Power</span>
                    <span class="value">{{ light.power }}</span></div>
                <div class="status-row"><span class="label">Brightness</span>
                    <span class="value">{{ light.brightness }}%</span></div>
                <div class="status-row"><span class="label">Color temp</span>
                    <span class="value">{{ light.color_temp }}K</span></div>
                <div class="status-row"><span class="label">Mode</span>
                    <span class="value">{{ light.mode }}</span></div>
                <div class="actions">
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="light">
                        <input type="hidden" name="action" value="ON">
                        <button class="btn btn-primary" type="submit">Turn On</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="light">
                        <input type="hidden" name="action" value="OFF">
                        <button class="btn btn-secondary" type="submit">Turn Off</button>
                    </form>
                </div>
                <div class="slider-group">
                    <form method="POST" action="/command" style="display:flex;align-items:center;gap:8px;flex:1">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="light">
                        <input type="hidden" name="action" value="SET_BRIGHTNESS">
                        <input type="range" name="brightness" min="0" max="100" value="{{ light.brightness }}">
                        <button class="btn btn-secondary" type="submit">Set</button>
                    </form>
                </div>
            </div>

            <!-- Smart Alarm Card -->
            <div class="card">
                <h2>
                    <span class="indicator {{ 'on' if alarm.enabled else 'off' }}"></span>
                    Smart Alarm
                </h2>
                <div class="status-row"><span class="label">Alarm time</span>
                    <span class="value">{{ alarm.alarm_time }}</span></div>
                <div class="status-row"><span class="label">Enabled</span>
                    <span class="value">{{ alarm.enabled }}</span></div>
                <div class="status-row"><span class="label">Ringing</span>
                    <span class="value">{{ alarm.ringing }}</span></div>
                <div class="status-row"><span class="label">Volume</span>
                    <span class="value">{{ alarm.volume }}%</span></div>
                <div class="status-row"><span class="label">Repeat</span>
                    <span class="value">{{ alarm.repeat | join(', ') }}</span></div>
                <div class="actions">
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="alarm">
                        <input type="hidden" name="action" value="ENABLE">
                        <button class="btn btn-primary" type="submit">Enable</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="alarm">
                        <input type="hidden" name="action" value="DISABLE">
                        <button class="btn btn-secondary" type="submit">Disable</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                        <input type="hidden" name="device" value="alarm">
                        <input type="hidden" name="action" value="DISMISS">
                        <button class="btn btn-danger" type="submit">Dismiss</button>
                    </form>
                </div>
            </div>

        </div>

        <!-- Event Log -->
        <div class="event-log">
            <h2>Event Log</h2>
            {% for ev in events %}
            <div class="event-item {{ ev.data.severity if ev.data.severity else '' }}">
                <span class="event-time">{{ ev.time }}</span> &mdash;
                <strong>{{ ev.data.event }}</strong> on {{ ev.data.device_id }}:
                {{ ev.data.detail }}
            </div>
            {% endfor %}
            {% if not events %}
            <div class="event-item">No events yet.</div>
            {% endif %}
        </div>

        <p class="refresh-note">Page auto-refreshes every 5 seconds</p>
    </div>

    <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>
"""


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    if "username" not in session:
        return redirect("/login")
    return redirect("/dashboard")


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template_string(CSRF_ERROR_PAGE, reason=e.description), 400


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if "username" in session:
            return redirect("/dashboard")
        if "pending_user_id" in session:
            return redirect("/verify-totp")
        return render_template_string(LOGIN_PAGE, error=None)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = "SELECT id, username, password, role, totp_secret FROM users WHERE username=?"
    print(f"[SQL] {query} | params=({username},)")  # Log safely for demo purposes

    try:
        c.execute(query, (username,))
        user = c.fetchone()
    except Exception as e:
        print(f"[SQL ERROR] {e}")
        user = None
    conn.close()

    clear_pending_login()

    if user and verify_password(password, user[2]):
        session["pending_user_id"] = user[0]
        session["pending_username"] = user[1]
        session["pending_role"] = user[3]
        session["pending_totp_secret"] = user[4] or pyotp.random_base32()
        session["pending_totp_setup"] = not bool(user[4])
        return redirect("/verify-totp")
    else:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    pending_user_id = session.get("pending_user_id")
    pending_username = session.get("pending_username")
    pending_role = session.get("pending_role")
    pending_secret = session.get("pending_totp_secret")
    is_setup = bool(session.get("pending_totp_setup"))

    if not all([pending_user_id, pending_username, pending_role, pending_secret]):
        clear_pending_login()
        return redirect("/login")

    if request.method == "GET":
        return render_totp_page()

    code = request.form.get("code", "").strip().replace(" ", "")
    totp = pyotp.TOTP(pending_secret)

    if not (code.isdigit() and len(code) == 6 and totp.verify(code, valid_window=1)):
        return render_totp_page(error="Invalid verification code. Please try again.")

    if is_setup:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "UPDATE users SET totp_secret=? WHERE id=?",
            (pending_secret, pending_user_id),
        )
        conn.commit()
        conn.close()

    session["username"] = pending_username
    session["role"] = pending_role
    clear_pending_login()
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")

    # Get latest device states with defaults
    lock = device_states.get("lock_01", {}).get("data", {
        "state": "LOCKED", "battery": 85, "last_user": "system", "method": "auto"
    })
    light = device_states.get("light_01", {}).get("data", {
        "power": "OFF", "brightness": 80, "color_temp": 4000, "mode": "manual"
    })
    alarm = device_states.get("alarm_01", {}).get("data", {
        "alarm_time": "07:30", "enabled": True, "ringing": False,
        "volume": 70, "repeat": ["MON", "TUE", "WED", "THU", "FRI"]
    })

    return render_template_string(
        DASHBOARD_PAGE,
        username=session["username"],
        role=session["role"],
        lock=lock,
        light=light,
        alarm=alarm,
        events=event_log[:20],
        alerts=alert_log[:10],
    )


@app.route("/command", methods=["POST"])
def command():
    # !! VULNERABLE: No CSRF token, no auth check on role !!
    if "username" not in session:
        return redirect("/login")

    device = request.form.get("device")
    action = request.form.get("action")

    topic_map = {
        "lock": "home/lock/command",
        "light": "home/light/command",
        "alarm": "home/alarm/command",
    }

    topic = topic_map.get(device)
    if not topic:
        return "Invalid device", 400

    payload = {
        "device_id": f"{device}_01",
        "device_type": device,
        "timestamp": int(time.time()),
        "version": "1.0",
        "action": action,
        "issued_by": session.get("username", "unknown"),
    }

    # Handle params for specific actions
    if action == "SET_BRIGHTNESS":
        brightness = request.form.get("brightness", 80)
        payload["params"] = {"brightness": int(brightness)}

    mqtt_client.publish(topic, json.dumps(payload))
    print(f"[CMD] {topic}: {json.dumps(payload)}")

    return redirect("/dashboard")


# !! VULNERABLE: Exposes device data without authentication !!
@app.route("/api/devices")
def api_devices():
    return jsonify(device_states)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Connect to MQTT in background
    thread = threading.Thread(target=mqtt_connect, daemon=True)
    thread.start()

    external_port = os.getenv("EXTERNAL_PORT", "5000")

    print("=" * 60)
    print("SmartNest Web Panel")
    print(f"Broker: {BROKER_HOST}:{BROKER_PORT}")
    print(f">>> Access the dashboard at: http://localhost:{external_port}")
    print(">>> Login: admin / admin")
    print("WARNING: This app is intentionally vulnerable!")
    print("=" * 60)

    # Silence Flask's default startup banner to avoid confusion
    # (it would print the container-internal port 5000, which is misleading)
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    import flask.cli
    flask.cli.show_server_banner = lambda *args, **kwargs: None

    app.run(host="0.0.0.0", port=5000, debug=False)
