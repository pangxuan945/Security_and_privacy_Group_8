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
from datetime import datetime

from flask import Flask, render_template_string, request, redirect, session, jsonify
import paho.mqtt.client as mqtt

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # Intentionally weak

BROKER_HOST = os.getenv("MQTT_BROKER", "broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", 1883))

# ──────────────────────────────────────────────
# In-memory device state (updated via MQTT)
# ──────────────────────────────────────────────

device_states = {}
event_log = []
MAX_EVENTS = 100

# ──────────────────────────────────────────────
# SQLite Setup (INTENTIONALLY VULNERABLE)
# ──────────────────────────────────────────────

DB_PATH = "/tmp/smartnest.db"


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
    # Default credentials - INTENTIONAL VULNERABILITY
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin', 'admin')")
        c.execute("INSERT INTO users (username, password, role) VALUES ('guest', 'guest123', 'viewer')")
    except sqlite3.IntegrityError:
        pass
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
    while True:
        try:
            mqtt_client.connect(BROKER_HOST, BROKER_PORT, 60)
            mqtt_client.loop_start()
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
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
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
                        <input type="hidden" name="device" value="lock">
                        <input type="hidden" name="action" value="UNLOCK">
                        <button class="btn btn-danger" type="submit">Unlock</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
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
                        <input type="hidden" name="device" value="light">
                        <input type="hidden" name="action" value="ON">
                        <button class="btn btn-primary" type="submit">Turn On</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="device" value="light">
                        <input type="hidden" name="action" value="OFF">
                        <button class="btn btn-secondary" type="submit">Turn Off</button>
                    </form>
                </div>
                <div class="slider-group">
                    <form method="POST" action="/command" style="display:flex;align-items:center;gap:8px;flex:1">
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
                        <input type="hidden" name="device" value="alarm">
                        <input type="hidden" name="action" value="ENABLE">
                        <button class="btn btn-primary" type="submit">Enable</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
                        <input type="hidden" name="device" value="alarm">
                        <input type="hidden" name="action" value="DISABLE">
                        <button class="btn btn-secondary" type="submit">Disable</button>
                    </form>
                    <form method="POST" action="/command" style="display:inline">
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # !! VULNERABLE: SQL Injection !!
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print(f"[SQL] {query}")  # Log the query for demo purposes

    try:
        c.execute(query)
        user = c.fetchone()
    except Exception as e:
        print(f"[SQL ERROR] {e}")
        user = None
    conn.close()

    if user:
        session["username"] = user[1]
        session["role"] = user[3]
        return redirect("/dashboard")
    else:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials")


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