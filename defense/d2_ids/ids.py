"""
SmartNest CW2 Defense D2 — AI-driven Intrusion Detection System

This IDS monitors all MQTT traffic on the SmartNest broker and detects
anomalous patterns that may indicate an active attack.

Detection methods:
  1. Statistical thresholds — message rate per topic per window
  2. Command anomaly detection — unexpected command sources or timing
  3. Isolation Forest — ML-based outlier detection on traffic features

The IDS connects with its own client certificate (ids_monitor) which has
read-only access to home/# plus write access to home/alert.
"""

import json
import os
import ssl
import time
import threading
from collections import defaultdict
from datetime import datetime

import numpy as np
import paho.mqtt.client as mqtt

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

BROKER_HOST = os.getenv("MQTT_BROKER", "broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", 8883))

CA_CERT     = os.getenv("CA_CERT",     "/certs/ca.crt")
CLIENT_CERT = os.getenv("CLIENT_CERT", "/certs/ids_monitor.crt")
CLIENT_KEY  = os.getenv("CLIENT_KEY",  "/certs/ids_monitor.key")

# Detection parameters
WINDOW_SECONDS      = 10     # sliding window size
RATE_THRESHOLD      = 15     # max messages per topic per window (normal is ~3)
COMMAND_RATE_THRESH = 3      # max commands per window (normal is 0-1)
BASELINE_DURATION   = int(os.getenv("BASELINE_DURATION", 60))  # seconds to collect baseline
ANOMALY_COOLDOWN    = 30     # seconds between repeated alerts for same anomaly type

# ──────────────────────────────────────────────
# State
# ──────────────────────────────────────────────

# Per-window message counters
window_counts = defaultdict(int)        # topic -> count in current window
command_counts = defaultdict(int)       # topic -> command count in current window
window_start = time.time()

# Baseline statistics (populated during Phase 1)
baseline = {
    "topic_rates": {},                  # topic -> (mean, std) messages per window
    "command_sources": set(),           # known legitimate command issuers
    "ready": False,
}

# Baseline collection buffer
baseline_buffer = defaultdict(list)     # topic -> [count_per_window, ...]
baseline_command_sources = set()

# Isolation Forest model (populated after baseline)
iso_forest = None

# Alert cooldown tracker
last_alert_time = defaultdict(float)    # alert_type -> last timestamp

# Stats for logging
total_messages = 0
total_alerts = 0


def ts():
    return datetime.now().strftime("%H:%M:%S")


# ──────────────────────────────────────────────
# Phase 1: Baseline Collection
# ──────────────────────────────────────────────

def collect_baseline_window():
    """Record current window counts into baseline buffer."""
    for topic, count in window_counts.items():
        baseline_buffer[topic].append(count)


def finalize_baseline():
    """Compute baseline statistics from collected data."""
    global iso_forest

    print(f"[IDS] {ts()} Computing baseline from {BASELINE_DURATION}s of traffic...")

    for topic, counts in baseline_buffer.items():
        mean = np.mean(counts) if counts else 0
        std = np.std(counts) if counts else 1
        baseline["topic_rates"][topic] = (mean, max(std, 0.5))
        print(f"[IDS]   {topic}: mean={mean:.1f}, std={std:.1f} msgs/window")

    baseline["command_sources"] = baseline_command_sources.copy()
    print(f"[IDS]   Known command sources: {baseline['command_sources'] or 'none observed'}")

    # Train Isolation Forest on the baseline feature vectors
    train_isolation_forest()

    baseline["ready"] = True
    print(f"[IDS] {ts()} Baseline ready. Switching to detection mode.")


def train_isolation_forest():
    """Train an Isolation Forest on baseline traffic features."""
    global iso_forest

    # Build feature vectors: [total_msg_rate, command_rate, num_active_topics]
    # One vector per recorded window
    all_topics = list(baseline_buffer.keys())
    if not all_topics or len(baseline_buffer[all_topics[0]]) < 3:
        print("[IDS]   Not enough data for Isolation Forest, using thresholds only")
        return

    num_windows = len(baseline_buffer[all_topics[0]])
    features = []

    for i in range(num_windows):
        total_rate = sum(
            baseline_buffer[t][i] if i < len(baseline_buffer[t]) else 0
            for t in all_topics
        )
        cmd_rate = sum(
            baseline_buffer[t][i] if i < len(baseline_buffer[t]) else 0
            for t in all_topics if "/command" in t
        )
        active_topics = sum(
            1 for t in all_topics
            if i < len(baseline_buffer[t]) and baseline_buffer[t][i] > 0
        )
        features.append([total_rate, cmd_rate, active_topics])

    X = np.array(features)

    try:
        from sklearn.ensemble import IsolationForest
        iso_forest = IsolationForest(
            contamination=0.05,
            n_estimators=100,
            random_state=42,
        )
        iso_forest.fit(X)
        print(f"[IDS]   Isolation Forest trained on {len(X)} windows, {len(X[0])} features")
    except ImportError:
        print("[IDS]   scikit-learn not available, using statistical thresholds only")
        iso_forest = None


# ──────────────────────────────────────────────
# Phase 2: Anomaly Detection
# ──────────────────────────────────────────────

def check_anomalies(client):
    """Run all detection methods on the current window."""
    alerts = []

    # ── Check 1: Message rate spike per topic ──
    for topic, count in window_counts.items():
        if topic in baseline["topic_rates"]:
            mean, std = baseline["topic_rates"][topic]
            threshold = max(mean + 3 * std, RATE_THRESHOLD)
        else:
            threshold = RATE_THRESHOLD

        if count > threshold:
            alerts.append({
                "type": "RATE_SPIKE",
                "severity": "high",
                "detail": f"Topic '{topic}' received {count} msgs in {WINDOW_SECONDS}s "
                          f"(baseline: {baseline['topic_rates'].get(topic, (0, 1))[0]})",
            })

    # ── Check 2: Command from unknown source ──
    for topic, count in command_counts.items():
        if count > COMMAND_RATE_THRESH:
            alerts.append({
                "type": "COMMAND_FLOOD",
                "severity": "critical",
                "detail": f"Burst of {count} commands on '{topic}' in {WINDOW_SECONDS}s",
            })

    # ── Check 3: Isolation Forest anomaly score ──
    if iso_forest is not None:
        total_rate = sum(window_counts.values())
        cmd_rate = sum(
            c for t, c in window_counts.items() if "/command" in t
        )
        active_topics = sum(1 for c in window_counts.values() if c > 0)
        features = np.array([[total_rate, cmd_rate, active_topics]])

        score = iso_forest.decision_function(features)[0]
        prediction = iso_forest.predict(features)[0]

        if prediction == -1:
            alerts.append({
                "type": "ML_ANOMALY",
                "severity": "high",
                "detail": f"Isolation Forest flagged anomaly (score={score:.3f}, "
                          f"features=[msgs={total_rate}, cmds={cmd_rate}, topics={active_topics}])",
            })

    # ── Fire alerts ──
    for alert in alerts:
        fire_alert(client, alert)


def fire_alert(client, alert):
    """Publish an alert to home/alert if cooldown has passed."""
    global total_alerts

    alert_type = alert["type"]
    now = time.time()

    # Cooldown: don't spam the same alert type
    if now - last_alert_time[alert_type] < ANOMALY_COOLDOWN:
        return

    last_alert_time[alert_type] = now
    total_alerts += 1

    payload = {
        "source": "ids_monitor",
        "timestamp": int(now),
        "alert_id": total_alerts,
        **alert,
    }

    client.publish("home/alert", json.dumps(payload))

    severity_icon = {
        "critical": "!!!",
        "high": "!! ",
        "medium": "!  ",
        "low": ".  ",
    }.get(alert["severity"], "?  ")

    print(f"[ALERT] {ts()} {severity_icon} [{alert['type']}] {alert['detail']}")


# ──────────────────────────────────────────────
# Window Management
# ──────────────────────────────────────────────

def window_tick(client):
    """Called every WINDOW_SECONDS to process the current window and reset."""
    global window_start, window_counts, command_counts

    elapsed = time.time() - window_start

    if not baseline["ready"]:
        # Still in baseline collection phase
        collect_baseline_window()
        remaining = BASELINE_DURATION - (time.time() - baseline_collection_start)
        if remaining <= 0:
            finalize_baseline()
    else:
        # Detection phase
        if any(window_counts.values()):
            check_anomalies(client)

    # Reset window
    window_counts = defaultdict(int)
    command_counts = defaultdict(int)
    window_start = time.time()


def window_loop(client):
    """Background thread: tick every WINDOW_SECONDS."""
    while True:
        time.sleep(WINDOW_SECONDS)
        window_tick(client)


# ──────────────────────────────────────────────
# MQTT Callbacks
# ──────────────────────────────────────────────

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[IDS] {ts()} Connected to broker at {BROKER_HOST}:{BROKER_PORT}")
        client.subscribe("home/#")
        print(f"[IDS] {ts()} Subscribed to home/# (read-only monitor)")
        print(f"[IDS] {ts()} Collecting baseline for {BASELINE_DURATION}s...")
    else:
        print(f"[IDS] Connection failed with code {rc}")


def on_message(client, userdata, msg):
    global total_messages

    topic = msg.topic
    total_messages += 1

    # Don't count our own alerts
    if topic == "home/alert":
        return

    # Count message in current window
    window_counts[topic] += 1

    # Track command messages separately
    if "/command" in topic:
        command_counts[topic] += 1

        # During baseline, record command sources
        if not baseline["ready"]:
            try:
                payload = json.loads(msg.payload.decode())
                source = payload.get("issued_by", "unknown")
                baseline_command_sources.add(source)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass


# ──────────────────────────────────────────────
# Status Report
# ──────────────────────────────────────────────

def status_loop(client):
    """Print periodic status summary."""
    while True:
        time.sleep(60)
        mode = "DETECTING" if baseline["ready"] else "BASELINE"
        print(f"[IDS] {ts()} Status: mode={mode}, "
              f"total_msgs={total_messages}, total_alerts={total_alerts}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

baseline_collection_start = time.time()


def main():
    global baseline_collection_start

    print("=" * 60)
    print("SmartNest Intrusion Detection System (D2)")
    print(f"Broker: {BROKER_HOST}:{BROKER_PORT}")
    print(f"Window: {WINDOW_SECONDS}s | Rate threshold: {RATE_THRESHOLD}")
    print(f"Baseline duration: {BASELINE_DURATION}s")
    print("=" * 60)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id="ids_monitor")
    client.on_connect = on_connect
    client.on_message = on_message

    # TLS with client certificate
    client.tls_set(
        ca_certs=CA_CERT,
        certfile=CLIENT_CERT,
        keyfile=CLIENT_KEY,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )
    client.tls_insecure_set(False)

    # Connect with retry
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, 60)
            break
        except Exception as e:
            print(f"[IDS] Waiting for broker... ({e})")
            time.sleep(3)

    baseline_collection_start = time.time()

    # Start background threads
    threading.Thread(target=window_loop, args=(client,), daemon=True).start()
    threading.Thread(target=status_loop, args=(client,), daemon=True).start()

    client.loop_forever()


if __name__ == "__main__":
    main()
