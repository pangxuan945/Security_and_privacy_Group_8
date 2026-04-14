"""
SmartNest IoT Device Simulator
Simulates: Smart Lock, Smart Light, Smart Alarm Clock
Each device publishes status every 10s and listens for commands.
"""

import json
import time
import random
import threading
import os
import ssl
from datetime import datetime

import paho.mqtt.client as mqtt

BROKER_HOST = os.getenv("MQTT_BROKER", "broker")
BROKER_PORT = int(os.getenv("MQTT_PORT", 8883))
CA_CERT     = os.getenv("CA_CERT",     "/certs/ca.crt")
CLIENT_CERT = os.getenv("CLIENT_CERT", "/certs/device_simulator.crt")
CLIENT_KEY  = os.getenv("CLIENT_KEY",  "/certs/device_simulator.key")

# ──────────────────────────────────────────────
# Device State
# ──────────────────────────────────────────────

devices = {
    "lock_01": {
        "device_id": "lock_01",
        "device_type": "lock",
        "state": "LOCKED",
        "battery": 85,
        "method": "auto",
        "last_user": "system",
    },
    "light_01": {
        "device_id": "light_01",
        "device_type": "light",
        "power": "OFF",
        "brightness": 80,
        "color_temp": 4000,
        "rgb": [255, 180, 100],
        "mode": "manual",
    },
    "alarm_01": {
        "device_id": "alarm_01",
        "device_type": "alarm",
        "alarm_time": "07:30",
        "enabled": True,
        "ringing": False,
        "volume": 70,
        "repeat": ["MON", "TUE", "WED", "THU", "FRI"],
        "snooze_count": 0,
    },
}


def ts():
    return int(time.time())


def build_msg(device_state: dict) -> dict:
    """Wrap device state with common fields."""
    msg = {
        "device_id": device_state["device_id"],
        "device_type": device_state["device_type"],
        "timestamp": ts(),
        "version": "1.0",
    }
    # Add device-specific fields (skip id and type, already added)
    for k, v in device_state.items():
        if k not in ("device_id", "device_type"):
            msg[k] = v
    return msg


def build_event(device_id: str, device_type: str, event: str, severity: str, detail: str) -> dict:
    return {
        "device_id": device_id,
        "device_type": device_type,
        "timestamp": ts(),
        "version": "1.0",
        "event": event,
        "severity": severity,
        "detail": detail,
    }


# ──────────────────────────────────────────────
# Command Handlers
# ──────────────────────────────────────────────

def handle_lock_command(client, payload: dict):
    lock = devices["lock_01"]
    action = payload.get("action", "")
    issued_by = payload.get("issued_by", "unknown")

    if action == "UNLOCK":
        lock["state"] = "UNLOCKED"
        lock["method"] = "remote"
        lock["last_user"] = issued_by
        print(f"[LOCK] UNLOCKED by {issued_by}")

    elif action == "LOCK":
        lock["state"] = "LOCKED"
        lock["method"] = "remote"
        lock["last_user"] = issued_by
        print(f"[LOCK] LOCKED by {issued_by}")

    elif action == "SET_PIN":
        pin = payload.get("pin", "")
        print(f"[LOCK] PIN updated by {issued_by}")

    else:
        print(f"[LOCK] Unknown action: {action}")
        return

    # Immediately publish updated status
    msg = build_msg(lock)
    client.publish("home/lock/status", json.dumps(msg))


def handle_light_command(client, payload: dict):
    light = devices["light_01"]
    action = payload.get("action", "")
    params = payload.get("params", {})
    issued_by = payload.get("issued_by", "unknown")

    if action == "ON":
        light["power"] = "ON"
        print(f"[LIGHT] Turned ON by {issued_by}")

    elif action == "OFF":
        light["power"] = "OFF"
        print(f"[LIGHT] Turned OFF by {issued_by}")

    elif action == "SET_BRIGHTNESS":
        brightness = params.get("brightness", light["brightness"])
        light["brightness"] = max(0, min(100, brightness))
        print(f"[LIGHT] Brightness set to {light['brightness']} by {issued_by}")

    elif action == "SET_COLOR":
        if "rgb" in params:
            light["rgb"] = params["rgb"]
            print(f"[LIGHT] RGB set to {light['rgb']} by {issued_by}")
        elif "color_temp" in params:
            light["color_temp"] = params["color_temp"]
            print(f"[LIGHT] Color temp set to {light['color_temp']}K by {issued_by}")

    elif action == "SET_MODE":
        light["mode"] = params.get("mode", light["mode"])
        print(f"[LIGHT] Mode set to {light['mode']} by {issued_by}")

    else:
        print(f"[LIGHT] Unknown action: {action}")
        return

    msg = build_msg(light)
    client.publish("home/light/status", json.dumps(msg))


def handle_alarm_command(client, payload: dict):
    alarm = devices["alarm_01"]
    action = payload.get("action", "")
    params = payload.get("params", {})
    issued_by = payload.get("issued_by", "unknown")

    if action == "SET_ALARM":
        alarm["alarm_time"] = params.get("alarm_time", alarm["alarm_time"])
        alarm["repeat"] = params.get("repeat", alarm["repeat"])
        alarm["volume"] = params.get("volume", alarm["volume"])
        alarm["enabled"] = True
        print(f"[ALARM] Set to {alarm['alarm_time']} by {issued_by}")

    elif action == "ENABLE":
        alarm["enabled"] = True
        print(f"[ALARM] Enabled by {issued_by}")

    elif action == "DISABLE":
        alarm["enabled"] = False
        alarm["ringing"] = False
        print(f"[ALARM] Disabled by {issued_by}")

    elif action == "DISMISS":
        alarm["ringing"] = False
        alarm["snooze_count"] = 0
        print(f"[ALARM] Dismissed by {issued_by}")

    elif action == "SNOOZE":
        if alarm["ringing"]:
            alarm["snooze_count"] += 1
            alarm["ringing"] = False
            print(f"[ALARM] Snoozed ({alarm['snooze_count']}x) by {issued_by}")
            if alarm["snooze_count"] >= 3:
                event = build_event("alarm_01", "alarm", "MAX_SNOOZE_REACHED", "medium",
                                     f"Snoozed {alarm['snooze_count']} times")
                client.publish("home/alarm/event", json.dumps(event))

    else:
        print(f"[ALARM] Unknown action: {action}")
        return

    msg = build_msg(alarm)
    client.publish("home/alarm/status", json.dumps(msg))


COMMAND_HANDLERS = {
    "home/lock/command": handle_lock_command,
    "home/light/command": handle_light_command,
    "home/alarm/command": handle_alarm_command,
}


# ──────────────────────────────────────────────
# MQTT Callbacks
# ──────────────────────────────────────────────

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"[MQTT] Connected to broker at {BROKER_HOST}:{BROKER_PORT}")
        # Subscribe to all command topics
        for topic in COMMAND_HANDLERS:
            client.subscribe(topic)
            print(f"[MQTT] Subscribed to {topic}")
    else:
        print(f"[MQTT] Connection failed with code {rc}")


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        topic = msg.topic
        print(f"[RECV] {topic}: {json.dumps(payload, indent=2)}")

        handler = COMMAND_HANDLERS.get(topic)
        if handler:
            handler(client, payload)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON on {msg.topic}: {msg.payload}")


# ──────────────────────────────────────────────
# Status Publishing Loop
# ──────────────────────────────────────────────

def publish_status_loop(client):
    """Publish all device statuses every 10 seconds."""
    topic_map = {
        "lock_01": "home/lock/status",
        "light_01": "home/light/status",
        "alarm_01": "home/alarm/status",
    }

    while True:
        time.sleep(10)

        # Simulate battery drain on lock
        lock = devices["lock_01"]
        lock["battery"] = max(0, lock["battery"] - random.choice([0, 0, 0, 1]))
        if lock["battery"] <= 15:
            event = build_event("lock_01", "lock", "LOW_BATTERY", "medium",
                                 f"Battery at {lock['battery']}%")
            client.publish("home/lock/event", json.dumps(event))
            print(f"[EVENT] Lock low battery: {lock['battery']}%")

        # Simulate temperature fluctuation on light (for realism)
        # (light might overheat if brightness is maxed for too long)

        # Publish all statuses
        for dev_id, topic in topic_map.items():
            msg = build_msg(devices[dev_id])
            payload = json.dumps(msg)
            client.publish(topic, payload)
            print(f"[PUB] {topic}: {payload}")


# ──────────────────────────────────────────────
# Heartbeat
# ──────────────────────────────────────────────

def heartbeat_loop(client):
    """Publish heartbeat for all devices every 30 seconds."""
    while True:
        time.sleep(30)
        for dev_id, dev in devices.items():
            hb = {
                "device_id": dev_id,
                "device_type": dev["device_type"],
                "timestamp": ts(),
                "version": "1.0",
                "uptime": int(time.time()),
                "status": "online",
            }
            client.publish("home/heartbeat", json.dumps(hb))


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print("=" * 50)
    print("SmartNest IoT Device Simulator")
    print(f"Broker: {BROKER_HOST}:{BROKER_PORT}")
    print(f"Devices: {list(devices.keys())}")
    print("=" * 50)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="device_simulator")
    client.on_connect = on_connect
    client.on_message = on_message

    # TLS configuration
    client.tls_set(
        ca_certs=CA_CERT,
        certfile=CLIENT_CERT,
        keyfile=CLIENT_KEY,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLSv1_2,
    )
    client.tls_insecure_set(False)

    # Retry connection
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, 60)
            break
        except Exception as e:
            print(f"[MQTT] Waiting for broker... ({e})")
            time.sleep(3)

    # Start background threads
    status_thread = threading.Thread(target=publish_status_loop, args=(client,), daemon=True)
    status_thread.start()

    heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(client,), daemon=True)
    heartbeat_thread.start()

    # Blocking loop
    client.loop_forever()


if __name__ == "__main__":
    main()
