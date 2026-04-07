# SmartNest - Smart Home Security Lab

> ELEC0138 Security & Privacy Coursework 2025/2026
> "Resilient Security: Threat Modeling and Defensive Strategies for Smart Home Ecosystems"

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Docker Network                     │
│                                                      │
│  ┌──────────┐    MQTT     ┌──────────────────────┐  │
│  │  Broker   │◄──────────►│  Device Simulator    │  │
│  │ Mosquitto │            │  lock_01, light_01,  │  │
│  │ :1883     │            │  alarm_01            │  │
│  └─────┬─────┘            └──────────────────────┘  │
│        │                                             │
│        │ MQTT                                        │
│        ▼                                             │
│  ┌──────────────────────┐                            │
│  │  Web Panel (Flask)   │                            │
│  │  :5000               │                            │
│  │  Dashboard + Login   │                            │
│  └──────────────────────┘                            │
│                                                      │
└──────────────────────────────────────────────────────┘
         │ :1883              │ :5000
         ▼                    ▼
   Wireshark / Attacker    Browser
```

## Quick Start

### Prerequisites
- Docker & Docker Compose installed
- (Optional) Wireshark for packet capture

### Launch

```bash
# Clone the repo
git clone <your-repo-url>
cd smartnest

# Build and start everything
docker-compose up --build

# Or run in background
docker-compose up --build -d

# Watch logs
docker-compose logs -f
```

### Verify

1. **Web Panel**: Open http://localhost:5000
   - Login: `admin` / `admin`
   - You should see 3 device cards with live status

2. **MQTT Traffic**: In a separate terminal:
   ```bash
   # Install mosquitto-clients if needed
   # sudo apt install mosquitto-clients

   # Subscribe to ALL topics
   mosquitto_sub -h localhost -t 'home/#' -v
   ```
   You should see JSON messages every 10 seconds.

3. **Docker Logs**: Check each container:
   ```bash
   docker logs smartnest-devices -f
   docker logs smartnest-web -f
   docker logs smartnest-broker -f
   ```

## MQTT Topic Reference

| Topic | Direction | Description |
|-------|-----------|-------------|
| `home/lock/status` | Device → Broker | Lock state, battery, last user |
| `home/lock/command` | Panel → Device | LOCK, UNLOCK, SET_PIN |
| `home/lock/event` | Device → Broker | TAMPER_DETECTED, LOW_BATTERY |
| `home/light/status` | Device → Broker | Power, brightness, color |
| `home/light/command` | Panel → Device | ON, OFF, SET_BRIGHTNESS, SET_COLOR |
| `home/light/event` | Device → Broker | OVERHEATING, BULB_FAILURE |
| `home/alarm/status` | Device → Broker | Alarm time, enabled, ringing |
| `home/alarm/command` | Panel → Device | SET_ALARM, ENABLE, DISABLE, DISMISS, SNOOZE |
| `home/alarm/event` | Device → Broker | ALARM_TRIGGERED, MAX_SNOOZE_REACHED |
| `home/heartbeat` | Device → Broker | Periodic health check |
| `home/alert` | IDS → Broker | Intrusion detection alerts |

## Intentional Vulnerabilities (Coursework 1)

> ⚠️ These are DELIBERATE for educational purposes.

| # | Vulnerability | Location | CWE |
|---|--------------|----------|-----|
| 1 | SQL Injection | `/login` form | CWE-89 |
| 2 | Default credentials | admin/admin | CWE-798 |
| 3 | No CSRF protection | `/command` endpoint | CWE-352 |
| 4 | Plaintext MQTT | Port 1883, no TLS | CWE-319 |
| 5 | No MQTT authentication | Broker allows anonymous | CWE-306 |
| 6 | Sensitive data in HTML comments | Login page source | CWE-615 |
| 7 | Unauthenticated API | `/api/devices` endpoint | CWE-306 |
| 8 | Weak session secret | `app.secret_key` | CWE-330 |

## Project Structure

```
smartnest/
├── docker-compose.yml          # Orchestration
├── README.md                   # This file
├── broker/
│   └── mosquitto.conf          # MQTT broker config
├── devices/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── simulator.py            # IoT device simulator
└── web/
    ├── Dockerfile
    ├── requirements.txt
    └── app.py                  # Flask web panel
```

## Team

| Member | Module | Responsibility |
|--------|--------|----------------|
| A | MQTT Security | MitM attack + TLS defense |
| B | Web Security | SQLi/CSRF attack + hardening |
| C | IDS | Anomaly detection + alerting |
| D | Architecture | OTA signing + report + integration |
