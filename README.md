# SmartNest — Smart Home Security Lab

**ELEC0138 Security & Privacy Coursework 2025/2026**
*Resilient Security: Threat Modeling and Defensive Strategies for Smart Home Ecosystems*

SmartNest is a containerized smart home platform that faithfully reproduces the architectural patterns and configuration defaults of consumer IoT hubs. It is used as the testbed for both the offensive analysis (Coursework 1) and the layered defensive redesign (Coursework 2) in this project.

The platform simulates three IoT devices — a smart lock, a smart light, and a smart alarm clock — communicating with a Mosquitto MQTT broker and a Flask-based web management panel. Everything runs as Docker containers on a private bridge network; no physical hardware is required.

## Branches

This repository contains two parallel runnable versions of SmartNest.

| Branch | Purpose | State |
|--------|---------|-------|
| `main` | Vulnerable baseline used for CW1 attack demonstrations | Every attack in `attacks/` succeeds |
| `cw2-defense` | Hardened version used for CW2 defense demonstrations | All CW1 attacks are blocked |

To switch between them:

```bash
docker compose down
git checkout main             # CW1 attack demonstrations
git checkout cw2-defense      # CW2 defense demonstrations
docker compose up --build
```

`git checkout cw1-final` (a permanent tag) points to the exact state used for the CW1 report screenshots, in case the `main` branch is later merged with `cw2-defense`.

## Architecture

Three Docker containers run on an internal bridge network. Only ports 1883 (or 8883 on the defense branch) and 5001 are exposed to the host.

```
                          Docker network (internal)
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │   ┌─────────────────┐    MQTT    ┌────────────────────────────┐  │
  │   │  MQTT Broker    │◄──────────►│  Device Simulator          │  │
  │   │  Mosquitto      │            │  lock_01, light_01,        │  │
  │   │  1883  / 8883   │            │  alarm_01                  │  │
  │   └────────┬────────┘            └────────────────────────────┘  │
  │            │                                                      │
  │            │ MQTT                                                 │
  │            ▼                                                      │
  │   ┌─────────────────────┐                                         │
  │   │  Web Panel (Flask)  │                                         │
  │   │  dashboard + login  │                                         │
  │   │  :5000              │                                         │
  │   └─────────────────────┘                                         │
  │                                                                   │
  └───────────────────────────────────────────────────────────────────┘
                 │                          │
          :1883 / :8883                  :5001
                 │                          │
                 ▼                          ▼
       Attacker / Wireshark            Browser / Attacker
```

Port `:5000` inside the container is mapped to host port `:5001`. On the `cw2-defense` branch, broker port `1883` is closed and replaced by `8883` (TLS with mutual client certificates).

## Quick start

Prerequisites: Docker Desktop (or Docker Engine + Docker Compose). Wireshark is optional but useful for inspecting MQTT traffic.

### On the `main` branch (vulnerable baseline)

```bash
git clone <your-repo-url>
cd Security_and_privacy_Group_8
git checkout main
docker compose up --build
```

Then open **http://localhost:5001** and log in with `admin` / `admin`. You should see three device cards with live-updating status.

### On the `cw2-defense` branch (hardened)

```bash
git checkout cw2-defense
cd defense && ./gen_certs.sh && cd ..       # generate TLS certificates once
docker compose up --build
```

Certificate private keys are not committed to the repository (see `.gitignore`), so every developer generates their own locally from the same CA configuration.

### Subscribing to MQTT traffic

On `main`:
```bash
mosquitto_sub -h localhost -p 1883 -t 'home/#' -v
```

On `cw2-defense`:
```bash
mosquitto_sub -h localhost -p 8883 -t 'home/#' -v \
  --cafile defense/certs/ca.crt \
  --cert   defense/certs/ids_monitor.crt \
  --key    defense/certs/ids_monitor.key
```

## MQTT topic reference

| Topic | Direction | Description |
|-------|-----------|-------------|
| `home/lock/status` | device → broker | lock state, battery, last user |
| `home/lock/command` | panel → device | LOCK, UNLOCK, SET_PIN |
| `home/lock/event` | device → broker | TAMPER_DETECTED, LOW_BATTERY |
| `home/light/status` | device → broker | power, brightness, color |
| `home/light/command` | panel → device | ON, OFF, SET_BRIGHTNESS, SET_COLOR |
| `home/light/event` | device → broker | OVERHEATING, BULB_FAILURE |
| `home/alarm/status` | device → broker | alarm time, enabled, ringing |
| `home/alarm/command` | panel → device | SET_ALARM, ENABLE, DISABLE, DISMISS, SNOOZE |
| `home/alarm/event` | device → broker | ALARM_TRIGGERED, MAX_SNOOZE_REACHED |
| `home/heartbeat` | device → broker | periodic health check |
| `home/alert` | IDS → broker | intrusion detection alerts |

## Coursework 1 — threats and attacks

The baseline deployment on `main` deliberately ships with the same security mistakes found in many commercial IoT hubs. Each vulnerability is exploited by a reproducible attack script or manual procedure documented in `attacks/`.

| # | Vulnerability | Threat ID | CWE | Evidence |
|---|---------------|-----------|-----|----------|
| 1 | Plaintext MQTT on port 1883, no TLS | T1 | CWE-319 | `attacks/mqtt_attack.sh eavesdrop` |
| 2 | Broker allows anonymous publish | T2 | CWE-306 | `attacks/mqtt_attack.sh unlock` |
| 3 | SQL injection in `/login` | T3 | CWE-89 | `sqlmap --dump` on login endpoint |
| 4 | Default credentials (`admin/admin`) | T3 | CWE-798 | login form |
| 5 | No CSRF protection on `/command` | T4 | CWE-352 | `attacks/csrf_poc.html` |
| 6 | Unauthenticated `/api/devices` | T5 | CWE-306 | `curl /api/devices` |
| 7 | Plaintext passwords in SQLite `users` table | T3 | CWE-256 | sqlmap dump |
| 8 | Weak `app.secret_key` | — | CWE-330 | `web/app.py` |

Full attack documentation and screenshots are in `attacks/README.md`.

## Coursework 2 — layered defenses

The `cw2-defense` branch adds four defenses, each targeting one or more of the threats above.

| Defense | Module | Mitigates | Status |
|---------|--------|-----------|--------|
| D1 | MQTT TLS + mutual client certificates | T1, T2 | complete |
| D2 | AI-driven intrusion detection system | residual T2, T4, DoS | in progress |
| D3 | Web panel hardening (parameterized SQL, CSRF tokens, TOTP MFA) | T3, T4, T5 | in progress |
| D4 | Signed update packages (Ed25519) | supply-chain | in progress |

Full defense documentation and evidence are in `defense/README.md`.

## Project structure

```
Security_and_privacy_Group_8/
├── README.md                  # this file
├── docker-compose.yml         # orchestration
├── broker/
│   ├── mosquitto.conf         # MQTT broker config (TLS on cw2-defense)
│   └── acl.conf               # per-identity ACL (cw2-defense only)
├── devices/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── simulator.py           # smart lock, light, alarm simulator
├── web/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                 # Flask management panel
├── attacks/                   # CW1 attack scripts and evidence
│   ├── README.md
│   ├── mqtt_attack.sh
│   ├── csrf_poc.html
│   ├── captures/
│   ├── screenshots/
│   └── recordings/
├── defense/                   # CW2 defense code and evidence
│   ├── README.md
│   ├── gen_certs.sh           # D1 TLS certificate generation
│   ├── certs/                 # generated certificates (.key gitignored)
│   ├── d2_ids/                # D2 intrusion detection
│   ├── d4_signing/            # D4 signed updates
│   ├── captures/
│   ├── screenshots/
│   └── recordings/
└── Sec_Plan.ipynb             # team planning notebook
```

## Team

| Member | Module | Responsibility |
|--------|--------|----------------|
| A | MQTT security | MQTT sniffing + injection attacks (CW1); TLS + mutual certificate defense D1 (CW2) |
| B | Web security | SQLi / CSRF / unauthenticated API attacks (CW1); parameterized queries + CSRF tokens + TOTP MFA defense D3 (CW2) |
| C | IDS | Risk matrix + STRIDE model (CW1); anomaly detection with Isolation Forest defense D2 (CW2) |
| D | Architecture & integration | System architecture + report integration (CW1); Ed25519 signed update packages defense D4 + final report (CW2) |

## Related links

- **Presentation video:** *(to be added — see top of the report template)*
- **Coursework report (PDF):** *(to be added at submission time)*
