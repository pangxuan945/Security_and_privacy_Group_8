# SmartNest Attack Toolkit (CW1)

This folder contains attack scripts and evidence for **Coursework 1: Threat Modeling & Attack Simulation**.

All attacks target the baseline (vulnerable) SmartNest configuration on the `main` branch. The hardened version on `cw2-defense` blocks every attack in this folder — see `defense/README.md` for the corresponding mitigations and evidence.

## Folder structure

```
attacks/
├── README.md                  # this file
├── mqtt_attack.sh             # MQTT eavesdrop + injection attacks (T1, T2)
├── csrf_poc.html              # CSRF proof of concept (T4)
├── captures/
│   └── mqtt_capture.pcap      # plaintext MQTT traffic captured with tcpdump
├── screenshots/               # evidence captures for the report
│   ├── cw1_evidence_00_mqtt_subscriber_plaintext.png
│   ├── cw1_evidence_01_mqtt_sniffing.png
│   ├── cw1_evidence_02_unlock_injection.png
│   ├── cw1_evidence_03_dashboard_last_user.png
│   ├── cw1_evidence_04_sqli_login_bypass.png
│   ├── cw1_evidence_05_sqlmap_confirm.png
│   ├── cw1_evidence_06_sqlmap_dump_users_01.png
│   ├── cw1_evidence_06_sqlmap_dump_users_02.png
│   └── cw1_evidence_07_csrf_unlock_dashboard.png
└── recordings/
    └── cw1_attack1_unlock_injection_demo.mov
```

## Prerequisites

The SmartNest stack must be running on the **baseline configuration** (plaintext MQTT on port 1883, vulnerable Flask panel on 5001):

```bash
cd ..
git checkout main             # baseline vulnerable version
docker compose up -d
```

Verify the network name used inside the script:

```bash
docker network ls | grep smartnest
```

If your network name is different, edit the `NETWORK` variable at the top of `mqtt_attack.sh`.

## Attack 1 — MQTT eavesdropping & command injection (T1, T2)

### Quick demos

```bash
./mqtt_attack.sh                 # show menu
./mqtt_attack.sh eavesdrop       # passively sniff all traffic
./mqtt_attack.sh unlock          # forge an UNLOCK command (no auth)
./mqtt_attack.sh alarm           # tamper with morning alarm
./mqtt_attack.sh flood           # rapid toggle DoS on the light
./mqtt_attack.sh all             # run unlock + alarm + flood in sequence
```

### Verifying the compromise

After running `unlock`, refresh the dashboard at `http://localhost:5001`:

- **State** changes from `LOCKED` to `UNLOCKED`
- **Last user** changes to `attacker`

The attacker never supplied any credential and never touched the web panel.

## Attack 2 — Web panel SQL injection & CSRF (T3, T4, T5)

### SQL injection login bypass

In the login form at `http://localhost:5001/login`:

- Username: `' OR '1'='1' --`
- Password: anything

The server returns a 302 redirect to `/dashboard` — full admin takeover without credentials.

### Automated exploitation with sqlmap

```bash
sqlmap -u "http://localhost:5001/login" \
       --data="username=a&password=b" --dump
```

sqlmap confirms boolean-based blind SQLi on the `username` parameter and dumps the `users` table, revealing plaintext credentials (`admin/admin`, `guest/guest123`).

### CSRF proof of concept

Open `csrf_poc.html` in a browser while logged into SmartNest in another tab. The page auto-submits a POST to `/command` with `device=lock&action=UNLOCK`, and the server accepts it because the session cookie is attached automatically. No CSRF token is required.

### Unauthenticated device API

```bash
curl -s http://localhost:5001/api/devices | jq
```

Returns the full device state JSON, including `last_user`, `alarm_time`, and lock history, without any authentication.

## Mapping to threats

| Attack | Threat | STRIDE |
|--------|--------|--------|
| `mqtt_attack.sh eavesdrop` | T1 | Information Disclosure |
| `mqtt_attack.sh unlock` | T2 | Spoofing + Tampering |
| SQLi login bypass | T3 | Elevation of Privilege + Info Disclosure |
| `csrf_poc.html` | T4 | Tampering (session riding) |
| `curl /api/devices` | T5 | Information Disclosure |