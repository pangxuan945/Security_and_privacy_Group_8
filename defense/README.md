# SmartNest Defense Suite (CW2)

This folder contains the layered defense implementation for **Coursework 2: Security & Privacy Defense Strategy**. Each defense directly mitigates one or more threats identified in CW1.

All defenses run on the `cw2-defense` branch. To switch between the vulnerable baseline and the hardened version:

```bash
docker compose down
git checkout main               # vulnerable baseline (CW1 attacks work)
git checkout cw2-defense        # hardened version (all attacks blocked)
docker compose up --build
```

## Defense → Threat coverage

| Defense | Module | Mitigates | Primary technique |
|---------|--------|-----------|-------------------|
| D1 | MQTT TLS + mutual certs | T1, T2 | Transport encryption, client certificate authentication, per-identity ACL |
| D2 | AI-driven IDS | T2 residual, T4, DoS | Isolation Forest anomaly detection on MQTT traffic |
| D3 | Web panel hardening | T3, T4, T5 | Parameterized queries, CSRF tokens, TOTP multi-factor auth, route-level authorization |
| D4 | Signed update packages | Supply-chain | Ed25519 signature verification |

## Folder structure

```
defense/
├── README.md                          # this file
├── gen_certs.sh                       # D1 certificate generation
├── certs/                             # generated TLS material (.key files gitignored)
│   ├── ca.crt, ca.key, ca.srl         # SmartNest root CA
│   ├── broker.crt, broker.key         # Mosquitto server certificate
│   ├── device_simulator.crt/.key      # device client certificate
│   ├── web_panel.crt/.key             # web panel client certificate
│   └── ids_monitor.crt/.key           # IDS client certificate (read-only ACL)
├── d2_ids/                            # D2 Intrusion Detection System
│   └── (populated by team member C)
├── d4_signing/                        # D4 signed update package verification
│   └── (populated by team member D)
├── captures/
│   └── mqtt_tls.pcap                  # post-defense Wireshark capture (all encrypted)
├── screenshots/                       # defense effectiveness evidence
│   ├── cw2_evidence_01_wireshark_tls_encrypted.png
│   ├── cw2_evidence_02_broker_rejects_no_cert.png
│   ├── cw2_evidence_03_three_attack_attempts_failed.png
│   └── cw2_evidence_04_dashboard_unchanged.png
└── recordings/                        # defense demo videos
```

## Defense 1 — MQTT TLS with mutual client certificates

**Mitigates:** T1 (plaintext eavesdropping), T2 (command injection).

### What changed

1. Mosquitto broker now listens **only on port 8883** (TLS). Port 1883 is closed.
2. `require_certificate true` forces every client to present a certificate signed by the SmartNest CA during the TLS handshake.
3. `use_identity_as_username true` maps the certificate's CN field to the MQTT username, which enables per-identity ACLs defined in `broker/acl.conf`.
4. `devices/simulator.py` and `web/app.py` load their client certificate at startup via `paho.mqtt.Client.tls_set()`.

### Setup

```bash
cd defense
./gen_certs.sh                  # generate CA + server + client certificates
cd ..
docker compose down
docker compose up --build
```

Successful startup shows the TLS cipher suite being negotiated:

```
Client device_simulator negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
Client web_panel       negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
```

`ECDHE` provides forward secrecy; `AES256-GCM` provides authenticated encryption; `SHA384` is the HMAC for handshake integrity.

### Verification

Re-run every CW1 MQTT attack against the hardened broker:

```bash
cd ../attacks
./mqtt_attack.sh eavesdrop      # fails: Protocol error (no valid certificate)
./mqtt_attack.sh unlock         # fails: certificate verify failed
```

Broker logs show the rejection at the TLS handshake stage, before the MQTT layer is reached:

```
OpenSSL Error while trying to get the error[0]:
    error:0A000418:SSL routines::tlsv1 alert unknown ca
Client 172.x.x.x disconnected: Protocol error.
```

A packet capture with `tcpdump -i any -w tls.pcap port 8883` shows only `TLSv1.2 Application Data` frames — no plaintext JSON is ever visible on the wire.

### Evidence screenshots

| File | Shows |
|------|-------|
| `screenshots/cw2_evidence_01_wireshark_tls_encrypted.png` | Wireshark with only encrypted Application Data |
| `screenshots/cw2_evidence_02_broker_rejects_no_cert.png` | Broker log rejecting a client with no certificate |
| `screenshots/cw2_evidence_03_three_attack_attempts_failed.png` | Terminal output of three failed attack attempts |
| `screenshots/cw2_evidence_04_dashboard_unchanged.png` | Dashboard unchanged after attack attempts |

## Defense 2 — AI-driven Intrusion Detection System

**Status:** in progress (team member C).

**Mitigates:** residual T2 (if a device certificate is leaked), T4 (CSRF), flood-based DoS.

**Approach:** A separate `ids_monitor` container subscribes read-only to `home/#` using its own client certificate (read-only ACL). It collects a baseline of normal message rates and trains an Isolation Forest model; at runtime it flags anomalous traffic patterns (publish rate spikes, unknown client IDs, commands outside normal time windows) and raises alerts on `home/alert`, which the web dashboard renders as a red warning banner.

Implementation files will be added to `d2_ids/` when complete.

## Defense 3 — Web panel hardening

**Status:** in progress (team member B).

**Mitigates:** T3 (SQLi), T4 (CSRF), T5 (unauthenticated API).

**Approach:**

1. **Parameterized queries** replace the f-string SQL in the login handler, eliminating T3.
2. **bcrypt password hashing** removes plaintext credentials from the `users` table.
3. **Flask-WTF CSRF tokens** on every state-changing POST, plus `SameSite=Strict` cookies, eliminate T4.
4. **TOTP multi-factor authentication** via `pyotp` adds a second authentication pillar (something you have, per Week 4's authentication taxonomy).
5. **`@login_required` decorator** on `/api/devices` and `/command` eliminates T5.

The code changes live directly in `web/app.py` on the `cw2-defense` branch.

## Defense 4 — Signed update packages

## Defense 4 — Signed update packages

**Mitigates:** supply-chain threats (malicious configuration or firmware updates).

**Approach:** An Ed25519 key pair is used to sign the device configuration bundle (`config.json`). The simulator refuses to load any configuration whose signature cannot be verified against the public key, preventing an attacker from injecting a malicious broker address or altered parameters.

### What changed

1. `devices/config.json` externalises key simulator parameters (`broker_host`, `broker_port`, `report_interval`) that were previously hard-coded.
2. `devices/simulator.py` reads these parameters from `config.json` at startup instead of using hard-coded values.
3. `defense/d4_signing/gen_keys.py` generates an Ed25519 private/public key pair.
4. `defense/d4_signing/sign_update.py` signs a configuration file with the private key, producing a `.sig` file.
5. `defense/d4_signing/verify_update.py` verifies the signature before the configuration is trusted. Any tampering causes immediate rejection.

### Setup

```bash
cd defense/d4_signing
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### Demo

```bash
# Step 1 — generate key pair (run once)
python gen_keys.py

# Step 2 — sign the configuration bundle
python sign_update.py config.json

# Step 3 — verify: authentic config passes
python verify_update.py config.json
# [OK] Signature valid. 'config.json' is authentic.
# [OK] Safe to load configuration.

# Step 4 — simulate attacker tampering (edit broker_host to evil.attacker.com)
python verify_update.py config.json
# [FAIL] Signature INVALID. 'config.json' has been tampered with.
# [FAIL] Configuration rejected.
```

### Evidence screenshots

| File | Shows |
|------|-------|
| `screenshots/cw2_evidence_d4_01_valid.png` | Terminal output — valid signature accepted |
| `screenshots/cw2_evidence_d4_02_tampered.png` | Terminal output — tampered config rejected |