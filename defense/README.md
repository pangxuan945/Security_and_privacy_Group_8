# SmartNest Defense Suite (CW2)

This folder contains the layered defense implementation for **Coursework 2: Security & Privacy Defense Strategy**. Each defense directly mitigates one or more threats identified in CW1.

All defenses run on the `cw2-defense` branch. To switch between the vulnerable baseline and the hardened version:

```bash
docker compose down
git checkout main               # vulnerable baseline (CW1 attacks work)
git checkout cw2-defense        # hardened version (all attacks blocked)
docker compose up --build
```

## Defense → threat coverage

| Defense | Module | Mitigates | Primary technique | Status |
|---------|--------|-----------|-------------------|--------|
| D1 | MQTT TLS + mutual certs | T1, T2 | Transport encryption, client certificate authentication, per-identity ACL | complete |
| D2 | AI-driven IDS | residual T2, T4, DoS | Isolation Forest anomaly detection on MQTT traffic | in progress |
| D3 | Web panel hardening | T3, T4, T5 | Parameterized queries, CSRF tokens, TOTP MFA, route-level authorization | in progress |
| D4 | Signed configuration updates | Supply-chain | Ed25519 signature verification with graceful fallback | complete |

## Folder structure

```
defense/
├── README.md                          # this file
├── gen_certs.sh                       # D1 certificate generation script
├── certs/                             # D1 TLS material (.key files gitignored)
│   ├── ca.crt, ca.key, ca.srl         # SmartNest root CA
│   ├── broker.crt, broker.key         # Mosquitto server certificate
│   ├── device_simulator.crt/.key      # device client certificate
│   ├── web_panel.crt/.key             # web panel client certificate
│   └── ids_monitor.crt/.key           # IDS client certificate (read-only ACL)
├── d2_ids/                            # D2 intrusion detection (team member C)
├── d4_signing/                        # D4 signing tools
│   ├── gen_keys.py                    # generate Ed25519 key pair
│   ├── sign_update.py                 # sign a file with the private key
│   ├── verify_update.py               # standalone verification tool
│   ├── public_key.pem                 # pinned public key (committed)
│   ├── private_key.pem                # signing key (gitignored)
│   └── requirements.txt
├── captures/
│   └── mqtt_tls.pcap                  # post-defense Wireshark capture (all encrypted)
├── screenshots/                       # defense effectiveness evidence
│   ├── cw2_evidence_01_wireshark_tls_encrypted.png
│   ├── cw2_evidence_02_broker_rejects_no_cert.png
│   ├── cw2_evidence_03_three_attack_attempts_failed.png
│   ├── cw2_evidence_04_dashboard_unchanged.png
│   ├── cw2_evidence_d4_01_simulator_verify_ok.png
│   └── cw2_evidence_d4_02_tampered_rejected_with_fallback.png
└── recordings/                        # defense demo videos
```

## Defense 1 — MQTT TLS with mutual client certificates

**Mitigates:** T1 (plaintext eavesdropping), T2 (command injection).

### What changed

1. Mosquitto broker now listens **only on port 8883** (TLS). Port 1883 is closed.
2. `require_certificate true` forces every client to present a certificate signed by the SmartNest CA during the TLS handshake. Clients without a valid certificate are rejected before the MQTT layer is reached.
3. `use_identity_as_username true` maps the certificate's CN field to the MQTT username, which enables per-identity ACLs defined in `broker/acl.conf`. Each identity has the minimum set of topics it needs: devices can only publish to their own status topics, the web panel can publish commands but not device state, and the IDS monitor has read-only access.
4. `devices/simulator.py` and `web/app.py` load their client certificate at startup via `paho.mqtt.Client.tls_set()` with strict hostname verification.

### Setup

```bash
cd defense
./gen_certs.sh                  # generate CA + server + client certificates
cd ..
docker compose down
docker compose up --build
```

A successful startup shows the TLS cipher suite being negotiated for each client:

```
Client device_simulator negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
Client web_panel       negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
```

`ECDHE` provides forward secrecy, `AES256-GCM` provides authenticated encryption, and `SHA384` is the HMAC for handshake integrity.

### Verification

Re-run every CW1 MQTT attack against the hardened broker:

```bash
cd ../attacks
./mqtt_attack.sh eavesdrop      # fails: Protocol error (no valid certificate)
./mqtt_attack.sh unlock         # fails: certificate verify failed
```

Broker logs show the rejection at the TLS handshake stage:

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

## Defense 2 — AI-driven intrusion detection system

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

## Defense 4 — Signed configuration updates

**Mitigates:** supply-chain tampering — an attacker who compromises the host filesystem and modifies device configuration files to redirect traffic, alter operational parameters, or inject malicious broker addresses.

**Threat model:** In the baseline implementation, simulator parameters such as `broker_host` are read from `devices/config.json` with no integrity check. An attacker with filesystem access could silently change `broker_host` to `evil.attacker.com` and the simulator would obediently connect to a malicious broker, leaking every device command and telemetry stream. D4 closes this gap with cryptographically signed configuration packages.

### What changed

1. `devices/config.json` externalises simulator parameters (`broker_host`, `broker_port`, `report_interval`, `device_ids`) that were previously hard-coded.
2. `defense/d4_signing/gen_keys.py` generates an Ed25519 key pair. The **private key never leaves the developer workstation**; only the public key is pinned into the simulator's trust store.
3. `defense/d4_signing/sign_update.py` signs `config.json` with the private key, producing a detached `config.json.sig` file.
4. `devices/simulator.py` now runs `verify_config_signature()` **at startup**, before any configuration value is read. The verification uses the pinned public key at `/keys/public_key.pem`, mounted read-only into the container from `defense/d4_signing/public_key.pem`.
5. If verification fails for any reason — missing signature, tampered content, missing public key — the simulator logs the failure, refuses to load the untrusted configuration, and **falls back to safe defaults** baked into the image. This graceful degradation preserves availability: the system stays operational and connects to the legitimate broker, but an attacker who tampers with `config.json` cannot influence the simulator's behaviour.

### Setup

```bash
cd defense/d4_signing
python -m venv venv
source venv/bin/activate          # macOS / Linux
# venv\Scripts\activate           # Windows
pip install -r requirements.txt

# Generate key pair (once per clone)
python gen_keys.py

# Sign the current config (regenerate after any config change)
python sign_update.py ../../devices/config.json
```

Both `private_key.pem` and `*.sig` files are gitignored and must be regenerated locally after cloning the repository. `public_key.pem` is committed because the simulator needs it to verify signatures, and its exposure is harmless by design.

### Verification

**Case 1 — authentic configuration loads normally.**

```bash
docker compose up --build
```

```
smartnest-devices  | [CONFIG] Signature verified — /app/config.json is authentic
smartnest-devices  | SmartNest IoT Device Simulator
smartnest-devices  | Broker: broker:8883
smartnest-devices  | [MQTT] Connected to broker at broker:8883
```

**Case 2 — tampered configuration is rejected with graceful fallback.**

```bash
docker compose down
# Simulate attacker: redirect broker to a malicious host
sed -i '' 's/"broker"/"evil.attacker.com"/' devices/config.json
docker compose up --build
```

```
smartnest-devices  | [CONFIG] SIGNATURE VERIFICATION FAILED: InvalidSignature
smartnest-devices  | [CONFIG] Refusing to load untrusted configuration
smartnest-devices  | [CONFIG] Falling back to safe defaults
smartnest-devices  | SmartNest IoT Device Simulator
smartnest-devices  | Broker: broker:8883                         ← NOT evil.attacker.com
smartnest-devices  | [MQTT] Connected to broker at broker:8883
```

The attacker's modification is detected, the tampered configuration is rejected, and the simulator connects to the legitimate broker using hard-coded defaults from the container image. Restoring `devices/config.json` to its signed state returns the system to normal operation.

The standalone tools `sign_update.py` and `verify_update.py` can also be used interactively for demonstration purposes, but the production integration is the startup-time check inside `simulator.py`.

### Evidence screenshots

| File | Shows |
|------|-------|
| `screenshots/cw2_evidence_d4_01_simulator_verify_ok.png` | Simulator startup log: `Signature verified — config.json is authentic` |
| `screenshots/cw2_evidence_d4_02_tampered_rejected_with_fallback.png` | Simulator startup log: tampered config rejected, fallback to safe defaults, system continues running |