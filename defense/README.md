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
| D2 | AI-driven IDS | residual T2, DoS | Statistical thresholds + Isolation Forest anomaly detection on MQTT traffic | complete |
| D3 | Web panel hardening | T3, T4, T5 | Parameterized queries, CSRF tokens, bcrypt hashing, TOTP MFA | complete |
| D4 | Signed configuration updates | Supply-chain | Ed25519 signature verification with graceful fallback | complete |

## Folder structure

```
defense/
├── README.md                          # this file
├── gen_certs.sh                       # D1 certificate generation script
├── verify_web_hardening.sh            # D3 automated validation script
├── certs/                             # D1 TLS material (.key files gitignored)
│   ├── ca.crt, ca.key, ca.srl
│   ├── broker.crt, broker.key
│   ├── device_simulator.crt/.key
│   ├── web_panel.crt/.key
│   └── ids_monitor.crt/.key
├── d2_ids/                            # D2 intrusion detection system
│   ├── ids.py                         # three-layer anomaly detection engine
│   ├── Dockerfile
│   └── requirements.txt              # paho-mqtt, numpy, scikit-learn
├── d4_signing/                        # D4 signing tools
│   ├── gen_keys.py
│   ├── sign_update.py
│   ├── verify_update.py
│   ├── public_key.pem
│   ├── private_key.pem               # gitignored
│   └── requirements.txt
├── captures/
│   └── mqtt_tls.pcap
├── screenshots/                       # defense effectiveness evidence
│   ├── cw2_evidence_01–04             # D1 evidence (4 screenshots)
│   ├── cw2_evidence_d2_01–03          # D2 evidence (3 screenshots)
│   ├── cw2_evidence_d3_01–06          # D3 evidence (6 screenshots)
│   └── cw2_evidence_d4_01–02          # D4 evidence (2 screenshots)
└── recordings/
```

---

## Defense 1 — MQTT TLS with mutual client certificates

**Status:** complete. **Mitigates:** T1 (plaintext eavesdropping), T2 (command injection).

### What changed

1. Mosquitto broker now listens **only on port 8883** (TLS). Port 1883 is closed.
2. `require_certificate true` forces every client to present a certificate signed by the SmartNest CA during the TLS handshake. Clients without a valid certificate are rejected before the MQTT layer is reached.
3. `use_identity_as_username true` maps the certificate's CN field to the MQTT username, which enables per-identity ACLs defined in `broker/acl.conf`. Each identity has the minimum set of topics it needs: devices can only publish to their own status topics, the web panel can publish commands but not device state, and the IDS monitor has read-only access plus write to `home/alert`.
4. `devices/simulator.py` and `web/app.py` load their client certificate at startup via `paho.mqtt.Client.tls_set()` with strict hostname verification.

### Setup

```bash
cd defense
./gen_certs.sh
cd ..
docker compose down
docker compose up --build
```

A successful startup shows the TLS cipher suite being negotiated:

```
Client device_simulator negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
Client web_panel       negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
Client ids_monitor     negotiated TLSv1.2 cipher ECDHE-RSA-AES256-GCM-SHA384
```

### Verification

```bash
cd attacks
./mqtt_attack.sh eavesdrop      # fails: Protocol error
./mqtt_attack.sh unlock         # fails: certificate verify failed
```

Broker logs show rejection at the TLS handshake stage:

```
OpenSSL Error: error:0A000418:SSL routines::tlsv1 alert unknown ca
Client 172.x.x.x disconnected: Protocol error.
```

### Evidence

| File | Shows |
|------|-------|
| `cw2_evidence_01_wireshark_tls_encrypted.png` | Wireshark: only encrypted Application Data |
| `cw2_evidence_02_broker_rejects_no_cert.png` | Broker log rejecting uncertified client |
| `cw2_evidence_03_three_attack_attempts_failed.png` | Three attack attempts all fail |
| `cw2_evidence_04_dashboard_unchanged.png` | Dashboard unchanged after attacks |

---

## Defense 2 — AI-driven intrusion detection system

**Status:** complete. **Mitigates:** residual T2 (compromised device certificate), flood-based DoS.

**Threat model:** Even after D1 closes the anonymous-access path, an attacker who compromises a legitimate client certificate (e.g. the web panel's private key) can still publish arbitrary commands through the broker. D2 addresses this residual risk with a separate monitoring container that detects anomalous traffic patterns in real time.

### Architecture

The IDS runs as a fourth Docker container (`smartnest-ids`) that connects to the broker using its own `ids_monitor` client certificate with a read-only ACL for `home/#` and write access to `home/alert` only. It operates in three phases:

**Phase 1 — Baseline collection (60 seconds).** The IDS records message counts per topic per 10-second sliding window, building a statistical profile of normal traffic: per-topic mean and standard deviation, active topic count, and command frequency.

**Phase 2 — Model training.** After baseline collection, the IDS trains a scikit-learn Isolation Forest on feature vectors extracted from the baseline windows: `[total_message_rate, command_rate, active_topics]`. The model learns the "shape" of normal traffic and can flag deviations that simple thresholds might miss.

**Phase 3 — Real-time detection.** Every 10-second window is evaluated by three detection layers:

| Layer | Method | Detects |
|-------|--------|---------|
| Statistical thresholds | Per-topic rate vs baseline mean + 3σ | Brute-force flood attacks |
| Command frequency | Command topic burst count > threshold | Unauthorized command injection |
| Isolation Forest | Multi-dimensional anomaly score | Novel attack patterns |

When any layer flags an anomaly, the IDS publishes a structured JSON alert to `home/alert`. The web dashboard subscribes to this topic and renders a **red alert banner** at the top of the page showing the alert type, detail, and timestamp.

### Setup

The IDS container is defined in `docker-compose.yml` and starts automatically:

```bash
docker compose up --build
```

After 60 seconds, the IDS logs:

```
[IDS] Computing baseline from 60s of traffic...
[IDS]   home/lock/status: mean=1.0, std=0.0 msgs/window
[IDS]   home/light/status: mean=1.2, std=0.4 msgs/window
[IDS]   home/alarm/status: mean=1.2, std=0.4 msgs/window
[IDS]   home/heartbeat: mean=3.0, std=0.0 msgs/window
[IDS]   Isolation Forest trained on 6 windows, 3 features
[IDS] Baseline ready. Switching to detection mode.
```

### Verification

After the IDS enters detection mode, simulate a compromised web panel certificate launching a command flood:

```bash
docker run --rm --network security_and_privacy_group_8_smartnest \
  -v $(pwd)/defense/certs:/certs:ro \
  eclipse-mosquitto:2 sh -c '
  for i in $(seq 1 30); do
    mosquitto_pub -h broker -p 8883 \
      --cafile /certs/ca.crt \
      --cert /certs/web_panel.crt \
      --key /certs/web_panel.key \
      -t "home/lock/command" \
      -m "{\"action\":\"UNLOCK\",\"issued_by\":\"attacker_$i\"}"
  done'
```

Within 10 seconds, the IDS fires alerts:

```
[ALERT] 00:18:54 !!  [RATE_SPIKE] Topic 'home/lock/command' received 26 msgs in 10s (baseline: 0)
[ALERT] 00:18:54 !!! [COMMAND_FLOOD] Burst of 26 commands on 'home/lock/command' in 10s
```

Refreshing the Dashboard shows a red "IDS Alert — Anomaly Detected" banner with the alert details.

**Note:** The attack uses the `web_panel` certificate (not `device_simulator`) because D1's ACL restricts `device_simulator` to read-only on command topics. This demonstrates that D2 provides defense-in-depth even when D1's ACL is bypassed via a compromised credential.

### Evidence

| File | Shows |
|------|-------|
| `cw2_evidence_d2_01_baseline_trained.png` | Baseline statistics and Isolation Forest training complete |
| `cw2_evidence_d2_02_attack_detected.png` | IDS logs: RATE_SPIKE + COMMAND_FLOOD alerts triggered |
| `cw2_evidence_d2_03_dashboard_alert_banner.png` | Dashboard red banner showing alert details and device compromise |

---

## Defense 3 — Web panel hardening

**Status:** complete. **Mitigates:** T3 (SQLi), T4 (CSRF), T5 (unauthenticated API).

### What changed

1. **Parameterized queries** replace the f-string SQL in the login handler. The original code built queries with `f"SELECT * FROM users WHERE username='{u}'"`, allowing injection payloads like `admin' --` to bypass authentication. The hardened version uses `cursor.execute("SELECT ... WHERE username=?", (u,))`, which treats user input as data rather than SQL syntax.

2. **bcrypt password hashing** replaces plaintext storage. On first startup after migration, `init_db()` detects legacy plaintext passwords and automatically hashes them with bcrypt. New accounts are created with hashed passwords from the start. Even if an attacker dumps the `users` table, they obtain bcrypt hashes rather than reusable credentials.

3. **Flask-WTF CSRF tokens** are injected into every state-changing form via a hidden input field. The server validates the token on every POST. Requests without a valid token — including those from the CW1 CSRF proof-of-concept (`attacks/csrf_poc.html`) — receive HTTP 400 with a "Request Blocked" page.

4. **TOTP multi-factor authentication** adds a second factor (something you have, per Week 4's authentication taxonomy). On first login, users are shown a QR code generated by `pyotp` and `qrcode`. After scanning with any RFC 6238 compatible authenticator (Google Authenticator, Microsoft Authenticator, Authy), the TOTP secret is stored in the database. Subsequent logins require both the password and a valid 6-digit code that changes every 30 seconds. Even if an attacker obtains the password through social engineering or SQL injection, they cannot complete authentication without physical access to the enrolled device.

5. **Route-level authorization** ensures that `/api/devices` and `/command` check for an active session before responding, eliminating T5.

### Setup

```bash
docker compose down
docker compose up --build
```

On first login (`admin` / `admin`), the panel redirects to `/verify-totp` and displays a QR code. Scan it with an authenticator app, enter the 6-digit code, and enrollment is complete.

To reset TOTP enrollment for a clean demo:

```bash
docker exec -it smartnest-web python -c \
  "import sqlite3; conn=sqlite3.connect('/tmp/smartnest.db'); \
   conn.execute(\"UPDATE users SET totp_secret=NULL WHERE username='admin'\"); \
   conn.commit(); conn.close()"
```

### Verification

**Automated check:**

```bash
chmod +x defense/verify_web_hardening.sh
./defense/verify_web_hardening.sh
```

**Manual checks:**

1. **SQLi blocked** — enter `admin' --` as username → "Invalid credentials"
2. **sqlmap fails** — sqlmap reports parameters not injectable
3. **CSRF blocked** — open `attacks/csrf_poc.html` → "Request Blocked" (HTTP 400)
4. **TOTP required** — log in with `admin` / `admin` → redirected to 6-digit code prompt
5. **Dashboard functional** — after completing TOTP, dashboard works normally

### Evidence

| File | Shows |
|------|-------|
| `cw2_evidence_d3_01_sqli_blocked.png` | `admin' --` login bypass fails |
| `cw2_evidence_d3_02_sqlmap_not_injectable.png` | sqlmap reports parameters not injectable |
| `cw2_evidence_d3_03_csrf_blocked.png` | CSRF PoC request rejected (HTTP 400) |
| `cw2_evidence_d3_04_totp_enrollment.png` | First-time TOTP QR code enrollment |
| `cw2_evidence_d3_05_totp_login.png` | Subsequent login requires 6-digit code |
| `cw2_evidence_d3_06_dashboard_functional.png` | Dashboard fully functional after hardening |

---

## Defense 4 — Signed configuration updates

**Status:** complete. **Mitigates:** supply-chain tampering.

**Threat model:** In the baseline implementation, simulator parameters such as `broker_host` are read from `devices/config.json` with no integrity check. An attacker with filesystem access could silently change `broker_host` to `evil.attacker.com` and the simulator would connect to a malicious broker. D4 closes this gap with cryptographically signed configuration packages.

### What changed

1. `devices/config.json` externalises simulator parameters (`broker_host`, `broker_port`, `report_interval`, `device_ids`) that were previously hard-coded.
2. `defense/d4_signing/gen_keys.py` generates an Ed25519 key pair. The **private key never leaves the developer workstation**; only the public key is pinned into the simulator's trust store.
3. `defense/d4_signing/sign_update.py` signs `config.json` with the private key, producing a detached `config.json.sig` file.
4. `devices/simulator.py` runs `verify_config_signature()` **at startup**, before any configuration value is read, using the pinned public key at `/keys/public_key.pem`.
5. If verification fails — missing signature, tampered content, missing public key — the simulator logs the failure, refuses to load the untrusted configuration, and **falls back to safe defaults** baked into the image. This graceful degradation preserves availability while preventing an attacker from influencing the simulator's behaviour.

### Setup

```bash
cd defense/d4_signing
python -m venv venv
source venv/bin/activate          # macOS / Linux
pip install -r requirements.txt
python gen_keys.py                # generate key pair (once per clone)
python sign_update.py ../../devices/config.json
```

Both `private_key.pem` and `*.sig` files are gitignored and must be regenerated locally after cloning. `public_key.pem` is committed because the simulator needs it to verify signatures.

**Important:** If you modify `devices/config.json`, you must regenerate `devices/config.json.sig` by running `python sign_update.py ../../devices/config.json` and commit both files together.

### Verification

**Case 1 — authentic configuration loads normally.**

```
smartnest-devices  | [CONFIG] Signature verified — /app/config.json is authentic
smartnest-devices  | Broker: broker:8883
smartnest-devices  | [MQTT] Connected to broker at broker:8883
```

**Case 2 — tampered configuration is rejected with graceful fallback.**

```bash
sed -i '' 's/"broker"/"evil.attacker.com"/' devices/config.json
docker compose up --build
```

```
smartnest-devices  | [CONFIG] SIGNATURE VERIFICATION FAILED: InvalidSignature
smartnest-devices  | [CONFIG] Refusing to load untrusted configuration
smartnest-devices  | [CONFIG] Falling back to safe defaults
smartnest-devices  | Broker: broker:8883                ← NOT evil.attacker.com
```

### Evidence

| File | Shows |
|------|-------|
| `cw2_evidence_d4_01_simulator_verify_ok.png` | Simulator startup: signature verified |
| `cw2_evidence_d4_02_tampered_rejected_with_fallback.png` | Tampered config rejected, safe-default fallback |
