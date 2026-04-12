# SmartNest Attack Toolkit (CW1)

This folder contains attack scripts and evidence for Coursework 1.

## Prerequisites

The SmartNest stack must be running:

```bash
cd ..
docker compose up -d
```

Verify the network name (used inside the script):

```bash
docker network ls | grep smartnest
```

If your network name is different, edit the `NETWORK` variable at the top of `mqtt_attack.sh`.

## Attack 1: MQTT Eavesdropping & Command Injection

### Quick demos

```bash
# Show all available attacks
./mqtt_attack.sh

# Passively sniff every device's traffic in real time
./mqtt_attack.sh eavesdrop

# Forge an UNLOCK command (no auth required!)
./mqtt_attack.sh unlock

# Tamper with the user's morning alarm
./mqtt_attack.sh alarm

# Flood the light with rapid toggles
./mqtt_attack.sh flood

# Run all active attacks in sequence
./mqtt_attack.sh all
```

### Verifying success

After running `unlock`, refresh the dashboard at `http://localhost:5001`:
- **State** should change from `LOCKED` to `UNLOCKED`
- **Last user** should change to `attacker`

## Folder structure

```
attacks/
├── README.md                # this file
├── mqtt_attack.sh           # MQTT eavesdrop + injection attacks
├── screenshots/             # evidence captures
│   ├── cw1_attack1_mqtt_eavesdropping_terminal.png
│   ├── cw1_evidence_01_mqtt_sniffing.png
│   ├── cw1_evidence_02_unlock_injection.png
│   └── cw1_attack1_dashboard_compromised.png
├── captures/
│   └── mqtt_plaintext.pcap  # Wireshark capture of plaintext MQTT
└── recordings/
    └── cw1_attack1_unlock_injection_demo.mov
```
