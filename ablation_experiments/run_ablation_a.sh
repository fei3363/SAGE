#!/bin/bash
# Ablation Study Version A: No Event Abstraction
# This script runs SAGE without event abstraction mapping

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BASE_DIR="/home/fei/SAGE"
ATTACK_PATH="/home/fei/Downloads/modbus2023_attack_packets"

# Test with False Injection attack (medium complexity)
ATTACK_TYPE="Falseinjection"
ATTACK_NAME="ablation_a_false_injection"

echo "=== Ablation Study Version A: No Event Abstraction ==="
echo "Testing with: $ATTACK_TYPE"
echo

# Step 1: Use existing Zeek logs
ZEEK_LOG_PATH="$ATTACK_PATH/$ATTACK_TYPE"
if [ ! -d "$ZEEK_LOG_PATH" ]; then
    echo "Error: Zeek logs not found at $ZEEK_LOG_PATH"
    exit 1
fi

# Step 2: Run modified SAGE (Version A)
cd "$SCRIPT_DIR/version_a"
echo "Running SAGE Version A (no event abstraction)..."

# Create output directory
OUTPUT_DIR="$BASE_DIR/ablation_experiments/results_a"
mkdir -p "$OUTPUT_DIR"

# Run SAGE with the modified version
python3 sage.py \
    --input_dir "$ATTACK_PATH/$ATTACK_TYPE" \
    --project_name "$ATTACK_NAME" \
    --output_dir "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/ablation_a_log.txt"

echo
echo "=== Version A Results ==="
echo "Check output in: $OUTPUT_DIR"

# Count unique event types (raw signatures)
if [ -f "$OUTPUT_DIR/${ATTACK_NAME}_alerts.json" ]; then
    echo -n "Unique raw signatures: "
    python3 -c "
import json
with open('$OUTPUT_DIR/${ATTACK_NAME}_alerts.json', 'r') as f:
    alerts = json.load(f)
    sigs = set(a['sig'] for a in alerts if 'sig' in a)
    print(len(sigs))
    "
fi

# Check model complexity
if [ -f "$OUTPUT_DIR/${ATTACK_NAME}.model" ]; then
    echo -n "Model states: "
    grep -c "^state" "$OUTPUT_DIR/${ATTACK_NAME}.model" || echo "N/A"
fi

echo "Ablation A completed."