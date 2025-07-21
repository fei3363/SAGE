#!/bin/bash
# Measure original SAGE performance on all attack types

set -e

BASE_DIR="/home/fei/SAGE"
ATTACK_PATH="/home/fei/Downloads/modbus2023_attack_packets"
RESULTS_DIR="$BASE_DIR/ablation_experiments/full_results"

mkdir -p "$RESULTS_DIR"

# Initialize timing log
TIMING_LOG="$RESULTS_DIR/original_timing.csv"
echo "Attack,Time(s),Graphs,Alerts,Episodes" > "$TIMING_LOG"

declare -a ATTACKS=(
    "Baselinereplay"
    "Falseinjection"
    "Modifylengthparameters"
    "Reconnaissance"
    "Stackmodbusframes"
    "WriteToAllCoils"
)

echo "=== Measuring Original SAGE Performance ==="

for ATTACK in "${ATTACKS[@]}"; do
    echo "Processing $ATTACK..."
    
    PCAP="$ATTACK_PATH/$ATTACK/1.pcapng"
    if [ ! -f "$PCAP" ]; then
        echo "  Skipping - no PCAP found"
        continue
    fi
    
    # Clean previous results
    rm -rf "$BASE_DIR/project/${ATTACK}_test_project"
    
    # Measure time
    START_TIME=$(date +%s)
    
    # Run SAGE
    cd "$BASE_DIR"
    ./analyze_pcap.sh "$PCAP" "${ATTACK}_test" > "$RESULTS_DIR/${ATTACK}_original.log" 2>&1
    
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    # Count results
    PROJECT_DIR="$BASE_DIR/project/${ATTACK}_test_project"
    GRAPHS=$(find "$PROJECT_DIR/attack_graphs" -name "*.dot" 2>/dev/null | wc -l || echo "0")
    
    # Extract statistics from summary
    if [ -f "$PROJECT_DIR/summary.txt" ]; then
        ALERTS=$(grep "Total alerts:" "$PROJECT_DIR/summary.txt" | awk '{print $3}' || echo "0")
        EPISODES=$(grep "Total episodes:" "$PROJECT_DIR/summary.txt" | awk '{print $3}' || echo "0")
    else
        ALERTS="0"
        EPISODES="0"
    fi
    
    echo "$ATTACK,$ELAPSED,$GRAPHS,$ALERTS,$EPISODES" >> "$TIMING_LOG"
    echo "  Completed in ${ELAPSED}s - Generated $GRAPHS graphs"
done

echo
echo "Results saved to: $TIMING_LOG"