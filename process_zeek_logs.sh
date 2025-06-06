#!/bin/bash
# process_zeek_logs.sh - Convert Zeek logs and run SAGE
set -e
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 zeek_logs_dir experiment_name [sage_options]"
    exit 1
fi
ZEEK_DIR="$1"
EXP_NAME="$2"
shift 2
SAGE_OPTIONS="$@"

python3 zeek_to_sage.py "$ZEEK_DIR" "${EXP_NAME}_alerts.json"
ALERT_DIR="${EXP_NAME}_alerts"
mkdir -p "$ALERT_DIR"
mv "${EXP_NAME}_alerts.json" "$ALERT_DIR/"
python3 sage.py "$ALERT_DIR" "$EXP_NAME" --dataset zeek --keep-files $SAGE_OPTIONS

echo "Done. Attack graphs in ${EXP_NAME}AGs/"
