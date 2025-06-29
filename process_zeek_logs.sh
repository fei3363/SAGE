#!/bin/bash
# process_zeek_logs.sh - Convert Zeek logs and run SAGE with organized output
set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 zeek_logs_dir experiment_name [sage_options]"
    exit 1
fi

ZEEK_DIR="$1"
EXP_NAME="$2"
shift 2
SAGE_OPTIONS="$@"

# 取得 SAGE 目錄的絕對路徑
SAGE_DIR=$(pwd)

# 建立專案資料夾
PROJECT_DIR="${EXP_NAME}_project"
echo "Creating project directory: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR"

# 在專案資料夾內建立子資料夾
ALERTS_DIR="$PROJECT_DIR/alerts"
GRAPHS_DIR="$PROJECT_DIR/attack_graphs"
LOGS_DIR="$PROJECT_DIR/logs"
OUTPUTS_DIR="$PROJECT_DIR/outputs"

mkdir -p "$ALERTS_DIR"
mkdir -p "$GRAPHS_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$OUTPUTS_DIR"

# 轉換 Zeek logs 到 SAGE 格式
echo "Converting Zeek logs to SAGE format..."
python3 zeek_to_sage.py "$ZEEK_DIR" "$ALERTS_DIR/${EXP_NAME}_alerts.json"

# 執行 SAGE 分析
echo "Running SAGE analysis..."
cd "$PROJECT_DIR"
# 建立 FlexFringe 的符號連結
ln -sf "$SAGE_DIR/FlexFringe" FlexFringe
# 使用絕對路徑執行 sage.py
python3 "$SAGE_DIR/sage.py" "alerts" "$EXP_NAME" --dataset zeek --keep-files $SAGE_OPTIONS
# 清理符號連結
rm -f FlexFringe
cd "$SAGE_DIR"

# 移動產生的檔案到正確的資料夾
echo "Organizing output files..."

# 移動攻擊圖
if [ -d "$PROJECT_DIR/${EXP_NAME}AGs" ]; then
    echo "Moving attack graphs..."
    mv "$PROJECT_DIR/${EXP_NAME}AGs"/* "$GRAPHS_DIR/" 2>/dev/null || true
    rmdir "$PROJECT_DIR/${EXP_NAME}AGs"
fi

# 移動其他輸出檔案（如直方圖、模型檔案等）
for file in "$PROJECT_DIR"/*.png "$PROJECT_DIR"/*.pdf "$PROJECT_DIR"/*.dot "$PROJECT_DIR"/*.json; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        # 根據檔案類型移動到適當資料夾
        case "$filename" in
            *histogram*|*plot*)
                mv "$file" "$OUTPUTS_DIR/"
                ;;
            *.dot)
                mv "$file" "$GRAPHS_DIR/"
                ;;
            *)
                mv "$file" "$OUTPUTS_DIR/"
                ;;
        esac
    fi
done

# 移動日誌檔案
for logfile in "$PROJECT_DIR"/*.log "$PROJECT_DIR"/*.txt; do
    if [ -f "$logfile" ] && [ "$logfile" != "$PROJECT_DIR/summary.txt" ]; then
        mv "$logfile" "$LOGS_DIR/"
    fi
done

# 移動模型檔案
if [ -d "$PROJECT_DIR/S-PDFA" ]; then
    mv "$PROJECT_DIR/S-PDFA" "$OUTPUTS_DIR/"
fi

# 產生摘要報告
SUMMARY_FILE="$PROJECT_DIR/summary.txt"
echo "=== SAGE Analysis Summary ===" > "$SUMMARY_FILE"
echo "Experiment Name: $EXP_NAME" >> "$SUMMARY_FILE"
echo "Date: $(date)" >> "$SUMMARY_FILE"
echo "Input Directory: $ZEEK_DIR" >> "$SUMMARY_FILE"
echo "SAGE Options: $SAGE_OPTIONS" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Output Structure:" >> "$SUMMARY_FILE"
echo "  - Alerts: $ALERTS_DIR" >> "$SUMMARY_FILE"
echo "  - Attack Graphs: $GRAPHS_DIR" >> "$SUMMARY_FILE"
echo "  - Logs: $LOGS_DIR" >> "$SUMMARY_FILE"
echo "  - Outputs: $OUTPUTS_DIR" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# 統計資訊
if [ -d "$GRAPHS_DIR" ]; then
    AG_COUNT=$(find "$GRAPHS_DIR" -name "*.dot" -o -name "*.png" -o -name "*.pdf" 2>/dev/null | wc -l)
    echo "Generated attack graphs: $AG_COUNT files" >> "$SUMMARY_FILE"
fi

if [ -d "$OUTPUTS_DIR" ]; then
    OUTPUT_COUNT=$(find "$OUTPUTS_DIR" -type f 2>/dev/null | wc -l)
    echo "Other output files: $OUTPUT_COUNT files" >> "$SUMMARY_FILE"
fi

# 顯示完成訊息
echo ""
echo "========================================="
echo "Analysis completed successfully!"
echo "All results saved in: $PROJECT_DIR/"
echo ""
echo "Directory structure:"
echo "  $PROJECT_DIR/"
echo "  ├── alerts/          # Alert JSON files"
echo "  ├── attack_graphs/   # Generated attack graphs"
echo "  ├── logs/            # Processing logs" 
echo "  ├── outputs/         # Other outputs (histograms, models, etc.)"
echo "  └── summary.txt      # Analysis summary"
echo "========================================="