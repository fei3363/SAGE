#!/bin/bash

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 顯示使用說明
usage() {
    echo "使用方法："
    echo "  $0 <PCAP檔案路徑> <攻擊名稱> [Zeek腳本路徑]"
    echo ""
    echo "參數："
    echo "  PCAP檔案路徑    - PCAP/PCAPNG 檔案的絕對路徑"
    echo "  攻擊名稱        - 用於產生攻擊圖的名稱"
    echo "  Zeek腳本路徑    - (選擇性) Zeek 腳本路徑，預設使用 ~/SAGE/zeek/ot_alert_filter_all_v1.0.zeek"
    echo ""
    echo "範例："
    echo "  $0 /home/fei/attack.pcapng my_attack"
    echo "  $0 /path/to/capture.pcap modbus_attack /custom/zeek/script.zeek"
    echo ""
    exit 1
}

# 檢查參數
if [ $# -lt 2 ]; then
    usage
fi

# 取得參數
PCAP_FILE="$1"
ATTACK_NAME="$2"
ZEEK_SCRIPT="${3:-$HOME/SAGE/zeek/ot_alert_filter_all_v1.0.zeek}"

# 定義路徑
SAGE_PATH="$HOME/SAGE"

# 檢查檔案是否存在
if [ ! -f "$PCAP_FILE" ]; then
    echo -e "${RED}錯誤：找不到 PCAP 檔案: $PCAP_FILE${NC}"
    exit 1
fi

if [ ! -f "$ZEEK_SCRIPT" ]; then
    echo -e "${RED}錯誤：找不到 Zeek 腳本: $ZEEK_SCRIPT${NC}"
    exit 1
fi

if [ ! -f "$SAGE_PATH/process_zeek_logs.sh" ]; then
    echo -e "${RED}錯誤：找不到 $SAGE_PATH/process_zeek_logs.sh${NC}"
    exit 1
fi

# 取得 PCAP 檔案的目錄和檔名
PCAP_DIR=$(dirname "$PCAP_FILE")
PCAP_FILENAME=$(basename "$PCAP_FILE")

# 建立時間統計報告檔案
REPORT_FILE="${PCAP_DIR}/zeek_analysis_${ATTACK_NAME}_$(date +%Y%m%d_%H%M%S).txt"
echo "Zeek 分析與攻擊圖產生統計報告" > "$REPORT_FILE"
echo "執行時間: $(date +%Y.%m.%d_%H:%M:%S)" >> "$REPORT_FILE"
echo "PCAP 檔案: $PCAP_FILE" >> "$REPORT_FILE"
echo "攻擊名稱: $ATTACK_NAME" >> "$REPORT_FILE"
echo "Zeek 腳本: $ZEEK_SCRIPT" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 總時間統計變數
TOTAL_START_TIME=$(date +%s)

# 函數：將秒數轉換為可讀格式
format_time() {
    local seconds=$1
    local minutes=$((seconds / 60))
    local remaining_seconds=$((seconds % 60))
    if [ $minutes -gt 0 ]; then
        echo "${minutes}分${remaining_seconds}秒"
    else
        echo "${seconds}秒"
    fi
}

# 函數：格式化檔案大小
format_size() {
    local size=$1
    if [ $size -gt 1048576 ]; then
        echo "$((size / 1048576)) MB"
    elif [ $size -gt 1024 ]; then
        echo "$((size / 1024)) KB"
    else
        echo "$size bytes"
    fi
}

# 函數：計算 pcap 檔案的封包數量
count_packets() {
    local pcap_file=$1
    local packet_count=0
    
    if command -v capinfos >/dev/null 2>&1; then
        packet_count=$(capinfos -c "$pcap_file" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
    elif command -v tcpdump >/dev/null 2>&1; then
        packet_count=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | wc -l)
    else
        packet_count="未知(需要 capinfos 或 tcpdump)"
    fi
    
    echo "$packet_count"
}

# 函數：計算 log 檔案的記錄數
count_log_records() {
    local log_file=$1
    local count=0
    
    if [ -f "$log_file" ]; then
        count=$(grep -v '^#' "$log_file" 2>/dev/null | grep -v '^$' | wc -l)
    fi
    
    echo "$count"
}

echo -e "${YELLOW}=========================================${NC}"
echo -e "${YELLOW}開始執行 Zeek 分析與攻擊圖產生${NC}"
echo -e "${YELLOW}=========================================${NC}"
echo -e "PCAP 檔案: ${BLUE}$PCAP_FILENAME${NC}"
echo -e "檔案路徑: ${BLUE}$PCAP_DIR${NC}"
echo -e "攻擊名稱: ${BLUE}$ATTACK_NAME${NC}"
echo ""

# 檢查可用的工具
echo -e "${CYAN}檢查可用工具...${NC}"
if command -v capinfos >/dev/null 2>&1; then
    echo -e "${GREEN}✓ capinfos 可用${NC}"
elif command -v tcpdump >/dev/null 2>&1; then
    echo -e "${YELLOW}✓ tcpdump 可用 (將使用 tcpdump 計算封包數)${NC}"
else
    echo -e "${YELLOW}⚠ 未找到 capinfos 或 tcpdump，無法準確計算封包數${NC}"
fi
echo ""

# 步驟 1: 進入 PCAP 檔案所在目錄
cd "$PCAP_DIR" || exit 1
echo -e "${CYAN}工作目錄: $(pwd)${NC}"

# 計算封包數量
echo -e "${CYAN}計算封包數量...${NC}"
PACKET_COUNT=$(count_packets "$PCAP_FILENAME")
echo -e "${CYAN}封包數量: $PACKET_COUNT${NC}"

# 刪除舊的 log 檔案
echo -e "${BLUE}清理舊的 log 檔案...${NC}"
rm -f *.log

# 步驟 2: 執行 Zeek 分析
echo ""
echo -e "${BLUE}[Zeek 分析] 開始處理 $PCAP_FILENAME${NC}"
ZEEK_START=$(date +%s)

# 執行 Zeek
/opt/zeek/bin/zeek -Cr "$PCAP_FILENAME" icsnpp-modbus "$ZEEK_SCRIPT"
ZEEK_STATUS=$?

ZEEK_END=$(date +%s)
ZEEK_DURATION=$((ZEEK_END - ZEEK_START))

if [ $ZEEK_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ Zeek 分析完成 (耗時: $(format_time $ZEEK_DURATION))${NC}"
    
    # 統計產生的 log 檔案
    LOG_FILES=$(ls -1 *.log 2>/dev/null | tr '\n' ' ')
    LOG_COUNT=$(ls -1 *.log 2>/dev/null | wc -l)
    TOTAL_LOG_SIZE=$(du -cb *.log 2>/dev/null | tail -1 | awk '{print $1}')
    
    # 計算每個 log 檔案的記錄數
    echo -e "${CYAN}計算 log 記錄數...${NC}"
    LOG_RECORDS=""
    TOTAL_RECORDS=0
    
    for log_file in *.log; do
        if [ -f "$log_file" ]; then
            records=$(count_log_records "$log_file")
            TOTAL_RECORDS=$((TOTAL_RECORDS + records))
            LOG_RECORDS="${LOG_RECORDS}${log_file}:${records} "
            echo -e "${CYAN}  $log_file: $records 筆${NC}"
        fi
    done
    
    echo -e "${CYAN}產生 $LOG_COUNT 個 log 檔案，總大小: $(format_size $TOTAL_LOG_SIZE)${NC}"
    echo -e "${CYAN}總記錄數: $TOTAL_RECORDS 筆${NC}"
else
    echo -e "${RED}✗ Zeek 分析失敗${NC}"
    exit 1
fi

# 步驟 3: 產生攻擊圖
echo ""
echo -e "${BLUE}[攻擊圖產生] 開始處理${NC}"

# 進入 SAGE 目錄
cd "$SAGE_PATH" || exit 1

GRAPH_START=$(date +%s)

# 執行 process_zeek_logs.sh
./process_zeek_logs.sh "$PCAP_DIR" "$ATTACK_NAME"
GRAPH_STATUS=$?

GRAPH_END=$(date +%s)
GRAPH_DURATION=$((GRAPH_END - GRAPH_START))

if [ $GRAPH_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ 攻擊圖產生完成 (耗時: $(format_time $GRAPH_DURATION))${NC}"
    
    # 找出產生的圖檔
    PROJECT_DIR="${ATTACK_NAME}_project"
    ATTACK_GRAPHS_DIR="$SAGE_PATH/${PROJECT_DIR}/attack_graphs"
    
    if [ -d "$ATTACK_GRAPHS_DIR" ]; then
        GRAPH_FILES=$(find "$ATTACK_GRAPHS_DIR" -name "*.png" 2>/dev/null)
        if [ -n "$GRAPH_FILES" ]; then
            GRAPH_COUNT=$(echo "$GRAPH_FILES" | wc -l)
            GRAPH_NAMES=$(echo "$GRAPH_FILES" | xargs -r basename -a 2>/dev/null | tr '\n' ' ')
        else
            GRAPH_COUNT=0
            GRAPH_NAMES="無"
        fi
    else
        GRAPH_COUNT=0
        GRAPH_NAMES="無圖檔目錄"
    fi
    
    echo -e "${CYAN}產生 $GRAPH_COUNT 張攻擊圖${NC}"
    if [ $GRAPH_COUNT -gt 0 ]; then
        echo -e "${CYAN}圖檔: $GRAPH_NAMES${NC}"
    fi
else
    echo -e "${RED}✗ 攻擊圖產生失敗${NC}"
    GRAPH_COUNT=0
    GRAPH_NAMES="失敗"
fi

# 計算總時間
TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START_TIME))

# 顯示統計資料
echo ""
echo -e "${GREEN}========== 統計資料 ==========${NC}"
echo -e "${CYAN}封包數量: $PACKET_COUNT${NC}"
echo -e "${CYAN}產生 log 檔案數: $LOG_COUNT${NC}"
echo -e "${CYAN}Log 檔案總大小: $(format_size $TOTAL_LOG_SIZE)${NC}"
echo -e "${CYAN}Log 總記錄數: $TOTAL_RECORDS 筆${NC}"
echo -e "${CYAN}產生攻擊圖數: $GRAPH_COUNT${NC}"
echo -e "${YELLOW}Zeek 轉換時間: $(format_time $ZEEK_DURATION)${NC}"
echo -e "${YELLOW}攻擊圖產生時間: $(format_time $GRAPH_DURATION)${NC}"
echo -e "${GREEN}總花費時間: $(format_time $TOTAL_DURATION)${NC}"
echo -e "${GREEN}==============================${NC}"

# 寫入報告
{
    echo "統計資料:"
    echo "  封包數量: $PACKET_COUNT"
    echo "  產生 log 檔案: $LOG_COUNT 個"
    echo "  Log 檔案大小: $(format_size $TOTAL_LOG_SIZE)"
    echo "  Log 檔案列表: $LOG_FILES"
    echo "  Log 總記錄數: $TOTAL_RECORDS 筆"
    echo "  Log 記錄明細: $LOG_RECORDS"
    echo "  產生攻擊圖: $GRAPH_COUNT 張"
    echo "  攻擊圖檔案: $GRAPH_NAMES"
    echo ""
    echo "時間統計:"
    echo "  Zeek 轉換時間: $(format_time $ZEEK_DURATION)"
    echo "  攻擊圖產生時間: $(format_time $GRAPH_DURATION)"
    echo "  總花費時間: $(format_time $TOTAL_DURATION)"
    echo ""
    echo "完成時間: $(date +%Y.%m.%d_%H:%M:%S)"
} >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}分析報告已儲存至: $REPORT_FILE${NC}"