#!/bin/bash

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 定義路徑
# ATTACK_BASE_PATH="/home/user/Downloads/modbus2023_attack_packets"


# 讓使用者輸入自製的攻擊封包路徑
read -p "請輸入自製的攻擊封包路徑: " ATTACK_BASE_PATH
if [ -z "$ATTACK_BASE_PATH" ]; then
    echo -e "${RED}錯誤：攻擊封包路徑不能為空！${NC}"
    exit 1
fi
# 檢查攻擊封包路徑是否存在
if [ ! -d "$ATTACK_BASE_PATH" ]; then
    echo -e "${RED}錯誤：找不到攻擊封包路徑: $ATTACK_BASE_PATH${NC}"
    exit 1
fi

SAGE_PATH="$HOME/SAGE"
ZEEK_CMD="/opt/zeek/bin/zeek -Cr 1.pcapng icsnpp-modbus ~/SAGE/zeek/ot_alert_filter_all_v1.0.zeek"

# 定義所有要處理的資料夾和對應的攻擊名稱
declare -A folders_and_attacks=(
    ["Baselinereplay"]="baseline_replay"
    ["Modifylengthparameters"]="modify_length_parameters"
    ["Stackmodbusframes"]="stack_modbus_frames"
    ["Falseinjection"]="false_injection"
    ["Queryflooding"]="query_flooding"
    ["WriteToAllCoils"]="write_to_all_coils"
    ["Reconnaissance"]="reconnaissance"
)

# 建立時間統計報告檔案
REPORT_FILE="zeek_attack_graph_timing_report_$(date +%Y%m%d_%H%M%S).txt"
echo "Zeek 分析與攻擊圖產生時間統計報告" > "$REPORT_FILE"
echo "執行時間: $(date +%Y.%m.%d_%H:%M:%S)" >> "$REPORT_FILE"
echo "==========================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# 總時間統計變數
TOTAL_START_TIME=$(date +%s)

# 用於儲存函數執行時間和統計資料的全域變數
LAST_ZEEK_DURATION=0
LAST_ATTACK_GRAPH_DURATION=0
LAST_PACKET_COUNT=0
LAST_LOG_FILES=""
LAST_LOG_COUNT=0
LAST_TOTAL_LOG_SIZE=0
LAST_GRAPH_COUNT=0
LAST_GRAPH_FILES=""
LAST_LOG_RECORDS=""
LAST_TOTAL_RECORDS=0

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

# 函數：計算 pcapng 檔案的封包數量
count_packets() {
    local pcap_file=$1
    local packet_count=0
    
    # 使用 capinfos 計算封包數量（如果可用）
    if command -v capinfos >/dev/null 2>&1; then
        packet_count=$(capinfos -c "$pcap_file" 2>/dev/null | grep "Number of packets" | awk '{print $NF}')
    elif command -v tcpdump >/dev/null 2>&1; then
        # 備用方案：使用 tcpdump
        packet_count=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | wc -l)
    else
        # 如果都沒有，使用 zeek 的 packet_filter.log
        packet_count="未知(需要 capinfos 或 tcpdump)"
    fi
    
    echo "$packet_count"
}

# 函數：計算 log 檔案的記錄數
count_log_records() {
    local log_file=$1
    local count=0
    
    if [ -f "$log_file" ]; then
        # 排除以 # 開頭的註解行和空行
        count=$(grep -v '^#' "$log_file" 2>/dev/null | grep -v '^$' | wc -l)
    fi
    
    echo "$count"
}

# 函數：執行 Zeek 分析
run_zeek_analysis() {
    local folder=$1
    local folder_path="${ATTACK_BASE_PATH}/${folder}"
    
    echo -e "${BLUE}[Zeek 分析] 開始處理 $folder${NC}"
    
    cd "$folder_path" || return 1
    
    # 計算封包數量
    if [ -f "1.pcapng" ]; then
        echo -e "${CYAN}計算封包數量...${NC}"
        LAST_PACKET_COUNT=$(count_packets "1.pcapng")
        echo -e "${CYAN}封包數量: $LAST_PACKET_COUNT${NC}"
    else
        LAST_PACKET_COUNT="檔案不存在"
    fi
    
    # 刪除舊的 log 檔案
    rm -f *.log
    
    # 開始計時
    local start_time=$(date +%s)
    
    # 執行 Zeek
    eval $ZEEK_CMD
    local zeek_status=$?
    
    # 結束計時
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $zeek_status -eq 0 ]; then
        # 統計產生的 log 檔案
        LAST_LOG_FILES=$(ls -1 *.log 2>/dev/null | tr '\n' ' ')
        LAST_LOG_COUNT=$(ls -1 *.log 2>/dev/null | wc -l)
        LAST_TOTAL_LOG_SIZE=$(du -cb *.log 2>/dev/null | tail -1 | awk '{print $1}')
        
        # 計算每個 log 檔案的記錄數
        LAST_LOG_RECORDS=""
        LAST_TOTAL_RECORDS=0
        
        echo -e "${CYAN}計算 log 記錄數...${NC}"
        for log_file in *.log; do
            if [ -f "$log_file" ]; then
                local records=$(count_log_records "$log_file")
                LAST_TOTAL_RECORDS=$((LAST_TOTAL_RECORDS + records))
                LAST_LOG_RECORDS="${LAST_LOG_RECORDS}${log_file}:${records} "
                echo -e "${CYAN}  $log_file: $records 筆${NC}"
            fi
        done
        
        echo -e "${GREEN}✓ Zeek 分析完成 (耗時: $(format_time $duration))${NC}"
        echo -e "${CYAN}產生 $LAST_LOG_COUNT 個 log 檔案，總大小: $(format_size $LAST_TOTAL_LOG_SIZE)${NC}"
        echo -e "${CYAN}總記錄數: $LAST_TOTAL_RECORDS 筆${NC}"
        
        # 將時間儲存到全域變數
        LAST_ZEEK_DURATION=$duration
        return 0
    else
        echo -e "${RED}✗ Zeek 分析失敗${NC}"
        return 1
    fi
}

# 函數：執行 process_zeek_logs.sh
run_process_zeek_logs() {
    local folder=$1
    local attack_name=$2
    local log_path="${ATTACK_BASE_PATH}/${folder}"
    
    echo -e "${BLUE}[攻擊圖產生] 開始處理 $folder${NC}"
    
    cd "$SAGE_PATH" || return 1
    
    # 記錄產生圖檔前的檔案
    local before_graphs=$(find . -name "*.png"  2>/dev/null | sort)
    
    # 開始計時
    local start_time=$(date +%s)
    
    # 執行 process_zeek_logs.sh
    ./process_zeek_logs.sh "$log_path" "$attack_name"
    local process_status=$?
    
    # 結束計時
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $process_status -eq 0 ]; then
        # 找出新產生的圖檔
        # 要去專案底下 attack_graphs 資料夾下找圖檔（只要 PNG）
        local project_dir="${attack_name}_project"
        local attack_graphs_dir="$SAGE_PATH/${project_dir}/attack_graphs"
        
        if [ -d "$attack_graphs_dir" ]; then
            local graph_files=$(find "$attack_graphs_dir" -name "*.png" 2>/dev/null)
            if [ -n "$graph_files" ]; then
                LAST_GRAPH_COUNT=$(echo "$graph_files" | wc -l)
                LAST_GRAPH_FILES=$(echo "$graph_files" | xargs -r basename -a 2>/dev/null | tr '\n' ' ')
            else
                LAST_GRAPH_COUNT=0
                LAST_GRAPH_FILES="無"
            fi
        else
            LAST_GRAPH_COUNT=0
            LAST_GRAPH_FILES="無圖檔目錄"
        fi
        
        echo -e "${GREEN}✓ 攻擊圖產生完成 (耗時: $(format_time $duration))${NC}"
        echo -e "${CYAN}產生 $LAST_GRAPH_COUNT 張攻擊圖${NC}"
        if [ $LAST_GRAPH_COUNT -gt 0 ]; then
            echo -e "${CYAN}圖檔: $LAST_GRAPH_FILES${NC}"
        fi
        
        # 將時間儲存到全域變數
        LAST_ATTACK_GRAPH_DURATION=$duration
        return 0
    else
        echo -e "${RED}✗ 攻擊圖產生失敗${NC}"
        LAST_GRAPH_COUNT=0
        LAST_GRAPH_FILES="失敗"
        return 1
    fi
}

# 主程式開始
echo -e "${YELLOW}=========================================${NC}"
echo -e "${YELLOW}開始執行 Zeek 分析與攻擊圖產生${NC}"
echo -e "${YELLOW}=========================================${NC}"
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

# 檢查必要的檔案和目錄
if [ ! -d "$ATTACK_BASE_PATH" ]; then
    echo -e "${RED}錯誤：找不到攻擊資料夾路徑 $ATTACK_BASE_PATH${NC}"
    exit 1
fi

if [ ! -f "$SAGE_PATH/process_zeek_logs.sh" ]; then
    echo -e "${RED}錯誤：找不到 $SAGE_PATH/process_zeek_logs.sh${NC}"
    exit 1
fi

# 總統計變數
TOTAL_PACKETS=0
TOTAL_LOG_FILES=0
TOTAL_LOG_SIZE=0
TOTAL_GRAPHS=0
TOTAL_LOG_RECORDS=0
TOTAL_LOG_RECORDS=0

# 處理每個資料夾
for folder in "${!folders_and_attacks[@]}"; do
    attack_name="${folders_and_attacks[$folder]}"
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}處理資料夾: $folder${NC}"
    echo -e "${YELLOW}攻擊類型: $attack_name${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    # 記錄到報告
    echo "資料夾: $folder (攻擊類型: $attack_name)" >> "$REPORT_FILE"
    
    # 該資料夾的總開始時間
    folder_start_time=$(date +%s)
    
    # 步驟 1: Zeek 分析
    run_zeek_analysis "$folder"
    zeek_status=$?
    
    if [ $zeek_status -ne 0 ]; then
        echo -e "${RED}跳過攻擊圖產生${NC}"
        echo "  Zeek 分析: 失敗" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        continue
    fi
    
    # 取得統計資料
    zeek_duration=$LAST_ZEEK_DURATION
    packet_count=$LAST_PACKET_COUNT
    log_count=$LAST_LOG_COUNT
    log_size=$LAST_TOTAL_LOG_SIZE
    log_records=$LAST_TOTAL_RECORDS
    log_details=$LAST_LOG_RECORDS
    
    # 更新總統計（如果是數字）
    if [[ "$packet_count" =~ ^[0-9]+$ ]]; then
        TOTAL_PACKETS=$((TOTAL_PACKETS + packet_count))
    fi
    TOTAL_LOG_FILES=$((TOTAL_LOG_FILES + log_count))
    TOTAL_LOG_SIZE=$((TOTAL_LOG_SIZE + log_size))
    TOTAL_LOG_RECORDS=$((TOTAL_LOG_RECORDS + log_records))
    
    # 步驟 2: 產生攻擊圖
    run_process_zeek_logs "$folder" "$attack_name"
    attack_graph_status=$?
    
    # 取得攻擊圖產生時間和圖檔數量
    attack_graph_duration=$LAST_ATTACK_GRAPH_DURATION
    graph_count=$LAST_GRAPH_COUNT
    graph_files=$LAST_GRAPH_FILES
    
    # 更新總圖檔數
    TOTAL_GRAPHS=$((TOTAL_GRAPHS + graph_count))
    
    # 計算該資料夾的總時間
    folder_end_time=$(date +%s)
    folder_total_duration=$((folder_end_time - folder_start_time))
    
    # 顯示時間統計
    echo ""
    echo -e "${GREEN}統計資料:${NC}"
    echo -e "  封包數量: $packet_count"
    echo -e "  產生 log 檔案數: $log_count"
    echo -e "  Log 檔案總大小: $(format_size $log_size)"
    echo -e "  Log 總記錄數: $log_records 筆"
    echo -e "  產生攻擊圖數: $graph_count"
    echo -e "  Zeek 轉換時間: $(format_time $zeek_duration)"
    echo -e "  攻擊圖產生時間: $(format_time $attack_graph_duration)"
    echo -e "  ${YELLOW}該攻擊總花費時間: $(format_time $folder_total_duration)${NC}"
    
    # 寫入報告
    echo "  封包數量: $packet_count" >> "$REPORT_FILE"
    echo "  產生 log 檔案: $log_count 個" >> "$REPORT_FILE"
    echo "  Log 檔案大小: $(format_size $log_size)" >> "$REPORT_FILE"
    echo "  Log 檔案列表: $LAST_LOG_FILES" >> "$REPORT_FILE"
    echo "  Log 總記錄數: $log_records 筆" >> "$REPORT_FILE"
    echo "  Log 記錄明細: $log_details" >> "$REPORT_FILE"
    echo "  產生攻擊圖: $graph_count 張" >> "$REPORT_FILE"
    echo "  攻擊圖檔案: $graph_files" >> "$REPORT_FILE"
    echo "  Zeek 轉換時間: $(format_time $zeek_duration)" >> "$REPORT_FILE"
    echo "  攻擊圖產生時間: $(format_time $attack_graph_duration)" >> "$REPORT_FILE"
    echo "  該攻擊總花費時間: $(format_time $folder_total_duration)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo ""
done

# 計算總執行時間
TOTAL_END_TIME=$(date +%s)
TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))

echo -e "${YELLOW}=========================================${NC}"
echo -e "${YELLOW}所有資料夾處理完成！${NC}"
echo -e "${YELLOW}=========================================${NC}"
echo -e "${CYAN}總封包數: $TOTAL_PACKETS${NC}"
echo -e "${CYAN}總 log 檔案數: $TOTAL_LOG_FILES${NC}"
echo -e "${CYAN}總 log 檔案大小: $(format_size $TOTAL_LOG_SIZE)${NC}"
echo -e "${CYAN}總 log 記錄數: $TOTAL_LOG_RECORDS 筆${NC}"
echo -e "${CYAN}總攻擊圖數: $TOTAL_GRAPHS${NC}"
echo -e "${YELLOW}總執行時間: $(format_time $TOTAL_DURATION)${NC}"
echo -e "${YELLOW}=========================================${NC}"

# 寫入總統計到報告
echo "==========================================" >> "$REPORT_FILE"
echo "總統計:" >> "$REPORT_FILE"
echo "  總封包數: $TOTAL_PACKETS" >> "$REPORT_FILE"
echo "  總 log 檔案數: $TOTAL_LOG_FILES" >> "$REPORT_FILE"
echo "  總 log 檔案大小: $(format_size $TOTAL_LOG_SIZE)" >> "$REPORT_FILE"
echo "  總 log 記錄數: $TOTAL_LOG_RECORDS 筆" >> "$REPORT_FILE"
echo "  總攻擊圖數: $TOTAL_GRAPHS" >> "$REPORT_FILE"
echo "  總執行時間: $(format_time $TOTAL_DURATION)" >> "$REPORT_FILE"
echo "完成時間: $(date)" >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}時間統計報告已儲存至: $REPORT_FILE${NC}"

# 顯示報告內容
echo ""
echo -e "${BLUE}時間統計報告摘要:${NC}"
cat "$REPORT_FILE"

# 主程式開始
echo -e "${YELLOW}=========================================${NC}"
echo -e "${YELLOW}開始執行 Zeek 分析與攻擊圖產生${NC}"
echo -e "${YELLOW}=========================================${NC}"
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

# 檢查必要的檔案和目錄
if [ ! -d "$ATTACK_BASE_PATH" ]; then
    echo -e "${RED}錯誤：找不到攻擊資料夾路徑 $ATTACK_BASE_PATH${NC}"
    exit 1
fi

if [ ! -f "$SAGE_PATH/process_zeek_logs.sh" ]; then
    echo -e "${RED}錯誤：找不到 $SAGE_PATH/process_zeek_logs.sh${NC}"
    exit 1
fi

# 總統計變數
TOTAL_PACKETS=0
TOTAL_LOG_FILES=0
TOTAL_LOG_SIZE=0
TOTAL_GRAPHS=0
TOTAL_LOG_RECORDS=0

# 處理每個資料夾
for folder in "${!folders_and_attacks[@]}"; do
    attack_name="${folders_and_attacks[$folder]}"
    
    echo -e "${YELLOW}=========================================${NC}"
    echo -e "${YELLOW}處理資料夾: $folder${NC}"
    echo -e "${YELLOW}攻擊類型: $attack_name${NC}"
    echo -e "${YELLOW}=========================================${NC}"
    
    # 記錄到報告
    echo "資料夾: $folder (攻擊類型: $attack_name)" >> "$REPORT_FILE"
    
    # 該資料夾的總開始時間
    folder_start_time=$(date +%s)
    
    # 步驟 1: Zeek 分析
    run_zeek_analysis "$folder"
    zeek_status=$?
    
    if [ $zeek_status -ne 0 ]; then
        echo -e "${RED}跳過攻擊圖產生${NC}"
        echo "  Zeek 分析: 失敗" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        continue
    fi
    
    # 取得統計資料
    zeek_duration=$LAST_ZEEK_DURATION
    packet_count=$LAST_PACKET_COUNT
    log_count=$LAST_LOG_COUNT
    log_size=$LAST_TOTAL_LOG_SIZE
    log_records=$LAST_TOTAL_RECORDS
    log_details=$LAST_LOG_RECORDS
    
    # 更新總統計（如果是數字）
    if [[ "$packet_count" =~ ^[0-9]+$ ]]; then
        TOTAL_PACKETS=$((TOTAL_PACKETS + packet_count))
    fi
    TOTAL_LOG_FILES=$((TOTAL_LOG_FILES + log_count))
    TOTAL_LOG_SIZE=$((TOTAL_LOG_SIZE + log_size))
    TOTAL_LOG_RECORDS=$((TOTAL_LOG_RECORDS + log_records))
    
    # 步驟 2: 產生攻擊圖
    run_process_zeek_logs "$folder" "$attack_name"
    attack_graph_status=$?
    
    # 取得攻擊圖產生時間和圖檔數量
    attack_graph_duration=$LAST_ATTACK_GRAPH_DURATION
    graph_count=$LAST_GRAPH_COUNT
    graph_files=$LAST_GRAPH_FILES
    
    # 更新總圖檔數
    TOTAL_GRAPHS=$((TOTAL_GRAPHS + graph_count))
    
    # 計算該資料夾的總時間
    folder_end_time=$(date +%s)
    folder_total_duration=$((folder_end_time - folder_start_time))
    
    # 顯示時間統計
    echo ""
    echo -e "${GREEN}統計資料:${NC}"
    echo -e "  封包數量: $packet_count"
    echo -e "  產生 log 檔案數: $log_count"
    echo -e "  Log 檔案總大小: $(format_size $log_size)"
    echo -e "  Log 總記錄數: $log_records 筆"
    echo -e "  產生攻擊圖數: $graph_count"
    echo -e "  Zeek 轉換時間: $(format_time $zeek_duration)"
    echo -e "  攻擊圖產生時間: $(format_time $attack_graph_duration)"
    echo -e "  ${YELLOW}該攻擊總花費時間: $(format_time $folder_total_duration)${NC}"
    
    # 寫入報告
    echo "  封包數量: $packet_count" >> "$REPORT_FILE"
    echo "  產生 log 檔案: $log_count 個" >> "$REPORT_FILE"
    echo "  Log 檔案大小: $(format_size $log_size)" >> "$REPORT_FILE"
    echo "  Log 檔案列表: $LAST_LOG_FILES" >> "$REPORT_FILE"
    echo "  Log 總記錄數: $log_records 筆" >> "$REPORT_FILE"
    echo "  Log 記錄明細: $log_details" >> "$REPORT_FILE"
    echo "  產生攻擊圖: $graph_count 張" >> "$REPORT_FILE"
    echo "  攻擊圖檔案: $graph_files" >> "$REPORT_FILE"
    echo "  Zeek 轉換時間: $(format_time $zeek_duration)" >> "$REPORT_FILE"
    echo "  攻擊圖產生時間: $(format_time $attack_graph_duration)" >> "$REPORT_FILE"
    echo "  該攻擊總花費時間: $(format_time $folder_total_duration)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo ""
done

# 計算總執行時間
TOTAL_END_TIME=$(date +%s)
TOTAL_DURATION=$((TOTAL_END_TIME - TOTAL_START_TIME))

echo -e "${YELLOW}=========================================${NC}"
echo -e "${YELLOW}所有資料夾處理完成！${NC}"
echo -e "${YELLOW}=========================================${NC}"
echo -e "${CYAN}總封包數: $TOTAL_PACKETS${NC}"
echo -e "${CYAN}總 log 檔案數: $TOTAL_LOG_FILES${NC}"
echo -e "${CYAN}總 log 檔案大小: $(format_size $TOTAL_LOG_SIZE)${NC}"
echo -e "${CYAN}總 log 記錄數: $TOTAL_LOG_RECORDS 筆${NC}"
echo -e "${CYAN}總攻擊圖數: $TOTAL_GRAPHS${NC}"
echo -e "${YELLOW}總執行時間: $(format_time $TOTAL_DURATION)${NC}"
echo -e "${YELLOW}=========================================${NC}"

# 寫入總統計到報告
echo "==========================================" >> "$REPORT_FILE"
echo "總統計:" >> "$REPORT_FILE"
echo "  總封包數: $TOTAL_PACKETS" >> "$REPORT_FILE"
echo "  總 log 檔案數: $TOTAL_LOG_FILES" >> "$REPORT_FILE"
echo "  總 log 檔案大小: $(format_size $TOTAL_LOG_SIZE)" >> "$REPORT_FILE"
echo "  總 log 記錄數: $TOTAL_LOG_RECORDS 筆" >> "$REPORT_FILE"
echo "  總攻擊圖數: $TOTAL_GRAPHS" >> "$REPORT_FILE"
echo "  總執行時間: $(format_time $TOTAL_DURATION)" >> "$REPORT_FILE"
echo "完成時間: $(date +%Y.%m.%d_%H:%M:%S)" >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}時間統計報告已儲存至: $REPORT_FILE${NC}"

# 顯示報告內容
echo ""
echo -e "${BLUE}時間統計報告摘要:${NC}"
cat "$REPORT_FILE"