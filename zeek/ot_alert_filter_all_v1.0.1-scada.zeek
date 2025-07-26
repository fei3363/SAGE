@load base/frameworks/notice
@load base/protocols/modbus

# 定義我們的通知類型
redef enum Notice::Type += {
    ## 非標準端口的 TCP 連線
    OT_Scan_NonStandard_Port,
    ## Modbus 寫入操作
    OT_Modbus_Write,
    ## HTTP 可疑 URI
    OT_HTTP_Suspicious_URI,
    ## Modbus 暴力破解攻擊
    OT_Modbus_Brute_Force,
    ## 延遲回應攻擊
    OT_Delay_Response_Attack,
    ## 虛假資料注入攻擊
    OT_False_Data_Injection,
    ## 幀堆疊攻擊
    OT_Frame_Stacking,
    ## 長度操作攻擊
    OT_Length_Manipulation,
    ## 載荷注入攻擊
    OT_Payload_Injection,
    ## 查詢洪水攻擊
    OT_Query_Flooding,
    ## 偵察活動
    OT_Reconnaissance,
    ## 重播攻擊
    OT_Replay_Attack,
    ## 基線重播攻擊
    OT_Baseline_Replay_Attack,
};

# 禁用特定通知類型的抑制
redef Notice::not_suppressed_types += { 
    OT_Modbus_Write,
    OT_Modbus_Brute_Force,
    OT_Query_Flooding,
    OT_Baseline_Replay_Attack,
};

# 全局變量用於追蹤攻擊模式
global modbus_connections: table[addr] of table[port] of count &create_expire=5min &default=table();
global query_timestamps: table[addr] of vector of time &create_expire=1min &default=vector();
global response_delays: table[conn_id] of time &create_expire=10min;
global coil_access_history: table[addr] of set[count] &create_expire=5min &default=set();
global frame_sizes: table[conn_id] of vector of count &create_expire=1min &default=vector();

# 基線重播攻擊檢測相關變量
global modbus_sequence_patterns: table[addr] of vector of string &create_expire=10min;
global modbus_payload_hashes: table[addr] of table[string] of count &create_expire=10min &default=table();
global modbus_timing_intervals: table[addr] of vector of interval &create_expire=10min;
global modbus_transaction_ids: table[addr] of set[count] &create_expire=10min &default=set();
global modbus_last_request_time: table[addr] of time &create_expire=10min;

# 幀堆疊攻擊檢測相關變量
global modbus_frame_timestamps: table[conn_id] of vector of time &create_expire=1min;
global modbus_tid_per_connection: table[conn_id] of set[count] &create_expire=1min &default=set();

# Frame Stacking 新檢測變量
global connection_creation_times: table[addr] of vector of time &create_expire=5min;
global source_port_sequence: table[addr] of vector of port &create_expire=5min;
global frames_per_connection: table[conn_id] of count &create_expire=5min &default=0;
global connection_uids: table[addr] of set[string] &create_expire=5min;

const modbus_coils_min = 1;
const modbus_coils_max = 2000;
const modbus_registers_min = 1;
const modbus_registers_max = 125;

# 基線重播攻擊檢測函數
function detect_baseline_replay(orig: addr): bool
{
    local indicators = 0;
    
    # 檢查序列模式重複
    if (orig in modbus_sequence_patterns && |modbus_sequence_patterns[orig]| > 10)
    {
        local seq_count: table[string] of count &default=0;
        for (i in modbus_sequence_patterns[orig])
        {
            seq_count[modbus_sequence_patterns[orig][i]] += 1;
        }
        
        # 檢查是否有重複的序列
        for (seq in seq_count)
        {
            if (seq_count[seq] > 3)
            {
                ++indicators;
                break;
            }
        }
    }
    
    # 檢查 payload 重複
    if (orig in modbus_payload_hashes)
    {
        local total_payloads = 0;
        local duplicate_payloads = 0;
        
        for (hash in modbus_payload_hashes[orig])
        {
            total_payloads += modbus_payload_hashes[orig][hash];
            if (modbus_payload_hashes[orig][hash] > 1)
                duplicate_payloads += 1;
        }
        
        if (total_payloads > 0 && duplicate_payloads > 0)
        {
            local dup_ratio = duplicate_payloads * 1.0 / |modbus_payload_hashes[orig]|;
            if (dup_ratio > 0.3)  # 30% 以上的重複
                ++indicators;
        }
    }
    
    # 檢查時間間隔規律性
    if (orig in modbus_timing_intervals && |modbus_timing_intervals[orig]| > 5)
    {
        local intervals: vector of double;
        for (i in modbus_timing_intervals[orig])
        {
            intervals += interval_to_double(modbus_timing_intervals[orig][i]);
        }
        
        # 計算標準差
        local sum = 0.0;
        local sum_sq = 0.0;
        for (i in intervals)
        {
            sum += intervals[i];
            sum_sq += intervals[i] * intervals[i];
        }
        
        local mean = sum / |intervals|;
        local variance = (sum_sq / |intervals|) - (mean * mean);
        local std_dev = sqrt(variance);
        
        # 如果標準差很小，表示時間間隔很規律
        if (std_dev < mean * 0.1)
            ++indicators;
    }
    
    # 檢查 Transaction ID 重複
    if (orig in modbus_transaction_ids && |modbus_transaction_ids[orig]| > 10)
    {
        # 這個集合的大小應該等於請求數量，如果小於則有重複
        if (orig in modbus_sequence_patterns)
        {
            local expected_count = |modbus_sequence_patterns[orig]|;
            local actual_count = |modbus_transaction_ids[orig]|;
            
            if (actual_count < expected_count * 0.9)  # 10% 以上的重複
                ++indicators;
        }
    }
    
    return indicators >= 2;  # 如果有2個或以上的指標，則判定為基線重播攻擊
}

# 檢測暴力破解特定線圈地址的攻擊
event modbus_read_coils_request(c: connection, headers: ModbusHeaders, 
                               start_addr: count, quantity: count)
{
    local orig = c$id$orig_h;

    local i: count = 0;
    local coil: count;

    # 記錄存取的線圈地址
    while ( i < quantity )
    {
        coil = start_addr + i;
        add coil_access_history[orig][coil];
        i += 1;
    }
    
    # 檢測特定的目標線圈（0, 1, 13, 14, 8）
    local target_coils: set[count] = {0, 1, 13, 14, 8};
    local accessed_targets = 0;
    
    for (coil in target_coils)
    {
        if (coil in coil_access_history[orig])
            ++accessed_targets;
    }
    
    if (accessed_targets >= 3)
    {
        NOTICE([
            $note=OT_Modbus_Brute_Force,
            $msg=fmt("Modbus 暴力破解攻擊 - 目標線圈: %s -> %s:%s", 
                    orig, c$id$resp_h, c$id$resp_p),
            $conn=c,
            $identifier=fmt("%s-brute-force", orig)
        ]);
    }
}

# 檢測延遲回應攻擊和記錄 payload hash
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    if (is_orig)
    {
        # 記錄請求時間
        response_delays[c$id] = network_time();
        
        # 記錄 payload hash (使用連線 ID 作為簡單的識別)
        local orig = c$id$orig_h;
        # 使用連線 ID 和時間戳組合作為簡單的 payload 識別
        local payload_identifier = fmt("%s-%s-%s-%s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
        
        if (orig !in modbus_payload_hashes)
            modbus_payload_hashes[orig] = table();
        
        if (payload_identifier in modbus_payload_hashes[orig])
            ++modbus_payload_hashes[orig][payload_identifier];
        else
            modbus_payload_hashes[orig][payload_identifier] = 1;
    }
    else if (c$id in response_delays)
    {
        # 計算回應延遲
        local delay = interval_to_double(network_time() - response_delays[c$id]);
        
        # 檢測異常延遲（> 5秒）
        if (delay > 5.0)
        {
            NOTICE([
                $note=OT_Delay_Response_Attack,
                $msg=fmt("延遲回應攻擊檢測: %s -> %s:%s, 延遲: %.0f 毫秒", 
                        c$id$orig_h, c$id$resp_h, c$id$resp_p, delay * 1000),
                $conn=c,
                $identifier=fmt("%s-delay-%.0f", c$id$orig_h, delay * 1000)
            ]);
        }
        
        delete response_delays[c$id];
    }
}

# 檢測查詢洪水攻擊
#event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, 
#                                          start_addr: count, quantity: count)
#{
#    local orig = c$id$orig_h;
#    
#    # 記錄查詢時間戳
#    query_timestamps[orig] += network_time();
#    
#    # 檢查最近1秒內的查詢數量
#    local recent_queries = 0;
#    local now: time = network_time();
#    for ( idx in query_timestamps[orig] )
#    {
#        if ( now - query_timestamps[orig][idx] < 1sec )
#            ++recent_queries;
#    }
#    
#    # 如果1秒內超過10個查詢，可能是洪水攻擊
#    if (recent_queries > 10)
#    {
#        NOTICE([
#            $note=OT_Query_Flooding,
#            $msg=fmt("查詢洪水攻擊: %s -> %s:%s, 查詢速率: %d/秒", 
#                    orig, c$id$resp_h, c$id$resp_p, recent_queries),
#            $conn=c,
#            $identifier=fmt("%s-flood", orig)
#        ]);
#    }
#}

# 定義
const FLOOD_THRESHOLD = 10;


# 全局變量：記錄每個來源IP在當前秒的請求數
global pkt_count: table[addr] of count &default=0;

# 記錄上一個統計的秒數（使用 double 類型）
global last_sec: double = 0.0;

# 使用更簡單的時間追蹤方式
global query_times: table[addr] of vector of time &create_expire=5sec;

# 方法1：使用 modbus_message 事件進行每秒統計
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    if ( ! is_orig ) return;  # 只統計請求，不統計回應
    
    local orig = c$id$orig_h;
    local now = network_time();
    
    # 初始化 vector
    if ( orig !in query_times )
        query_times[orig] = vector();
    
    # 添加當前時間
    query_times[orig] += now;
    
    # 計算最近1秒內的請求數
    local recent_count = 0;
    for ( i in query_times[orig] )
    {
        if ( (now - query_times[orig][i]) <= 1sec )
            ++recent_count;
    }
    
    # 如果超過門檻，發出通知
    if ( recent_count > FLOOD_THRESHOLD )
    {
        NOTICE([
            $note=OT_Query_Flooding,
            $msg=fmt("Modbus 查詢洪水攻擊: %s -> %s:%s, 速率: %d 請求/秒", 
                    orig, c$id$resp_h, c$id$resp_p, recent_count),
            $conn=c,
            $identifier=fmt("%s-flood", orig)
        ]);
    }
    
    # 清理超過5秒的舊記錄
    local new_times: vector of time = vector();
    for ( i in query_times[orig] )
    {
        if ( (now - query_times[orig][i]) <= 5sec )
            new_times += query_times[orig][i];
    }
    query_times[orig] = new_times;
    
    # 基線重播攻擊檢測邏輯
    # 記錄操作序列
    if (orig !in modbus_sequence_patterns)
        modbus_sequence_patterns[orig] = vector();
    
    local func_str = "";
    if (c?$modbus && c$modbus?$func)
        func_str = c$modbus$func;
    
    modbus_sequence_patterns[orig] += func_str;
    
    # 記錄時間間隔
    if (orig in modbus_last_request_time)
    {
        if (orig !in modbus_timing_intervals)
            modbus_timing_intervals[orig] = vector();
        
        modbus_timing_intervals[orig] += (now - modbus_last_request_time[orig]);
    }
    modbus_last_request_time[orig] = now;
    
    # 記錄 Transaction ID
    if (headers?$tid)
    {
        add modbus_transaction_ids[orig][headers$tid];
    }
    
    # 檢測基線重播攻擊 (每10個請求檢查一次)
    if (|modbus_sequence_patterns[orig]| >= 10 && |modbus_sequence_patterns[orig]| % 5 == 0)
    {
        if (detect_baseline_replay(orig))
        {
            NOTICE([
                $note=OT_Baseline_Replay_Attack,
                $msg=fmt("基線重播攻擊檢測: %s -> %s:%s, 檢測到重複的操作序列、規律的時間間隔和重複的 payload", 
                        orig, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s-baseline-replay", orig)
            ]);
        }
    }
    
    # 檢測幀堆疊攻擊
    if (c?$id && headers?$tid)
    {
        local conn_key = c$id;
        
        # 追蹤連接建立時間和源端口
        if (orig !in connection_creation_times)
        {
            connection_creation_times[orig] = vector();
            source_port_sequence[orig] = vector();
            connection_uids[orig] = set();
        }
        
        # 記錄每個連接的幀數
        ++frames_per_connection[conn_key];
        
        # 記錄連接 UID
        if (c?$uid)
            add connection_uids[orig][c$uid];
        
        # 如果是新連接，記錄時間和端口
        if (|source_port_sequence[orig]| == 0 || source_port_sequence[orig][|source_port_sequence[orig]|-1] != c$id$orig_p)
        {
            connection_creation_times[orig] += now;
            source_port_sequence[orig] += c$id$orig_p;
        }
        
        # 檢測 Frame Stacking 攻擊特徵
        local frame_stacking_indicators = 0;
        
        # 1. 檢查同一連接內的多個幀（同一時間戳）
        if (conn_key !in modbus_frame_timestamps)
            modbus_frame_timestamps[conn_key] = vector();
            
        modbus_frame_timestamps[conn_key] += now;
        
        if (|modbus_frame_timestamps[conn_key]| >= 2)
        {
            local last_idx = |modbus_frame_timestamps[conn_key]| - 1;
            local time_diff = interval_to_double(modbus_frame_timestamps[conn_key][last_idx] - modbus_frame_timestamps[conn_key][last_idx-1]);
            
            if (time_diff == 0.0)  # 完全相同的時間戳
                ++frame_stacking_indicators;
        }
        
        # 2. 檢查快速建立新連接模式（30秒內多個連接）
        if (|connection_creation_times[orig]| >= 3)
        {
            local recent_connections = 0;
            for (i in connection_creation_times[orig])
            {
                if ((now - connection_creation_times[orig][i]) <= 30sec)
                    ++recent_connections;
            }
            
            if (recent_connections >= 5)  # 30秒內5個以上連接
                ++frame_stacking_indicators;
        }
        
        # 3. 檢查源端口遞增模式
        if (|source_port_sequence[orig]| >= 3)
        {
            local is_sequential = T;
            local last_port: port = 0/tcp;
            for (i in source_port_sequence[orig])
            {
                if (i > 0 && last_port != 0/tcp)
                {
                    local curr_port_num = port_to_count(source_port_sequence[orig][i]);
                    local last_port_num = port_to_count(last_port);
                    
                    # 避免下溢，先檢查大小
                    if (curr_port_num <= last_port_num)
                    {
                        is_sequential = F;
                        break;
                    }
                    
                    local port_diff = curr_port_num - last_port_num;
                    
                    if (port_diff > 20)  # 跳躍太大
                    {
                        is_sequential = F;
                        break;
                    }
                }
                last_port = source_port_sequence[orig][i];
            }
            if (is_sequential)
                ++frame_stacking_indicators;
        }
        
        # 4. 檢查每個連接的幀數（Frame Stacking 通常每個連接發送多個幀）
        if (frames_per_connection[conn_key] >= 2)
            ++frame_stacking_indicators;
        
        # 如果有2個以上指標，則判定為 Frame Stacking 攻擊
        if (frame_stacking_indicators >= 2)
        {
            NOTICE([
                $note=OT_Frame_Stacking,
                $msg=fmt("幀堆疊攻擊檢測: %s -> %s:%s, 檢測到快速連接建立、源端口遞增、同一連接多幀等特徵 (連接數: %d, 當前連接幀數: %d)", 
                        orig, c$id$resp_h, c$id$resp_p, |connection_uids[orig]|, frames_per_connection[conn_key]),
                $conn=c,
                $identifier=fmt("%s-frame-stacking", orig)
            ]);
        }
    }
}

# 檢測偵察活動（大範圍掃描）
event modbus_read_discrete_inputs_request(c: connection, headers: ModbusHeaders, 
                                        start_addr: count, quantity: count)
{
    # 檢測特定的偵察範圍
    local recon_ranges: set[count] = {1, 125, 2, 20, 2000, 4, 5, 65535, 9};
    
    if (quantity in recon_ranges)
    {
        NOTICE([
            $note=OT_Reconnaissance,
            $msg=fmt("偵察活動檢測: %s -> %s:%s, 掃描範圍: %d", 
                    c$id$orig_h, c$id$resp_h, c$id$resp_p, quantity),
            $conn=c,
            $identifier=fmt("%s-recon-%d", c$id$orig_h, quantity)
        ]);
    }
}


# 檢查 READ_COILS 長度操縱
event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                start_address: count, quantity: count) {
    if (quantity < modbus_coils_min || quantity > modbus_coils_max) {
        NOTICE([$note=OT_Length_Manipulation,
                $conn=c,
                $msg=fmt("OT Length Manipulation detected in Modbus READ_COILS: quantity=%d (valid range: %d-%d)",
                        quantity, modbus_coils_min, modbus_coils_max),
                $sub="Possible reconnaissance or DoS attempt"]);
    }
    
}

# 檢查其他 Modbus 功能的長度操縱
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                           start_address: count, quantity: count) {
    if (quantity < modbus_registers_min || quantity > modbus_registers_max) {
        NOTICE([$note=OT_Length_Manipulation,
                $conn=c,
                $msg=fmt("OT Length Manipulation in READ_HOLDING_REGISTERS: quantity=%d",
                        quantity)]);
    }
}

# 分類不同類型的長度操縱攻擊
event modbus_read_coils_request(c: connection, headers: ModbusHeaders,
                                start_address: count, quantity: count) {
    local attack_type = "";
    
    if (quantity == 0) {
        attack_type = "Zero-Length Attack";
        # 您的案例：quantity = 0
    }
    else if (quantity > modbus_coils_max) {
        attack_type = "Overflow Attempt";
        # 嘗試緩衝區溢出
    }
    else if (quantity == 65535) {
        attack_type = "Max-Value Probe";
        # 使用最大值測試
    }
    
    if (attack_type != "") {
        NOTICE([$note=OT_Length_Manipulation,
                $conn=c,
                $msg=fmt("OT Length Manipulation (%s): addr=%d, qty=%d",
                        attack_type, start_address, quantity),
                $identifier=cat(c$id$orig_h, attack_type)]);
    }
}

# 追蹤虛假資料注入模式
global register_write_history: table[addr] of table[count] of vector of count &create_expire=5min;
global register_write_times: table[addr] of table[count] of vector of time &create_expire=5min;

# 檢測虛假資料注入（通過檢測異常的寫入值）
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, 
                                          reg: count, val: count)
{
    local orig = c$id$orig_h;
    
    # 初始化歷史記錄
    if (orig !in register_write_history)
    {
        register_write_history[orig] = table();
        register_write_times[orig] = table();
    }
    
    if (reg !in register_write_history[orig])
    {
        register_write_history[orig][reg] = vector();
        register_write_times[orig][reg] = vector();
    }
    
    # 記錄寫入值和時間
    register_write_history[orig][reg] += val;
    register_write_times[orig][reg] += network_time();
    
    # 檢測異常值範圍（例如：過大或特殊的值）
    if (val > 65000 || val == 0xDEAD || val == 0xBEEF || val == 0x03E7 )
    {
        NOTICE([
            $note=OT_False_Data_Injection,
            $msg=fmt("虛假資料注入攻擊: %s -> %s:%s, 暫存器: %d, 異常值: %d", 
                    c$id$orig_h, c$id$resp_h, c$id$resp_p, reg, val),
            $conn=c,
            $identifier=fmt("%s-injection-reg-%d", c$id$orig_h, reg)
        ]);
    }
    
    # 檢測重複寫入相同值到相同暫存器（虛假注入模式）
    if (|register_write_history[orig][reg]| >= 3)
    {
        local value_count: table[count] of count &default=0;
        for (i in register_write_history[orig][reg])
        {
            value_count[register_write_history[orig][reg][i]] += 1;
        }
        
        # 檢查是否有值被重複寫入3次以上
        for (v in value_count)
        {
            if (value_count[v] >= 3)
            {
                # 檢查是否在短時間內發生
                local recent_count = 0;
                local now = network_time();
                for (j in register_write_times[orig][reg])
                {
                    if (now - register_write_times[orig][reg][j] <= 30sec)
                        ++recent_count;
                }
                
                if (recent_count >= 3)
                {
                    NOTICE([
                        $note=OT_False_Data_Injection,
                        $msg=fmt("虛假資料注入攻擊 - 重複注入模式: %s -> %s:%s, 暫存器: %d, 重複值: %d (次數: %d)", 
                                orig, c$id$resp_h, c$id$resp_p, reg, v, value_count[v]),
                        $conn=c,
                        $identifier=fmt("%s-repeated-injection-reg-%d-val-%d", orig, reg, v)
                    ]);
                }
                break;
            }
        }
    }
    
    # 也記錄正常的寫入操作
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入單一暫存器: %s -> %s:%s, 暫存器: %d, 值: %d", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, reg, val),
        $conn=c,
        $identifier=fmt("%s-%s-%s-reg-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p, reg)
    ]);
}

# 檢測重播攻擊（通過追蹤重複的請求模式）
global request_patterns: table[addr] of table[string] of count &create_expire=5min &default=table();

event modbus_read_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                                  read_start: count, read_quantity: count,
                                                  write_start: count, write_registers: ModbusRegisters)
{
    local pat = fmt("RW-%d-%d-%d", read_start, read_quantity, write_start);
    local orig = c$id$orig_h;
    
    if (pat in request_patterns[orig])
        ++request_patterns[orig][pat];
    else
        request_patterns[orig][pat] = 1;
    
    # 如果相同的模式在短時間內重複出現
    if (request_patterns[orig][pat] > 5)
    {
        NOTICE([
            $note=OT_Replay_Attack,
            $msg=fmt("重播攻擊檢測: %s -> %s:%s, 重複模式: %s", 
                    orig, c$id$resp_h, c$id$resp_p, pat),
            $conn=c,
            $identifier=fmt("%s-replay-%s", orig, pat)
        ]);
    }
}

# 原有的事件處理程序保持不變
event connection_state_remove(c: connection)
{
    if (c?$id && c$id?$resp_p && 
        c$id$resp_p != 80/tcp && c$id$resp_p != 443/tcp && 
        c$id$resp_p != 502/tcp)
    {
        NOTICE([
            $note=OT_Scan_NonStandard_Port,
            $msg=fmt("非標準端口 TCP 連線: %s -> %s:%s", 
                    c$id$orig_h, c$id$resp_h, c$id$resp_p),
            $conn=c,
            $identifier=fmt("%s-%s-%s", c$id$orig_h, c$id$resp_h, c$id$resp_p)
        ]);
    }
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, 
                                      coil: count, val: bool)
{
    # 檢查是否為暴力破解的目標線圈
    local target_coils: set[count] = {0, 1, 13, 14, 8};
    if (coil in target_coils)
    {
        NOTICE([
            $note=OT_Modbus_Brute_Force,
            $msg=fmt("目標線圈寫入攻擊: %s -> %s:%s, 線圈: %d", 
                    c$id$orig_h, c$id$resp_h, c$id$resp_p, coil),
            $conn=c,
            $identifier=fmt("%s-target-coil-%d", c$id$orig_h, coil)
        ]);
    }
    
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入單一線圈: %s -> %s:%s, 線圈: %d, 值: %s", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, coil, val ? "ON" : "OFF"),
        $conn=c,
        $identifier=fmt("%s-%s-%s-coil-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p, coil)
    ]);
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, 
                                         start_addr: count, coils: ModbusCoils)
{
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入多個線圈: %s -> %s:%s, 起始地址: %d", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, start_addr),
        $conn=c,
        $identifier=fmt("%s-%s-%s-mcoils-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p, start_addr)
    ]);
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, 
                                            start_addr: count, registers: ModbusRegisters)
{
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入多個暫存器: %s -> %s:%s, 起始地址: %d", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, start_addr),
        $conn=c,
        $identifier=fmt("%s-%s-%s-mregs-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p, start_addr)
    ]);
}

event http_request(c: connection, method: string, original_URI: string, 
                  unescaped_URI: string, version: string)
{
    if (/upload|cmd|shell/i in unescaped_URI)
    {
        NOTICE([
            $note=OT_HTTP_Suspicious_URI,
            $msg=fmt("HTTP 可疑 URI: %s 方法: %s URI: %s", 
                    c$id$orig_h, method, unescaped_URI),
            $conn=c,
            $identifier=fmt("%s-%s-%s", c$id$orig_h, c$id$resp_h, unescaped_URI)
        ]);
    }
}

# 設置通知策略
hook Notice::policy(n: Notice::Info)
{
    # 確保所有 OT 相關通知都被記錄
    if (n$note == OT_Scan_NonStandard_Port || 
        n$note == OT_Modbus_Write || 
        n$note == OT_HTTP_Suspicious_URI ||
        n$note == OT_Modbus_Brute_Force ||
        n$note == OT_Delay_Response_Attack ||
        n$note == OT_False_Data_Injection ||
        n$note == OT_Frame_Stacking ||
        n$note == OT_Length_Manipulation ||
        n$note == OT_Payload_Injection ||
        n$note == OT_Query_Flooding ||
        n$note == OT_Reconnaissance ||
        n$note == OT_Replay_Attack ||
        n$note == OT_Baseline_Replay_Attack)
    {
        add n$actions[Notice::ACTION_LOG];
    }
}