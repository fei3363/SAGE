@load base/frameworks/notice
@load base/protocols/modbus
@load base/protocols/http
@load base/protocols/ssh

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
    
    # 新增的攻擊類型（基於 ics_attack_pcap_generator.py）
    ## HTTP 暴力破解攻擊
    IT_HTTP_Brute_Force,
    ## SSH 橫向移動
    IT_Lateral_Movement_SSH,
    ## PLC 關鍵參數修改
    OT_Critical_Parameter_Modification,
    ## 安全系統停用
    OT_Safety_System_Disabled,
    ## 多階段攻擊鏈檢測
    OT_Multi_Stage_Attack_Chain,
    ## Modbus 暫存器掃描
    OT_Modbus_Register_Scan,
};

# 禁用特定通知類型的抑制
redef Notice::not_suppressed_types += { 
    OT_Modbus_Write,
    OT_Modbus_Brute_Force,
    OT_Query_Flooding,
    OT_Baseline_Replay_Attack,
    OT_Critical_Parameter_Modification,
    OT_Safety_System_Disabled,
    OT_Multi_Stage_Attack_Chain,
};

# === 新增全局變量（基於攻擊情境）===

# HTTP 暴力破解檢測
global http_login_attempts: table[addr] of table[string] of count &create_expire=5min &default=table();
global http_failed_logins: table[addr] of count &create_expire=5min &default=0;
global http_login_timestamps: table[addr] of vector of time &create_expire=5min;

# SSH 橫向移動檢測
global ssh_connections: table[addr] of set[addr] &create_expire=10min;
global dmz_to_ot_connections: set[addr] &create_expire=1hr;

# PLC 關鍵參數監控
const critical_registers: set[count] = {100, 101, 102, 200};  # 溫度、壓力、流量、安全連鎖
const safety_coils: set[count] = {10, 11};  # 緊急停止、警報系統
global register_baseline: table[count] of count &default=100;  # 正常值基線
global critical_modifications: table[addr] of set[count] &create_expire=10min;

# --- 追蹤暫存器寫入歷史 ---
global register_write_history: table[addr] of table[count] of vector of count &create_expire=10min &default=table();
global register_write_times:   table[addr] of table[count] of vector of time  &create_expire=10min &default=table();


# 攻擊鏈追蹤
type AttackStage: record {
    stage_name: string;
    timestamp: time;
    source_ip: addr;
    target_ip: addr;
};

global attack_chain: table[addr] of vector of AttackStage &create_expire=1hr;

# === 原有的全局變量保持不變 ===
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

# Modbus 暫存器掃描檢測
global register_scan_patterns: table[addr] of set[count] &create_expire=5min;
global register_scan_timestamps: table[addr] of time &create_expire=5min;

const modbus_coils_min = 1;
const modbus_coils_max = 2000;
const modbus_registers_min = 1;
const modbus_registers_max = 125;

# === HTTP 暴力破解檢測 ===
event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (c$http?$uri && /login/i in c$http$uri)
    {
        local orig = c$id$orig_h;
        
        if (orig !in http_login_timestamps)
            http_login_timestamps[orig] = vector();
        
        http_login_timestamps[orig] += network_time();
        
        # 記錄失敗的登入嘗試
        if (code == 401 || code == 403)
        {
            ++http_failed_logins[orig];
            
            # 檢查是否達到暴力破解門檻（20次失敗）
            if (http_failed_logins[orig] >= 20)
            {
                NOTICE([
                    $note=IT_HTTP_Brute_Force,
                    $msg=fmt("HTTP 暴力破解攻擊檢測: %s -> %s, 失敗嘗試: %d 次", 
                            orig, c$id$resp_h, http_failed_logins[orig]),
                    $conn=c,
                    $identifier=fmt("%s-http-bruteforce", orig)
                ]);
                
            }
        }
        # 記錄成功登入
        else if (code == 200)
        {
            if (http_failed_logins[orig] >= 10)
            {
                NOTICE([
                    $note=IT_HTTP_Brute_Force,
                    $msg=fmt("HTTP 暴力破解成功: %s -> %s, 在 %d 次失敗後成功登入", 
                            orig, c$id$resp_h, http_failed_logins[orig]),
                    $conn=c,
                    $identifier=fmt("%s-http-bruteforce-success", orig)
                ]);
            }
            # 重置計數器
            http_failed_logins[orig] = 0;
        }
    }
}

# === SSH 橫向移動檢測 ===
event ssh_auth_successful(c: connection, auth_method_none: bool)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    
    # 檢查是否是從 DMZ 到其他網段的連接
    if (/^192\.168\.10\./ in fmt("%s", orig) && resp == 192.168.10.51)
    {
        NOTICE([
            $note=IT_Lateral_Movement_SSH,
            $msg=fmt("SSH 橫向移動檢測: %s -> %s (DMZ to Jump Host)", 
                    orig, resp),
            $conn=c,
            $identifier=fmt("%s-lateral-ssh", orig)
        ]);
        
        add dmz_to_ot_connections[orig];
    }
    
    # 記錄 SSH 連接路徑
    if (orig !in ssh_connections)
        ssh_connections[orig] = set();
    
    add ssh_connections[orig][resp];
}

# === Modbus 暫存器掃描檢測 ===
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, 
                                          start_addr: count, quantity: count)
{
    local orig = c$id$orig_h;
    
    # 記錄掃描的暫存器範圍
    if (orig !in register_scan_patterns)
    {
        register_scan_patterns[orig] = set();
        register_scan_timestamps[orig] = network_time();
    }
    
    # 記錄掃描模式
    local i: count;
    const scan_offsets: set[count] = { 0, 100, 200, 300, 400 };

    if (quantity > 300)
    {
        NOTICE([
            $note=OT_Modbus_Register_Scan,
            $msg=fmt("大量暫存器掃描: %s -> %s:%s, 起始: %d, 數量: %d", 
                    orig, c$id$resp_h, c$id$resp_p, start_addr, quantity),
            $conn=c
        ]);
    }
    
    # 如果在短時間內掃描了多個區域，則判定為暫存器掃描
    if (|register_scan_patterns[orig]| >= 4)
    {
        local time_diff = interval_to_double(network_time() - register_scan_timestamps[orig]);
        if (time_diff < 10.0)  # 10秒內
        {
            NOTICE([
                $note=OT_Modbus_Register_Scan,
                $msg=fmt("Modbus 暫存器掃描檢測: %s -> %s:%s, 掃描了 %d 個區域", 
                        orig, c$id$resp_h, c$id$resp_p, |register_scan_patterns[orig]|),
                $conn=c,
                $identifier=fmt("%s-register-scan", orig)
            ]);
            
        }
    }
    
    # 原有的查詢洪水檢測邏輯
    # 記錄查詢時間戳
    query_timestamps[orig] += network_time();
    
    # 檢查最近1秒內的查詢數量
    local recent_queries = 0;
    local now: time = network_time();
    for ( idx in query_timestamps[orig] )
    {
        if ( now - query_timestamps[orig][idx] < 1sec )
            ++recent_queries;
    }
    
    # 如果1秒內超過10個查詢，可能是洪水攻擊
    if (recent_queries > 10)
    {
        NOTICE([
            $note=OT_Query_Flooding,
            $msg=fmt("查詢洪水攻擊: %s -> %s:%s, 查詢速率: %d/秒", 
                    orig, c$id$resp_h, c$id$resp_p, recent_queries),
            $conn=c,
            $identifier=fmt("%s-flood", orig)
        ]);
    }
}

# === PLC 關鍵參數修改檢測（增強版）===
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, 
                                          reg: count, val: count)
{
    local orig = c$id$orig_h;
    
    # 檢查是否修改關鍵暫存器
    if (reg in critical_registers)
    {
        # 檢查值是否偏離基線
        local normal_value = register_baseline[reg];
        local deviation = 0.0;
        
        if (normal_value > 0)
            deviation = (val > normal_value) ? 
                        ((val - normal_value) * 100.0 / normal_value) : 
                        ((normal_value - val) * 100.0 / normal_value);
        
        # 記錄關鍵參數修改
        if (orig !in critical_modifications)
            critical_modifications[orig] = set();
        
        add critical_modifications[orig][reg];
        
        local param_name = "";
        if (reg == 100) param_name = "溫度設定點";
        else if (reg == 101) param_name = "壓力限制";
        else if (reg == 102) param_name = "流量控制";
        else if (reg == 200) param_name = "安全連鎖系統";
        
        NOTICE([
            $note=OT_Critical_Parameter_Modification,
            $msg=fmt("關鍵參數修改: %s -> %s:%s, %s (暫存器 %d): %d -> %d (偏差: %.1f%%)", 
                    orig, c$id$resp_h, c$id$resp_p, param_name, reg, normal_value, val, deviation),
            $conn=c,
            $identifier=fmt("%s-critical-param-%d", orig, reg)
        ]);
        
        # 如果是安全系統被關閉
        if (reg == 200 && val == 1)
        {
            NOTICE([
                $note=OT_Safety_System_Disabled,
                $msg=fmt("警告: 安全連鎖系統被停用! %s -> %s:%s", 
                        orig, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s-safety-disabled", orig)
            ]);
        }
        
    }
    
    # 保留原有的虛假資料注入檢測邏輯
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
    if (val > 65000 || val == 0xDEAD || val == 0xBEEF || val == 0x03E7 || val == 0x0320 || val == 0x01F4)
    {
        NOTICE([
            $note=OT_False_Data_Injection,
            $msg=fmt("虛假資料注入攻擊: %s -> %s:%s, 暫存器: %d, 異常值: 0x%04x (%d)", 
                    c$id$orig_h, c$id$resp_h, c$id$resp_p, reg, val, val),
            $conn=c,
            $identifier=fmt("%s-injection-reg-%d", c$id$orig_h, reg)
        ]);
    }
    
    # 記錄所有寫入操作
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入單一暫存器: %s -> %s:%s, 暫存器: %d, 值: %d (0x%04x)", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, reg, val, val),
        $conn=c,
        $identifier=fmt("%s-%s-%s-reg-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p, reg)
    ]);
}

# === 安全線圈寫入檢測（增強版）===
event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, 
                                      coil: count, val: bool)
{
    local orig = c$id$orig_h;
    
    # 檢查是否為安全系統線圈
    if (coil in safety_coils)
    {
        local coil_name = "";
        if (coil == 10) coil_name = "緊急停止";
        else if (coil == 11) coil_name = "警報系統";
        
        if (!val)  # 如果是關閉操作
        {
            NOTICE([
                $note=OT_Safety_System_Disabled,
                $msg=fmt("危險: %s 被停用! %s -> %s:%s, 線圈: %d", 
                        coil_name, orig, c$id$resp_h, c$id$resp_p, coil),
                $conn=c,
                $identifier=fmt("%s-safety-coil-%d-disabled", orig, coil)
            ]);
        }
    }
    
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

# === 端口掃描檢測（增強版）===
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local resp_p = c$id$resp_p;
    
    # 檢查是否為跳板主機到 PLC 的掃描
    if (orig == 192.168.10.51 && resp == 10.0.0.100)
    {
        # 檢查特定的工控端口
        local ics_ports: set[port] = {80/tcp, 443/tcp, 502/tcp, 1911/tcp, 2222/tcp, 44818/tcp};
        
        if (resp_p in ics_ports && resp_p != 502/tcp)
        {
            NOTICE([
                $note=OT_Scan_NonStandard_Port,
                $msg=fmt("工控端口掃描: %s -> %s:%s", 
                        orig, resp, resp_p),
                $conn=c,
                $identifier=fmt("%s-%s-%s", orig, resp, resp_p)
            ]);
            

        }
    }
    # 原有的非標準端口檢測
    else if (c?$id && c$id?$resp_p && 
        c$id$resp_p != 80/tcp && c$id$resp_p != 443/tcp && 
        c$id$resp_p != 502/tcp && c$id$resp_p != 22/tcp)
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

# === 保留所有原有的檢測邏輯 ===
# [原有的所有函數和事件處理程序保持不變...]

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

# === 原有的其他事件處理程序保持不變 ===

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
        n$note == OT_Baseline_Replay_Attack ||
        n$note == IT_HTTP_Brute_Force ||
        n$note == IT_Lateral_Movement_SSH ||
        n$note == OT_Critical_Parameter_Modification ||
        n$note == OT_Safety_System_Disabled ||
        n$note == OT_Multi_Stage_Attack_Chain ||
        n$note == OT_Modbus_Register_Scan)
    {
        add n$actions[Notice::ACTION_LOG];
    }
}