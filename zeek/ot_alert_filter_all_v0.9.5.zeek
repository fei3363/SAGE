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
    
    # 新增的攻擊類型
    ## HTTP 暴力破解攻擊
    IT_HTTP_Brute_Force,
    ## SSH 橫向移動
    IT_Lateral_Movement_SSH,
    ## PLC 關鍵參數修改
    OT_Critical_Parameter_Modification,
    ## 安全系統停用
    OT_Safety_System_Disabled,
    ## Modbus 暫存器掃描
    OT_Modbus_Register_Scan,
    ## Modbus 異常功能碼
    OT_Modbus_Invalid_Function,
    ## Modbus 正常活動（用於基線）
    OT_Modbus_Normal_Activity,
};

# 禁用特定通知類型的抑制
redef Notice::not_suppressed_types += { 
    OT_Modbus_Write,
    OT_Modbus_Brute_Force,
    OT_Query_Flooding,
    OT_Critical_Parameter_Modification,
    OT_Safety_System_Disabled,
    IT_HTTP_Brute_Force,
    IT_Lateral_Movement_SSH,
    OT_Modbus_Register_Scan,
};

# === 全局變量 ===
# HTTP 暴力破解檢測
global http_login_attempts: table[addr] of count &create_expire=5min &default=0;
global http_login_timestamps: table[addr] of vector of time &create_expire=5min;
global http_login_threshold = 15;  # 降低暴力破解門檻

# SSH 橫向移動檢測
global ssh_connections: table[addr] of set[addr] &create_expire=10min;
global dmz_to_ot_connections: set[addr] &create_expire=1hr;

# PLC 關鍵參數監控
const critical_registers: set[count] = {100, 101, 102, 200};  # 溫度、壓力、流量、安全連鎖
const safety_coils: set[count] = {10, 11};  # 緊急停止、警報系統
global register_baseline: table[count] of count &default=100;  # 正常值基線

# Modbus 暫存器掃描檢測
global register_scan_patterns: table[addr] of set[count] &create_expire=5min;
global register_scan_timestamps: table[addr] of time &create_expire=5min;
global modbus_read_count: table[addr] of count &create_expire=5min &default=0;
global register_read_history: table[addr] of vector of count &create_expire=5min;

# 查詢洪水檢測
global query_timestamps: table[addr] of vector of time &create_expire=1min &default=vector();

# Modbus 異常功能碼檢測
const valid_modbus_functions: set[count] = {1, 2, 3, 4, 5, 6, 15, 16};

# === HTTP 暴力破解檢測 ===
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # 檢查是否為登入請求
    if (/login/i in original_URI)
    {
        local orig = c$id$orig_h;
        
        # 增加登入嘗試計數
        ++http_login_attempts[orig];
        
        # 記錄時間戳
        if (orig !in http_login_timestamps)
            http_login_timestamps[orig] = vector();
        
        http_login_timestamps[orig] += network_time();
        
        # 檢查是否達到暴力破解門檻
        if (http_login_attempts[orig] >= http_login_threshold)
        {
            # 計算攻擊速率
            local time_window = 0.0;
            if (|http_login_timestamps[orig]| >= 2)
            {
                local first_time = http_login_timestamps[orig][0];
                local last_time = http_login_timestamps[orig][|http_login_timestamps[orig]| - 1];
                time_window = interval_to_double(last_time - first_time);
            }
            
            NOTICE([
                $note=IT_HTTP_Brute_Force,
                $msg=fmt("HTTP 暴力破解攻擊檢測: %s -> %s, 登入嘗試: %d 次, 時間窗口: %.2f 秒", 
                        orig, c$id$resp_h, http_login_attempts[orig], time_window),
                $conn=c,
                $identifier=fmt("%s-http-bruteforce", orig)
            ]);
        }
    }
}

# === SSH 橫向移動檢測 ===
event new_connection(c: connection)
{
    # 檢查 SSH 連接（端口 22）
    if (c$id$resp_p == 22/tcp)
    {
        local orig = c$id$orig_h;
        local resp = c$id$resp_h;
        
        # 檢查是否是橫向移動模式
        # DMZ (192.168.10.50) -> Jump Host (192.168.10.51)
        if (orig == 192.168.10.50 && resp == 192.168.10.51)
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
}

# === Modbus 異常功能碼檢測 ===
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    local func_code = headers$function_code;
    local orig = c$id$orig_h;
    
    if (is_orig)  # 檢查請求
    {
        # 檢查是否為無效的功能碼
        if (func_code == 0)
        {
            NOTICE([
                $note=OT_Modbus_Invalid_Function,
                $msg=fmt("Modbus 異常功能碼: %s -> %s:%s, 功能碼: %d", 
                        orig, c$id$resp_h, c$id$resp_p, func_code),
                $conn=c,
                $identifier=fmt("%s-invalid-func-%d", orig, func_code)
            ]);
            
            # 如果是從跳板主機發出的異常請求
            if (orig == 192.168.10.51)
            {
                NOTICE([
                    $note=OT_Reconnaissance,
                    $msg=fmt("Modbus 偵察活動: 跳板主機 %s 發送異常功能碼 %d 到 %s", 
                            orig, func_code, c$id$resp_h),
                    $conn=c,
                    $identifier=fmt("%s-recon-func-%d", orig, func_code)
                ]);
            }
        }
    }
    else  # 檢查響應
    {
        # 檢查寫入操作響應
        if (func_code == 5 && orig == 192.168.10.51)
        {
            NOTICE([
                $note=OT_Modbus_Write,
                $msg=fmt("Modbus 寫入單一線圈（響應）: %s -> %s:%s", 
                        orig, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s-write-coil-response", orig)
            ]);
        }
        else if (func_code == 6 && orig == 192.168.10.51)
        {
            NOTICE([
                $note=OT_Modbus_Write,
                $msg=fmt("Modbus 寫入單一暫存器（響應）: %s -> %s:%s", 
                        orig, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s-write-register-response", orig)
            ]);
        }
    }
    
    # 記錄正常的 Modbus 活動（來自 HMI/SCADA）
    if (is_orig && func_code == 3 && orig == 10.0.0.50)
    {
        ++modbus_read_count[orig];
        
        # 每隔一段時間記錄一次正常活動
        if (modbus_read_count[orig] % 10 == 1)
        {
            NOTICE([
                $note=OT_Modbus_Normal_Activity,
                $msg=fmt("Modbus 正常活動: HMI %s 讀取 PLC %s (總計: %d 次)", 
                        orig, c$id$resp_h, modbus_read_count[orig]),
                $conn=c,
                $identifier=fmt("%s-normal-activity", orig),
                $suppress_for=5min
            ]);
        }
    }
}

# === Modbus 暫存器掃描檢測 ===
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, 
                                          start_addr: count, quantity: count)
{
    local orig = c$id$orig_h;
    
    # 特別關注來自跳板主機的讀取
    if (orig == 192.168.10.51)
    {
        # 記錄掃描的暫存器範圍
        if (orig !in register_scan_patterns)
        {
            register_scan_patterns[orig] = set();
            register_scan_timestamps[orig] = network_time();
            register_read_history[orig] = vector();
        }
        
        # 記錄訪問的地址範圍
        add register_scan_patterns[orig][start_addr];
        register_read_history[orig] += start_addr;
        
        # 檢測暫存器掃描模式（0-500範圍）
        if (start_addr <= 500)
        {
            NOTICE([
                $note=OT_Modbus_Register_Scan,
                $msg=fmt("Modbus 暫存器掃描: 跳板主機 %s -> %s:%s, 掃描地址: %d-%d", 
                        orig, c$id$resp_h, c$id$resp_p, start_addr, start_addr + quantity - 1),
                $conn=c,
                $identifier=fmt("%s-register-scan-%d", orig, start_addr)
            ]);
        }
        
        # 檢測是否為完整掃描（多個區域）
        if (|register_scan_patterns[orig]| >= 5)
        {
            NOTICE([
                $note=OT_Reconnaissance,
                $msg=fmt("Modbus 偵察活動: %s 已掃描 %d 個不同的暫存器區域", 
                        orig, |register_scan_patterns[orig]|),
                $conn=c,
                $identifier=fmt("%s-extensive-scan", orig)
            ]);
        }
    }
    
    # 記錄正常的 HMI 讀取
    if (orig == 10.0.0.50 && start_addr == 0 && quantity == 5)
    {
        # 這是正常的週期性讀取，不需要告警
    }
}

# === PLC 關鍵參數修改檢測 ===
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, 
                                          reg: count, val: count)
{
    local orig = c$id$orig_h;
    
    # 記錄所有寫入操作
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入暫存器: %s -> %s:%s, 暫存器: %d, 值: %d", 
                orig, c$id$resp_h, c$id$resp_p, reg, val),
        $conn=c,
        $identifier=fmt("%s-write-reg-%d", orig, reg)
    ]);
    
    # 檢查是否修改關鍵暫存器
    if (reg in critical_registers)
    {
        local param_name = "";
        if (reg == 100) param_name = "溫度設定點";
        else if (reg == 101) param_name = "壓力限制";
        else if (reg == 102) param_name = "流量控制";
        else if (reg == 200) param_name = "安全連鎖系統";
        
        NOTICE([
            $note=OT_Critical_Parameter_Modification,
            $msg=fmt("關鍵參數修改: %s -> %s:%s, %s (暫存器 %d) 設為 %d", 
                    orig, c$id$resp_h, c$id$resp_p, param_name, reg, val),
            $conn=c,
            $identifier=fmt("%s-critical-param-%d", orig, reg)
        ]);
        
        # 如果是安全系統被關閉
        if (reg == 200 && val == 0)
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
}

# === 安全線圈寫入檢測 ===
event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, 
                                      coil: count, val: bool)
{
    local orig = c$id$orig_h;
    
    # 記錄所有寫入操作
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入線圈: %s -> %s:%s, 線圈: %d, 值: %s", 
                orig, c$id$resp_h, c$id$resp_p, coil, val ? "ON" : "OFF"),
        $conn=c,
        $identifier=fmt("%s-write-coil-%d", orig, coil)
    ]);
    
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
}

# === 端口掃描檢測 ===
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
}

# === 額外的 Modbus 事件檢測 ===
# 檢測所有 Modbus 異常響應
event modbus_exception(c: connection, headers: ModbusHeaders, code: count)
{
    NOTICE([
        $note=OT_Modbus_Invalid_Function,
        $msg=fmt("Modbus 異常: %s -> %s:%s, 異常碼: %d", 
                c$id$orig_h, c$id$resp_h, c$id$resp_p, code),
        $conn=c,
        $identifier=fmt("%s-modbus-exception-%d", c$id$orig_h, code)
    ]);
}

# 檢測讀取線圈請求
event modbus_read_coils_request(c: connection, headers: ModbusHeaders, 
                               start_addr: count, quantity: count)
{
    local orig = c$id$orig_h;
    if (orig == 192.168.10.51)
    {
        NOTICE([
            $note=OT_Modbus_Register_Scan,
            $msg=fmt("Modbus 讀取線圈: 跳板主機 %s -> %s:%s, 起始: %d, 數量: %d", 
                    orig, c$id$resp_h, c$id$resp_p, start_addr, quantity),
            $conn=c,
            $identifier=fmt("%s-read-coils-%d", orig, start_addr)
        ]);
    }
}

# 檢測多個暫存器寫入
event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                            start_addr: count, registers: ModbusRegisters)
{
    local orig = c$id$orig_h;
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入多個暫存器: %s -> %s:%s, 起始地址: %d, 數量: %d", 
                orig, c$id$resp_h, c$id$resp_p, start_addr, |registers|),
        $conn=c,
        $identifier=fmt("%s-write-multiple-%d", orig, start_addr)
    ]);
}

# 檢測多個線圈寫入
event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders,
                                        start_addr: count, coils: ModbusCoils)
{
    local orig = c$id$orig_h;
    NOTICE([
        $note=OT_Modbus_Write,
        $msg=fmt("Modbus 寫入多個線圈: %s -> %s:%s, 起始地址: %d, 數量: %d", 
                orig, c$id$resp_h, c$id$resp_p, start_addr, |coils|),
        $conn=c,
        $identifier=fmt("%s-write-multiple-coils-%d", orig, start_addr)
    ]);
}

# 設置通知策略
hook Notice::policy(n: Notice::Info)
{
    # 確保所有通知都被記錄
    add n$actions[Notice::ACTION_LOG];
}