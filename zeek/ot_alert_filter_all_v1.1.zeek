@load base/frameworks/notice
@load base/protocols/modbus
@load base/protocols/http
@load base/protocols/ssh

# 定義通知類型
redef enum Notice::Type += {
    # 原有的通知類型
    OT_Scan_NonStandard_Port,
    OT_Modbus_Write,
    OT_HTTP_Suspicious_URI,
    OT_Modbus_Brute_Force,
    OT_Query_Flooding,
    OT_Reconnaissance,
    
    # 新增的攻擊類型
    IT_HTTP_Brute_Force,
    IT_Lateral_Movement_SSH,
    OT_Critical_Parameter_Modification,
    OT_Safety_System_Disabled,
    OT_Multi_Stage_Attack_Chain,
    OT_Modbus_Register_Scan,
    OT_Modbus_Coil_Write,
    OT_Suspicious_Modbus_Pattern,
};

# 禁用特定通知類型的抑制
redef Notice::not_suppressed_types += { 
    OT_Modbus_Write,
    OT_Critical_Parameter_Modification,
    OT_Safety_System_Disabled,
    OT_Multi_Stage_Attack_Chain,
    IT_HTTP_Brute_Force,
};

# === 全局變量 ===

# HTTP 暴力破解檢測
global http_login_attempts: table[addr] of count &create_expire=10min &default=0;
global http_failed_logins: table[addr] of count &create_expire=10min &default=0;
global http_success_after_failures: set[addr] &create_expire=1hr;

# SSH 橫向移動檢測
global ssh_connections: table[addr] of set[addr] &create_expire=10min;
global dmz_to_internal_ssh: set[addr] &create_expire=1hr;

# Modbus 掃描檢測
global modbus_scan_addresses: table[addr] of set[count] &create_expire=5min;
global modbus_scan_start_time: table[addr] of time &create_expire=5min;
global modbus_access_count: table[addr] of count &create_expire=5min &default=0;

# 關鍵參數監控
const critical_registers: set[count] = {100, 101, 102, 200};
const safety_coils: set[count] = {10, 11};
global register_modifications: table[addr] of set[count] &create_expire=10min;
global coil_modifications: table[addr] of set[count] &create_expire=10min;

# 攻擊鏈追蹤
type AttackStage: record {
    stage: string;
    timestamp: time;
    src: addr;
    dst: addr;
    details: string;
};

global attack_chains: table[addr] of vector of AttackStage &create_expire=1hr;



function check_attack_chain(attacker: addr)
{
    local stages: set[string] = set();
    local chain_details = "";
    
    for (i in attack_chains[attacker])
    {
        add stages[attack_chains[attacker][i]$stage];
        chain_details = fmt("%s -> %s", chain_details, attack_chains[attacker][i]$stage);
    }
    
    # 檢查是否包含關鍵階段
    if ("HTTP_BRUTEFORCE_SUCCESS" in stages || "HTTP_LOGIN_ATTEMPT" in stages)
    {
        if ("LATERAL_MOVEMENT" in stages || "LATERAL_MOVEMENT_SSH" in stages)
        {
            if ("MODBUS_SCAN" in stages || "PORT_SCAN" in stages)
            {
                if ("PARAMETER_MODIFICATION" in stages || "SAFETY_MODIFICATION" in stages)
                {
                    NOTICE([
                        $note=OT_Multi_Stage_Attack_Chain,
                        $msg=fmt("檢測到完整攻擊鏈！攻擊者: %s, 階段: %s",
                                attacker, chain_details),
                        $identifier=fmt("%s-complete-attack-chain", attacker)
                    ]);
                }
            }
        }
    }
}


# === 攻擊鏈追蹤函數 ===
function add_attack_stage(attacker: addr, stage: string, target: addr, details: string)
{
    local s: AttackStage;
    s$stage = stage;
    s$timestamp = network_time();
    s$src = attacker;
    s$dst = target;
    s$details = details;
    
    if (attacker !in attack_chains)
        attack_chains[attacker] = vector();
    
    attack_chains[attacker] += s;
    
    # 檢查是否形成完整攻擊鏈
    if (|attack_chains[attacker]| >= 4)
    {
        check_attack_chain(attacker);
    }
}


# Modbus 連接追蹤
global modbus_sources: set[addr] &create_expire=1hr;
global unusual_modbus_sources: set[addr] &create_expire=1hr;

# === HTTP 暴力破解檢測（修正版）===
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    if (/login/i in original_URI)
    {
        local orig = c$id$orig_h;
        http_login_attempts[orig] += 1;
        
        # 記錄攻擊階段
        add_attack_stage(orig, "HTTP_LOGIN_ATTEMPT", c$id$resp_h, 
                        fmt("Login attempt #%d", http_login_attempts[orig]));
    }
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if (c$http?$uri && /login/i in c$http$uri)
    {
        local orig = c$id$orig_h;
        
        if (code == 401 || code == 403)
        {
            http_failed_logins[orig] += 1;
            
            # 每10次失敗發出警告
            if (http_failed_logins[orig] % 10 == 0)
            {
                NOTICE([
                    $note=IT_HTTP_Brute_Force,
                    $msg=fmt("HTTP 暴力破解進行中: %s -> %s, 失敗嘗試: %d 次", 
                            orig, c$id$resp_h, http_failed_logins[orig]),
                    $conn=c,
                    $identifier=fmt("%s-http-bruteforce", orig)
                ]);
            }
        }
        else if (code == 200 || code == 302)  # 成功或重定向
        {
            if (http_failed_logins[orig] >= 10)
            {
                NOTICE([
                    $note=IT_HTTP_Brute_Force,
                    $msg=fmt("HTTP 暴力破解成功！%s -> %s 在 %d 次失敗後登入成功", 
                            orig, c$id$resp_h, http_failed_logins[orig]),
                    $conn=c,
                    $identifier=fmt("%s-http-bruteforce-success", orig)
                ]);
                
                add http_success_after_failures[orig];
                add_attack_stage(orig, "HTTP_BRUTEFORCE_SUCCESS", c$id$resp_h, 
                                fmt("Successful login after %d failures", http_failed_logins[orig]));
            }
            http_failed_logins[orig] = 0;
        }
    }
}

# === SSH 橫向移動檢測（修正版）===
event ssh_auth_successful(c: connection, auth_method_none: bool)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    
    # 記錄 SSH 連接
    if (orig !in ssh_connections)
        ssh_connections[orig] = set();
    add ssh_connections[orig][resp];
    
    # 檢查橫向移動模式
    # DMZ (192.168.10.x) -> 內部網路
    if (/^192\.168\.10\./ in fmt("%s", orig))
    {
        NOTICE([
            $note=IT_Lateral_Movement_SSH,
            $msg=fmt("SSH 橫向移動檢測: %s -> %s (可能從 DMZ 到內部網路)", 
                    orig, resp),
            $conn=c,
            $identifier=fmt("%s-lateral-ssh-%s", orig, resp)
        ]);
        
        add dmz_to_internal_ssh[orig];
        add_attack_stage(orig, "LATERAL_MOVEMENT_SSH", resp, 
                        fmt("SSH from DMZ to %s", resp));
    }
}

# 如果沒有 ssh_auth_successful 事件，使用連接建立事件
event connection_established(c: connection)
{
    if (c$id$resp_p == 22/tcp)
    {
        local orig = c$id$orig_h;
        local resp = c$id$resp_h;
        
        # 檢查特定的橫向移動模式
        if ((orig == 192.168.10.50 && resp == 192.168.10.51) ||
            (orig == 192.168.10.51 && /^10\.0\.0\./ in fmt("%s", resp)))
        {
            NOTICE([
                $note=IT_Lateral_Movement_SSH,
                $msg=fmt("SSH 橫向移動檢測（基於連接）: %s -> %s", orig, resp),
                $conn=c,
                $identifier=fmt("%s-ssh-movement-%s", orig, resp)
            ]);
            
            add_attack_stage(orig, "LATERAL_MOVEMENT", resp, "SSH connection");
        }
    }
}

# === Modbus 掃描檢測（增強版）===
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                          start_addr: count, quantity: count)
{
    local orig = c$id$orig_h;
    
    # 記錄訪問的地址
    if (orig !in modbus_scan_addresses)
    {
        modbus_scan_addresses[orig] = set();
        modbus_scan_start_time[orig] = network_time();
    }
    
    add modbus_scan_addresses[orig][start_addr];
    modbus_access_count[orig] += 1;
    
    # 檢查是否為異常來源
    if (orig == 192.168.10.51)  # 來自跳板主機
    {
        add unusual_modbus_sources[orig];
        
        # 檢查掃描模式
        if (|modbus_scan_addresses[orig]| >= 3 && 
            interval_to_double(network_time() - modbus_scan_start_time[orig]) < 30.0)
        {
            NOTICE([
                $note=OT_Modbus_Register_Scan,
                $msg=fmt("Modbus 暫存器掃描檢測: %s -> %s:%s, 已掃描 %d 個不同地址區域",
                        orig, c$id$resp_h, c$id$resp_p, |modbus_scan_addresses[orig]|),
                $conn=c,
                $identifier=fmt("%s-modbus-scan", orig)
            ]);
            
            add_attack_stage(orig, "MODBUS_SCAN", c$id$resp_h,
                            fmt("Scanned %d register areas", |modbus_scan_addresses[orig]|));
        }
    }
    
    # 檢查異常的 Modbus 來源
    if (orig !in modbus_sources)
    {
        add modbus_sources[orig];
        
        # 如果不是已知的 HMI (10.0.0.50)
        if (orig != 10.0.0.50)
        {
            NOTICE([
                $note=OT_Suspicious_Modbus_Pattern,
                $msg=fmt("異常 Modbus 來源: %s -> %s:%s (非標準 HMI)",
                        orig, c$id$resp_h, c$id$resp_p),
                $conn=c,
                $identifier=fmt("%s-unusual-modbus-source", orig)
            ]);
        }
    }
}

# === Modbus 寫入檢測（包含 Coil）===
event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                      address: count, value: bool)
{
    local orig = c$id$orig_h;
    
    # 記錄線圈修改
    if (orig !in coil_modifications)
        coil_modifications[orig] = set();
    add coil_modifications[orig][address];
    
    # 檢查安全線圈
    if (address in safety_coils)
    {
        local coil_name = "";
        if (address == 10) coil_name = "緊急停止";
        else if (address == 11) coil_name = "警報系統";
        
        NOTICE([
            $note=OT_Safety_System_Disabled,
            $msg=fmt("安全系統修改: %s 被設為 %s! %s -> %s:%s, 線圈地址: %d",
                    coil_name, value ? "ON" : "OFF", orig, c$id$resp_h, c$id$resp_p, address),
            $conn=c,
            $identifier=fmt("%s-safety-coil-%d", orig, address)
        ]);
        
        add_attack_stage(orig, "SAFETY_MODIFICATION", c$id$resp_h,
                        fmt("Modified safety coil %d: %s", address, coil_name));
    }
    
    # 記錄所有線圈寫入
    NOTICE([
        $note=OT_Modbus_Coil_Write,
        $msg=fmt("Modbus 線圈寫入: %s -> %s:%s, 地址: %d, 值: %s",
                orig, c$id$resp_h, c$id$resp_p, address, value ? "ON" : "OFF"),
        $conn=c,
        $identifier=fmt("%s-coil-write-%d", orig, address)
    ]);
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                          address: count, value: count)
{
    local orig = c$id$orig_h;
    
    # 記錄暫存器修改
    if (orig !in register_modifications)
        register_modifications[orig] = set();
    add register_modifications[orig][address];
    
    # 檢查關鍵暫存器
    if (address in critical_registers)
    {
        local param_name = "";
        if (address == 100) param_name = "溫度設定點";
        else if (address == 101) param_name = "壓力限制";
        else if (address == 102) param_name = "流量控制";
        else if (address == 200) param_name = "安全連鎖系統";
        
        NOTICE([
            $note=OT_Critical_Parameter_Modification,
            $msg=fmt("關鍵參數修改: %s (暫存器 %d) = %d (0x%04x), %s -> %s:%s",
                    param_name, address, value, value, orig, c$id$resp_h, c$id$resp_p),
            $conn=c,
            $identifier=fmt("%s-critical-reg-%d", orig, address)
        ]);
        
        add_attack_stage(orig, "PARAMETER_MODIFICATION", c$id$resp_h,
                        fmt("Modified %s (reg %d) to %d", param_name, address, value));
    }
}

# === 端口掃描檢測 ===
event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local resp_p = c$id$resp_p;
    
    # 檢查從跳板主機的掃描
    if (orig == 192.168.10.51 && resp == 10.0.0.100)
    {
        local scan_ports: set[port] = {80/tcp, 443/tcp, 1911/tcp, 2222/tcp, 44818/tcp};
        
        if (resp_p in scan_ports)
        {
            NOTICE([
                $note=OT_Scan_NonStandard_Port,
                $msg=fmt("工控端口掃描: %s -> %s:%s",
                        orig, resp, resp_p),
                $conn=c,
                $identifier=fmt("%s-port-scan-%s", orig, resp_p)
            ]);
            
            add_attack_stage(orig, "PORT_SCAN", resp,
                            fmt("Scanned port %s", resp_p));
        }
    }
}


# === 通知策略 ===
hook Notice::policy(n: Notice::Info)
{
    add n$actions[Notice::ACTION_LOG];
}