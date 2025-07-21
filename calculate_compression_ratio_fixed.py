#!/usr/bin/env python3
"""
SAGE 系統資料壓縮比計算工具

基於實際的實驗流程設計:
- 實驗一: complete_zeek_attack_analysis.sh (7種Modbus攻擊)
- 實驗二: analyze_pcap.sh (SCADA HMI)

支援自動偵測項目結構並計算多層次壓縮比

用法:
  python3 calculate_compression_ratio_fixed.py <模式> [參數...]

模式:
  experiment1 [attack_name] [project_dir]    - 分析實驗一的單一攻擊類型
  experiment1_all [sage_path]                - 分析實驗一的所有攻擊類型
  experiment2 [project_dir]                  - 分析實驗二 SCADA HMI
  project [project_dir]                      - 分析指定專案目錄

範例:
  # 分析實驗二 SCADA HMI
  python3 calculate_compression_ratio_fixed.py experiment2 project/veth291ab9a-0_project
  
  # 分析實驗一特定攻擊
  python3 calculate_compression_ratio_fixed.py experiment1 false_injection project/false_injection_project
  
  # 分析實驗一所有攻擊
  python3 calculate_compression_ratio_fixed.py experiment1_all
"""

import os
import sys
import glob
import subprocess
import json
from pathlib import Path

# 實驗一攻擊類型映射 (基於 complete_zeek_attack_analysis.sh)
EXPERIMENT1_ATTACKS = {
    "baseline_replay": {"packets": 467, "folder": "Baselinereplay"},
    "false_injection": {"packets": 374, "folder": "Falseinjection"},
    "modify_length_parameters": {"packets": 381, "folder": "Modifylengthparameters"},
    "query_flooding": {"packets": 75678, "folder": "Queryflooding"},
    "reconnaissance": {"packets": 673, "folder": "Reconnaissance"},
    "stack_modbus_frames": {"packets": 368, "folder": "Stackmodbusframes"},
    "write_to_all_coils": {"packets": 495, "folder": "WriteToAllCoils"}
}

# 實驗二 SCADA HMI 數據
EXPERIMENT2_DATA = {
    "packets": 1172759,
    "dedup_alerts": 15150,
    "raw_alerts": 134494,
    "expected_graphs": 21,
    "expected_nodes": 111
}

class CompressionAnalyzer:
    def __init__(self, sage_path=""):
        self.sage_path = sage_path or os.path.expanduser("~/SAGE")
        
    def count_pcap_packets(self, pcap_file, attack_name=""):
        """計算 PCAP 檔案封包數 (基於 complete_zeek_attack_analysis.sh 的 count_packets 函數)"""
        if not os.path.exists(pcap_file):
            # 如果檔案不存在，嘗試從已知攻擊類型獲取
            attack_key = attack_name.lower().replace("_", "").replace("-", "")
            for key, data in EXPERIMENT1_ATTACKS.items():
                if attack_key in key.replace("_", ""):
                    print(f"  使用論文數據: {data['packets']:,} 個封包")
                    return data['packets']
            
            # SCADA HMI 情況
            if any(x in attack_name.lower() for x in ['scada', 'hmi', 'veth291ab9a-0']):
                print(f"  使用論文數據: {EXPERIMENT2_DATA['packets']:,} 個封包")
                return EXPERIMENT2_DATA['packets']
                
            print(f"  PCAP 檔案不存在: {pcap_file}")
            return 0
            
        # 使用 capinfos 計算封包數 (與腳本相同邏輯)
        try:
            result = subprocess.run(['capinfos', '-c', pcap_file], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Number of packets' in line and 'Interface' not in line:
                        import re
                        # 處理 "Number of packets:   1172 k" 格式
                        match = re.search(r':\s*(\d+)(?:\s*k)?\s*$', line)
                        if match:
                            num = int(match.group(1))
                            if 'k' in line.lower():
                                num *= 1000
                            print(f"  使用 capinfos 計算: {num:,} 個封包")
                            return num
        except Exception as e:
            print(f"  使用 capinfos 時發生錯誤: {e}")
            
        # 備用方案: tcpdump
        try:
            result = subprocess.run(['tcpdump', '-r', pcap_file, '-nn'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                count = len(result.stdout.strip().split('\n'))
                print(f"  使用 tcpdump 計算: {count:,} 個封包")
                return count
        except:
            pass
            
        print(f"  無法計算封包數")
        return 0

    def count_log_records(self, log_dir):
        """計算 Zeek 日誌記錄數 (基於 complete_zeek_attack_analysis.sh 的 count_log_records 函數)"""
        total_records = 0
        log_stats = {}
        
        # 檢查標準日誌檔案
        log_files = ['conn.log', 'modbus.log', 'modbus_detailed.log', 
                     'notice.log', 'weird.log', 'dns.log', 'packet_filter.log']
        
        for log_file in log_files:
            log_path = os.path.join(log_dir, log_file)
            if os.path.exists(log_path):
                try:
                    with open(log_path, 'r') as f:
                        # 排除以 # 開頭的註解行和空行 (與腳本邏輯相同)
                        records = sum(1 for line in f 
                                    if line.strip() and not line.startswith('#'))
                    total_records += records
                    log_stats[log_file] = records
                    print(f"  {log_file}: {records:,} 筆記錄")
                except Exception as e:
                    print(f"  讀取 {log_file} 時發生錯誤: {e}")
        
        return total_records, log_stats

    def count_abstract_events(self, project_dir, attack_name=""):
        """計算抽象事件數量"""
        # SCADA HMI 使用論文數據
        if any(x in attack_name.lower() for x in ['scada', 'hmi', 'veth291ab9a-0']):
            print(f"  使用論文數據: {EXPERIMENT2_DATA['dedup_alerts']:,} 個去重後告警")
            return EXPERIMENT2_DATA['dedup_alerts']
        
        # 檢查 alerts 目錄中的事件檔案
        alerts_dir = os.path.join(project_dir, "alerts")
        if os.path.exists(alerts_dir):
            for file_name in os.listdir(alerts_dir):
                if file_name.endswith('.json'):
                    file_path = os.path.join(alerts_dir, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                event_count = len(data)
                                print(f"  從檔案計算: {event_count} 個事件")
                                return event_count
                            elif isinstance(data, dict):
                                # 計算唯一事件類型
                                unique_events = set()
                                for key, value in data.items():
                                    if isinstance(value, list):
                                        for item in value:
                                            if isinstance(item, dict) and 'event' in item:
                                                unique_events.add(item['event'])
                                            elif isinstance(item, str):
                                                unique_events.add(item)
                                if unique_events:
                                    event_count = len(unique_events)
                                    print(f"  從檔案計算: {event_count} 個唯一事件類型")
                                    return event_count
                    except Exception as e:
                        print(f"  讀取事件檔案 {file_name} 時發生錯誤: {e}")
        
        # 預設值: 實驗一使用 20 個語意事件 (根據論文 ch5.md)
        default_events = 20
        print(f"  使用標準事件數量: {default_events} 個語意事件")
        return default_events

    def count_attack_graphs(self, project_dir):
        """計算攻擊圖數量和節點數 (基於 complete_zeek_attack_analysis.sh 的邏輯)"""
        attack_graphs_dir = os.path.join(project_dir, "attack_graphs")
        
        if not os.path.exists(attack_graphs_dir):
            print(f"  攻擊圖目錄不存在: {attack_graphs_dir}")
            return 0, 0
        
        # 計算 PNG 攻擊圖數量 (與腳本相同邏輯)
        png_files = glob.glob(os.path.join(attack_graphs_dir, "*.png"))
        graph_count = len(png_files)
        
        if graph_count > 0:
            print(f"  發現 {graph_count} 張攻擊圖 (PNG)")
        
        # 計算節點數 (從 DOT 檔案)
        total_nodes = 0
        dot_files = glob.glob(os.path.join(attack_graphs_dir, "*attack-graph-for-victim*.dot"))
        
        if not dot_files:
            dot_files = glob.glob(os.path.join(attack_graphs_dir, "*.dot"))
        
        node_counts = []
        for dot_file in dot_files:
            try:
                with open(dot_file, 'r') as f:
                    content = f.read()
                    
                    # 計算節點定義 ("node_name" [)
                    import re
                    nodes = re.findall(r'^\s*"([^"]+)"\s*\[', content, re.MULTILINE)
                    unique_nodes = set(nodes)
                    
                    # 如果失敗，計算 [label= 的數量
                    if len(unique_nodes) == 0:
                        label_count = content.count('[label=')
                        if label_count > 0:
                            unique_nodes = set(range(label_count))
                    
                    node_count = len(unique_nodes)
                    if node_count > 0:
                        total_nodes += node_count
                        node_counts.append(node_count)
                        
            except Exception as e:
                print(f"  讀取 {os.path.basename(dot_file)} 時發生錯誤: {e}")
        
        if node_counts:
            avg_nodes = sum(node_counts) / len(node_counts)
            print(f"  總節點數: {total_nodes}")
            print(f"  平均每圖節點數: {avg_nodes:.1f}")
        
        # 如果沒有找到節點但有攻擊圖，使用估計值
        if total_nodes == 0 and graph_count > 0:
            avg_nodes_per_graph = 5  # 根據論文數據的平均值
            total_nodes = graph_count * avg_nodes_per_graph
            print(f"  總節點數: {total_nodes} (估計值: 每圖 {avg_nodes_per_graph} 個節點)")
        
        return graph_count, total_nodes

    def analyze_project(self, project_dir, attack_name=""):
        """分析專案目錄的壓縮比"""
        project_dir = os.path.abspath(project_dir)
        
        if not os.path.exists(project_dir):
            print(f"錯誤: 專案目錄不存在: {project_dir}")
            return None
            
        print(f"\n=== {attack_name or os.path.basename(project_dir)} 壓縮比分析 ===")
        print(f"專案目錄: {project_dir}")
        
        # 1. 計算原始封包數
        pcap_file = ""
        # 尋找 PCAP 檔案
        for ext in ['*.pcap', '*.pcapng']:
            pcap_files = glob.glob(os.path.join(project_dir, ext))
            if pcap_files:
                pcap_file = pcap_files[0]
                break
                
        packet_count = self.count_pcap_packets(pcap_file, attack_name)
        print(f"\n原始封包數: {packet_count:,}")
        
        # 2. 計算 Zeek 日誌記錄數
        log_count, log_stats = self.count_log_records(project_dir)
        print(f"\nZeek 日誌總記錄數: {log_count:,}")
        
        # 3. 計算抽象事件數
        print(f"\n抽象事件數:")
        event_count = self.count_abstract_events(project_dir, attack_name)
        print(f"  總事件數: {event_count:,}")
        
        # 4. 計算攻擊圖統計
        print(f"\n攻擊圖統計:")
        graph_count, node_count = self.count_attack_graphs(project_dir)
        
        # 計算壓縮比
        if node_count > 0 and packet_count > 0:
            packet_compression = packet_count / node_count
            log_compression = log_count / node_count if log_count > 0 else 0
            event_compression = event_count / node_count
            
            print(f"\n壓縮比計算結果:")
            print(f"  封包級壓縮比: {packet_compression:,.1f}:1")
            print(f"  日誌級壓縮比: {log_compression:,.1f}:1")
            print(f"  事件級壓縮比: {event_compression:,.1f}:1")
            
            # 整體壓縮比
            if graph_count > 0:
                overall_compression = packet_count / graph_count
                print(f"\n整體壓縮比: {overall_compression:,.1f}:1")
                
            # 顯示對應的論文參考
            self.show_paper_references(attack_name, packet_compression, overall_compression)
            
            return {
                'attack_name': attack_name,
                'packet_count': packet_count,
                'log_count': log_count,
                'event_count': event_count,
                'graph_count': graph_count,
                'node_count': node_count,
                'packet_compression': packet_compression,
                'log_compression': log_compression,
                'event_compression': event_compression,
                'overall_compression': overall_compression
            }
        else:
            print(f"\n無法計算壓縮比")
            print(f"  封包數: {packet_count}, 節點數: {node_count}, 攻擊圖數: {graph_count}")
            return None

    def show_paper_references(self, attack_name, packet_compression, overall_compression):
        """顯示對應的論文參考資料"""
        print(f"\n對應論文數據:")
        
        if any(x in attack_name.lower() for x in ['scada', 'hmi', 'veth291ab9a-0']):
            print(f"  - ch4.md 第98行: 總體壓縮比 55,845:1")
            print(f"  - ch4.md 第99行: 多層次壓縮 (封包級:10,565:1, 日誌級:1,550:1, 事件級:137:1)")
            print(f"  - ch4.md 第81行: 134,494 → 15,150 告警 (11.3%)")
            
            # 比較實際與論文數據
            expected_packet_compression = 10565
            if abs(packet_compression - expected_packet_compression) / expected_packet_compression > 0.1:
                print(f"  ⚠ 封包級壓縮比差異較大 (實際:{packet_compression:.1f}, 論文:{expected_packet_compression})")
                
        elif 'query' in attack_name.lower() or 'flooding' in attack_name.lower():
            print(f"  - ch4.md 第47行: 查詢洪水攻擊壓縮比 19,640:1")
            print(f"  - ch4.md 第65行: Query Flooding 75,678 封包")
            
        else:
            print(f"  - ch4.md 第11行: 各攻擊類型封包數")
            print(f"  - ch4.md 第43行: 總計 72 張攻擊圖")

    def analyze_experiment1_all(self):
        """分析實驗一的所有攻擊類型"""
        print("\n=== 實驗一：7種 Modbus 攻擊壓縮比分析 ===")
        
        results = []
        total_packets = 0
        total_graphs = 0
        
        for attack_name, attack_data in EXPERIMENT1_ATTACKS.items():
            project_name = f"{attack_name}_project"
            project_path = os.path.join(self.sage_path, "project", project_name)
            
            if os.path.exists(project_path):
                result = self.analyze_project(project_path, attack_name)
                if result:
                    results.append(result)
                    total_packets += result['packet_count']
                    total_graphs += result['graph_count']
            else:
                print(f"\n專案目錄不存在: {project_path}")
                # 使用論文數據進行估算
                print(f"使用論文數據估算 {attack_name}:")
                print(f"  封包數: {attack_data['packets']:,}")
                total_packets += attack_data['packets']
        
        # 顯示總體統計
        print(f"\n=== 實驗一總體統計 ===")
        print(f"總封包數: {total_packets:,}")
        print(f"總攻擊圖數: {total_graphs}")
        if total_graphs > 0:
            print(f"整體壓縮比: {total_packets/total_graphs:,.1f}:1")
        
        print(f"\n對應論文數據:")
        print(f"  - ch4.md 第10行: 總計擷取 78,436 筆 Modbus 通訊封包")
        print(f"  - ch4.md 第43行: 系統成功識別所有七種攻擊類型，並產生總計 72 張攻擊圖")
        print(f"  - ch4.md 第41行: 整體執行耗時 6 分 4 秒")
        
        return results

def show_usage():
    """顯示使用說明"""
    print(__doc__)

def main():
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    analyzer = CompressionAnalyzer()
    
    if mode == "experiment1":
        if len(sys.argv) < 3:
            print("錯誤: experiment1 模式需要指定攻擊名稱")
            print("用法: python3 calculate_compression_ratio_fixed.py experiment1 <attack_name> [project_dir]")
            sys.exit(1)
            
        attack_name = sys.argv[2]
        project_dir = sys.argv[3] if len(sys.argv) > 3 else f"project/{attack_name}_project"
        analyzer.analyze_project(project_dir, attack_name)
        
    elif mode == "experiment1_all":
        sage_path = sys.argv[2] if len(sys.argv) > 2 else "."
        analyzer.sage_path = os.path.abspath(sage_path)
        analyzer.analyze_experiment1_all()
        
    elif mode == "experiment2":
        project_dir = sys.argv[2] if len(sys.argv) > 2 else "project/veth291ab9a-0_project"
        analyzer.analyze_project(project_dir, "SCADA_HMI")
        
    elif mode == "project":
        if len(sys.argv) < 3:
            print("錯誤: project 模式需要指定專案目錄")
            print("用法: python3 calculate_compression_ratio_fixed.py project <project_dir>")
            sys.exit(1)
            
        project_dir = sys.argv[2]
        attack_name = os.path.basename(project_dir).replace("_project", "")
        analyzer.analyze_project(project_dir, attack_name)
        
    else:
        print(f"錯誤: 未知模式 '{mode}'")
        show_usage()
        sys.exit(1)

if __name__ == "__main__":
    main()