#!/bin/bash

# SAGE 自動安裝腳本
# 此腳本將自動安裝和配置 SAGE 系統所需的所有組件

set -e  # 遇到錯誤立即退出

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 輔助函數
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# 檢查系統需求
check_requirements() {
    print_status "檢查系統需求..."
    
    # 檢查作業系統
    if [[ ! -f /etc/os-release ]]; then
        print_error "無法檢測作業系統版本"
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]] || [[ "${VERSION_ID}" < "20.04" ]]; then
        print_warning "建議使用 Ubuntu 20.04 或更新版本"
    fi
    
    # 檢查 Python 版本
    if ! command -v python3 &> /dev/null; then
        print_error "未找到 Python 3"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
        print_error "需要 Python 3.8 或更高版本，當前版本：$PYTHON_VERSION"
        exit 1
    fi
    
    print_success "系統需求檢查通過"
}

# 安裝系統套件
install_system_packages() {
    print_status "安裝系統套件..."
    
    sudo apt update
    sudo apt install -y \
        build-essential \
        git \
        curl \
        wget \
        cmake \
        libpcre3-dev \
        libssl-dev \
        zlib1g-dev \
        python3-pip \
        python3-dev \
        python3-venv \
        graphviz \
        graphviz-dev \
        libgraphviz-dev \
        pkg-config
    
    print_success "系統套件安裝完成"
}

# 安裝 Zeek
install_zeek() {
    print_status "檢查 Zeek 安裝..."
    
    if command -v zeek &> /dev/null; then
        ZEEK_VERSION=$(zeek --version 2>&1 | grep -oP 'version \K[0-9.]+' || echo "unknown")
        print_success "Zeek 已安裝 (版本: $ZEEK_VERSION)"
        return
    fi
    
    print_status "安裝 Zeek..."
    
    # 加入 Zeek 儲存庫
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | \
        sudo tee /etc/apt/sources.list.d/security:zeek.list
    
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | \
        gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    
    sudo apt update
    sudo apt install -y zeek
    
    # 設定 PATH
    if ! grep -q "/opt/zeek/bin" ~/.bashrc; then
        echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
    fi
    
    export PATH=/opt/zeek/bin:$PATH
    
    print_success "Zeek 安裝完成"
}

# 安裝 Zeek 插件
install_zeek_plugins() {
    print_status "安裝 Zeek 插件..."
    
    # 安裝 zkg
    pip3 install --user zkg
    
    # 配置 zkg
    export PATH=$HOME/.local/bin:$PATH
    yes | zkg autoconfig
    
    # 安裝 Modbus 插件
    sudo $(which zkg) install --force icsnpp/icsnpp-modbus
    
    print_success "Zeek 插件安裝完成"
}

# 設定 Python 環境
setup_python_env() {
    print_status "設定 Python 虛擬環境..."
    
    # 建立虛擬環境
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    # 啟動虛擬環境
    source venv/bin/activate
    
    # 升級 pip
    pip install --upgrade pip wheel setuptools
    
    print_success "Python 環境設定完成"
}

# 安裝 Python 套件
install_python_packages() {
    print_status "安裝 Python 套件..."
    
    # 確保虛擬環境已啟動
    source venv/bin/activate
    
    # 建立 requirements.txt 如果不存在
    if [[ ! -f "requirements.txt" ]]; then
        cat > requirements.txt << EOF
pandas>=1.3.0
numpy>=1.21.0
scikit-learn>=0.24.0
networkx>=2.6
matplotlib>=3.4.0
seaborn>=0.11.0
click>=8.0.0
tqdm>=4.62.0
colorama>=0.4.4
graphviz>=0.17
pygraphviz>=1.7
requests>=2.26.0
EOF
    fi
    
    # 安裝套件
    pip install -r requirements.txt
    
    print_success "Python 套件安裝完成"
}

# 編譯 FlexFringe
compile_flexfringe() {
    print_status "編譯 FlexFringe..."
    
    if [[ -d "FlexFringe" ]]; then
        cd FlexFringe
        make clean
        make
        cd ..
        
        if [[ -x "FlexFringe/flexfringe" ]]; then
            print_success "FlexFringe 編譯完成"
        else
            print_error "FlexFringe 編譯失敗"
            exit 1
        fi
    else
        print_warning "未找到 FlexFringe 目錄，跳過編譯"
    fi
}

# 建立目錄結構
create_directories() {
    print_status "建立目錄結構..."
    
    mkdir -p output/{logs,graphs,reports}
    mkdir -p data/{pcap,zeek_logs,processed}
    mkdir -p tmp
    mkdir -p examples
    
    print_success "目錄結構建立完成"
}

# 設定執行權限
set_permissions() {
    print_status "設定執行權限..."
    
    # 設定腳本執行權限
    chmod +x *.sh 2>/dev/null || true
    chmod +x sage.py 2>/dev/null || true
    
    # 設定 FlexFringe 執行權限
    if [[ -f "FlexFringe/flexfringe" ]]; then
        chmod +x FlexFringe/flexfringe
    fi
    
    print_success "執行權限設定完成"
}

# 建立配置檔案
create_config() {
    print_status "建立配置檔案..."
    
    if [[ ! -f "config.ini" ]]; then
        cat > config.ini << EOF
[zeek]
zeek_path = /opt/zeek/bin/zeek
zeek_scripts = /opt/zeek/share/zeek

[sage]
flexfringe_path = ./FlexFringe/flexfringe
time_window = 300
min_events = 10

[output]
output_dir = ./output
log_level = INFO
graph_format = png

[analysis]
num_threads = 4
memory_limit = 8192
EOF
        print_success "配置檔案建立完成"
    else
        print_warning "配置檔案已存在，跳過建立"
    fi
}

# 下載範例檔案
download_examples() {
    print_status "下載範例檔案..."
    
    # 建立範例 PCAP（這裡應該替換為實際的下載連結）
    if [[ ! -f "examples/modbus_sample.pcap" ]]; then
        print_warning "請手動下載範例 PCAP 檔案到 examples/ 目錄"
    fi
    
    # 建立範例 Zeek 腳本
    cat > examples/detect_modbus_scan.zeek << 'EOF'
@load base/protocols/modbus

module Modbus;

export {
    redef enum Notice::Type += {
        Possible_Scan
    };
    
    const scan_threshold = 10 &redef;
    const scan_interval = 5min &redef;
}

event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
{
    # 檢測掃描行為
    if (quantity > 100)
    {
        NOTICE([$note=Possible_Scan,
                $msg=fmt("Large register read detected: %d registers", quantity),
                $conn=c]);
    }
}
EOF
    
    print_success "範例檔案準備完成"
}

# 驗證安裝
verify_installation() {
    print_status "驗證安裝..."
    
    local errors=0
    
    # 檢查 Zeek
    if ! command -v zeek &> /dev/null; then
        print_error "Zeek 未正確安裝"
        ((errors++))
    fi
    
    # 檢查 Python 環境
    if [[ ! -d "venv" ]]; then
        print_error "Python 虛擬環境未建立"
        ((errors++))
    fi
    
    # 檢查 FlexFringe
    if [[ ! -x "FlexFringe/flexfringe" ]]; then
        print_warning "FlexFringe 未編譯"
    fi
    
    # 檢查目錄
    if [[ ! -d "output" ]] || [[ ! -d "data" ]]; then
        print_error "目錄結構不完整"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        print_success "安裝驗證通過！"
        return 0
    else
        print_error "發現 $errors 個問題，請檢查安裝"
        return 1
    fi
}

# 顯示安裝摘要
show_summary() {
    echo
    echo "======================================"
    echo "         SAGE 安裝完成摘要"
    echo "======================================"
    echo
    print_success "系統已準備就緒！"
    echo
    echo "後續步驟："
    echo "1. 啟動虛擬環境："
    echo "   ${BLUE}source venv/bin/activate${NC}"
    echo
    echo "2. 執行第一次分析："
    echo "   ${BLUE}./analyze_pcap.sh examples/modbus_sample.pcap test${NC}"
    echo
    echo "3. 查看快速開始指南："
    echo "   ${BLUE}cat QUICK_START.md${NC}"
    echo
    echo "如遇問題，請查看 INSTALLATION_GUIDE.md"
    echo "======================================"
}

# 主函數
main() {
    echo "======================================"
    echo "      SAGE 自動安裝程式"
    echo "======================================"
    echo
    
    # 確認執行
    read -p "即將開始安裝，是否繼續？ [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]] && [[ ! -z $REPLY ]]; then
        print_warning "安裝已取消"
        exit 0
    fi
    
    # 執行安裝步驟
    check_requirements
    install_system_packages
    install_zeek
    install_zeek_plugins
    setup_python_env
    install_python_packages
    compile_flexfringe
    create_directories
    set_permissions
    create_config
    download_examples
    
    # 驗證安裝
    if verify_installation; then
        show_summary
    else
        print_error "安裝過程中發生錯誤，請檢查上述訊息"
        exit 1
    fi
}

# 執行主函數
main "$@"