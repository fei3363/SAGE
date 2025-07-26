# SAGE Docker 映像檔
FROM ubuntu:20.04

# 設定環境變數
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV PYTHONUNBUFFERED=1
ENV PATH=/opt/zeek/bin:$PATH

# 設定工作目錄
WORKDIR /opt/sage

# 安裝系統相依套件
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    cmake \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    python3.8 \
    python3-pip \
    python3-dev \
    python3-venv \
    graphviz \
    graphviz-dev \
    libgraphviz-dev \
    pkg-config \
    tcpdump \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# 安裝 Zeek
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' > /etc/apt/sources.list.d/security:zeek.list && \
    wget -nv https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key -O Release.key && \
    apt-key add - < Release.key && \
    apt-get update && \
    apt-get install -y zeek && \
    rm -rf /var/lib/apt/lists/*

# 安裝 Python 套件
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# 安裝 Zeek 插件
RUN pip3 install zkg && \
    zkg autoconfig --force && \
    zkg install --force icsnpp/icsnpp-modbus

# 複製 SAGE 原始碼
COPY . .

# 編譯 FlexFringe
RUN if [ -d "FlexFringe" ]; then \
        cd FlexFringe && \
        make clean && \
        make && \
        cd ..; \
    fi

# 建立必要目錄
RUN mkdir -p output/{logs,graphs,reports} \
             data/{pcap,zeek_logs,processed} \
             tmp

# 設定執行權限
RUN chmod +x *.sh && \
    if [ -f "FlexFringe/flexfringe" ]; then chmod +x FlexFringe/flexfringe; fi

# 建立非 root 使用者
RUN useradd -m -s /bin/bash sage && \
    chown -R sage:sage /opt/sage

# 切換到非 root 使用者
USER sage

# 設定進入點
ENTRYPOINT ["/bin/bash"]

# 預設指令
CMD ["--help"]