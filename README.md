# DNS-RAG-LLM

基于检索增强生成（Retrieval-Augmented Generation）的网络安全事件智能分析系统。

## 项目概述

本项目是一个完整的网络安全分析系统，包含两个主要子系统：

| 子系统 | 技术栈 | 功能 |
|--------|--------|------|
| DNS-RAG-LLM | Python + Streamlit | DNS日志智能分析、异常检测、RAG-LLM研判 |
| DNS-Main | Go + Docker | DNS流量采集、服务端存储、Web管理界面 |

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        数据来源层                                │
│                                                                 │
│  DNS实时日志(探针→MySQL)    Ubuntu PCAP离线分析   Zeek dns.log │
│  (dnsClient → dnsServer)   (Zeek + Suricata)   (网络监控)      │
└──────────────┬──────────────────────┬──────────────┬────────────┘
               │                      │              │
               ▼                      ▼              ▼
┌──────────────────────────┐ ┌──────────────────────────────┐
│ Python聚合引擎            │ │ 3个JSON聚合块(手动从Ubuntu拷贝)│
│ (pandas, Win11本地运行)   │ │ - Suricata告警聚合           │
│ - 高频DNS查询聚合         │ │ - Zeek DNS/HTTP/连接聚合      │
│ - NXDOMAIN风暴聚合        │ └──────────────┬─────────────┘
│ - 可疑域名聚合            │                 │
│ - 低TTL异常聚合           │                 │
│ - DNS隧道检测聚合         │                 │
│ (支持 Zeek dns.log)      │                 │
└──────────────┬───────────┘                 │
               │                               │
               ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     DNS异常检测模块                               │
│  规则引擎: 高频检测 / NXDOMAIN风暴 / 可疑域名 / DNS隧道 /        │
│           未知DNS服务器                                          │
│  输出: 告警列表 → 自动转换为RAG文本块 → 写入FAISS知识库           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  统一文本块格式化层                               │
│  每个聚合结果 / 异常告警 → 结构化文本块 + 元数据                  │
│  (源文件、ATT&CK映射、时间范围、告警严重性)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  向量化 & FAISS索引层                             │
│  all-mpnet-base-v2 嵌入 → FAISS IndexFlatIP → 持久化到磁盘      │
│  支持增量追加写入，无需全量重建                                   │
│  原则: Embed once, query many times                              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                  RAG-LLM 分析层                                  │
│  用户问题 → 嵌入 → FAISS top-k检索 → 构建提示词 → DeepSeek API  │
│  → 结构化安全事件分析报告（支持流式输出）                         │
└─────────────────────────────────────────────────────────────────┘
```

## 目录结构

```
d:\Bishe\
│
├── DNS--main/                    # DNS日志收集系统
│   ├── dnsClient/               # DNS探针端 (Go)
│   │   ├── main.go             # 主程序入口
│   │   ├── capturePacket.go    # 流量捕获
│   │   ├── parsePacket.go      # DNS解析
│   │   ├── webSocket.go        # WebSocket通信
│   │   └── sendFiles.go        # 文件发送
│   │   └── ...
│   │
│   └── dnsServer/              # DNS服务端 (Go + Docker)
│       ├── back/               # 后端API
│       │   ├── api.go          # API入口
│       │   ├── database.go     # 数据库操作
│       │   ├── webSocket.go    # WebSocket处理
│       │   └── ...
│       │
│       ├── front/              # 前端页面
│       │   ├── index.html      # 主页
│       │   ├── login.js        # 登录
│       │   ├── device.js       # 设备管理
│       │   ├── packet.js       # 数据包查看
│       │   └── ...
│       │
│       ├── docker-compose.yml  # Docker编排
│       ├── Dockerfile
│       └── dns_server.sql      # 数据库表结构
│
├── rag_llm/                      # RAG-LLM智能分析系统
│   ├── app.py                   # Streamlit主入口
│   ├── config.py                # 全局配置
│   ├── requirements.txt         # Python依赖
│   │
│   ├── core/                    # 核心模块
│   │   ├── aggregator.py        # DNS日志聚合引擎
│   │   ├── preprocessor.py       # 文本块格式化
│   │   ├── embedder.py          # 向量化+FAISS
│   │   ├── retriever.py         # 语义检索
│   │   ├── analyzer.py          # LLM分析
│   │   └── pipeline.py          # 端到端流水线
│   │
│   ├── integration/             # 融合模块
│   │   ├── dns_adapter.py       # MySQL/JSON数据适配
│   │   ├── anomaly_detector.py  # 异常检测规则引擎
│   │   ├── bridge.py            # 异常→RAG知识库桥接
│   │   └── zeek_adapter.py      # Zeek dns.log解析
│   │
│   ├── ui/                      # Streamlit界面
│   │   ├── page_data.py         # 数据管理页面
│   │   ├── page_analysis.py     # 智能分析页面
│   │   └── page_anomaly.py      # 异常检测页面
│   │
│   └── data/                    # 数据目录
│       ├── raw/                  # 原始数据
│       ├── processed/            # 处理后数据
│       └── faiss_index/          # FAISS向量索引
│
└── .gitignore                    # Git忽略规则
```

## 快速开始

### 1. DNS日志收集系统

#### 探针端 (dnsClient)

**Windows:**
```powershell
.\dnsProbe.exe --ip=服务器地址 --u=用户名 --p=密码
```

**Linux:**
```bash
sudo ./dnsProbe --ip=服务器地址 --u=用户名 --p=密码
```

#### 服务端 (dnsServer)

```bash
sudo docker-compose up --build
```

### 2. RAG-LLM分析系统

#### 安装依赖

```powershell
conda activate bishe_env
pip install -r rag_llm/requirements.txt
```

#### 启动

```powershell
streamlit run rag_llm/app.py --server.port 8501
```

浏览器访问 http://localhost:8501

## 功能特性

### DNS日志收集 (DNS--main)

- 实时DNS流量捕获
- WebSocket实时传输
- MySQL数据库存储
- Web管理界面
- 设备管理、用户管理、日志查看

### RAG-LLM分析 (rag_llm)

- **多数据源支持**: DNS日志JSON、MySQL导出、Zeek dns.log、PCAP聚合
- **异常检测**: 高频查询、NXDOMAIN风暴、可疑域名、DNS隧道、未知DNS服务器
- **智能研判**: 基于DeepSeek LLM的自然语言分析
- **向量检索**: FAISS语义搜索
- **流式输出**: 实时打字机效果

## 技术栈

### DNS收集系统
- Go 1.x
- Docker & Docker Compose
- MySQL
- WebSocket

### RAG-LLM系统
- Python 3.10
- Streamlit
- FAISS (faiss-cpu)
- Sentence-Transformers (all-mpnet-base-v2)
- DeepSeek API

## License

MIT
