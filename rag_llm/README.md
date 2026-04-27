# RAG-LLM 安全事件分析系统

基于检索增强生成（Retrieval-Augmented Generation）的网络安全事件智能分析系统，融合DNS日志收集系统与离线PCAP流量分析，实现从数据采集、异常检测到智能研判的端到端安全分析流水线。

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DNS-RAG-LLM 完整系统                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────── DNS--main 子系统 ──────────────────────────┐ │
│  │                                                                          │ │
│  │   ┌──────────────┐         ┌──────────────────┐        ┌───────────┐  │ │
│  │   │  dnsClient   │         │    dnsServer     │        │  Ubuntu   │  │ │
│  │   │  (Go 探针端)  │ ──WS──▶ │  (Go + Docker)   │        │ (Zeek/Suri)│  │ │
│  │   │ Win/Linux    │         │   MySQL + Web    │        │  PCAP聚合  │  │ │
│  │   └──────────────┘         └────────┬─────────┘        └─────┬─────┘  │ │
│  │                                     │                        │        │ │
│  │                                     │ MySQL导出              │ JSON   │  │
│  │                                     ▼                        ▼        │ │
│  └─────────────────────────────────────┼────────────────────────┼────────┘ │
│                                        │                        │          │
│  ┌─────────────────────────────────────┼────────────────────────┼────────┐ │
│  │                                     │                        │          │ │
│  │   ┌──────────────────────────────┐ │ │ ┌────────────────────┴───────┐ │ │
│  │   │      rag_llm 子系统          │ │ │ │     rag_llm 子系统          │ │ │
│  │   │      (Python + Streamlit)    │ │ │ │     (Python + Streamlit)    │ │ │
│  │   │                              │ │ │ │                              │ │ │
│  │   │  ┌────────────────────────┐  │ │ │ │  ┌────────────────────────┐  │ │ │
│  │   │  │   DNS适配器            │◀─┼─┼─┘  │  │   Zeek适配器            │  │ │ │
│  │   │  │ dns_adapter.py         │  │ │    │  │ zeek_adapter.py        │  │ │ │
│  │   │  │ (MySQL/JSON读取)       │  │ │    │  │ (TSV解析)              │  │ │ │
│  │   │  └───────────┬────────────┘  │ │    │  └───────────┬────────────┘  │ │ │
│  │   │              │               │ │    │              │               │ │ │
│  │   │              ▼               │ │    │              ▼               │ │ │
│  │   │  ┌────────────────────────┐  │ │    │  ┌────────────────────────┐  │ │ │
│  │   │  │   聚合引擎             │  │ │    │  │   PCAP预处理器          │  │ │ │
│  │   │  │ aggregator.py         │◀─┼─┼────┼─│   preprocessor.py       │  │ │ │
│  │   │  │ (5种DNS聚合+Zeek)      │  │ │    │  │                         │  │ │ │
│  │   │  └───────────┬────────────┘  │ │    │  └───────────┬────────────┘  │ │ │
│  │   │              │               │ │    │              │               │ │ │
│  │   │              └───────┬───────┘ │    │              │               │ │ │
│  │   │                      │         │    │              │               │ │ │
│  │   │                      ▼         │    │              ▼               │ │ │
│  │   │  ┌────────────────────────────────────────────────────────────────┐│ │
│  │   │  │                    统一文本块格式化层                           ││ │
│  │   │  │   聚合结果 / 异常告警 → 结构化文本块 + 元数据                  ││ │
│  │   │  │   (源文件、ATT&CK映射、时间范围、告警严重性)                   ││ │
│  │   │  └────────────────────────────────────────────────────────────────┘│ │
│  │   │                              │                                      │ │
│  │   │                              ▼                                      │ │
│  │   │  ┌────────────────────────────────────────────────────────────────┐│ │
│  │   │  │                    向量化 & FAISS索引层                        ││ │
│  │   │  │   all-mpnet-base-v2 → FAISS IndexFlatIP → 持久化磁盘          ││ │
│  │   │  │   支持增量追加写入  |  Embed once, query many times            ││ │
│  │   │  └────────────────────────────────────────────────────────────────┘│ │
│  │   │                              │                                      │ │
│  │   │                              ▼                                      │ │
│  │   │  ┌────────────────────────────────────────────────────────────────┐│ │
│  │   │  │                    RAG-LLM 分析层                               ││ │
│  │   │  │   用户问题 → 嵌入 → FAISS top-k → 提示词 → DeepSeek API       ││ │
│  │   │  │   → 结构化安全事件分析报告 (支持流式输出)                       ││ │
│  │   │  └────────────────────────────────────────────────────────────────┘│ │
│  │   │                                                                     │ │
│  │   └─────────────────────────────────────────────────────────────────────┘ │
│  │                                                                           │ │
│  └───────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 项目结构

```
d:\Bishe\rag_llm\
│
├── app.py                      # Streamlit主入口，侧边栏导航+API Key配置
├── config.py                   # 全局配置（模型、路径、API、ATT&CK映射）
├── requirements.txt            # Python依赖
│
├── data/                       # 数据目录
│   ├── raw/                    # 原始数据
│   │   ├── dns_logs/           #   DNS日志JSON文件（上传或MySQL导出）
│   │   ├── pcap_agg/          #   Ubuntu PCAP聚合JSON
│   │   └── zeek_dns/          #   Zeek dns.log 文件（TSV格式）
│   ├── processed/              # 聚合后的文本块JSON + 检测历史
│   │   ├── detection_history/ #   检测历史JSON（每条检测一条文件）
│   │   └── dns_aggregations_*.json
│   └── faiss_index/            # FAISS向量索引文件
│       ├── index.faiss         #   FAISS索引
│       └── metadata.pkl        #   元数据
│
├── core/                       # 核心模块
│   ├── aggregator.py           #   DNS日志聚合引擎（5种聚合，支持Zeek格式）
│   ├── preprocessor.py         #   JSON聚合块→文本块转换（DNS+PCAP）
│   ├── embedder.py             #   向量化+FAISS索引构建/检索/增量追加
│   ├── retriever.py            #   语义检索，返回上下文+证据
│   ├── analyzer.py             #   DeepSeek LLM调用+提示词构建
│   └── pipeline.py             #   端到端流水线（串联所有模块）
│
├── integration/                # 融合模块
│   ├── dns_adapter.py          #   从MySQL/JSON获取DNS日志，含精细化错误分类
│   ├── anomaly_detector.py     #   DNS异常检测（5种规则引擎）
│   ├── bridge.py               #   异常检测结果→RAG知识库桥接
│   └── zeek_adapter.py         #   Zeek dns.log TSV解析器（新增）
│
└── ui/                         # Streamlit界面
    ├── page_data.py             #   数据管理页面（DNS/PCAP/Zeek/知识库Tab）
    ├── page_analysis.py         #   智能分析页面（支持流式输出）
    └── page_anomaly.py          #   异常检测页面
```

---

## 环境要求

- Python 3.10（conda环境 `bishe_env`）
- Miniconda安装在 `D:\miniconda3`
- 无需GPU，faiss-cpu即可运行
- DeepSeek API Key（用于LLM分析）

---

## 安装依赖

```powershell
conda activate bishe_env
pip install streamlit faiss-cpu sentence-transformers openai pandas pymysql
```

或：

```powershell
pip install -r requirements.txt
```

---

## 启动系统

```powershell
conda activate bishe_env
cd d:\Bishe\rag_llm
streamlit run app.py --server.port 8501
```

浏览器访问 http://localhost:8501

---

## 使用流程

### 第一步：准备数据

#### 方式A：上传DNS日志JSON

1. 在「📊 数据管理」页面，DNS日志标签页
2. 上传DNS日志JSON文件（支持单条或数组格式）
3. JSON格式参考下方「DNS日志JSON格式」章节
4. 文件保存到 `data/raw/dns_logs/` 目录

#### 方式B：从MySQL导出

1. 在「📊 数据管理」页面，展开MySQL连接配置
2. 填写DNS服务端的MySQL连接信息（主机、端口、用户名、密码、数据库）
3. 点击「从MySQL导出DNS日志」，自动导出到 `data/raw/dns_logs/mysql_export.json`
4. 连接失败时，系统会显示具体错误类型（连接失败/认证失败/数据库不存在）

#### 方式C：上传Zeek dns.log文件（新增）

1. 切换到「📊 数据管理」页面的「Zeek DNS日志」标签页
2. 上传 Zeek 网络监控生成的 dns.log 文件（TSV格式）
3. 系统自动解析TSV格式、映射字段、执行5种聚合分析
4. 支持查看解析后的数据预览和记录数

#### 方式D：上传PCAP聚合数据

1. 从Ubuntu虚拟机拷贝聚合JSON文件到Windows
2. 在「📊 数据管理」页面的PCAP标签页上传
3. 文件保存到 `data/raw/pcap_agg/` 目录

### 第二步：构建向量索引

1. 在「📊 数据管理」页面的「知识库管理」标签
2. 选择数据来源（全部数据 / 仅DNS日志 / 仅PCAP聚合 / 仅Zeek DNS）
3. 点击「🔨 构建向量索引」
4. 等待向量化完成（首次运行会下载 all-mpnet-base-v2 模型，约438MB）
5. 已有的向量索引支持增量追加，无需全量重建
6. 构建成功后，侧边栏显示知识库块数和向量维度

### 第三步：智能分析

1. 切换到「🔍 智能分析」页面
2. 在侧边栏输入DeepSeek API Key
3. 调整模型参数（Temperature控制随机性）
4. 输入安全问题，或点击预设问题按钮
5. 调整检索证据块数量（top-k）
6. 可选：勾选「启用流式输出」获得打字机效果的实时响应
7. 点击「🚀 开始分析」
8. 右侧显示检索到的证据块，左侧显示LLM生成的分析报告

### 第四步：异常检测（可选）

1. 切换到「🚨 异常检测」页面
2. 选择数据来源（上传的JSON文件 / MySQL数据库）
3. 调整检测阈值
4. 勾选「自动将检测结果写入RAG知识库」
5. 点击「🔍 执行异常检测」
6. 查看告警详情，异常文本块自动写入FAISS索引

### 第四步（续）：检测历史

1. 切换到「🚨 异常检测」页面的「检测历史」标签
2. 查看历次检测的概要信息（时间、数据源、告警数量、高/中/低危分布）
3. 点击任意历史条目展开，查看完整告警详情
4. 可按严重性筛选告警
5. 支持单条删除或清空全部历史
6. 历史记录持久化到 `data/processed/detection_history/` 目录，重启后保留

---

## 核心模块说明

### 聚合引擎（core/aggregator.py）

对标论文的IOC查询库，从原始DNS日志中提取安全相关信息，支持标准DNS JSON和Zeek dns.log两种格式。

| 聚合类型 | 查询逻辑 | ATT&CK映射 |
|---------|---------|-----------|
| high_freq_dns | 按源IP分组统计查询次数，取Top N | T1071.004 应用层协议:DNS |
| nxdomain_storm | 按源IP统计NXDOMAIN响应次数 | T1071.004 DGA域名探测 |
| suspicious_domain | 匹配可疑TLD、超长域名、DGA特征子标签（向量化优化） | T1071.004 C2通信 |
| low_ttl | 检测TTL≤60s的DNS响应 | T1071.004 快速Flux域名 |
| dns_tunnel | 检测超长域名和TXT/NULL记录异常 | T1071.004 DNS隧道 |

使用方式：

```python
from core.aggregator import run_all_aggregations, run_all_zeek_aggregations, save_aggregations

# 对DNS日志JSON执行全部聚合
aggregations = run_all_aggregations("data/raw/dns_logs/sample.json")

# 对Zeek dns.log文件执行全部聚合
zeek_aggregations = run_all_zeek_aggregations("data/raw/zeek_dns/dns.log")

# 保存聚合结果
save_aggregations(aggregations)
```

### Zeek适配器（integration/zeek_adapter.py）

解析 Zeek 网络安全监控系统生成的 dns.log 文件（TSV格式），支持标准Zeek头部、字段映射和空字段处理。

```python
from integration.zeek_adapter import load_zeek_dns_log, load_zeek_dns_logs, is_zeek_log_file

# 加载单个文件
df = load_zeek_dns_log("data/raw/zeek_dns/dns.log")

# 批量加载目录
df_all = load_zeek_dns_logs("data/raw/zeek_dns/")

# 检查文件是否为Zeek dns.log格式
is_zeek = is_zeek_log_file("some_file.log")
```

Zeek dns.log 文件格式示例（`#fields` 行定义了列名，`\t` 制表符分隔）：

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2024-01-01-00-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	query	qtype	qclass	rcode	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	string	count	string	string	string	string	vector[string]	vector[interval]	bool
1704067200.000000	Cxyz123	192.168.1.100	54321	8.8.8.8	53	udp	12345	example.com	A	1	0	NOERROR	example.com,1.2.3.4	300.000000	F
```

字段映射规则：

| Zeek 字段 | 系统内部字段 |
|-----------|-------------|
| ts | metadata.timestamp |
| uid | metadata.uid |
| id.orig_h | network.src_ip |
| id.orig_p | network.src_port |
| id.resp_h | network.dst_ip |
| id.resp_p | network.dst_port |
| proto | network.protocol |
| query | dns.question.name |
| qtype | dns.question.type |
| qclass | dns.question.class |
| rcode | dns.rcode |
| answers | dns.answers |
| TTLs | dns.ttl |
| rejected | dns.rejected |

### 预处理器（core/preprocessor.py）

将聚合JSON转换为论文要求的语义完整文本块。每个聚合结果作为一个独立chunk，保持语义连贯性。

```python
from core.preprocessor import process_dns_aggregations, process_pcap_aggregations

# 处理DNS聚合结果
dns_chunks = process_dns_aggregations(aggregations)

# 处理PCAP聚合文件（自动读取 data/raw/pcap_agg/ 下所有JSON）
pcap_chunks = process_pcap_aggregations()
```

### 向量化（core/embedder.py）

使用 all-mpnet-base-v2 将文本块嵌入768维向量空间，存入FAISS IndexFlatIP索引。支持增量追加写入，已有的索引可持续扩展。

```python
from core.embedder import build_index_from_chunks, load_or_build_index, FAISSIndex

# 从文本块构建索引并保存
faiss_idx = build_index_from_chunks(chunks, save=True)

# 加载已有索引或从chunks构建
faiss_idx = load_or_build_index(chunks)

# 增量追加新文本块（不重建全量索引）
faiss_idx.add_chunks(new_chunks)
```

### 检索器（core/retriever.py）

语义检索，将用户问题嵌入向量空间，检索最相关的top-k个证据块。

```python
from core.retriever import Retriever

retriever = Retriever(faiss_index)
context, results = retriever.retrieve_context("哪些主机可能被感染？")
```

### LLM分析器（core/analyzer.py）

构建提示词模板（角色设定+网络拓扑+检索上下文+问题），调用DeepSeek API生成分析报告。支持运行时参数调整（temperature）。

```python
from core.analyzer import Analyzer

# 使用默认参数
analyzer = Analyzer(api_key="your-key")

# 自定义运行时参数
analyzer = Analyzer(
    api_key="your-key",
    temperature=0.5,  # 控制随机性
)

# 流式输出（返回迭代器）
for chunk in analyzer.analyze_stream("哪些主机可能被感染？", context):
    print(chunk, end="", flush=True)
```

### 异常检测（integration/anomaly_detector.py）

5种轻量规则引擎，从DNS日志中检测异常行为，输出结构化告警。

| 检测类型 | 逻辑 | 默认阈值 |
|---------|------|---------|
| high_frequency_dns | 单IP查询次数超阈值 | 50次 |
| nxdomain_storm | 单IP NXDOMAIN响应超阈值 | 10次 |
| suspicious_domain | 可疑TLD/超长域名/DGA特征 | 自动 |
| dns_tunnel | 超长域名/TXT+异常子标签 | 自动 |
| unknown_dns_server | 向非标准DNS服务器查询超5次 | 5次 |

### DNS适配器错误分类（integration/dns_adapter.py）

MySQL连接错误细分为4类，提供可操作的排查建议：

| 异常类型 | 触发条件 | 用户操作建议 |
|---------|---------|-------------|
| DNSConnectionError | 主机不可达/连接超时 | 检查MySQL服务是否运行，端口是否正确 |
| DNSAuthenticationError | 用户名或密码错误 | 检查config.py或界面中的MySQL用户名密码 |
| DNSDatabaseError | 数据库不存在 | 检查配置的数据库名是否正确 |
| DNSQueryError | SQL执行失败 | 检查表结构或查询语法 |

### 桥接模块（integration/bridge.py）

将异常检测结果转换为RAG文本块，自动写入FAISS知识库，实现异常检测与RAG-LLM的衔接。

```python
from integration.bridge import detect_and_bridge

result = detect_and_bridge(
    source="data/raw/dns_logs/sample.json",
    pipeline=pipeline,  # 自动写入知识库
    freq_threshold=50,
    nxdomain_threshold=10,
)
```

### 检测历史（integration/bridge.py）

每次执行异常检测后自动保存历史记录，支持查询、删除和清空。

```python
from integration.bridge import (
    load_detection_history,
    save_detection_history,
    delete_detection_history,
    clear_all_detection_history,
)

# 加载所有历史记录（按时间倒序）
history = load_detection_history()

# 保存单条检测记录
save_detection_history(result, source_type="json_file", source_name="sample.json", thresholds={"freq_threshold": 50})

# 删除单条记录
delete_detection_history("20260423_143052")

# 清空全部历史
clear_all_detection_history()
```

历史记录存储在 `data/processed/detection_history/history_<timestamp>.json`，每条记录包含：检测时间、数据来源、阈值参数、告警列表、是否已写入知识库。

---

## 配置说明（config.py）

| 配置项 | 默认值 | 说明 |
|-------|--------|------|
| EMBEDDING_MODEL | all-mpnet-base-v2 | 嵌入模型 |
| RAW_ZEEK_DNS_DIR | data/raw/zeek_dns | Zeek dns.log文件目录 |
| LLM_BASE_URL | https://api.deepseek.com | DeepSeek API地址 |
| LLM_MODEL | deepseek-chat | 模型名称 |
| LLM_TEMPERATURE | 0.3 | 生成温度 |
| TOP_K | 5 | 默认检索块数 |
| NETWORK_CONTEXT | - | 网络拓扑上下文 |

API Key通过环境变量 `DEEPSEEK_API_KEY` 或Streamlit侧边栏设置。

---

## DNS日志JSON格式

系统接受与DNS探针输出一致的JSON格式：

```json
{
  "metadata": {
    "device_id": "probe-001",
    "collector_version": "1.0",
    "timestamp": "2025-01-22T08:15:23.456Z"
  },
  "network": {
    "src_ip": "192.168.1.100",
    "src_port": "54321",
    "dst_ip": "8.8.8.8",
    "dst_port": "53",
    "protocol": "udp"
  },
  "dns": {
    "transaction_id": 43981,
    "opcode": "QUERY",
    "flags": {"qr": true, "aa": false, "tc": false, "rd": true, "ra": true},
    "rcode": "NOERROR",
    "question": {"name": "example.com", "type": "A", "class": "IN"},
    "answers": [{"name": "example.com", "type": "A", "class": "IN", "ttl": 300, "address": "93.184.216.34"}],
    "authorities": [],
    "additionals": []
  }
}
```

支持单条对象或数组格式，文件放在 `data/raw/dns_logs/` 下即可。

---

## PCAP聚合JSON格式

从Ubuntu虚拟机Elasticsearch导出的聚合JSON，需包含以下字段：

```json
{
  "agg_type": "suricata_alert",
  "attack_mapping": "多技术 - IDS告警",
  "time_range": {"start": "2025-01-22T08:00:00Z", "end": "2025-01-22T20:00:00Z"},
  "results": [...]
}
```

支持的agg_type：`suricata_alert`、`zeek_http`、`zeek_conn`、`zeek_dns`、`zeek_ssl`、`zeek_kerberos`

文件放在 `data/raw/pcap_agg/` 下即可。

---

## 与DNS日志收集系统的融合关系

```
DNS日志收集系统 (DNS--main/)
├── dnsClient (Go探针) → 抓包/解析 → WebSocket发送
└── dnsServer (Go服务端) → MySQL存储 → Web管理界面
         │
         │  数据桥接
         ▼
RAG-LLM系统 (rag_llm/)
├── dns_adapter.py → 从MySQL读取DNS日志 / 接受JSON文件上传
├── zeek_adapter.py → 解析Zeek dns.log（TSV格式）
├── anomaly_detector.py → 异常检测（规则引擎）
├── bridge.py → 告警→RAG知识库
├── aggregator.py → 聚合查询（对标论文IOC查询库）
├── preprocessor.py → 文本块格式化
├── embedder.py → 向量化+FAISS（支持增量追加）
├── retriever.py → 语义检索
├── analyzer.py → DeepSeek LLM分析（支持流式输出）
└── Streamlit界面 → 可视化操作（模型参数调节/文件管理）
```

融合方式：
1. **数据桥接**：dns_adapter从DNS系统MySQL读取日志，或接受JSON文件上传；zeek_adapter直接解析Zeek网络监控生成的dns.log
2. **异常触发**：异常检测发现可疑行为后，自动生成文本块写入FAISS
3. **统一知识库**：DNS实时异常 + PCAP离线聚合 + Zeek DNS日志 共享同一个FAISS向量库
4. **独立界面**：DNS系统原有Web界面保持独立，RAG-LLM是新的Streamlit入口

---

## 常见问题

**Q: 首次构建索引很慢？**
A: 首次运行会下载 all-mpnet-base-v2 模型（约438MB），后续运行会使用缓存。

**Q: 向量索引存在哪里？**
A: `data/faiss_index/index.faiss` 和 `data/faiss_index/metadata.pkl`，构建一次后续可直接加载。

**Q: DeepSeek API Key怎么获取？**
A: 注册 https://platform.deepseek.com ，在API Keys页面创建。

**Q: 不想用DeepSeek，能用其他模型吗？**
A: 修改 config.py 中的 LLM_BASE_URL 和 LLM_MODEL 即可，只要兼容OpenAI API格式就行（如Qwen、GLM等）。

**Q: Ubuntu上的PCAP聚合数据怎么弄过来？**
A: 从虚拟机拷贝JSON文件到Windows的 `d:\Bishe\rag_llm\data\raw\pcap_agg\` 目录，或在Streamlit界面上传。

**Q: DNS系统的MySQL连不上？**
A: 确保DNS服务端的MySQL端口（默认3306）对Windows可达，检查防火墙和Docker网络配置。连接失败时系统会显示具体错误类型。

**Q: Zeek dns.log文件怎么获取？**
A: 在Zeek网络监控服务器上，DNS日志默认输出为 `dns.log`（通常是 `/var/log/zeek/dns.log` 或 `zeek/logs/dns.log`），拷贝到Windows即可。

**Q: 流式输出是什么？**
A: 启用后，LLM的响应会实时逐字显示，有打字机效果，体验更好。但需要后端模型API支持chunked response。
