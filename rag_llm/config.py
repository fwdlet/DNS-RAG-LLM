import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DNS_DIR = os.path.join(DATA_DIR, "raw", "dns_logs")
RAW_PCAP_DIR = os.path.join(DATA_DIR, "raw", "pcap_agg")
RAW_ZEEK_DNS_DIR = os.path.join(DATA_DIR, "raw", "zeek_dns")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
FAISS_DIR = os.path.join(DATA_DIR, "faiss_index")

EMBEDDING_MODEL = "all-mpnet-base-v2"
FAISS_INDEX_FILE = os.path.join(FAISS_DIR, "index.faiss")
FAISS_META_FILE = os.path.join(FAISS_DIR, "metadata.pkl")
FAISS_MANIFEST_FILE = os.path.join(FAISS_DIR, "build_manifest.json")
ANOMALY_CHUNKS_FILE = os.path.join(PROCESSED_DIR, "anomaly_chunks.json")

SOURCE_INDEX_CONFIG = {
    "dns_json": {
        "index_file": os.path.join(FAISS_DIR, "index_dns_json.faiss"),
        "meta_file": os.path.join(FAISS_DIR, "metadata_dns_json.pkl"),
    },
    "pcap_agg": {
        "index_file": os.path.join(FAISS_DIR, "index_pcap_agg.faiss"),
        "meta_file": os.path.join(FAISS_DIR, "metadata_pcap_agg.pkl"),
    },
    "zeek_dns": {
        "index_file": os.path.join(FAISS_DIR, "index_zeek_dns.faiss"),
        "meta_file": os.path.join(FAISS_DIR, "metadata_zeek_dns.pkl"),
    },
    "anomaly": {
        "index_file": os.path.join(FAISS_DIR, "index_anomaly.faiss"),
        "meta_file": os.path.join(FAISS_DIR, "metadata_anomaly.pkl"),
    },
}

LLM_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
LLM_BASE_URL = "https://api.deepseek.com"
LLM_MODEL = "deepseek-chat"
LLM_MAX_TOKENS = 2048
LLM_TEMPERATURE = 0.3

LLM_PROVIDERS = {
    "DeepSeek": {
        "base_url": "https://api.deepseek.com",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "default_model": "deepseek-chat",
    },
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "default_model": "gpt-4o",
    },
    "Qwen (通义千问)": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "models": ["qwen-max", "qwen-plus", "qwen-turbo"],
        "default_model": "qwen-plus",
    },
    "GLM (智谱)": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "models": ["glm-4", "glm-4-flash", "glm-4-plus"],
        "default_model": "glm-4-flash",
    },
    "自定义 (OpenAI兼容)": {
        "base_url": "",
        "models": ["custom-model"],
        "default_model": "custom-model",
    },
}

LLM_SETTINGS_FILE = os.path.join(BASE_DIR, "data", "llm_settings.json")
MYSQL_SETTINGS_FILE = os.path.join(BASE_DIR, "data", "mysql_settings.json")

TOP_K = 5

NETWORK_CONTEXT = {
    "lan_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "company_domain": "internal.corp",
    "dns_servers": ["8.8.8.8", "8.8.4.4", "1.1.1.1"],
}

ATTACK_MAPPING = {
    "high_freq_dns": "T1071.004 - 应用层协议:DNS",
    "nxdomain_storm": "T1071.004 - DGA域名探测",
    "suspicious_domain": "T1071.004 - C2通信",
    "low_ttl": "T1071.004 - 快速Flux域名",
    "dns_tunnel": "T1071.004 - DNS隧道",
    "new_domain": "T1071.004 - 可疑新域名",
    "suricata_alert": "多技术 - IDS告警",
    "zeek_http": "T1071.001 - 应用层协议:Web",
    "zeek_conn": "T1071 - 应用层协议",
}
