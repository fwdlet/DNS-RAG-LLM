import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from config import LLM_API_KEY, LLM_PROVIDERS, LLM_SETTINGS_FILE


def _load_llm_settings():
    if os.path.exists(LLM_SETTINGS_FILE):
        try:
            with open(LLM_SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "provider": "DeepSeek",
        "model": "deepseek-chat",
        "base_url": "https://api.deepseek.com",
    }


def _save_llm_settings(settings):
    os.makedirs(os.path.dirname(LLM_SETTINGS_FILE), exist_ok=True)
    safe_settings = {
        "provider": settings.get("provider", "DeepSeek"),
        "model": settings.get("model", "deepseek-chat"),
        "base_url": settings.get("base_url", "https://api.deepseek.com"),
    }
    try:
        with open(LLM_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(safe_settings, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _apply_llm_settings(provider, model, base_url, api_key):
    from core.analyzer import Analyzer

    st.session_state.pipeline.analyzer = Analyzer(
        api_key=api_key,
        base_url=base_url,
        model=model,
        temperature=st.session_state.llm_temperature,
    )
    st.session_state.llm_provider = provider
    st.session_state.llm_model = model
    st.session_state.llm_base_url = base_url
    st.session_state.api_key = api_key

    _save_llm_settings({
        "provider": provider,
        "model": model,
        "base_url": base_url,
    })


def _render_data_page():
    from ui.page_data import render
    render()


def _render_analysis_page():
    from ui.page_analysis import render
    render()


def _render_anomaly_page():
    from ui.page_anomaly import render
    render()


st.set_page_config(
    page_title="RAG-LLM 安全事件分析系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "pipeline" not in st.session_state:
    from core.pipeline import RAGPipeline
    st.session_state.pipeline = RAGPipeline()

saved_settings = _load_llm_settings()

if "api_key" not in st.session_state:
    st.session_state.api_key = LLM_API_KEY
if "llm_provider" not in st.session_state:
    st.session_state.llm_provider = saved_settings.get("provider", "DeepSeek")
if "llm_model" not in st.session_state:
    st.session_state.llm_model = saved_settings.get("model", "deepseek-chat")
if "llm_base_url" not in st.session_state:
    st.session_state.llm_base_url = saved_settings.get("base_url", "https://api.deepseek.com")

st.sidebar.title("🛡️ RAG-LLM 安全分析")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "功能模块",
    ["📊 数据管理", "🔍 智能分析", "🚨 异常检测"],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.markdown("#### 🤖 大模型配置")

provider_names = list(LLM_PROVIDERS.keys())
current_provider_idx = provider_names.index(st.session_state.llm_provider) \
    if st.session_state.llm_provider in provider_names else 0

selected_provider = st.sidebar.selectbox(
    "模型提供商",
    provider_names,
    index=current_provider_idx,
    key="provider_select",
)

provider_cfg = LLM_PROVIDERS[selected_provider]
provider_models = provider_cfg["models"]

if selected_provider != st.session_state.llm_provider:
    default_model = provider_cfg["default_model"]
    default_base_url = provider_cfg["base_url"]
    st.session_state.llm_provider = selected_provider
    st.session_state.llm_model = default_model
    st.session_state.llm_base_url = default_base_url
    _apply_llm_settings(
        selected_provider, default_model, default_base_url, st.session_state.api_key
    )
    st.rerun()

current_model_idx = provider_models.index(st.session_state.llm_model) \
    if st.session_state.llm_model in provider_models else 0

selected_model = st.sidebar.selectbox(
    "选择模型",
    provider_models,
    index=current_model_idx,
    key="model_select",
)

if selected_provider == "自定义 (OpenAI兼容)":
    custom_url = st.sidebar.text_input(
        "API Base URL",
        value=st.session_state.llm_base_url,
        key="custom_base_url",
    )
    custom_model_name = st.sidebar.text_input(
        "模型名称",
        value=selected_model,
        key="custom_model_name",
    )
    effective_base_url = custom_url
    effective_model = custom_model_name
else:
    effective_base_url = provider_cfg["base_url"]
    effective_model = selected_model

if effective_model != st.session_state.llm_model or effective_base_url != st.session_state.llm_base_url:
    st.session_state.llm_model = effective_model
    st.session_state.llm_base_url = effective_base_url
    _apply_llm_settings(
        st.session_state.llm_provider, effective_model, effective_base_url, st.session_state.api_key
    )

api_key_label = f"{selected_provider} API Key"
api_key_input = st.sidebar.text_input(
    api_key_label,
    value=st.session_state.api_key,
    type="password",
    key="api_key_input",
)
if api_key_input != st.session_state.api_key:
    st.session_state.api_key = api_key_input
    _apply_llm_settings(
        st.session_state.llm_provider, st.session_state.llm_model,
        st.session_state.llm_base_url, api_key_input
    )

st.sidebar.markdown("---")
st.sidebar.markdown("#### ⚙️ 模型参数")

if "llm_temperature" not in st.session_state:
    st.session_state.llm_temperature = 0.7

temperature = st.sidebar.slider(
    "Temperature",
    min_value=0.0,
    max_value=2.0,
    value=st.session_state.llm_temperature,
    step=0.1,
    help="控制输出的随机性，值越高越随机",
)
if temperature != st.session_state.llm_temperature:
    st.session_state.llm_temperature = temperature

st.sidebar.caption(f"当前: temp={st.session_state.llm_temperature}")

st.sidebar.markdown("---")
st.sidebar.markdown(f"**当前模型**: `{st.session_state.llm_model}`")
st.sidebar.caption(f"API: {st.session_state.llm_base_url}")

stats_by_source = st.session_state.pipeline.get_stats_by_source()
total = sum(stats_by_source.values())
st.sidebar.metric("知识库总块数", total)
st.sidebar.caption(f"DNS:{stats_by_source.get('dns_json',0)} PCAP:{stats_by_source.get('pcap_agg',0)} Zeek:{stats_by_source.get('zeek_dns',0)} Anomaly:{stats_by_source.get('anomaly',0)}")

if page == "📊 数据管理":
    _render_data_page()
elif page == "🔍 智能分析":
    _render_analysis_page()
elif page == "🚨 异常检测":
    _render_anomaly_page()
