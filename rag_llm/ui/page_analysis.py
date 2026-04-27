import streamlit as st


PRESET_QUESTIONS = [
    "局域网中可能受感染的内部主机的IP地址是什么？",
    "有哪些可疑的域名被查询？它们可能关联什么攻击？",
    "是否存在DNS隧道通信的迹象？",
    "哪些主机产生了大量NXDOMAIN响应？是否可能存在DGA行为？",
    "是否存在与已知C2服务器的通信？",
    "请综合分析当前网络中的威胁情况，并给出攻击路径重构和防御建议。",
]


def _render_answer(answer):
    st.markdown("#### 📋 分析报告")
    st.markdown(answer)


def _render_evidence(evidence):
    if evidence:
        for i, ev in enumerate(evidence, 1):
            with st.expander(f"证据块 {i} (相似度: {ev.get('score', 0):.3f})"):
                meta = ev.get("metadata", {})
                st.markdown(f"**来源**: {meta.get('source', 'N/A')}")
                st.markdown(f"**类型**: {meta.get('agg_type', 'N/A')}")
                st.markdown(f"**ATT&CK**: {meta.get('attack_mapping', 'N/A')}")
                text = meta.get("source_text", "")
                if text:
                    st.text(text[:500] + ("..." if len(text) > 500 else ""))


def render():
    st.title("🔍 智能分析")
    st.markdown("基于RAG-LLM的网络安全事件智能分析")

    pipeline = st.session_state.pipeline
    stats = pipeline.get_stats()

    if stats.get("total_chunks", 0) == 0:
        st.warning("⚠️ 知识库为空，请先在「数据管理」页面构建向量索引")
        st.info("💡 路径：数据管理 → 选择数据来源 → 点击「🔨 构建向量索引」")
        return

    if "analysis_question" not in st.session_state:
        st.session_state.analysis_question = ""
    if "preset_triggered" not in st.session_state:
        st.session_state.preset_triggered = False

    col1, col2 = st.columns([2, 1])

    def _on_q_change():
        current = st.session_state._q
        saved = st.session_state.analysis_question
        if current != saved:
            st.session_state.analysis_question = current

    with col1:
        st.markdown("#### 提问分析")
        question = st.text_area(
            "请输入安全问题",
            value=st.session_state.analysis_question,
            key="_q",
            on_change=_on_q_change,
            height=100,
        )

        st.markdown("##### 预设问题")
        cols = st.columns(2)
        for i, pq in enumerate(PRESET_QUESTIONS):
            with cols[i % 2]:
                if st.button(pq[:30] + "...", key=f"preset_{i}", help=pq):
                    st.session_state.analysis_question = pq
                    st.session_state.preset_triggered = True
                    st.rerun()

        top_k = st.slider("检索证据块数量", min_value=1, max_value=10, value=5, key="top_k")

        col_cfg1, col_cfg2 = st.columns([1, 1])
        with col_cfg1:
            st.checkbox("启用流式输出", value=True, key="use_stream",
                        help="开启后AI回答将逐步显示，减少等待焦虑感")
        with col_cfg2:
            if "llm_temperature" in st.session_state:
                st.caption(f"Temp={st.session_state.llm_temperature}")

        trigger_analysis = st.session_state.get("preset_triggered", False)
        st.session_state.preset_triggered = False

        _did_stream_this_run = False

        if trigger_analysis or st.button("🚀 开始分析", key="start_analysis", type="primary"):
            question = st.session_state.analysis_question
            if not question.strip():
                st.warning("请输入问题")
                return
            if not st.session_state.api_key:
                provider = st.session_state.get("llm_provider", "DeepSeek")
                st.warning(f"请先在侧边栏配置{provider} API Key")
                return

            use_streaming = st.session_state.get("use_stream", True)
            st.session_state.pop("last_result", None)
            st.session_state.pop("last_answer", None)
            st.session_state.pop("last_evidence", None)
            st.session_state.pop("last_context", None)

            with st.spinner("正在检索相关证据并分析..."):
                result = pipeline.query(question, top_k=top_k, stream=use_streaming)

                if result["status"] == "success":
                    if use_streaming:
                        _did_stream_this_run = True
                        answer_stream = result.get("answer_stream", [])
                        evidence = result.get("evidence", [])
                        context = result.get("context", "")
                        if answer_stream:
                            container = st.empty()
                            full = ""
                            for chunk in answer_stream:
                                full += chunk
                                container.markdown(full + "▌")
                            container.markdown(full)
                        else:
                            full = "（无分析内容）"
                        st.session_state.last_answer = full
                        st.session_state.last_evidence = evidence
                        st.session_state.last_context = context
                    else:
                        st.session_state.last_result = result
                        st.session_state.last_answer = result.get("answer", "")
                        st.session_state.last_evidence = result.get("evidence", [])
                        st.session_state.last_context = result.get("context", "")
                elif result["status"] == "warning":
                    st.warning(result.get("message", "未找到相关证据"))
                else:
                    st.error(result.get("message", "分析失败"))

        if use_streaming and not _did_stream_this_run and "last_answer" in st.session_state:
            _render_answer(st.session_state.last_answer)

    with col2:
        use_streaming = st.session_state.get("use_stream", True)
        if not use_streaming:
            if "last_result" in st.session_state:
                r = st.session_state.last_result
                if r.get("answer"):
                    _render_answer(r["answer"])

        st.markdown("#### 📎 检索到的证据")
        evidence = st.session_state.get("last_evidence", [])
        if evidence:
            _render_evidence(evidence)
        else:
            st.info("提交问题后将显示相关证据")

    context = st.session_state.get("last_context", "")
    if context:
        with st.expander("查看完整检索上下文"):
            st.text(context[:2000] + ("..." if len(context) > 2000 else ""))
