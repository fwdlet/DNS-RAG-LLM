import json
import os
import streamlit as st
from config import RAW_DNS_DIR, RAW_PCAP_DIR, RAW_ZEEK_DNS_DIR, PROCESSED_DIR


def render():
    st.title("📊 数据管理")
    st.markdown("管理DNS日志、PCAP聚合数据、Zeek DNS日志和向量知识库")

    tab1, tab2, tab3, tab4 = st.tabs(["DNS日志", "PCAP聚合数据", "Zeek DNS日志", "知识库管理"])

    with tab1:
        _render_dns_tab()

    with tab2:
        _render_pcap_tab()

    with tab3:
        _render_zeek_tab()

    with tab4:
        _render_index_tab()


def _render_dns_tab():
    st.subheader("DNS日志数据")
    st.markdown("上传DNS日志JSON文件，或从MySQL导出")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 上传JSON文件")
        uploaded = st.file_uploader(
            "选择DNS日志JSON文件",
            type=["json"],
            key="dns_upload",
        )
        if uploaded is not None:
            save_dir = RAW_DNS_DIR
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, uploaded.name)
            with open(save_path, "wb") as f:
                f.write(uploaded.getbuffer())
            st.success(f"已保存: {uploaded.name}")

    from integration.dns_adapter import load_mysql_settings, save_mysql_settings

    saved_mysql = load_mysql_settings()
    default_host = saved_mysql["host"] if saved_mysql else "localhost"
    default_port = saved_mysql["port"] if saved_mysql else 3306
    default_user = saved_mysql["user"] if saved_mysql else "root"
    default_pass = saved_mysql["password"] if saved_mysql else ""
    default_db = saved_mysql["database"] if saved_mysql else "dns_server"

    with col2:
        st.markdown("#### 从MySQL导出")
        with st.expander("MySQL连接配置"):
            db_host = st.text_input("主机", value=default_host, key="db_host")
            db_port = st.number_input("端口", value=default_port, key="db_port")
            db_user = st.text_input("用户名", value=default_user, key="db_user")
            db_pass = st.text_input("密码", type="password", value=default_pass, key="db_pass")
            db_name = st.text_input("数据库", value=default_db, key="db_name")

        if st.button("从MySQL导出DNS日志", key="export_mysql"):
            try:
                from integration.dns_adapter import DNSAdapter
                adapter = DNSAdapter(
                    host=db_host, port=db_port,
                    user=db_user, password=db_pass,
                    database=db_name,
                )
                export_name = f"mysql_{db_user}_{db_name}_export.json"
                save_path = os.path.join(RAW_DNS_DIR, export_name)
                count = adapter.export_to_file(save_path)
                adapter.close()
                if count > 0:
                    save_mysql_settings(db_host, db_port, db_user, db_pass, db_name)
                    st.success(f"成功导出 {count} 条DNS日志 → {export_name}")
                else:
                    st.warning("未导出任何数据，请检查连接配置")
            except Exception as e:
                st.error(f"导出失败: {e}")

    st.markdown("---")
    st.markdown("#### 当前DNS日志文件")
    if os.path.isdir(RAW_DNS_DIR):
        files = [f for f in os.listdir(RAW_DNS_DIR) if f.endswith(".json")]
        if files:
            selected = st.multiselect("选择文件（支持多选删除）", files, key="dns_delete_select")
            if selected and st.button("🗑️ 删除选中文件", key="dns_delete_btn"):
                for f in selected:
                    os.remove(os.path.join(RAW_DNS_DIR, f))
                st.success(f"已删除 {len(selected)} 个文件")
                st.rerun()
            for f in files:
                fpath = os.path.join(RAW_DNS_DIR, f)
                size = os.path.getsize(fpath)
                col_f1, col_f2 = st.columns([4, 1])
                with col_f1:
                    st.text(f"📄 {f} ({size:,} bytes)")
                with col_f2:
                    if st.button("删除", key=f"del_{f}", type="secondary"):
                        os.remove(fpath)
                        st.rerun()
        else:
            st.info("暂无DNS日志文件，请上传或从MySQL导出")
    else:
        st.info("暂无DNS日志文件")


def _render_pcap_tab():
    st.subheader("PCAP聚合数据")
    st.markdown("上传从Ubuntu虚拟机导出的Zeek/Suricata聚合JSON文件")

    uploaded = st.file_uploader(
        "选择PCAP聚合JSON文件",
        type=["json"],
        key="pcap_upload",
    )
    if uploaded is not None:
        save_dir = RAW_PCAP_DIR
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, uploaded.name)
        with open(save_path, "wb") as f:
            f.write(uploaded.getbuffer())
        st.success(f"已保存: {uploaded.name}")

    st.markdown("---")
    st.markdown("#### 当前PCAP聚合文件")
    if os.path.isdir(RAW_PCAP_DIR):
        files = [f for f in os.listdir(RAW_PCAP_DIR) if f.endswith(".json")]
        if files:
            for f in files:
                fpath = os.path.join(RAW_PCAP_DIR, f)
                size = os.path.getsize(fpath)
                col_f1, col_f2 = st.columns([4, 1])
                with col_f1:
                    st.text(f"📄 {f} ({size:,} bytes)")
                with col_f2:
                    if st.button("删除", key=f"pcap_del_{f}", type="secondary"):
                        os.remove(fpath)
                        st.rerun()
        else:
            st.info("暂无PCAP聚合文件，请上传")
    else:
        st.info("暂无PCAP聚合文件")


def _render_zeek_tab():
    st.subheader("Zeek DNS日志")
    st.markdown("上传Zeek网络监控生成的dns.log文件（TSV格式），系统将自动解析并执行聚合分析")

    uploaded = st.file_uploader(
        "选择Zeek dns.log文件",
        type=["log"],
        key="zeek_upload",
    )
    if uploaded is not None:
        save_dir = RAW_ZEEK_DNS_DIR
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, uploaded.name)
        with open(save_path, "wb") as f:
            f.write(uploaded.getbuffer())
        try:
            from integration.zeek_adapter import is_zeek_log_file
            if is_zeek_log_file(save_path):
                from integration.zeek_adapter import load_zeek_dns_log
                df = load_zeek_dns_log(save_path)
                st.success(f"已保存并解析: {uploaded.name}，共 {len(df)} 条DNS记录")
            else:
                st.warning(f"文件 {uploaded.name} 不符合Zeek dns.log格式，已保存但无法解析")
        except Exception as e:
            st.error(f"解析失败: {e}")

    st.markdown("---")
    st.markdown("#### 当前Zeek DNS日志文件")
    if os.path.isdir(RAW_ZEEK_DNS_DIR):
        files = [f for f in os.listdir(RAW_ZEEK_DNS_DIR) if f.endswith(".log")]
        if files:
            for f in files:
                fpath = os.path.join(RAW_ZEEK_DNS_DIR, f)
                size = os.path.getsize(fpath)
                try:
                    from integration.zeek_adapter import load_zeek_dns_log
                    df_preview = load_zeek_dns_log(fpath)
                    record_count = len(df_preview)
                except Exception:
                    record_count = "解析失败"
                col_f1, col_f2 = st.columns([4, 1])
                with col_f1:
                    st.text(f"📄 {f} ({size:,} bytes, {record_count} 条记录)")
                with col_f2:
                    if st.button("删除", key=f"zeek_del_{f}", type="secondary"):
                        os.remove(fpath)
                        st.rerun()
        else:
            st.info("暂无Zeek DNS日志文件，请上传dns.log文件")
    else:
        st.info("暂无Zeek DNS日志文件")


def _render_index_tab():
    st.subheader("向量知识库管理")
    pipeline = st.session_state.pipeline

    manifest = pipeline.get_manifest()
    indexed = pipeline.get_indexed_sources()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("#### 构建知识库")
        build_mode = st.selectbox(
            "构建模式",
            ["增量追加（新数据追加到现有索引）", "完整重建（丢弃后重新构建）"],
            key="build_mode",
            help="增量追加：只处理新增/变化的文件，保留已有块\n完整重建：丢弃现有索引，从所有源文件重新构建",
        )
        rebuild = build_mode.startswith("完整重建")

        source_choices = ["全部数据", "仅DNS日志", "仅PCAP聚合", "仅Zeek DNS日志"]

        if os.path.isdir(RAW_DNS_DIR):
            dns_files = [f for f in os.listdir(RAW_DNS_DIR) if f.endswith(".json")]
            if dns_files:
                source_choices.insert(1, f"选择DNS文件... ({len(dns_files)}个)")

        build_source = st.selectbox(
            "数据来源",
            source_choices,
            key="build_source",
        )

        selected_dns_file = None
        if build_source.startswith("选择DNS文件"):
            dns_files_list = sorted([f for f in os.listdir(RAW_DNS_DIR) if f.endswith(".json")])
            selected_dns_file = st.selectbox("选择文件", dns_files_list, key="selected_dns_file")

        if st.button("🔨 构建向量索引", key="build_index"):
            with st.spinner("正在构建向量索引..."):
                step_text = st.empty()
                try:
                    if selected_dns_file:
                        step_text.info(f"步骤1/3: 处理 {selected_dns_file}...")
                        result = pipeline.build_from_dns_logs(
                            source=os.path.join(RAW_DNS_DIR, selected_dns_file),
                            rebuild=rebuild
                        )
                    elif build_source == "仅DNS日志":
                        step_text.info("步骤1/3: 加载DNS日志...")
                        result = pipeline.build_from_dns_logs(rebuild=rebuild)
                    elif build_source == "仅PCAP聚合":
                        step_text.info("步骤1/2: 加载PCAP聚合数据...")
                        result = pipeline.build_from_pcap_aggregations(rebuild=rebuild)
                    elif build_source == "仅Zeek DNS日志":
                        step_text.info("步骤1/3: 解析Zeek dns.log...")
                        result = pipeline.build_from_zeek_dns(rebuild=rebuild)
                    else:
                        step_text.info("步骤1/4: 加载全部数据源...")
                        result = pipeline.build_from_all(rebuild=rebuild)
                    step_text.empty()

                    if result["status"] == "success":
                        mode = result.get("mode", "N/A")
                        chunks = result.get("total_chunks", result.get("chunks", 0))
                        stats = result.get("index_stats", {})
                        total = stats.get("total_chunks", chunks)
                        st.success(f"构建成功! [{mode}] 共 {total} 个文本块")
                    elif result["status"] == "skip":
                        st.info(result.get("message", "跳过"))
                    else:
                        st.warning(result.get("message", "构建失败"))
                except Exception as e:
                    step_text.empty()
                    st.error(f"构建失败: {e}")

    with col2:
        st.markdown("#### 加载已有索引")
        if st.button("📂 加载向量索引", key="load_index"):
            if pipeline.load_index():
                stats = pipeline.get_stats()
                by_source = pipeline.get_stats_by_source()
                parts = [f"{k}={v}" for k, v in by_source.items() if v > 0]
                st.success(f"加载成功! 共 {stats['total_chunks']} 文本块, 维度 {stats['dimension']} ({', '.join(parts)})")
            else:
                st.warning("未找到已有索引，请先构建")

    with col3:
        st.markdown("#### 索引状态")
        stats_by_source = pipeline.get_stats_by_source()
        total_stats = pipeline.get_stats()
        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            st.metric("DNS日志", stats_by_source.get("dns_json", 0))
        with col_b:
            st.metric("PCAP聚合", stats_by_source.get("pcap_agg", 0))
        with col_c:
            st.metric("Zeek DNS", stats_by_source.get("zeek_dns", 0))
        with col_d:
            st.metric("异常告警", stats_by_source.get("anomaly", 0))
        st.caption(f"向量维度: {total_stats.get('dimension', 0)}")
        if manifest:
            st.markdown("**已索引来源:**")
            for src_type, entries in manifest.items():
                if isinstance(entries, list) and entries:
                    names = [e.get("source_path", "N/A") for e in entries if isinstance(e, dict)]
                    st.caption(f"  {src_type}: {', '.join(names[:3])}{'...' if len(names) > 3 else ''}")

    st.markdown("---")
    st.markdown("#### 已处理的文本块")
    if os.path.isdir(PROCESSED_DIR):
        files = [f for f in os.listdir(PROCESSED_DIR) if f.endswith(".json")]
        if files:
            sorted_files = sorted(files, key=lambda x: os.path.getmtime(os.path.join(PROCESSED_DIR, x)), reverse=True)[:10]
            for f in sorted_files:
                fpath = os.path.join(PROCESSED_DIR, f)
                size = os.path.getsize(fpath)
                mtime = os.path.getmtime(fpath)
                import datetime
                time_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
                with st.expander(f"📋 {f} ({size:,} bytes, {time_str})"):
                    try:
                        with open(fpath, "r", encoding="utf-8") as fh:
                            data = json.load(fh)
                        if isinstance(data, list):
                            st.text(f"类型: 列表, 元素数: {len(data)}")
                            st.json(data[:2] if len(data) >= 2 else data)
                        elif isinstance(data, dict):
                            st.text(f"类型: 对象, keys: {list(data.keys())}")
                    except Exception as e:
                        st.error(f"读取失败: {e}")
        else:
            st.info("暂无已处理的文本块")
    else:
        st.info("暂无已处理的文本块")
