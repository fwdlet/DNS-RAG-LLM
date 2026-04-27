import json
import os
import streamlit as st
from config import RAW_DNS_DIR


def render():
    st.title("🚨 异常检测")
    st.markdown("DNS日志异常检测，检测结果自动写入RAG知识库")

    pipeline = st.session_state.pipeline

    tab1, tab2, tab3 = st.tabs(["检测配置", "检测结果", "检测历史"])

    with tab1:
        _render_config_tab(pipeline)

    with tab2:
        _render_results_tab()

    with tab3:
        _render_history_tab()


def _render_config_tab(pipeline):
    st.subheader("检测配置")

    source_type = st.radio("数据来源", ["上传的JSON文件", "MySQL数据库"], key="anomaly_source")

    source_name = ""
    if source_type == "上传的JSON文件":
        json_files = []
        if os.path.isdir(RAW_DNS_DIR):
            json_files = [f for f in os.listdir(RAW_DNS_DIR) if f.endswith(".json")]
        if json_files:
            selected = st.selectbox("选择DNS日志文件", json_files, key="anomaly_file")
            source_path = os.path.join(RAW_DNS_DIR, selected)
            source_name = selected
        else:
            st.info("暂无DNS日志文件，请先在「数据管理」页面上传")
            source_path = None
    else:
        from integration.dns_adapter import load_mysql_settings, save_mysql_settings
        saved_mysql = load_mysql_settings()
        default_host = saved_mysql["host"] if saved_mysql else "localhost"
        default_port = saved_mysql["port"] if saved_mysql else 3306
        default_user = saved_mysql["user"] if saved_mysql else "root"
        default_pass = saved_mysql["password"] if saved_mysql else ""
        default_db = saved_mysql["database"] if saved_mysql else "dns_server"

        with st.expander("MySQL连接配置"):
            db_host = st.text_input("主机", value=default_host, key="anomaly_db_host")
            db_port = st.number_input("端口", value=default_port, key="anomaly_db_port")
            db_user = st.text_input("用户名", value=default_user, key="anomaly_db_user")
            db_pass = st.text_input("密码", type="password", value=default_pass, key="anomaly_db_pass")
            db_name = st.text_input("数据库", value=default_db, key="anomaly_db_name")
        source_path = None
        source_name = f"MySQL:{db_host}/{db_name}"

    st.markdown("---")
    st.markdown("#### 检测阈值")

    col1, col2 = st.columns(2)
    with col1:
        freq_threshold = st.number_input("高频查询阈值", value=50, min_value=1, key="freq_threshold")
    with col2:
        nxdomain_threshold = st.number_input("NXDOMAIN风暴阈值", value=10, min_value=1, key="nxdomain_threshold")

    auto_bridge = st.checkbox("自动将检测结果写入RAG知识库", value=True, key="auto_bridge")

    if st.button("🔍 执行异常检测", key="run_detection", type="primary"):
        with st.spinner("正在执行异常检测..."):
            try:
                thresholds = {"freq_threshold": freq_threshold, "nxdomain_threshold": nxdomain_threshold}
                if source_type == "上传的JSON文件" and source_path:
                    from integration.bridge import detect_and_bridge, save_detection_history
                    result = detect_and_bridge(
                        source=source_path,
                        pipeline=pipeline if auto_bridge else None,
                        freq_threshold=freq_threshold,
                        nxdomain_threshold=nxdomain_threshold,
                    )
                    save_detection_history(result, "json_file", source_name, thresholds)
                elif source_type == "MySQL数据库":
                    from integration.bridge import detect_from_mysql, save_detection_history
                    result = detect_from_mysql(
                        pipeline=pipeline if auto_bridge else None,
                        host=db_host, port=db_port,
                        user=db_user, password=db_pass,
                        database=db_name,
                    )
                    if result["status"] == "success":
                        save_mysql_settings(db_host, db_port, db_user, db_pass, db_name)
                    save_detection_history(result, "mysql", source_name, thresholds)
                else:
                    st.warning("请选择数据来源")
                    return

                st.session_state.last_detection = result
                if result["status"] == "success":
                    st.success(f"检测完成! 共发现 {len(result['alerts'])} 个异常")
                else:
                    st.warning(result.get("message", "检测未产生结果"))
            except Exception as e:
                st.error(f"检测失败: {e}")


def _render_results_tab():
    st.subheader("检测结果")

    if "last_detection" not in st.session_state:
        st.info("请先执行异常检测")
        return

    result = st.session_state.last_detection
    summary = result.get("summary", {})

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("总告警数", summary.get("total_alerts", 0))
    with col2:
        high_count = summary.get("by_severity", {}).get("high", 0)
        st.metric("高危告警", high_count)
    with col3:
        medium_count = summary.get("by_severity", {}).get("medium", 0)
        st.metric("中危告警", medium_count)

    if summary.get("by_type"):
        st.markdown("#### 告警类型分布")
        st.json(summary["by_type"])

    alerts = result.get("alerts", [])
    if alerts:
        st.markdown("#### 告警详情")
        severity_filter = st.selectbox(
            "按严重性筛选", ["全部", "high", "medium", "low"], key="alert_filter"
        )
        filtered = alerts if severity_filter == "全部" else \
                   [a for a in alerts if a.get("severity") == severity_filter]

        for i, alert in enumerate(filtered[:30]):
            sev = alert.get("severity", "unknown")
            icon = "🔴" if sev == "high" else "🟡" if sev == "medium" else "🟢"
            with st.expander(f"{icon} [{sev.upper()}] {alert.get('alert_type', 'N/A')} - {alert.get('src_ip', 'N/A')}"):
                st.markdown(f"**描述**: {alert.get('description', 'N/A')}")
                st.markdown(f"**ATT&CK**: {alert.get('attack_mapping', 'N/A')}")
                if alert.get("domain"):
                    st.markdown(f"**域名**: {alert['domain']}")
                if alert.get("count"):
                    st.markdown(f"**次数**: {alert['count']}")
                if alert.get("reasons"):
                    st.markdown(f"**原因**: {', '.join(alert['reasons'])}")

    bridge_result = result.get("index_update", {})
    if bridge_result.get("status") == "success":
        st.success(f"✅ 已将 {bridge_result.get('added', 0)} 个异常文本块写入RAG知识库")


def _render_history_tab():
    st.subheader("检测历史")
    from integration.bridge import load_detection_history, delete_detection_history, clear_all_detection_history

    history = load_detection_history()

    if not history:
        st.info("暂无检测历史记录，请先执行异常检测")
        return

    col_tool, col_clear = st.columns([4, 1])
    with col_clear:
        if st.button("🗑️ 清空全部", type="secondary"):
            clear_all_detection_history()
            st.rerun()

    st.markdown(f"共 {len(history)} 条历史记录")
    st.markdown("---")

    selected_id = None
    for entry in history:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        src = entry.get("source_name", entry.get("source_type", "N/A"))
        alert_count = entry.get("alert_count", 0)
        summary = entry.get("summary", {})
        high = summary.get("by_severity", {}).get("high", 0)
        medium = summary.get("by_severity", {}).get("medium", 0)
        low = summary.get("by_severity", {}).get("low", 0)
        written = "✅已入知识库" if entry.get("index_written") else "❌未入知识库"
        thresholds = entry.get("thresholds", {})

        cols = st.columns([0.5, 1, 1.5, 1, 1, 1, 0.5, 0.5])
        with cols[0]:
            st.caption(f"🔴{high}")
        with cols[1]:
            st.caption(f"🟡{medium}")
        with cols[2]:
            st.caption(f"🟢{low}")
        with cols[3]:
            st.caption(f"📊 {alert_count}告警")
        with cols[4]:
            st.caption(f"📁 {src[:15]}")
        with cols[5]:
            st.caption(f"⏱️ {ts}")
        with cols[6]:
            st.caption(written)
        with cols[7]:
            if st.button("🗑️", key=f"del_{entry['id']}"):
                delete_detection_history(entry["id"])
                st.rerun()

        with st.expander(f"详细 - {ts} | {src}"):
            st.markdown(f"**检测时间**: {ts}")
            st.markdown(f"**数据来源**: {src}")
            st.markdown(f"**阈值**: freq={thresholds.get('freq_threshold', 'N/A')}, nxdomain={thresholds.get('nxdomain_threshold', 'N/A')}")
            st.markdown(f"**数据包数**: {entry.get('total_packets', 0)}")
            st.markdown(f"**写入知识库**: {'是' if entry.get('index_written') else '否'}")

            alerts = entry.get("alerts", [])
            if alerts:
                sev_filter = st.selectbox(
                    "按严重性筛选", ["全部", "high", "medium", "low"],
                    key=f"hist_filter_{entry['id']}"
                )
                filtered = alerts if sev_filter == "全部" else \
                           [a for a in alerts if a.get("severity") == sev_filter]
                for alert in filtered[:50]:
                    sev = alert.get("severity", "unknown")
                    icon = "🔴" if sev == "high" else "🟡" if sev == "medium" else "🟢"
                    st.markdown(f"{icon} **[{sev.upper()}]** {alert.get('alert_type', 'N/A')} | "
                                f"IP: {alert.get('src_ip', 'N/A')} | {alert.get('description', 'N/A')[:60]}")
