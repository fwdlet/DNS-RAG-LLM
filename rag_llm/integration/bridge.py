import json
import os
from datetime import datetime

from integration.anomaly_detector import AnomalyDetector
from integration.dns_adapter import DNSAdapter, load_dns_json
from core.preprocessor import format_aggregation_to_text

HISTORY_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "processed", "detection_history")


def _ensure_history_dir():
    os.makedirs(HISTORY_DIR, exist_ok=True)


def save_detection_history(result, source_type, source_name, thresholds):
    _ensure_history_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary = result.get("summary", {})
    history_entry = {
        "id": timestamp,
        "timestamp": datetime.now().isoformat(),
        "source_type": source_type,
        "source_name": source_name,
        "thresholds": thresholds,
        "status": result.get("status", "unknown"),
        "total_packets": result.get("total_packets", 0),
        "alert_count": len(result.get("alerts", [])),
        "summary": summary,
        "alerts": result.get("alerts", []),
        "index_written": result.get("index_update", {}).get("status") == "success",
    }
    filepath = os.path.join(HISTORY_DIR, f"history_{timestamp}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(history_entry, f, ensure_ascii=False, indent=2)
    return timestamp


def load_detection_history():
    _ensure_history_dir()
    files = sorted([f for f in os.listdir(HISTORY_DIR) if f.startswith("history_") and f.endswith(".json")],
                   reverse=True)
    history = []
    for fname in files:
        try:
            with open(os.path.join(HISTORY_DIR, fname), "r", encoding="utf-8") as f:
                history.append(json.load(f))
        except Exception:
            pass
    return history


def delete_detection_history(history_id):
    filepath = os.path.join(HISTORY_DIR, f"history_{history_id}.json")
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False


def clear_all_detection_history():
    _ensure_history_dir()
    for fname in os.listdir(HISTORY_DIR):
        if fname.startswith("history_") and fname.endswith(".json"):
            os.remove(os.path.join(HISTORY_DIR, fname))


def anomaly_alerts_to_chunks(alerts):
    if not alerts:
        return []
    by_type = {}
    for alert in alerts:
        atype = alert.get("alert_type", "unknown")
        if atype not in by_type:
            by_type[atype] = []
        by_type[atype].append(alert)
    chunks = []
    for atype, type_alerts in by_type.items():
        lines = [f"【DNS异常检测告警 - {atype}】"]
        lines.append(f"告警数量: {len(type_alerts)}")
        lines.append(f"检测时间: {datetime.now().isoformat()}")
        attack = type_alerts[0].get("attack_mapping", "")
        if attack:
            lines.append(f"ATT&CK映射: {attack}")
        lines.append("")
        for a in type_alerts[:20]:
            lines.append(f"  严重性: {a.get('severity', 'N/A')}")
            lines.append(f"  描述: {a.get('description', 'N/A')}")
            if a.get("src_ip"):
                lines.append(f"  源IP: {a['src_ip']}")
            if a.get("domain"):
                lines.append(f"  域名: {a['domain']}")
            if a.get("count"):
                lines.append(f"  次数: {a['count']}")
            if a.get("reasons"):
                lines.append(f"  原因: {', '.join(a['reasons'])}")
            lines.append("")
        text = "\n".join(lines)
        chunks.append({
            "text": text,
            "metadata": {
                "agg_type": f"anomaly_{atype}",
                "attack_mapping": attack,
                "source": "dns_anomaly_detector",
                "created_at": datetime.now().isoformat(),
                "alert_count": len(type_alerts),
            },
        })
    return chunks


def detect_and_bridge(packets=None, source=None, pipeline=None,
                      freq_threshold=50, nxdomain_threshold=10):
    if packets is None:
        packets = load_dns_json(source)
    if not packets:
        return {"status": "warning", "message": "无DNS日志数据", "alerts": [], "chunks": []}
    detector = AnomalyDetector(packets)
    alerts = detector.run_all(
        freq_threshold=freq_threshold,
        nxdomain_threshold=nxdomain_threshold,
    )
    chunks = anomaly_alerts_to_chunks(alerts)
    result = {
        "status": "success",
        "total_packets": len(packets),
        "alerts": alerts,
        "chunks": chunks,
        "summary": detector.get_alerts_summary(),
    }
    if pipeline is not None:
        add_result = pipeline.add_anomaly_chunks(chunks)
        result["index_update"] = add_result
    return result


def detect_from_mysql(pipeline=None, **db_kwargs):
    adapter = DNSAdapter(**db_kwargs)
    packets = adapter.fetch_as_json_packets()
    adapter.close()
    if not packets:
        return {"status": "warning", "message": "MySQL中无DNS日志数据"}
    return detect_and_bridge(packets=packets, pipeline=pipeline)
