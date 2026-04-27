import json
import os
from datetime import datetime

from config import PROCESSED_DIR, RAW_PCAP_DIR, RAW_DNS_DIR, ATTACK_MAPPING


def _format_dns_agg_text(agg):
    agg_type = agg.get("agg_type", "unknown")
    attack = agg.get("attack_mapping", "N/A")
    time_range = agg.get("time_range", {})
    time_start = time_range.get("start", "N/A")
    time_end = time_range.get("end", "N/A")

    lines = []
    type_labels = {
        "high_freq_dns": "高频DNS查询聚合",
        "nxdomain_storm": "NXDOMAIN风暴聚合",
        "suspicious_domain": "可疑域名聚合",
        "low_ttl": "低TTL异常聚合",
        "dns_tunnel": "DNS隧道检测聚合",
    }
    label = type_labels.get(agg_type, "DNS聚合")
    lines.append(f"【{label}】")
    lines.append(f"时间范围: {time_start} ~ {time_end}")
    lines.append(f"ATT&CK映射: {attack}")
    lines.append("")

    if agg_type == "high_freq_dns":
        total = agg.get("total_queries", 0)
        lines.append(f"总查询数: {total}")
        lines.append("")
        for r in agg.get("results", []):
            lines.append(f"源IP {r['src_ip']} 共发起 {r['query_count']} 次DNS查询")
            top_domains = r.get("top_domains", {})
            if top_domains:
                lines.append("  查询目标域名Top5:")
                for i, (dom, cnt) in enumerate(top_domains.items(), 1):
                    lines.append(f"    {i}. {dom} ({cnt}次)")
            dns_servers = r.get("dns_servers", {})
            if dns_servers:
                lines.append(f"  目标DNS服务器: {', '.join(f'{k}({v}次)' for k, v in dns_servers.items())}")
            lines.append("")

    elif agg_type == "nxdomain_storm":
        total = agg.get("total_nxdomain", 0)
        lines.append(f"总NXDOMAIN响应数: {total}")
        lines.append("")
        for r in agg.get("results", []):
            lines.append(f"源IP {r['src_ip']} 产生 {r['nxdomain_count']} 次NXDOMAIN响应")
            failed = r.get("failed_domains", [])
            if failed:
                lines.append(f"  失败域名: {', '.join(failed[:10])}")
            lines.append("")

    elif agg_type == "suspicious_domain":
        total = agg.get("total_suspicious", 0)
        lines.append(f"可疑域名总数: {total}")
        lines.append("")
        top = agg.get("top_suspicious_domains", [])
        if top:
            lines.append("高频可疑域名:")
            for item in top:
                lines.append(f"  {item['domain']} ({item['count']}次)")
        lines.append("")
        details = agg.get("details", [])
        if details:
            lines.append("详细记录:")
            for d in details[:10]:
                lines.append(f"  {d['timestamp']} | {d['src_ip']} -> {d['domain']} ({d['query_type']}) -> {d['dst_ip']}")
        lines.append("")

    elif agg_type == "low_ttl":
        total = agg.get("total_low_ttl", 0)
        lines.append(f"低TTL记录总数: {total}")
        lines.append("")
        details = agg.get("details", [])
        if details:
            lines.append("详细记录:")
            for d in details[:10]:
                lines.append(f"  {d['timestamp']} | {d['src_ip']} -> {d['domain']} TTL={d['ttl']}s -> {d['resolved_ip']}")
        lines.append("")

    elif agg_type == "dns_tunnel":
        total = agg.get("total_tunnel_suspects", 0)
        lines.append(f"DNS隧道嫌疑总数: {total}")
        lines.append("")
        details = agg.get("details", [])
        if details:
            lines.append("详细记录:")
            for d in details[:10]:
                lines.append(f"  {d['timestamp']} | {d['src_ip']} -> {d['domain']} ({d['query_type']}) 原因:{d['reason']}")
        lines.append("")

    return "\n".join(lines)


def _format_pcap_agg_text(agg, source_file=""):
    agg_type = agg.get("agg_type", "unknown")
    attack = agg.get("attack_mapping", ATTACK_MAPPING.get(agg_type, "N/A"))
    time_range = agg.get("time_range", {})
    time_start = time_range.get("start", "N/A")
    time_end = time_range.get("end", "N/A")

    lines = []
    type_labels = {
        "suricata_alert": "Suricata IDS告警聚合",
        "zeek_http": "Zeek HTTP流量聚合",
        "zeek_conn": "Zeek连接日志聚合",
        "zeek_dns": "Zeek DNS流量聚合",
        "zeek_ssl": "Zeek SSL/TLS聚合",
        "zeek_kerberos": "Zeek Kerberos认证聚合",
    }
    label = type_labels.get(agg_type, "PCAP流量聚合")
    lines.append(f"【{label}】")
    if source_file:
        lines.append(f"数据来源: {source_file}")
    lines.append(f"时间范围: {time_start} ~ {time_end}")
    lines.append(f"ATT&CK映射: {attack}")
    lines.append("")

    if agg_type == "suricata_alert":
        alerts = agg.get("results", agg.get("alerts", []))
        if isinstance(alerts, list):
            lines.append(f"告警总数: {len(alerts)}")
            lines.append("")
            for a in alerts[:15]:
                if isinstance(a, dict):
                    sig = a.get("signature", a.get("alert", {}).get("signature", "N/A"))
                    src = a.get("src_ip", a.get("source", {}).get("ip", "N/A"))
                    dst = a.get("dst_ip", a.get("destination", {}).get("ip", "N/A"))
                    sev = a.get("severity", a.get("alert", {}).get("severity", "N/A"))
                    lines.append(f"  [{sev}] {src} -> {dst} | {sig}")
        lines.append("")

    elif agg_type in ("zeek_http", "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_kerberos"):
        results = agg.get("results", [])
        if isinstance(results, list):
            lines.append(f"记录总数: {len(results)}")
            lines.append("")
            for r in results[:15]:
                if isinstance(r, dict):
                    parts = [f"{k}={v}" for k, v in r.items()]
                    lines.append(f"  {' | '.join(parts)}")
        lines.append("")

    else:
        raw = json.dumps(agg, ensure_ascii=False, indent=2)
        lines.append(raw[:2000])
        lines.append("")

    return "\n".join(lines)


def format_aggregation_to_text(agg, source_file=""):
    agg_type = agg.get("agg_type", "")
    dns_types = {"high_freq_dns", "nxdomain_storm", "suspicious_domain", "low_ttl", "dns_tunnel"}
    if agg_type in dns_types:
        return _format_dns_agg_text(agg)
    return _format_pcap_agg_text(agg, source_file)


def process_dns_aggregations(aggregations):
    chunks = []
    for agg in aggregations:
        text = format_aggregation_to_text(agg)
        if text.strip():
            chunks.append({
                "text": text,
                "metadata": {
                    "agg_type": agg.get("agg_type", "unknown"),
                    "attack_mapping": agg.get("attack_mapping", ""),
                    "time_range": agg.get("time_range", {}),
                    "source": "dns_aggregation",
                    "source_file": agg.get("source_file", ""),
                    "created_at": datetime.now().isoformat(),
                },
            })
    return chunks


def process_pcap_aggregations(input_dir=None):
    in_dir = input_dir or RAW_PCAP_DIR
    if not os.path.isdir(in_dir):
        return []
    chunks = []
    for fname in sorted(os.listdir(in_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(in_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for item in data:
                text = format_aggregation_to_text(item, source_file=fname)
                if text.strip():
                    chunks.append({
                        "text": text,
                        "metadata": {
                            "agg_type": item.get("agg_type", "unknown"),
                            "attack_mapping": item.get("attack_mapping", ""),
                            "time_range": item.get("time_range", {}),
                            "source": f"pcap_agg/{fname}",
                            "source_file": fname,
                            "created_at": datetime.now().isoformat(),
                        },
                    })
        elif isinstance(data, dict):
            text = format_aggregation_to_text(data, source_file=fname)
            if text.strip():
                chunks.append({
                    "text": text,
                    "metadata": {
                        "agg_type": data.get("agg_type", "unknown"),
                        "attack_mapping": data.get("attack_mapping", ""),
                        "time_range": data.get("time_range", {}),
                        "source": f"pcap_agg/{fname}",
                        "source_file": fname,
                        "created_at": datetime.now().isoformat(),
                    },
                })
    return chunks


def process_all(aggregations=None):
    all_chunks = []
    if aggregations:
        all_chunks.extend(process_dns_aggregations(aggregations))
    all_chunks.extend(process_pcap_aggregations())
    return all_chunks


def save_chunks(chunks, output_dir=None):
    out_dir = output_dir or PROCESSED_DIR
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"chunks_{timestamp}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(chunks, f, ensure_ascii=False, indent=2)
    return out_file
