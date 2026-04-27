import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime

import pandas as pd

from config import RAW_DNS_DIR, RAW_ZEEK_DNS_DIR, PROCESSED_DIR, ATTACK_MAPPING


def load_dns_logs(source=None):
    if source and os.path.isfile(source):
        from integration.zeek_adapter import is_zeek_log_file
        if is_zeek_log_file(source):
            from integration.zeek_adapter import load_zeek_dns_log
            return load_zeek_dns_log(source)
        with open(source, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return pd.json_normalize(data)
        return pd.json_normalize([data])

    all_records = []
    if os.path.isdir(RAW_DNS_DIR):
        from integration.zeek_adapter import is_zeek_log_file
        for fname in os.listdir(RAW_DNS_DIR):
            fpath = os.path.join(RAW_DNS_DIR, fname)
            if fname.endswith(".json"):
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    all_records.extend(data)
                else:
                    all_records.append(data)
            elif fname.endswith(".log") and is_zeek_log_file(fpath):
                from integration.zeek_adapter import load_zeek_dns_log
                zeek_df = load_zeek_dns_log(fpath)
                if not zeek_df.empty:
                    all_records.extend(zeek_df.to_dict(orient="records"))
    return pd.json_normalize(all_records) if all_records else pd.DataFrame()


def load_zeek_dns_logs(source=None):
    from integration.zeek_adapter import load_zeek_dns_log, is_zeek_log_file
    if source:
        if os.path.isfile(source) and is_zeek_log_file(source):
            return load_zeek_dns_log(source)
        return pd.DataFrame()
    all_dfs = []
    if os.path.isdir(RAW_ZEEK_DNS_DIR):
        for fname in sorted(os.listdir(RAW_ZEEK_DNS_DIR)):
            if fname.endswith(".log"):
                fpath = os.path.join(RAW_ZEEK_DNS_DIR, fname)
                if is_zeek_log_file(fpath):
                    df = load_zeek_dns_log(fpath)
                    if not df.empty:
                        df["_source_file"] = fname
                        all_dfs.append(df)
    if not all_dfs:
        return pd.DataFrame()
    return pd.concat(all_dfs, ignore_index=True)


def run_all_zeek_aggregations(source=None):
    df = load_zeek_dns_logs(source)
    if df.empty:
        return []
    agg_file_tag = os.path.basename(source) if source and os.path.isfile(source) else "zeek_dns(all)"
    aggregators = [
        aggregate_high_freq_dns,
        aggregate_nxdomain_storm,
        aggregate_suspicious_domains,
        aggregate_low_ttl,
        aggregate_dns_tunnel,
    ]
    results = []
    for agg_fn in aggregators:
        result = agg_fn(df)
        if result is not None:
            result["data_source"] = "zeek_dns"
            result["source_file"] = agg_file_tag
            results.append(result)
    return results


def _extract_domain(row_prefix="dns.question"):
    def _inner(row):
        name = row.get(f"{row_prefix}.name", "")
        return str(name).rstrip(".") if name else ""
    return _inner


def _is_private_ip(ip):
    if not ip or not isinstance(ip, str):
        return False
    return ip.startswith("10.") or ip.startswith("192.168.") or \
           (ip.startswith("172.") and _in_172_range(ip))


def _in_172_range(ip):
    parts = ip.split(".")
    if len(parts) < 2:
        return False
    try:
        second = int(parts[1])
        return 16 <= second <= 31
    except ValueError:
        return False


def _is_suspicious_domain(domain):
    if not domain:
        return False
    suspicious_tlds = [".xyz", ".top", ".club", ".win", ".bid", ".stream",
                       ".gq", ".ml", ".cf", ".tk", ".pw", ".cc", ".cn.com"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True
    if len(domain) > 50:
        return True
    labels = domain.split(".")
    for label in labels:
        if len(label) > 20 and re.match(r'^[a-z0-9]+$', label):
            return True
    return False


def aggregate_high_freq_dns(df, top_n=10):
    if df.empty:
        return None
    src_col = "network.src_ip"
    if src_col not in df.columns:
        return None
    freq = df[src_col].value_counts().head(top_n)
    results = []
    for ip, count in freq.items():
        ip_df = df[df[src_col] == ip]
        domain_col = "dns.question.name"
        domain_counts = {}
        if domain_col in ip_df.columns:
            domain_counts = ip_df[domain_col].value_counts().head(5).to_dict()
        dst_col = "network.dst_ip"
        dns_server_counts = {}
        if dst_col in ip_df.columns:
            dns_server_counts = ip_df[dst_col].value_counts().head(3).to_dict()
        results.append({
            "src_ip": ip,
            "query_count": int(count),
            "top_domains": {str(k).rstrip("."): int(v) for k, v in domain_counts.items()},
            "dns_servers": dns_server_counts,
        })
    time_min = df.get("metadata.timestamp", pd.Series()).min() if "metadata.timestamp" in df.columns else "N/A"
    time_max = df.get("metadata.timestamp", pd.Series()).max() if "metadata.timestamp" in df.columns else "N/A"
    return {
        "agg_type": "high_freq_dns",
        "attack_mapping": ATTACK_MAPPING["high_freq_dns"],
        "time_range": {"start": str(time_min), "end": str(time_max)},
        "total_queries": len(df),
        "results": results,
    }


def aggregate_nxdomain_storm(df, threshold=None):
    if df.empty:
        return None
    rcode_col = "dns.rcode"
    src_col = "network.src_ip"
    if rcode_col not in df.columns or src_col not in df.columns:
        return None
    nx_df = df[df[rcode_col].str.upper().isin(["NXDOMAIN", "SERVFAIL"])]
    if nx_df.empty:
        return None
    if threshold is None:
        total_src = df[src_col].nunique()
        threshold = max(2, min(10, total_src // 3))
    nx_counts = nx_df[src_col].value_counts()
    nx_counts = nx_counts[nx_counts >= threshold]
    if nx_counts.empty:
        return None
    results = []
    for ip, count in nx_counts.items():
        ip_nx = nx_df[nx_df[src_col] == ip]
        domain_col = "dns.question.name"
        failed_domains = []
        if domain_col in ip_nx.columns:
            failed_domains = ip_nx[domain_col].value_counts().head(10).index.tolist()
        results.append({
            "src_ip": ip,
            "nxdomain_count": int(count),
            "failed_domains": [str(d).rstrip(".") for d in failed_domains],
        })
    time_min = df.get("metadata.timestamp", pd.Series()).min() if "metadata.timestamp" in df.columns else "N/A"
    time_max = df.get("metadata.timestamp", pd.Series()).max() if "metadata.timestamp" in df.columns else "N/A"
    return {
        "agg_type": "nxdomain_storm",
        "attack_mapping": ATTACK_MAPPING["nxdomain_storm"],
        "time_range": {"start": str(time_min), "end": str(time_max)},
        "total_nxdomain": len(nx_df),
        "results": results,
    }


def aggregate_suspicious_domains(df):
    if df.empty:
        return None
    domain_col = "dns.question.name"
    src_col = "network.src_ip"
    if domain_col not in df.columns:
        return None
    domains = df[domain_col].astype(str).str.rstrip(".")
    mask = pd.Series(False, index=df.index)
    suspicious_tlds = [".xyz", ".top", ".club", ".win", ".bid", ".stream",
                       ".gq", ".ml", ".cf", ".tk", ".pw", ".cc", ".cn.com"]
    mask = mask | domains.str.endswith(tuple(suspicious_tlds))
    mask = mask | (domains.str.len() > 50)
    label_lengths = domains.str.split(".").str.len()
    for i in range(20):
        label_mask = pd.Series(False, index=df.index)
        for j, label_list in enumerate(domains.str.split(".")):
            if label_list and i < len(label_list):
                label = label_list[i]
                if len(label) > 20 and re.match(r'^[a-z0-9]+$', label):
                    label_mask.iloc[j] = True
        mask = mask | label_mask
    suspicious_df = df[mask]
    if suspicious_df.empty:
        return None
    results = []
    for _, row in suspicious_df.iterrows():
        results.append({
            "src_ip": row.get(src_col, "N/A"),
            "domain": str(row.get(domain_col, "")).rstrip("."),
            "query_type": row.get("dns.question.type", "N/A"),
            "dst_ip": row.get("network.dst_ip", "N/A"),
            "timestamp": row.get("metadata.timestamp", "N/A"),
        })
    domain_counter = Counter(r["domain"] for r in results)
    top_suspicious = domain_counter.most_common(20)
    time_min = df.get("metadata.timestamp", pd.Series()).min() if "metadata.timestamp" in df.columns else "N/A"
    time_max = df.get("metadata.timestamp", pd.Series()).max() if "metadata.timestamp" in df.columns else "N/A"
    return {
        "agg_type": "suspicious_domain",
        "attack_mapping": ATTACK_MAPPING["suspicious_domain"],
        "time_range": {"start": str(time_min), "end": str(time_max)},
        "total_suspicious": len(results),
        "top_suspicious_domains": [{"domain": d, "count": c} for d, c in top_suspicious],
        "details": results[:30],
    }


def aggregate_low_ttl(df, ttl_threshold=60):
    if df.empty:
        return None
    answers_col = "dns.answers"
    src_col = "network.src_ip"
    if answers_col not in df.columns:
        return None
    results = []
    for _, row in df.iterrows():
        answers = row.get(answers_col)
        if not answers:
            continue
        if isinstance(answers, str):
            try:
                answers = json.loads(answers)
            except (json.JSONDecodeError, TypeError):
                continue
        if not isinstance(answers, list):
            continue
        for ans in answers:
            ttl = ans.get("ttl", 0)
            if isinstance(ttl, (int, float)) and ttl <= ttl_threshold:
                results.append({
                    "src_ip": row.get(src_col, "N/A"),
                    "domain": str(ans.get("name", "")).rstrip("."),
                    "ttl": int(ttl),
                    "resolved_ip": ans.get("address", "N/A"),
                    "timestamp": row.get("metadata.timestamp", "N/A"),
                })
    if not results:
        return None
    time_min = df.get("metadata.timestamp", pd.Series()).min() if "metadata.timestamp" in df.columns else "N/A"
    time_max = df.get("metadata.timestamp", pd.Series()).max() if "metadata.timestamp" in df.columns else "N/A"
    return {
        "agg_type": "low_ttl",
        "attack_mapping": ATTACK_MAPPING["low_ttl"],
        "time_range": {"start": str(time_min), "end": str(time_max)},
        "total_low_ttl": len(results),
        "details": results[:30],
    }


def aggregate_dns_tunnel(df, domain_len_threshold=50, label_len_threshold=20):
    if df.empty:
        return None
    domain_col = "dns.question.name"
    src_col = "network.src_ip"
    type_col = "dns.question.type"
    if domain_col not in df.columns:
        return None
    results = []
    for _, row in df.iterrows():
        domain = str(row.get(domain_col, "")).rstrip(".")
        qtype = str(row.get(type_col, "")).upper()
        if len(domain) > domain_len_threshold:
            results.append({
                "src_ip": row.get(src_col, "N/A"),
                "domain": domain,
                "query_type": qtype,
                "reason": "超长域名",
                "timestamp": row.get("metadata.timestamp", "N/A"),
            })
            continue
        if qtype in ["TXT", "NULL"]:
            labels = domain.split(".")
            for label in labels:
                if len(label) > label_len_threshold and re.match(r'^[a-z0-9]+$', label):
                    results.append({
                        "src_ip": row.get(src_col, "N/A"),
                        "domain": domain,
                        "query_type": qtype,
                        "reason": f"异常子标签({label[:30]}...)",
                        "timestamp": row.get("metadata.timestamp", "N/A"),
                    })
                    break
    if not results:
        return None
    time_min = df.get("metadata.timestamp", pd.Series()).min() if "metadata.timestamp" in df.columns else "N/A"
    time_max = df.get("metadata.timestamp", pd.Series()).max() if "metadata.timestamp" in df.columns else "N/A"
    return {
        "agg_type": "dns_tunnel",
        "attack_mapping": ATTACK_MAPPING["dns_tunnel"],
        "time_range": {"start": str(time_min), "end": str(time_max)},
        "total_tunnel_suspects": len(results),
        "details": results[:30],
    }


def run_all_aggregations(source=None):
    df = load_dns_logs(source)
    if df.empty:
        return []

    aggregators = [
        aggregate_high_freq_dns,
        aggregate_nxdomain_storm,
        aggregate_suspicious_domains,
        aggregate_low_ttl,
        aggregate_dns_tunnel,
    ]

    agg_file_tag = None
    if source and os.path.isfile(source):
        agg_file_tag = os.path.basename(source)
    elif os.path.isdir(RAW_DNS_DIR):
        json_files = sorted([f for f in os.listdir(RAW_DNS_DIR) if f.endswith(".json")])
        agg_file_tag = f"dns_logs({len(json_files)}files)"

    results = []
    for agg_fn in aggregators:
        result = agg_fn(df)
        if result is not None:
            if agg_file_tag:
                result["source_file"] = agg_file_tag
            results.append(result)
    return results


def save_aggregations(aggregations, output_dir=None):
    out_dir = output_dir or PROCESSED_DIR
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"dns_aggregations_{timestamp}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(aggregations, f, ensure_ascii=False, indent=2)
    return out_file
