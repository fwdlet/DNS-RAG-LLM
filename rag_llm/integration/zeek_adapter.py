import os
import re
import pandas as pd

from config import RAW_ZEEK_DNS_DIR


ZEEK_DNS_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "trans_id", "query", "qtype", "qclass", "rcode",
    "answers", "TTLs", "rejected", "snet", "cnet", "emergent",
]

ZEEK_TO_SYSTEM_COLUMNS = {
    "ts": "metadata.timestamp",
    "uid": "metadata.uid",
    "id.orig_h": "network.src_ip",
    "id.orig_p": "network.src_port",
    "id.resp_h": "network.dst_ip",
    "id.resp_p": "network.dst_port",
    "proto": "network.protocol",
    "trans_id": "dns.transaction_id",
    "query": "dns.question.name",
    "qtype": "dns.question.type",
    "qclass": "dns.question.class",
    "rcode": "dns.rcode",
}


def _parse_zeek_tsv_header(lines):
    field_names = []
    for line in lines:
        if line.startswith("#fields"):
            parts = line.split("\t")
            field_names = [p.strip() for p in parts[1:]]
            break
    return field_names


def _parse_zeek_answers(answers_str):
    if not answers_str or answers_str == "-":
        return []
    results = []
    entries = answers_str.split(";")
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if "," in entry:
            parts = entry.split(",", 1)
            name = parts[0].strip()
            address = parts[1].strip() if len(parts) > 1 else ""
            results.append({"name": name, "address": address})
        else:
            results.append({"name": entry, "address": ""})
    return results


def _normalize_zeek_row(row, field_names):
    record = {}
    for zeek_col, system_col in ZEEK_TO_SYSTEM_COLUMNS.items():
        if zeek_col in field_names:
            idx = field_names.index(zeek_col)
            value = row[idx] if idx < len(row) else "-"
            if value == "-":
                value = ""
            if system_col.startswith("metadata.") or system_col.startswith("network.") or system_col.startswith("dns."):
                if system_col.split(".")[-1] in ("src_port", "dst_port", "transaction_id"):
                    try:
                        value = int(value) if value else 0
                    except (ValueError, TypeError):
                        value = 0
            record[system_col] = value
    if "answers" in field_names:
        idx = field_names.index("answers")
        if idx < len(row):
            answers_str = row[idx]
            if answers_str and answers_str != "-":
                record["dns.answers"] = _parse_zeek_answers(answers_str)
    if "TTLs" in field_names:
        idx = field_names.index("TTLs")
        if idx < len(row) and record.get("dns.answers"):
            ttl_str = row[idx]
            if ttl_str and ttl_str != "-":
                try:
                    first_ttl = float(ttl_str.split(";")[0].strip())
                    if record["dns.answers"]:
                        record["dns.answers"][0]["ttl"] = int(first_ttl)
                except (ValueError, IndexError, TypeError):
                    pass
    return record


def load_zeek_dns_log(filepath):
    if not os.path.isfile(filepath):
        return pd.DataFrame()
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()
    data_lines = []
    header_lines = []
    for line in raw_lines:
        line = line.rstrip("\n")
        if line.startswith("#"):
            header_lines.append(line)
            if line.startswith("#types"):
                type_line = line
        else:
            if line.strip():
                data_lines.append(line)
    if not header_lines:
        return pd.DataFrame()
    field_names = _parse_zeek_tsv_header(header_lines)
    if not field_names:
        return pd.DataFrame()
    records = []
    for line in data_lines:
        fields = line.split("\t")
        if len(fields) < len(field_names):
            fields += ["-"] * (len(field_names) - len(fields))
        normalized = _normalize_zeek_row(fields, field_names)
        records.append(normalized)
    if not records:
        return pd.DataFrame()
    df = pd.json_normalize(records)
    return df


def load_zeek_dns_logs_from_dir(source_dir=None):
    directory = source_dir or RAW_ZEEK_DNS_DIR
    if not os.path.isdir(directory):
        return pd.DataFrame()
    all_dfs = []
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(directory, fname)
        df = load_zeek_dns_log(fpath)
        if not df.empty:
            df["_source_file"] = fname
            all_dfs.append(df)
    if not all_dfs:
        return pd.DataFrame()
    return pd.concat(all_dfs, ignore_index=True)


def is_zeek_log_file(filepath):
    if not os.path.isfile(filepath):
        return False
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            header_lines = []
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if line.startswith("#"):
                    header_lines.append(line.rstrip())
                else:
                    break
        for line in header_lines:
            if line.startswith("#separator") or line.startswith("#fields"):
                return True
        return False
    except Exception:
        return False
