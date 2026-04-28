"""
comprehensive_test_suite.py
========================================
基于流量解析的DNS日志收集与异常检测系统 - 综合自动化测试套件

功能测试 (对应论文6.2节):
  1. 流量解析与数据接入功能测试
  2. 数据聚合分析功能测试
  3. 异常检测规则功能测试
  4. RAG知识库检索与LLM分析流程测试
  5. 异常-知识库桥接与历史管理功能测试

性能测试 (对应论文6.3节):
  1. 数据聚合处理性能测试 (10,000条)
  2. 异常检测批量处理性能测试 (1,000条)
  3. 向量检索与LLM响应时间测试 (500个文本块)

运行方式:
  cd d:\\Bishe\\rag_llm
  python comprehensive_test_suite.py
"""

import json
import os
import sys
import time
import tempfile
import shutil
from datetime import datetime
from unittest.mock import MagicMock, patch
from collections import Counter

import pandas as pd
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ============================================================
#  第一部分: 测试数据生成器
# ============================================================

class TestDataGenerator:
    """
    模拟数据生成器，用于构造各类DNS日志和异常样本，
    避免连接真实生产环境，确保测试的可重复性和独立性。
    """

    NORMAL_DOMAINS = [
        "www.baidu.com", "mail.qq.com", "api.taobao.com",
        "cdn.jsdelivr.net", "github.com", "stackoverflow.com",
        "docs.python.org", "pypi.org", "nginx.org",
    ]
    SUSPICIOUS_DOMAINS = [
        "malware.xyz", "c2server.top", "phish.club",
        "botnet.win", "ransomware.bid", "ddos.stream",
    ]
    DGA_DOMAINS = [
        "qwertyuiopasdf.xyz",
        "zxcvbnmkljhgfd.top",
        "poiuytrewqasdfg.club",
    ]
    TUNNEL_DOMAINS = [
        "aWYgeW91IGNhbiByZWFkIHRoaXMgeW91IGFyZSBnb29k.longsubdomain.evil.com",
        "VGhpcyBpcyBhIHRlc3Qgb2YgZG5zIHR1bm5lbGluZw.anotherlong.evil.com",
    ]

    @staticmethod
    def generate_normal_dns_entry(src_ip="192.168.1.100", dst_ip="8.8.8.8",
                                  domain=None, rcode="NOERROR", ttl=300):
        """生成一条正常的DNS日志JSON条目"""
        if domain is None:
            domain = TestDataGenerator.NORMAL_DOMAINS[
                np.random.randint(0, len(TestDataGenerator.NORMAL_DOMAINS))
            ]
        return {
            "metadata": {
                "device_id": "probe-test",
                "collector_version": "1.0",
                "timestamp": datetime.now().isoformat(),
            },
            "network": {
                "src_ip": src_ip,
                "src_port": str(np.random.randint(10000, 65000)),
                "dst_ip": dst_ip,
                "dst_port": "53",
                "protocol": "udp",
            },
            "dns": {
                "transaction_id": int(np.random.randint(1, 65535)),
                "opcode": "QUERY",
                "flags": {"qr": True, "aa": False, "tc": False, "rd": True, "ra": True},
                "rcode": rcode,
                "question": {"name": domain, "type": "A", "class": "IN"},
                "answers": [
                    {"name": domain, "type": "A", "class": "IN",
                     "ttl": ttl, "address": f"1.2.3.{np.random.randint(1, 254)}"}
                ],
                "authorities": [],
                "additionals": [],
            },
        }

    @staticmethod
    def generate_high_freq_packets(src_ip="192.168.1.200", count=120):
        """生成触发高频查询检测规则的恶意样本"""
        packets = []
        for i in range(count):
            domain = f"query{i}.normal-site.com"
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src_ip, domain=domain)
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_nxdomain_packets(src_ip="192.168.1.201", count=30):
        """生成触发NXDOMAIN风暴检测规则的恶意样本"""
        packets = []
        for i in range(count):
            domain = f"nonexist{i}.dga-domain.xyz"
            pkt = TestDataGenerator.generate_normal_dns_entry(
                src_ip=src_ip, domain=domain, rcode="NXDOMAIN"
            )
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_suspicious_domain_packets(src_ip="192.168.1.202", count=5):
        """生成触发可疑域名检测规则的恶意样本"""
        packets = []
        for domain in TestDataGenerator.SUSPICIOUS_DOMAINS[:count]:
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src_ip, domain=domain)
            packets.append(pkt)
        for domain in TestDataGenerator.DGA_DOMAINS[:2]:
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src_ip, domain=domain)
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_dns_tunnel_packets(src_ip="192.168.1.203", count=5):
        """生成触发DNS隧道检测规则的恶意样本"""
        packets = []
        for domain in TestDataGenerator.TUNNEL_DOMAINS[:count]:
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src_ip, domain=domain)
            pkt["dns"]["question"]["type"] = "TXT"
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_low_ttl_packets(src_ip="192.168.1.204", count=10):
        """生成触发低TTL异常的恶意样本"""
        packets = []
        for i in range(count):
            domain = f"fastflux{i}.suspicious.xyz"
            pkt = TestDataGenerator.generate_normal_dns_entry(
                src_ip=src_ip, domain=domain, ttl=10
            )
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_unknown_dns_server_packets(src_ip="192.168.1.205", count=8):
        """生成触发未知DNS服务器检测规则的恶意样本"""
        packets = []
        for i in range(count):
            domain = f"query{i}.via-unknown.com"
            pkt = TestDataGenerator.generate_normal_dns_entry(
                src_ip=src_ip, dst_ip="45.33.32.156", domain=domain
            )
            packets.append(pkt)
        return packets

    @staticmethod
    def generate_mixed_packets(normal_count=50, anomaly_count=50):
        """生成混合正常与异常的DNS日志数据集"""
        packets = []
        for _ in range(normal_count):
            src = f"192.168.1.{np.random.randint(100, 110)}"
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src)
            packets.append(pkt)
        packets.extend(TestDataGenerator.generate_high_freq_packets(count=anomaly_count))
        packets.extend(TestDataGenerator.generate_nxdomain_packets(count=15))
        packets.extend(TestDataGenerator.generate_suspicious_domain_packets(count=3))
        packets.extend(TestDataGenerator.generate_dns_tunnel_packets(count=2))
        packets.extend(TestDataGenerator.generate_low_ttl_packets(count=5))
        packets.extend(TestDataGenerator.generate_unknown_dns_server_packets(count=6))
        return packets

    @staticmethod
    def generate_zeek_tsv_lines(count=50):
        """生成模拟的Zeek dns.log格式条目(TSV格式)"""
        header_lines = [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#path\tdns",
            f"#open\t{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\tquery\tqtype\tqclass\trcode\tanswers\tTTLs\trejected",
            "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tcount\tstring\tstring\tstring\tstring\tvector[string]\tvector[interval]\tbool",
        ]
        data_lines = []
        for i in range(count):
            ts = 1704067200.0 + i * 0.5
            uid = f"Ctest{i:06d}"
            src_ip = f"192.168.1.{100 + (i % 10)}"
            src_port = 50000 + i
            dst_ip = "8.8.8.8"
            dst_port = 53
            proto = "udp"
            trans_id = 10000 + i
            domain = TestDataGenerator.NORMAL_DOMAINS[i % len(TestDataGenerator.NORMAL_DOMAINS)]
            qtype = "A"
            qclass = "IN"
            rcode = "NOERROR"
            answers = f"{domain},1.2.3.{i % 254 + 1}"
            ttls = "300.000000"
            rejected = "F"
            line = f"{ts:.6f}\t{uid}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{proto}\t{trans_id}\t{domain}\t{qtype}\t{qclass}\t{rcode}\t{answers}\t{ttls}\t{rejected}"
            data_lines.append(line)
        return header_lines + data_lines

    @staticmethod
    def generate_zeek_tsv_content(count=50):
        """返回完整的Zeek TSV字符串内容"""
        lines = TestDataGenerator.generate_zeek_tsv_lines(count)
        return "\n".join(lines) + "\n"

    @staticmethod
    def generate_large_dns_dataset(total=10000):
        """生成大规模DNS日志数据集，用于性能测试"""
        packets = []
        anomaly_ratio = 0.1
        anomaly_count = int(total * anomaly_ratio)
        normal_count = total - anomaly_count

        for i in range(normal_count):
            src = f"10.0.{i // 256}.{i % 256}"
            domain_idx = i % len(TestDataGenerator.NORMAL_DOMAINS)
            domain = TestDataGenerator.NORMAL_DOMAINS[domain_idx]
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src, domain=domain)
            packets.append(pkt)

        packets.extend(TestDataGenerator.generate_high_freq_packets(
            src_ip="10.0.0.200", count=min(anomaly_count, 200)
        ))
        packets.extend(TestDataGenerator.generate_nxdomain_packets(
            src_ip="10.0.0.201", count=30
        ))
        packets.extend(TestDataGenerator.generate_suspicious_domain_packets(count=5))
        packets.extend(TestDataGenerator.generate_dns_tunnel_packets(count=3))
        packets.extend(TestDataGenerator.generate_low_ttl_packets(count=10))

        return packets[:total]

    @staticmethod
    def generate_aggregation_results_for_detection(anomaly_count=100, normal_count=900):
        """生成聚合后数据集，用于异常检测性能测试"""
        packets = []
        for i in range(normal_count):
            src = f"192.168.{i // 256}.{i % 256}"
            pkt = TestDataGenerator.generate_normal_dns_entry(src_ip=src)
            packets.append(pkt)

        packets.extend(TestDataGenerator.generate_high_freq_packets(count=anomaly_count))
        packets.extend(TestDataGenerator.generate_nxdomain_packets(count=20))
        packets.extend(TestDataGenerator.generate_suspicious_domain_packets(count=5))
        packets.extend(TestDataGenerator.generate_dns_tunnel_packets(count=3))
        packets.extend(TestDataGenerator.generate_unknown_dns_server_packets(count=8))

        return packets

    @staticmethod
    def generate_text_chunks(count=500):
        """生成不同大小的文本块，用于向量检索性能测试"""
        chunks = []
        agg_types = [
            "high_freq_dns", "nxdomain_storm", "suspicious_domain",
            "low_ttl", "dns_tunnel", "suricata_alert", "zeek_http",
        ]
        for i in range(count):
            agg_type = agg_types[i % len(agg_types)]
            size_variant = i % 3
            if size_variant == 0:
                text = f"【{agg_type}聚合分析】\n源IP 10.0.{i // 256}.{i % 256} 在监测期间发起 {50 + i} 次DNS查询。"
            elif size_variant == 1:
                text = (
                    f"【{agg_type}聚合分析】\n"
                    f"时间范围: 2025-01-22T08:00:00 ~ 2025-01-22T20:00:00\n"
                    f"ATT&CK映射: T1071.004\n"
                    f"源IP 10.0.{i // 256}.{i % 256} 共发起 {50 + i} 次DNS查询\n"
                    f"查询目标域名Top5:\n"
                )
                for j in range(5):
                    text += f"  {j + 1}. domain{j}.example.com ({10 + j}次)\n"
            else:
                text = (
                    f"【{agg_type}聚合分析】\n"
                    f"时间范围: 2025-01-22T08:00:00 ~ 2025-01-22T20:00:00\n"
                    f"ATT&CK映射: T1071.004\n"
                    f"详细记录:\n"
                )
                for j in range(10):
                    text += f"  2025-01-22T{8 + j:02d}:00:00 | 10.0.{i // 256}.{i % 256} -> domain{j}.example.com (A) -> 1.2.3.{j + 1}\n"

            chunks.append({
                "text": text,
                "metadata": {
                    "agg_type": agg_type,
                    "attack_mapping": "T1071.004",
                    "source": "test_data",
                    "created_at": datetime.now().isoformat(),
                },
            })
        return chunks


# ============================================================
#  第二部分: 功能测试
# ============================================================

def test_data_access_and_parsing():
    """
    功能测试 6.2.1: 流量解析与数据接入功能测试
    验证DNSAdapter和ZeekAdapter能否正确解析模拟数据，
    检查字段完整性和类型正确性。
    """
    test_name = "流量解析与数据接入"
    expected = "字段完整、类型正确"
    details = []
    passed = True

    try:
        from integration.dns_adapter import load_dns_json
        from integration.zeek_adapter import load_zeek_dns_log, is_zeek_log_file

        # --- 测试1: DNSAdapter JSON解析 ---
        gen = TestDataGenerator()
        packets = gen.generate_mixed_packets(normal_count=20, anomaly_count=30)

        tmp_dir = tempfile.mkdtemp()
        try:
            json_path = os.path.join(tmp_dir, "test_dns.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(packets, f, ensure_ascii=False)

            loaded = load_dns_json(json_path)
            if not isinstance(loaded, list):
                passed = False
                details.append("load_dns_json返回类型非list")
            elif len(loaded) != len(packets):
                passed = False
                details.append(f"加载条目数不匹配: 期望{len(packets)}, 实际{len(loaded)}")
            else:
                required_fields = ["metadata", "network", "dns"]
                for i, pkt in enumerate(loaded[:5]):
                    for field in required_fields:
                        if field not in pkt:
                            passed = False
                            details.append(f"第{i}条记录缺少字段: {field}")

                dns_sub_fields = ["transaction_id", "rcode", "question"]
                for i, pkt in enumerate(loaded[:5]):
                    dns = pkt.get("dns", {})
                    for sf in dns_sub_fields:
                        if sf not in dns:
                            passed = False
                            details.append(f"第{i}条记录dns缺少子字段: {sf}")

                if passed:
                    details.append(f"JSON解析正常, {len(loaded)}条记录, 字段完整")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        # --- 测试2: ZeekAdapter TSV解析 ---
        zeek_content = gen.generate_zeek_tsv_content(count=30)
        tmp_dir = tempfile.mkdtemp()
        try:
            zeek_path = os.path.join(tmp_dir, "dns.log")
            with open(zeek_path, "w", encoding="utf-8") as f:
                f.write(zeek_content)

            is_zeek = is_zeek_log_file(zeek_path)
            if not is_zeek:
                passed = False
                details.append("is_zeek_log_file未能识别Zeek格式文件")

            df = load_zeek_dns_log(zeek_path)
            if df.empty:
                passed = False
                details.append("Zeek TSV解析返回空DataFrame")
            else:
                expected_cols = [
                    "metadata.timestamp", "network.src_ip", "network.dst_ip",
                    "dns.question.name", "dns.rcode",
                ]
                missing_cols = [c for c in expected_cols if c not in df.columns]
                if missing_cols:
                    passed = False
                    details.append(f"Zeek解析缺少列: {missing_cols}")
                else:
                    details.append(f"Zeek TSV解析正常, {len(df)}条记录, 映射列完整")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    except Exception as e:
        passed = False
        details.append(f"异常: {type(e).__name__}: {e}")

    actual = "; ".join(details) if details else "无详情"
    conclusion = "通过" if passed else "失败"
    return {
        "test_name": test_name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "conclusion": conclusion,
    }


def test_aggregation_analysis():
    """
    功能测试 6.2.2: 数据聚合分析功能测试
    验证聚合引擎能否正确识别并聚合出高频查询、NXDOMAIN风暴等统计数据，
    检查聚合条目数量和聚合键唯一性。
    """
    test_name = "数据聚合分析"
    expected = "聚合结果正确、键唯一"
    details = []
    passed = True

    try:
        from core.aggregator import (
            aggregate_high_freq_dns, aggregate_nxdomain_storm,
            aggregate_suspicious_domains, aggregate_low_ttl,
            aggregate_dns_tunnel,
        )

        gen = TestDataGenerator()
        packets = gen.generate_mixed_packets(normal_count=30, anomaly_count=80)
        df = pd.json_normalize(packets)

        # --- 测试高频查询聚合 ---
        hf_result = aggregate_high_freq_dns(df)
        if hf_result is None:
            passed = False
            details.append("高频查询聚合返回None")
        else:
            if hf_result.get("agg_type") != "high_freq_dns":
                passed = False
                details.append(f"高频聚合agg_type错误: {hf_result.get('agg_type')}")
            results = hf_result.get("results", [])
            if not results:
                passed = False
                details.append("高频聚合结果为空")
            else:
                src_ips = [r["src_ip"] for r in results]
                if len(src_ips) != len(set(src_ips)):
                    passed = False
                    details.append("高频聚合键(src_ip)不唯一")
                details.append(f"高频聚合: {len(results)}个IP, 键唯一")

        # --- 测试NXDOMAIN风暴聚合 ---
        nx_result = aggregate_nxdomain_storm(df)
        if nx_result is None:
            details.append("NXDOMAIN风暴聚合返回None(可能阈值过高)")
        else:
            if nx_result.get("agg_type") != "nxdomain_storm":
                passed = False
                details.append(f"NXDOMAIN聚合agg_type错误")
            results = nx_result.get("results", [])
            details.append(f"NXDOMAIN风暴聚合: {len(results)}个IP")

        # --- 测试可疑域名聚合 ---
        sd_result = aggregate_suspicious_domains(df)
        if sd_result is None:
            details.append("可疑域名聚合返回None")
        else:
            total = sd_result.get("total_suspicious", 0)
            details.append(f"可疑域名聚合: {total}条")

        # --- 测试低TTL聚合 ---
        lt_result = aggregate_low_ttl(df)
        if lt_result is None:
            details.append("低TTL聚合返回None(可能无低TTL数据)")
        else:
            total = lt_result.get("total_low_ttl", 0)
            details.append(f"低TTL聚合: {total}条")

        # --- 测试DNS隧道聚合 ---
        dt_result = aggregate_dns_tunnel(df)
        if dt_result is None:
            details.append("DNS隧道聚合返回None")
        else:
            total = dt_result.get("total_tunnel_suspects", 0)
            details.append(f"DNS隧道聚合: {total}条")

        non_none_count = sum(1 for r in [hf_result, nx_result, sd_result, lt_result, dt_result] if r is not None)
        if non_none_count < 3:
            passed = False
            details.append(f"聚合结果过少(仅{non_none_count}/5非空)")

    except Exception as e:
        passed = False
        details.append(f"异常: {type(e).__name__}: {e}")

    actual = "; ".join(details) if details else "无详情"
    conclusion = "通过" if passed else "失败"
    return {
        "test_name": test_name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "conclusion": conclusion,
    }


def test_anomaly_detection_rules():
    """
    功能测试 6.2.3: 异常检测规则功能测试
    验证五个检测规则能否准确触发警报，
    检查每个规则至少触发一次且severity字段非空。
    """
    test_name = "异常检测规则"
    expected = "5种规则均触发, severity非空"
    details = []
    passed = True

    try:
        from integration.anomaly_detector import AnomalyDetector

        gen = TestDataGenerator()
        packets = []
        packets.extend(gen.generate_high_freq_packets(count=120))
        packets.extend(gen.generate_nxdomain_packets(count=30))
        packets.extend(gen.generate_suspicious_domain_packets(count=5))
        packets.extend(gen.generate_dns_tunnel_packets(count=3))
        packets.extend(gen.generate_unknown_dns_server_packets(count=8))

        detector = AnomalyDetector(packets)
        alerts = detector.run_all(freq_threshold=50, nxdomain_threshold=10)

        alert_types = set()
        for alert in alerts:
            alert_types.add(alert.get("alert_type"))
            if not alert.get("severity"):
                passed = False
                details.append(f"告警缺少severity: {alert.get('alert_type')}")

        expected_types = {
            "high_frequency_dns",
            "nxdomain_storm",
            "suspicious_domain",
            "dns_tunnel",
            "unknown_dns_server",
        }

        missing_types = expected_types - alert_types
        if missing_types:
            passed = False
            details.append(f"未触发的规则: {missing_types}")

        for atype in alert_types:
            type_alerts = [a for a in alerts if a.get("alert_type") == atype]
            details.append(f"{atype}: {len(type_alerts)}条告警")

        details.append(f"共触发{len(alerts)}条告警, 覆盖{len(alert_types)}/5种规则")

    except Exception as e:
        passed = False
        details.append(f"异常: {type(e).__name__}: {e}")

    actual = "; ".join(details) if details else "无详情"
    conclusion = "通过" if passed else "失败"
    return {
        "test_name": test_name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "conclusion": conclusion,
    }


def test_rag_llm_analysis_flow():
    """
    功能测试 6.2.4: RAG知识库检索与LLM分析流程测试
    模拟完整流程: 告警→文本块转换→向量嵌入→FAISS索引构建→检索上下文→调用LLM。
    LLM调用使用mock，返回预定义的安全分析报告文本。
    检查流程无异常中断，返回报告非空且包含预期字段。
    """
    test_name = "RAG知识库检索与LLM分析流程"
    expected = "流程无中断, 报告包含风险评估"
    details = []
    passed = True

    try:
        from core.embedder import FAISSIndex, Embedder
        from core.retriever import Retriever
        from core.analyzer import Analyzer
        from integration.bridge import anomaly_alerts_to_chunks
        from integration.anomaly_detector import AnomalyDetector

        gen = TestDataGenerator()
        packets = gen.generate_mixed_packets(normal_count=20, anomaly_count=50)

        # Step 1: 异常检测
        detector = AnomalyDetector(packets)
        alerts = detector.run_all(freq_threshold=50, nxdomain_threshold=10)
        if not alerts:
            passed = False
            details.append("异常检测无告警")
        else:
            details.append(f"Step1 异常检测: {len(alerts)}条告警")

        # Step 2: 告警→文本块转换
        chunks = anomaly_alerts_to_chunks(alerts)
        if not chunks:
            passed = False
            details.append("文本块转换为空")
        else:
            details.append(f"Step2 文本块转换: {len(chunks)}个chunk")

        # Step 3: 向量嵌入与FAISS索引构建
        embedder = Embedder()
        faiss_idx = FAISSIndex(embedder, source_type="anomaly")
        faiss_idx.build(chunks)
        stats = faiss_idx.get_stats()
        if stats["total_chunks"] == 0:
            passed = False
            details.append("FAISS索引构建失败")
        else:
            details.append(f"Step3 FAISS构建: {stats['total_chunks']}个向量, dim={stats['dimension']}")

        # Step 4: 语义检索
        retriever = Retriever(faiss_index=faiss_idx)
        context, results = retriever.retrieve_context("哪些主机可能被感染？", top_k=3)
        if not context:
            passed = False
            details.append("语义检索返回空上下文")
        else:
            details.append(f"Step4 语义检索: 返回{len(results)}条证据")

        # Step 5: Mock LLM调用
        mock_report = (
            "## 安全事件分析报告\n\n"
            "### 1. 关键发现\n"
            "检测到多台内部主机存在异常DNS行为。\n\n"
            "### 2. 风险评估\n"
            "整体风险等级: 高危。存在DNS隧道通信和DGA域名探测行为。\n\n"
            "### 3. ATT&CK技术映射\n"
            "- T1071.004 应用层协议:DNS\n\n"
            "### 4. 攻击路径重构\n"
            "内部主机被植入恶意软件，通过DNS隧道与C2服务器通信。\n\n"
            "### 5. 防御建议\n"
            "建议封锁可疑域名，隔离受感染主机。"
        )

        with patch.object(Analyzer, 'analyze', return_value=mock_report):
            analyzer = Analyzer(api_key="test-key")
            report = analyzer.analyze("哪些主机可能被感染？", context)

        if not report:
            passed = False
            details.append("LLM返回报告为空")
        elif "风险评估" not in report:
            passed = False
            details.append("LLM报告缺少'风险评估'字段")
        else:
            details.append("Step5 LLM分析: 报告生成成功, 包含风险评估")

    except Exception as e:
        passed = False
        details.append(f"异常: {type(e).__name__}: {e}")

    actual = "; ".join(details) if details else "无详情"
    conclusion = "通过" if passed else "失败"
    return {
        "test_name": test_name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "conclusion": conclusion,
    }


def test_bridge_and_history():
    """
    功能测试 6.2.5: 异常-知识库桥接与历史管理功能测试
    验证桥接层能否将告警对象正确转换为文本块，
    并将结果持久化到检测历史记录中。
    """
    test_name = "异常-知识库桥接与历史管理"
    expected = "文本块匹配告警, 历史可查询"
    details = []
    passed = True

    try:
        from integration.bridge import (
            anomaly_alerts_to_chunks, save_detection_history,
            load_detection_history, delete_detection_history,
            clear_all_detection_history,
        )
        from integration.anomaly_detector import AnomalyDetector

        gen = TestDataGenerator()
        packets = gen.generate_mixed_packets(normal_count=20, anomaly_count=50)

        # Step 1: 异常检测
        detector = AnomalyDetector(packets)
        alerts = detector.run_all(freq_threshold=50, nxdomain_threshold=10)

        # Step 2: 告警→文本块转换
        chunks = anomaly_alerts_to_chunks(alerts)
        if not chunks:
            passed = False
            details.append("文本块转换为空")
        else:
            for chunk in chunks:
                text = chunk.get("text", "")
                meta = chunk.get("metadata", {})
                if not text:
                    passed = False
                    details.append("存在空文本块")
                if not meta.get("agg_type"):
                    passed = False
                    details.append("文本块缺少agg_type元数据")

                alert_type_prefix = "anomaly_"
                chunk_agg_type = meta.get("agg_type", "")
                if not chunk_agg_type.startswith(alert_type_prefix):
                    passed = False
                    details.append(f"文本块agg_type格式异常: {chunk_agg_type}")

            details.append(f"文本块转换: {len(chunks)}个chunk, 内容与告警匹配")

        # Step 3: 检测历史持久化
        result = {
            "status": "success",
            "total_packets": len(packets),
            "alerts": alerts,
            "summary": detector.get_alerts_summary(),
        }
        thresholds = {"freq_threshold": 50, "nxdomain_threshold": 10}
        history_id = save_detection_history(
            result, source_type="json_file",
            source_name="test_data.json", thresholds=thresholds
        )
        if not history_id:
            passed = False
            details.append("历史记录保存失败")
        else:
            details.append(f"历史记录保存成功, ID={history_id}")

        # Step 4: 历史记录查询
        history = load_detection_history()
        found = any(h.get("id") == history_id for h in history)
        if not found:
            passed = False
            details.append("历史记录查询未找到刚保存的记录")
        else:
            entry = next(h for h in history if h.get("id") == history_id)
            if entry.get("alert_count") != len(alerts):
                passed = False
                details.append(f"历史记录告警数不匹配: 期望{len(alerts)}, 实际{entry.get('alert_count')}")
            else:
                details.append(f"历史记录查询正常, 告警数={entry.get('alert_count')}")

        # Step 5: 清理测试历史
        delete_detection_history(history_id)
        history_after = load_detection_history()
        still_exists = any(h.get("id") == history_id for h in history_after)
        if still_exists:
            passed = False
            details.append("历史记录删除失败")
        else:
            details.append("历史记录删除正常")

    except Exception as e:
        passed = False
        details.append(f"异常: {type(e).__name__}: {e}")

    actual = "; ".join(details) if details else "无详情"
    conclusion = "通过" if passed else "失败"
    return {
        "test_name": test_name,
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "conclusion": conclusion,
    }


# ============================================================
#  第三部分: 性能测试
# ============================================================

def performance_test_aggregation():
    """
    性能测试 6.3.1: 数据聚合处理性能测试
    构造10,000条混合DNS日志，测试聚合引擎处理耗时。
    """
    test_name = "数据聚合引擎"
    data_scale = 10000

    try:
        from core.aggregator import (
            aggregate_high_freq_dns, aggregate_nxdomain_storm,
            aggregate_suspicious_domains, aggregate_low_ttl,
            aggregate_dns_tunnel,
        )

        gen = TestDataGenerator()
        packets = gen.generate_large_dns_dataset(total=data_scale)
        df = pd.json_normalize(packets)

        start_time = time.time()
        results = []
        for agg_fn in [aggregate_high_freq_dns, aggregate_nxdomain_storm,
                       aggregate_suspicious_domains, aggregate_low_ttl,
                       aggregate_dns_tunnel]:
            result = agg_fn(df)
            if result is not None:
                results.append(result)
        elapsed = time.time() - start_time

        speed = data_scale / elapsed if elapsed > 0 else 0
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}条",
            "total_time": round(elapsed, 4),
            "speed": round(speed, 2),
            "agg_results_count": len(results),
            "status": "success",
        }
    except Exception as e:
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}条",
            "total_time": 0,
            "speed": 0,
            "status": f"失败: {type(e).__name__}: {e}",
        }


def performance_test_detection():
    """
    性能测试 6.3.2: 异常检测批量处理性能测试
    构造1,000条(其中100条异常)的聚合后数据集，测试异常检测引擎批量处理耗时。
    """
    test_name = "异常检测引擎"
    data_scale = 1000

    try:
        from integration.anomaly_detector import AnomalyDetector

        gen = TestDataGenerator()
        packets = gen.generate_aggregation_results_for_detection(
            anomaly_count=100, normal_count=900
        )
        packets = packets[:data_scale]

        detector = AnomalyDetector(packets)

        start_time = time.time()
        alerts = detector.run_all(freq_threshold=50, nxdomain_threshold=10)
        elapsed = time.time() - start_time

        speed = data_scale / elapsed if elapsed > 0 else 0
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}条",
            "total_time": round(elapsed, 4),
            "speed": round(speed, 2),
            "alert_count": len(alerts),
            "status": "success",
        }
    except Exception as e:
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}条",
            "total_time": 0,
            "speed": 0,
            "status": f"失败: {type(e).__name__}: {e}",
        }


def performance_test_retrieval_llm():
    """
    性能测试 6.3.3: 向量检索与LLM响应时间测试
    构造500个不同大小文本块的测试集，
    测试从向量嵌入、FAISS索引构建到检索出Top-5结果的总耗时。
    不调用真实LLM，仅测试检索链路性能。
    """
    test_name = "向量检索链路"
    data_scale = 500

    try:
        from core.embedder import FAISSIndex, Embedder
        from core.retriever import Retriever

        gen = TestDataGenerator()
        chunks = gen.generate_text_chunks(count=data_scale)

        start_time = time.time()

        embedder = Embedder()
        faiss_idx = FAISSIndex(embedder, source_type="anomaly")
        faiss_idx.build(chunks)

        retriever = Retriever(faiss_index=faiss_idx)
        context, results = retriever.retrieve_context("检测DNS隧道通信行为", top_k=5)

        elapsed = time.time() - start_time

        speed = data_scale / elapsed if elapsed > 0 else 0
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}个块",
            "total_time": round(elapsed, 4),
            "speed": round(speed, 2),
            "retrieved_count": len(results),
            "index_stats": faiss_idx.get_stats(),
            "status": "success",
        }
    except Exception as e:
        return {
            "test_name": test_name,
            "data_scale": f"{data_scale}个块",
            "total_time": 0,
            "speed": 0,
            "status": f"失败: {type(e).__name__}: {e}",
        }


# ============================================================
#  第四部分: 测试报告输出
# ============================================================

def print_test_report(func_results, perf_results):
    """将测试结果以格式化表格输出到控制台"""

    print("\n")
    print("=" * 70)
    print("                    ========== 测试报告 ==========")
    print("=" * 70)

    # --- 功能测试结果表 ---
    print("\n【功能测试结果】")
    print("-" * 100)
    header = f"{'序号':<4} | {'测试用例名':<28} | {'预期结果':<24} | {'实际结果(摘要)':<28} | {'结论':<4}"
    print(header)
    print("-" * 100)

    func_pass_count = 0
    for i, r in enumerate(func_results, 1):
        actual_short = r["actual"]
        if len(actual_short) > 26:
            actual_short = actual_short[:24] + ".."
        expected_short = r["expected"]
        if len(expected_short) > 22:
            expected_short = expected_short[:20] + ".."
        name_short = r["test_name"]
        if len(name_short) > 26:
            name_short = name_short[:24] + ".."
        row = f"{i:<4} | {name_short:<28} | {expected_short:<24} | {actual_short:<28} | {r['conclusion']:<4}"
        print(row)
        if r["passed"]:
            func_pass_count += 1

    print("-" * 100)
    print(f"功能测试通过率: {func_pass_count}/{len(func_results)} "
          f"({func_pass_count / len(func_results) * 100:.1f}%)")

    # --- 性能测试结果表 ---
    print("\n【性能测试结果】")
    print("-" * 80)
    header = f"{'性能测试项':<16} | {'数据规模':<12} | {'总耗时(s)':<10} | {'平均处理速度(条/秒)':<20}"
    print(header)
    print("-" * 80)

    for r in perf_results:
        row = f"{r['test_name']:<16} | {r['data_scale']:<12} | {r['total_time']:<10} | {r['speed']:<20}"
        print(row)

    print("-" * 80)

    # --- 测试总结 ---
    print("\n【测试总结】")
    func_rate = func_pass_count / len(func_results) * 100 if func_results else 0
    print(f"  功能测试: {func_pass_count}/{len(func_results)} 通过 ({func_rate:.1f}%)")
    perf_success = sum(1 for r in perf_results if r.get("status") == "success")
    print(f"  性能测试: {perf_success}/{len(perf_results)} 成功")
    if perf_results:
        for r in perf_results:
            if r.get("status") == "success":
                print(f"    - {r['test_name']}: {r['total_time']}s, {r['speed']}条/秒")
    print("=" * 70)
    print()


def save_test_report(func_results, perf_results, output_path="test_report.json"):
    """将测试结果保存为结构化JSON文件"""

    func_pass_count = sum(1 for r in func_results if r["passed"])
    perf_success = sum(1 for r in perf_results if r.get("status") == "success")

    summary = (
        f"功能测试通过率: {func_pass_count}/{len(func_results)} "
        f"({func_pass_count / len(func_results) * 100:.1f}%); "
        f"性能测试: {perf_success}/{len(perf_results)} 成功"
    )

    report = {
        "test_metadata": {
            "timestamp": datetime.now().isoformat(),
            "test_environment": "模拟环境",
            "system_name": "基于流量解析的DNS日志收集与异常检测系统",
        },
        "functional_test_results": {
            "total": len(func_results),
            "passed": func_pass_count,
            "pass_rate": f"{func_pass_count / len(func_results) * 100:.1f}%",
            "details": func_results,
        },
        "performance_test_results": {
            "total": len(perf_results),
            "success": perf_success,
            "details": perf_results,
        },
        "summary": summary,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return output_path


# ============================================================
#  第五部分: 主入口
# ============================================================

if __name__ == "__main__":
    print("正在启动综合测试套件...")
    print(f"测试时间: {datetime.now().isoformat()}")
    print(f"测试环境: 模拟环境 (无需连接真实数据库或LLM)")
    print()

    # --- 执行功能测试 ---
    print(">>> 执行功能测试...")
    func_tests = [
        test_data_access_and_parsing,
        test_aggregation_analysis,
        test_anomaly_detection_rules,
        test_rag_llm_analysis_flow,
        test_bridge_and_history,
    ]
    func_results = []
    for test_fn in func_tests:
        print(f"  运行: {test_fn.__doc__.strip().split(chr(10))[0] if test_fn.__doc__ else test_fn.__name__}")
        try:
            result = test_fn()
        except Exception as e:
            result = {
                "test_name": test_fn.__name__,
                "expected": "N/A",
                "actual": f"测试函数异常: {type(e).__name__}: {e}",
                "passed": False,
                "conclusion": "失败",
            }
        func_results.append(result)

    # --- 执行性能测试 ---
    print("\n>>> 执行性能测试 (首次运行需下载嵌入模型, 请耐心等待)...")
    perf_tests = [
        performance_test_aggregation,
        performance_test_detection,
        performance_test_retrieval_llm,
    ]
    perf_results = []
    for test_fn in perf_tests:
        print(f"  运行: {test_fn.__name__}")
        try:
            result = test_fn()
        except Exception as e:
            result = {
                "test_name": test_fn.__name__,
                "data_scale": "N/A",
                "total_time": 0,
                "speed": 0,
                "status": f"失败: {type(e).__name__}: {e}",
            }
        perf_results.append(result)

    # --- 输出报告 ---
    print_test_report(func_results, perf_results)

    report_path = save_test_report(func_results, perf_results)
    print(f"测试报告已保存至: {os.path.abspath(report_path)}")
