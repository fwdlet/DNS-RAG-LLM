import re
from collections import Counter, defaultdict
from datetime import datetime


SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".win", ".bid", ".stream",
                   ".gq", ".ml", ".cf", ".tk", ".pw", ".cc"]

KNOWN_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                     "114.114.114.114", "223.5.5.5", "119.29.29.29"]

DGA_PATTERN = re.compile(r'^[a-z0-9]{8,}$', re.IGNORECASE)


class AnomalyDetector:
    def __init__(self, packets=None):
        self.packets = packets or []
        self.alerts = []

    def load_packets(self, packets):
        self.packets = packets
        self.alerts = []

    def _get_field(self, pkt, *keys):
        current = pkt
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current

    def detect_high_frequency(self, threshold=50):
        src_counts = Counter()
        for pkt in self.packets:
            src_ip = self._get_field(pkt, "network", "src_ip")
            if src_ip:
                src_counts[src_ip] += 1
        alerts = []
        for ip, count in src_counts.items():
            if count >= threshold:
                alerts.append({
                    "alert_type": "high_frequency_dns",
                    "severity": "high" if count >= threshold * 5 else "medium",
                    "src_ip": ip,
                    "count": count,
                    "description": f"源IP {ip} 在监测期间发起 {count} 次DNS查询，超过阈值 {threshold}",
                    "attack_mapping": "T1071.004 - 应用层协议:DNS",
                })
        self.alerts.extend(alerts)
        return alerts

    def detect_nxdomain_storm(self, threshold=10):
        nx_counts = Counter()
        nx_domains = defaultdict(list)
        for pkt in self.packets:
            rcode = self._get_field(pkt, "dns", "rcode")
            src_ip = self._get_field(pkt, "network", "src_ip")
            domain = self._get_field(pkt, "dns", "question", "name")
            if rcode and str(rcode).upper() in ("NXDOMAIN", "SERVFAIL") and src_ip:
                nx_counts[src_ip] += 1
                if domain:
                    nx_domains[src_ip].append(str(domain).rstrip("."))
        alerts = []
        for ip, count in nx_counts.items():
            if count >= threshold:
                top_domains = Counter(nx_domains[ip]).most_common(5)
                alerts.append({
                    "alert_type": "nxdomain_storm",
                    "severity": "high" if count >= threshold * 5 else "medium",
                    "src_ip": ip,
                    "count": count,
                    "top_failed_domains": [d for d, _ in top_domains],
                    "description": f"源IP {ip} 产生 {count} 次NXDOMAIN响应，可能存在DGA域名探测",
                    "attack_mapping": "T1071.004 - DGA域名探测",
                })
        self.alerts.extend(alerts)
        return alerts

    def detect_suspicious_domains(self):
        alerts = []
        seen_domains = set()
        for pkt in self.packets:
            domain = self._get_field(pkt, "dns", "question", "name")
            src_ip = self._get_field(pkt, "network", "src_ip")
            if not domain:
                continue
            domain = str(domain).rstrip(".")
            if domain in seen_domains:
                continue
            is_suspicious = False
            reasons = []
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    is_suspicious = True
                    reasons.append(f"可疑TLD({tld})")
                    break
            if len(domain) > 50:
                is_suspicious = True
                reasons.append("超长域名")
            labels = domain.split(".")
            for label in labels[:-1]:
                if len(label) > 15 and DGA_PATTERN.match(label):
                    is_suspicious = True
                    reasons.append(f"DGA特征子标签({label[:20]}...)")
                    break
            if is_suspicious:
                seen_domains.add(domain)
                alerts.append({
                    "alert_type": "suspicious_domain",
                    "severity": "high",
                    "src_ip": src_ip or "N/A",
                    "domain": domain,
                    "reasons": reasons,
                    "description": f"可疑域名 {domain}，原因: {', '.join(reasons)}",
                    "attack_mapping": "T1071.004 - C2通信",
                })
        self.alerts.extend(alerts)
        return alerts

    def detect_dns_tunnel(self, domain_len_threshold=50):
        alerts = []
        seen = set()
        for pkt in self.packets:
            domain = self._get_field(pkt, "dns", "question", "name")
            qtype = self._get_field(pkt, "dns", "question", "type")
            src_ip = self._get_field(pkt, "network", "src_ip")
            if not domain:
                continue
            domain = str(domain).rstrip(".")
            key = (src_ip, domain)
            if key in seen:
                continue
            is_tunnel = False
            reasons = []
            if len(domain) > domain_len_threshold:
                is_tunnel = True
                reasons.append("超长域名(可能DNS隧道)")
            if qtype and str(qtype).upper() in ("TXT", "NULL"):
                labels = domain.split(".")
                for label in labels[:-1]:
                    if len(label) > 20 and DGA_PATTERN.match(label):
                        is_tunnel = True
                        reasons.append(f"TXT/NULL记录+异常子标签")
                        break
            if is_tunnel:
                seen.add(key)
                alerts.append({
                    "alert_type": "dns_tunnel",
                    "severity": "high",
                    "src_ip": src_ip or "N/A",
                    "domain": domain,
                    "query_type": qtype or "N/A",
                    "reasons": reasons,
                    "description": f"DNS隧道嫌疑: {domain}，原因: {', '.join(reasons)}",
                    "attack_mapping": "T1071.004 - DNS隧道",
                })
        self.alerts.extend(alerts)
        return alerts

    def detect_unknown_dns_servers(self):
        alerts = []
        unknown_server_counts = Counter()
        for pkt in self.packets:
            dst_ip = self._get_field(pkt, "network", "dst_ip")
            dst_port = self._get_field(pkt, "network", "dst_port")
            src_ip = self._get_field(pkt, "network", "src_ip")
            if dst_ip and str(dst_port) == "53" and dst_ip not in KNOWN_DNS_SERVERS:
                if not dst_ip.startswith(("192.168.", "10.", "172.")):
                    unknown_server_counts[(src_ip, dst_ip)] += 1
        for (src_ip, dns_ip), count in unknown_server_counts.items():
            if count >= 5:
                alerts.append({
                    "alert_type": "unknown_dns_server",
                    "severity": "medium",
                    "src_ip": src_ip or "N/A",
                    "dns_server": dns_ip,
                    "count": count,
                    "description": f"源IP {src_ip} 向非标准DNS服务器 {dns_ip} 发起 {count} 次查询",
                    "attack_mapping": "T1071.004 - 可疑DNS服务器",
                })
        self.alerts.extend(alerts)
        return alerts

    def run_all(self, freq_threshold=50, nxdomain_threshold=10):
        all_alerts = []
        all_alerts.extend(self.detect_high_frequency(freq_threshold))
        all_alerts.extend(self.detect_nxdomain_storm(nxdomain_threshold))
        all_alerts.extend(self.detect_suspicious_domains())
        all_alerts.extend(self.detect_dns_tunnel())
        all_alerts.extend(self.detect_unknown_dns_servers())
        return all_alerts

    def get_alerts(self):
        return self.alerts

    def get_alerts_by_severity(self, severity="high"):
        return [a for a in self.alerts if a.get("severity") == severity]

    def get_alerts_summary(self):
        type_counts = Counter(a.get("alert_type", "unknown") for a in self.alerts)
        severity_counts = Counter(a.get("severity", "unknown") for a in self.alerts)
        return {
            "total_alerts": len(self.alerts),
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
        }
