from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pandas as pd

from config import RAW_DNS_DIR, MYSQL_SETTINGS_FILE

if TYPE_CHECKING:
    import pymysql


class DNSAdapterError(Exception):
    pass


class DNSConnectionError(DNSAdapterError):
    pass


class DNSAuthenticationError(DNSAdapterError):
    pass


class DNSDatabaseError(DNSAdapterError):
    pass


class DNSQueryError(DNSAdapterError):
    pass


def load_dns_json(source=None):
    if source and os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return [data]
    all_records = []
    if os.path.isdir(RAW_DNS_DIR):
        for fname in os.listdir(RAW_DNS_DIR):
            if fname.endswith(".json"):
                fpath = os.path.join(RAW_DNS_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        all_records.extend(data)
                    else:
                        all_records.append(data)
                except json.JSONDecodeError:
                    pass
    return all_records


class DNSAdapter:
    def __init__(self, host="localhost", port=3306, user="root", password="", database="dns_server"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self._connection = None

    def _get_connection(self):
        if self._connection is None:
            try:
                import pymysql
            except ImportError:
                raise DNSAdapterError(
                    "pymysql库未安装，请运行: pip install pymysql"
                )
            try:
                self._connection = pymysql.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.database,
                    charset="utf8mb4",
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=10,
                )
            except pymysql.err.OperationalError as e:
                error_code = e.args[0] if e.args else 0
                msg = str(e)
                if error_code == 1045 or "Access denied" in msg:
                    raise DNSAuthenticationError(
                        f"MySQL认证失败: 用户名或密码错误。请检查配置。\n详情: {msg}"
                    )
                elif error_code == 2003 or "Can't connect" in msg or "connect" in msg.lower():
                    raise DNSConnectionError(
                        f"无法连接到MySQL服务器 ({self.host}:{self.port})。"
                        "请检查: 1) MySQL服务是否运行; 2) 主机地址/端口是否正确; 3) 防火墙是否允许连接。"
                    )
                elif error_code == 1049:
                    raise DNSDatabaseError(
                        f"数据库 '{self.database}' 不存在。请先创建数据库或检查数据库名称。"
                    )
                else:
                    raise DNSConnectionError(
                        f"MySQL连接失败 (错误码: {error_code})\n详情: {msg}"
                    )
            except pymysql.err.InterfaceError as e:
                raise DNSConnectionError(
                    f"网络连接异常: {e}\n请检查网络状况和MySQL服务器状态。"
                )
            except Exception as e:
                raise DNSAdapterError(f"连接MySQL时发生未知错误: {type(e).__name__}: {e}")
        return self._connection

    def fetch_packets(self, device_id=None, start_time=None, end_time=None, limit=10000):
        conn = self._get_connection()
        try:
            with conn.cursor() as cursor:
                sql = "SELECT id, timestamp, device_id, src_ip, dst_ip, dns_data FROM dns_packets WHERE 1=1"
                params = []
                if device_id:
                    sql += " AND device_id = %s"
                    params.append(device_id)
                if start_time:
                    sql += " AND timestamp >= %s"
                    params.append(start_time)
                if end_time:
                    sql += " AND timestamp <= %s"
                    params.append(end_time)
                sql += " ORDER BY timestamp DESC LIMIT %s"
                params.append(limit)
                cursor.execute(sql, params)
                rows = cursor.fetchall()
                return rows
        except pymysql.err.OperationalError as e:
            raise DNSQueryError(f"SQL执行失败: {e}")
        except Exception as e:
            raise DNSAdapterError(f"查询数据时发生错误: {type(e).__name__}: {e}")

    def fetch_as_json_packets(self, **kwargs):
        rows = self.fetch_packets(**kwargs)
        packets = []
        for row in rows:
            dns_data = row.get("dns_data")
            if isinstance(dns_data, str):
                try:
                    dns_data = json.loads(dns_data)
                except json.JSONDecodeError:
                    continue
            if isinstance(dns_data, dict):
                packets.append(dns_data)
        return packets

    def export_to_file(self, output_path, **kwargs):
        packets = self.fetch_as_json_packets(**kwargs)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(packets, f, ensure_ascii=False, indent=2)
        return len(packets)

    def close(self):
        if self._connection:
            self._connection.close()
            self._connection = None


def load_mysql_settings():
    if not os.path.exists(MYSQL_SETTINGS_FILE):
        return None
    try:
        with open(MYSQL_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_mysql_settings(host, port, user, password, database):
    os.makedirs(os.path.dirname(MYSQL_SETTINGS_FILE), exist_ok=True)
    settings = {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
    }
    with open(MYSQL_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)
