"""UTC 时间工具。

领域内所有时间均为 UTC ISO-8601（秒精度，Z 结尾）。
"""

from datetime import datetime, timezone


def now():
    """当前 UTC 时间（ISO-8601 字符串）。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse(value):
    """解析 ISO-8601 字符串为感知 UTC 的 datetime。"""
    if value is None:
        return None
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_valid(value, at=None):
    """有效期半开区间 [start, end)；None 端点表示不限。"""
    moment = parse(at) if at else datetime.now(timezone.utc)
    start = parse(value.get("start")) if value.get("start") else None
    end = parse(value.get("end")) if value.get("end") else None
    if start and moment < start:
        return False
    if end and moment >= end:
        return False
    return True
