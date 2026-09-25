"""哈希链只增审计日志。

每条记录包含：seq、ts、actor、action、payload，以及上一条记录哈希 prev_hash
与自身哈希 hash。任何插入、删除、改写都会在 verify() 中暴露。
持久化为 JSONL（每行一条记录），重启后可继续追加。
"""

import hashlib
import json
import os
import threading

from . import timeutil

GENESIS = "0" * 64


def _digest(record):
    """对除 hash 外的字段做规范化哈希。"""
    material = {k: v for k, v in record.items() if k != "hash"}
    blob = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLog:
    """线程安全的哈希链只增日志。"""

    def __init__(self, path=None):
        self._path = path
        self._lock = threading.RLock()
        self._records = []
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        self._records.append(json.loads(line))
            self.verify()

    def append(self, action, payload=None, actor="system", ts=None):
        """追加一条记录，返回该记录。"""
        with self._lock:
            record = {
                "seq": len(self._records) + 1,
                "ts": ts or timeutil.now(),
                "actor": actor,
                "action": action,
                "payload": payload or {},
                "prev_hash": self._records[-1]["hash"] if self._records else GENESIS,
            }
            record["hash"] = _digest(record)
            self._records.append(record)
            if self._path:
                # 全量原子重写，保证磁盘上的日志始终完整且与内存一致
                tmp = self._path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as handle:
                    for item in self._records:
                        handle.write(json.dumps(item, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self._path)
            return dict(record)

    def all(self):
        with self._lock:
            return [dict(r) for r in self._records]

    def by_action(self, action):
        with self._lock:
            return [dict(r) for r in self._records if r["action"] == action]

    def verify(self):
        """校验整条哈希链；失败抛出 TamperError。"""
        with self._lock:
            prev = GENESIS
            for record in self._records:
                if record["prev_hash"] != prev:
                    raise TamperError(record["seq"], "链断裂")
                if record["hash"] != _digest(record):
                    raise TamperError(record["seq"], "记录被改写")
                prev = record["hash"]
            return True

    def chain_anchor(self):
        """最后一条记录哈希（用于外部锚定/交接）。"""
        with self._lock:
            return self._records[-1]["hash"] if self._records else GENESIS


class TamperError(RuntimeError):
    def __init__(self, seq, reason):
        super().__init__(f"审计日志在第 {seq} 条校验失败：{reason}")
        self.seq = seq
        self.reason = reason
