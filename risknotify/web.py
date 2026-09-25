"""风险通知闭环的 HTTP 适配层。

仅做协议解析与命令分发，领域逻辑全部在 RiskNotificationService 中；
所有写操作走同一条命令白名单并落哈希链审计。
"""

import inspect
import json
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from .service import ConflictError, RuleError, RiskNotificationService

# 命令白名单：名称 -> (方法名, 是否写操作)
COMMANDS = {
    "register_member": ("register_member", True),
    "add_guardianship": ("add_guardianship", True),
    "end_guardianship": ("end_guardianship", True),
    "grant_consent": ("grant_consent", True),
    "revoke_consent": ("revoke_consent", True),
    "add_contact": ("add_contact", True),
    "disable_contact": ("disable_contact", True),
    "set_preference": ("set_preference", True),
    "relocate_household": ("relocate_household", True),
    "ingest_window": ("ingest_window", True),
    "scan_window": ("scan_window", True),
    "field_confirm": ("field_confirm", True),
    "ethics_approve": ("ethics_approve", True),
    "dispatch": ("dispatch", True),
    "emergency_send": ("emergency_send", True),
    "attempt_delivery": ("attempt_delivery", True),
    "confirm_receipt": ("confirm_receipt", True),
    "report_receipt_conflict": ("report_receipt_conflict", True),
    "opt_out": ("opt_out", True),
    "run_due_tasks": ("run_due_tasks", True),
}


class RiskNotifyApi:
    """持有服务实例与串行锁，供 HTTP Handler 调用。"""

    def __init__(self, store_dir=None, service=None):
        self.service = service or RiskNotificationService(store_dir=store_dir)
        self.lock = threading.RLock()

    def execute(self, command, args, actor=None, at=None):
        if command not in COMMANDS:
            raise RuleError(f"未知命令: {command}")
        method = getattr(self.service, COMMANDS[command][0])
        params = inspect.signature(method).parameters
        kwargs = dict(args or {})
        if actor and "actor" in params:
            kwargs["actor"] = actor
        if at and "at" in params:
            kwargs["at"] = at
        with self.lock:
            return method(**kwargs)

    def advance_timers(self, at=None):
        with self.lock:
            return self.service.advance_timers(at=at)


def _json_safe(value):
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def make_handler(api):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, payload):
            body = json.dumps(_json_safe(payload), ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            try:
                if parsed.path == "/health":
                    from service import health_payload
                    self._send(200, health_payload())
                elif parsed.path == "/api/trace":
                    candidate_id = (query.get("candidate_id") or [""])[0]
                    with api.lock:
                        self._send(200, api.service.trace(candidate_id))
                elif parsed.path == "/api/summary":
                    with api.lock:
                        self._send(200, api.service.community_summary())
                elif parsed.path == "/api/followups":
                    with api.lock:
                        self._send(200, {"followups": api.service.followups})
                elif parsed.path == "/api/candidates":
                    with api.lock:
                        self._send(200, {"candidates": list(api.service.candidates.values())})
                elif parsed.path == "/api/tasks":
                    with api.lock:
                        self._send(200, {"tasks": list(api.service.tasks.values())})
                elif parsed.path == "/api/verify":
                    with api.lock:
                        self._send(200, {"ok": api.service.verify_audit(),
                                         "anchor": api.service.audit.chain_anchor()})
                else:
                    self.send_error(404)
            except (RuleError, KeyError, ValueError) as error:
                self._send(400, {"error": str(error)})

        def do_POST(self):
            parsed = urlparse(self.path)
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length) if length else b"{}"
                envelope = json.loads(raw.decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "请求体不是合法 JSON"})
                return
            try:
                if parsed.path == "/api/commands":
                    result = api.execute(
                        envelope.get("command"),
                        envelope.get("args", {}),
                        actor=envelope.get("actor"),
                        at=envelope.get("at"),
                    )
                    with api.lock:
                        anchor = api.service.audit.chain_anchor()
                    self._send(200, {"ok": True, "result": result, "audit_anchor": anchor})
                elif parsed.path == "/api/timers/advance":
                    self._send(200, {"escalations": api.advance_timers(at=envelope.get("at"))})
                else:
                    self.send_error(404)
            except ConflictError as error:
                self._send(409, {"error": "receipt_conflict", "detail": str(error)})
            except (RuleError, KeyError, ValueError, TypeError) as error:
                self._send(400, {"error": str(error)})

        def log_message(self, *_args):
            return

    return Handler
