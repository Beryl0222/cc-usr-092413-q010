"""二手烟暴露干预研究的运行入口。

- GET  /health：稳定服务身份
- POST /api   ：风险通知闭环动作网关，JSON in / JSON out
"""

import argparse
import inspect
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from notification_loop import (
    DomainError,
    NotificationService,
    utcnow,
)

SERVICE_ID = "secondhand-smoke-study"
SERVICE_NAME = "二手烟暴露干预研究"

_state_lock = threading.Lock()
_state_service = None


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def get_service():
    """惰性创建领域服务单例；状态文件由 RISK_STATE_FILE 指定。"""
    global _state_service
    if _state_service is None:
        with _state_lock:
            if _state_service is None:
                path = os.environ.get("RISK_STATE_FILE") or None
                _state_service = NotificationService(path=path, clock=utcnow)
    return _state_service


def reset_service():
    """测试辅助：丢弃内存单例（使用临时状态文件的测试用）。"""
    global _state_service
    with _state_lock:
        _state_service = None


def _candidate_args(method, payload):
    """只传入方法签名中声明的参数，忽略多余字段。"""
    sig = inspect.signature(method)
    kwargs = {}
    for name, param in sig.parameters.items():
        if name in payload:
            kwargs[name] = payload[name]
        elif param.default is inspect.Parameter.empty:
            raise DomainError("bad_request", f"缺少参数: {name}")
    return kwargs


def dispatch(action, payload):
    """把 API 动作映射到领域服务方法；集中登记，避免暴露任意方法。"""
    service = get_service()
    table = {
        # 家庭/成员与时态授权数据
        "register_household": service.register_household,
        "register_member": service.register_member,
        "add_consent": service.add_consent,
        "add_guardianship": service.add_guardianship,
        "end_guardianship": service.end_guardianship,
        "add_contact": service.add_contact,
        "invalidate_contact": service.invalidate_contact,
        "relocate_household": service.relocate_household,
        "add_preference": service.add_preference,
        # 数据与规则
        "register_window": service.register_window,
        "evaluate_quality": service.evaluate_quality,
        "register_rule": service.register_rule,
        "run_rules": service.run_rules,
        # 接收人解析与复核
        "resolve_recipients": service.resolve_recipients,
        "field_confirm": service.field_confirm,
        "ethics_approve": service.ethics_approve,
        "send_emergency_notice": service.send_emergency_notice,
        "review_status": service.review_status,
        # 投递与后续
        "deliver_due": service.deliver_due,
        "sweep": service.sweep,
        "record_receipt": service.record_receipt,
        "reconcile_receipt": service.reconcile_receipt,
        "resolve_followup": service.resolve_followup,
        "reroute_task": service.reroute_task,
        "resolve_escalation": service.resolve_escalation,
        # 汇总/审计
        "community_summary": service.community_summary,
        "notification_trace": service.notification_trace,
        "verify_audit_chain": service.verify_audit_chain,
    }
    method = table.get(action)
    if method is None:
        raise DomainError("unknown_action", f"未知动作: {action}")
    return method(**_candidate_args(method, payload))


class Handler(BaseHTTPRequestHandler):
    """健康检查与风险通知闭环 API。"""

    def do_GET(self):
        if self.path == "/health":
            self._write_json(200, health_payload())
            return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/api":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._write_json(400, {"ok": False, "error": {"code": "bad_json",
                                                          "message": "请求体不是合法 JSON"}})
            return
        action = payload.pop("action", None)
        if not action:
            self._write_json(400, {"ok": False, "error": {"code": "missing_action",
                                                          "message": "缺少 action"}})
            return
        try:
            result = dispatch(action, payload)
        except DomainError as exc:
            status = 404 if exc.code == "not_found" else 409 if exc.code in (
                "already_confirmed", "already_approved", "emergency_already_sent",
                "duplicate_consent", "duplicate_window", "rule_version_conflict",
                "followup_closed", "task_not_reroutable",
            ) else 400
            self._write_json(status, {"ok": False, "error": {"code": exc.code,
                                                             "message": str(exc)}})
            return
        self._write_json(200, {"ok": True, "result": _jsonable(result)})

    def _write_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _jsonable(obj):
    """把领域返回值中的元组等结构转为 JSON 友好形式。"""
    if isinstance(obj, tuple):
        return list(obj)
    if isinstance(obj, list):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    return obj


def _sweep_loop(interval):
    while True:
        time.sleep(interval)
        try:
            get_service().sweep()
        except Exception:  # 扫表异常不得拖垮进程
            pass


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        # 领域模块关键路径自检
        svc = NotificationService()
        assert svc.verify_audit_chain()[0] is True
        print("基础检查通过")
        return

    interval = int(os.environ.get("RISK_SWEEP_SECONDS", "30"))
    if interval > 0:
        threading.Thread(target=_sweep_loop, args=(interval,), daemon=True).start()

    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
