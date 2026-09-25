"""服务契约测试：健康检查与风险通知闭环 HTTP API。"""

import json
import os
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from service import Handler, SERVICE_ID, SERVICE_NAME, health_payload, reset_service


class ServiceContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        # 每个用例使用独立的临时状态文件支撑的服务实例
        fd, self.state_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.state_path)
        os.environ["RISK_STATE_FILE"] = self.state_path
        reset_service()

    def tearDown(self):
        reset_service()
        os.environ.pop("RISK_STATE_FILE", None)
        if os.path.exists(self.state_path):
            os.unlink(self.state_path)

    def _post(self, payload):
        req = Request(
            f"{self.base_url}/api",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    # ---------------------------------------------------------- 基础契约

    def test_health_payload_has_stable_identity(self):
        self.assertEqual(
            health_payload(),
            {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME},
        )

    def test_health_endpoint_returns_json(self):
        with urlopen(f"{self.base_url}/health", timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "application/json")
            self.assertEqual(json.load(response), health_payload())

    def test_unknown_route_is_not_exposed(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(f"{self.base_url}/unknown", timeout=2)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    # ---------------------------------------------------------- API 契约

    def test_api_requires_action(self):
        status, body = self._post({})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "missing_action")

    def test_api_rejects_unknown_action(self):
        status, body = self._post({"action": "drop_tables"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "unknown_action")

    def test_api_rejects_bad_json(self):
        req = Request(f"{self.base_url}/api", data=b"{not-json",
                      headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as error:
            urlopen(req, timeout=2)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()

    def test_not_found_maps_to_404(self):
        status, body = self._post({"action": "review_status", "candidate_id": "nope"})
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_full_notification_loop_over_http(self):
        T0 = "2026-09-20T08:00:00+00:00"
        T1 = "2026-09-20T10:00:00+00:00"
        NOTICE = "2026-09-23T09:00:00+00:00"

        def ok(payload):
            status, body = self._post(payload)
            self.assertEqual(status, 200, body)
            self.assertTrue(body["ok"])
            return body["result"]

        ok({"action": "register_household",
            "household": {"household_id": "H1", "community_id": "C1"}})
        ok({"action": "register_member",
            "member": {"member_id": "A", "household_id": "H1"}})
        ok({"action": "add_consent", "record": {
            "consent_id": "cA", "member_id": "A", "version": "v1", "start": T0}})
        ok({"action": "add_contact", "record": {
            "contact_id": "pA", "member_id": "A", "channel": "sms", "start": T0}})
        ok({"action": "register_window", "window": {
            "window_id": "W1", "household_id": "H1", "start": T0, "end": T1,
            "checks": [{"name": "coverage", "passed": True}],
            "points": [{"member_id": "A", "metric": "pm25", "value": 150}]}})
        ok({"action": "register_rule", "rule": {
            "rule_id": "r1", "version": "1", "predicate": "max_threshold",
            "params": {"metric": "pm25", "threshold": 100},
            "risk_level": "urgent", "template_id": "tpl"}})
        candidates = ok({"action": "run_rules", "window_id": "W1"})
        cid = candidates[0]["candidate_id"]

        evidence = ok({"action": "resolve_recipients", "candidate_id": cid, "at": NOTICE})
        self.assertEqual(evidence["selected"][0]["recipient_member_id"], "A")

        ok({"action": "field_confirm", "candidate_id": cid, "researcher_id": "res1"})
        messages = ok({"action": "ethics_approve", "candidate_id": cid,
                       "officer_id": "eth1"})
        self.assertEqual(len(messages), 1)

        ok({"action": "deliver_due"})
        tasks = ok({"action": "notification_trace", "candidate_id": cid})["tasks"]
        task_id = tasks[0]["task_id"]
        token = tasks[0]["receipt_token"]
        receipt = ok({"action": "record_receipt", "task_id": task_id,
                      "receipt_status": "delivered", "token": token})
        self.assertEqual(receipt["status"], "delivered")

        # 小社区计数被抑制
        summary = ok({"action": "community_summary", "k": 5})
        self.assertTrue(summary["communities"]["C1"]["suppressed"])

        # 审计链完整可验证（元组在 JSON 中为数组）
        verified = ok({"action": "verify_audit_chain"})
        self.assertEqual(verified, [True, None])

    def test_duplicate_approval_conflicts(self):
        T0 = "2026-09-20T08:00:00+00:00"
        T1 = "2026-09-20T10:00:00+00:00"

        def ok(payload):
            status, body = self._post(payload)
            self.assertEqual(status, 200, body)
            return body["result"]

        ok({"action": "register_household",
            "household": {"household_id": "H1", "community_id": "C1"}})
        ok({"action": "register_member",
            "member": {"member_id": "A", "household_id": "H1"}})
        ok({"action": "add_consent", "record": {
            "consent_id": "cA", "member_id": "A", "version": "v1", "start": T0}})
        ok({"action": "add_contact", "record": {
            "contact_id": "pA", "member_id": "A", "channel": "sms", "start": T0}})
        ok({"action": "register_window", "window": {
            "window_id": "W1", "household_id": "H1", "start": T0, "end": T1,
            "checks": [{"name": "coverage", "passed": True}],
            "points": [{"member_id": "A", "metric": "pm25", "value": 150}]}})
        ok({"action": "register_rule", "rule": {
            "rule_id": "r1", "version": "1", "predicate": "max_threshold",
            "params": {"metric": "pm25", "threshold": 100},
            "risk_level": "urgent", "template_id": "tpl"}})
        cid = ok({"action": "run_rules", "window_id": "W1"})[0]["candidate_id"]
        ok({"action": "field_confirm", "candidate_id": cid, "researcher_id": "r"})
        status, body = self._post({"action": "field_confirm", "candidate_id": cid,
                                   "researcher_id": "r2"})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "already_confirmed")


if __name__ == "__main__":
    unittest.main()
