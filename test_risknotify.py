"""风险通知闭环的全量场景测试。

覆盖：质量门槛、双时点授权与最小接收人、双签、消息快照防泄露、
紧急先行与补齐复核、重排只动未完成任务、幂等与规则差异、
拒收/失败/回执冲突分流、升级时限重启续跑、社区汇总隐私门槛、
审计追溯与篡改检测，以及 HTTP 冒烟。
"""

import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

from risknotify import quality
from risknotify.auditlog import AuditLog, TamperError
from risknotify.service import (
    ConflictError,
    RiskNotificationService,
    ScriptedTransport,
)
from risknotify.timeutil import parse
from service import build_server

T = "2026-09-01T00:00Z"
EXP_START = "2026-09-20T10:00Z"
EXP_END = "2026-09-20T11:00Z"
NOTIFY = "2026-09-20T11:30Z"


def routine_window(window_id="w1", community="east", members=None, **overrides):
    window = {
        "window_id": window_id,
        "household_id": "H1",
        "community": community,
        "sensor_ids": ["s1", "s2"],
        "sensor_coverage": 0.99,
        "duration_min": 60,
        "qc_status": "passed",
        "start": EXP_START,
        "end": EXP_END,
        "avg_pm25": 40.0,
        "member_ids": members or ["mom", "dad", "kid1", "kid2"],
    }
    window.update(overrides)
    return window


def urgent_window(window_id="wu", members=None):
    return routine_window(window_id, members=members or ["kid1"], avg_pm25=300.0, duration_min=45)


def build_family(transport=None, consents=True, guardians=True, contacts=True, audit=None):
    """标准家庭：mom/dad 成人，kid1/kid2 儿童；mom 监护两孩，dad 仅监护 kid1。"""
    svc = RiskNotificationService(transport=transport or ScriptedTransport(), audit=audit)
    for mid, role in (("mom", "adult"), ("dad", "adult"),
                      ("kid1", "child"), ("kid2", "child")):
        svc.register_member(mid, "H1", role,
                            sensitive=["minor"] if role == "child" else [], at=T)
    if guardians:
        svc.add_guardianship("kid1", "mom", T, gid="g-mom-k1")
        svc.add_guardianship("kid2", "mom", T, gid="g-mom-k2")
        svc.add_guardianship("kid1", "dad", T, gid="g-dad-k1")
    if consents:
        svc.grant_consent("c-mom", "mom", ["self", "child:kid1", "child:kid2", "dependents"],
                          ["sms"], T)
        svc.grant_consent("c-dad", "dad", ["self", "child:kid1"], ["sms"], T)
    if contacts:
        svc.add_contact("ct-mom", "mom", "sms", "+100", T)
        svc.add_contact("ct-dad", "dad", "sms", "+200", T)
    return svc


def approve_and_dispatch(svc, cid, at=NOTIFY):
    svc.field_confirm(cid, at=at)
    svc.ethics_approve(cid, at=at)
    return svc.dispatch(cid, at=at)


def task_ids(svc, cid):
    return {t["task_id"]: t for t in svc.tasks.values() if t["candidate_id"] == cid}


# ========== 1. 质量门槛 ==========

class QualityGateTest(unittest.TestCase):
    def test_low_coverage_window_creates_no_candidate(self):
        svc = build_family()
        svc.ingest_window(routine_window("wq", sensor_coverage=0.5))
        result = svc.scan_window("wq", at=NOTIFY)
        self.assertFalse(result["created"])
        self.assertEqual(result["reason"], "quality_gate_failed")
        self.assertTrue(any("覆盖率" in r for r in result["reasons"]))
        self.assertEqual(svc.candidates, {})

    def test_missing_qc_and_short_duration_blocked(self):
        svc = build_family()
        svc.ingest_window(routine_window("wq2", qc_status="failed", duration_min=5))
        result = svc.scan_window("wq2", at=NOTIFY)
        self.assertEqual(result["reason"], "quality_gate_failed")
        self.assertEqual(len(result["reasons"]), 2)

    def test_below_threshold_is_no_risk(self):
        svc = build_family()
        svc.ingest_window(routine_window("wn", avg_pm25=10.0))
        result = svc.scan_window("wn", at=NOTIFY)
        self.assertEqual(result["reason"], "no_risk")

    def test_passed_window_creates_candidate(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        result = svc.scan_window("w1", at=NOTIFY)
        self.assertTrue(result["created"])
        self.assertEqual(svc.candidates[result["candidate_id"]]["level"], "routine")


# ========== 2/3. 双时点授权与最小接收人 ==========

class RecipientResolutionTest(unittest.TestCase):
    def test_minimal_recipients_covers_all_members(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        # mom 一人覆盖两孩；dad 本人必须由 dad 自己接收
        recipients = {svc.tasks[t]["recipient_id"]: svc.tasks[t] for t in dispatched["tasks"]}
        self.assertEqual(set(recipients), {"mom", "dad"})
        self.assertEqual(sorted(recipients["mom"]["covers"]), ["kid1", "kid2", "mom"])
        self.assertEqual(recipients["dad"]["covers"], ["dad"])

    def test_revoked_consent_at_notify_excludes_adult(self):
        svc = build_family()
        svc.revoke_consent("c-dad", end=EXP_START)  # 暴露时即已撤回
        svc.ingest_window(routine_window(members=["dad"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        self.assertEqual(dispatched["tasks"], [])
        self.assertEqual(dispatched["excluded"][0]["member_id"], "dad")
        self.assertIn("暴露发生时", dispatched["excluded"][0]["reason"])

    def test_consent_granted_after_exposure_insufficient(self):
        svc = RiskNotificationService(transport=ScriptedTransport())
        svc.register_member("preg", "H1", "pregnant_adult", sensitive=["pregnancy"], at=T)
        svc.grant_consent("c-late", "preg", ["self"], ["sms"], EXP_END)  # 暴露后才授权
        svc.add_contact("ct", "preg", "sms", "+9", T)
        svc.ingest_window(routine_window("w1", members=["preg"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        self.assertEqual(dispatched["tasks"], [])
        self.assertIn("暴露发生时", dispatched["excluded"][0]["reason"])

    def test_guardianship_ended_before_notify_excludes_guardian(self):
        svc = build_family()
        # mom 的监护保留；dad 对 kid1 的监护在暴露后、通知前终止，且 dad 不暴露
        svc.end_guardianship("g-dad-k1", end="2026-09-20T11:15Z")
        svc.ingest_window(routine_window(members=["kid1"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        recipients = {svc.tasks[t]["recipient_id"] for t in dispatched["tasks"]}
        self.assertEqual(recipients, {"mom"})  # 只通知 mom，dad 已失去授权

    def test_safety_preference_min_level_filters_routine(self):
        svc = build_family()
        svc.set_preference("dad", {"min_level": "urgent"}, start=T)
        svc.ingest_window(routine_window(members=["dad"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        self.assertEqual(dispatched["tasks"], [])
        self.assertIn("仅接收 urgent", dispatched["excluded"][0]["reason"])

    def test_do_not_contact_blocks_recipient(self):
        svc = build_family()
        svc.set_preference("mom", {"do_not_contact": True}, start=T)
        svc.ingest_window(routine_window(members=["kid1"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        # mom 拒收后 dad 仍是 kid1 监护人
        recipients = {svc.tasks[t]["recipient_id"] for t in dispatched["tasks"]}
        self.assertEqual(recipients, {"dad"})

    def test_channel_intersection_consent_preference_contact(self):
        svc = build_family()
        # dad 只同意 sms，偏好限定 email，且没有 email 联系方式 -> 不可达
        svc.set_preference("dad", {"allowed_channels": ["email"]}, start=T)
        svc.ingest_window(routine_window(members=["dad"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        self.assertEqual(dispatched["tasks"], [])

    def test_resolution_is_deterministic(self):
        from risknotify.recipients import resolve_recipients
        svc = build_family()
        window = routine_window()
        svc.ingest_window(window)
        first = resolve_recipients(svc.state, svc.state.get_window("w1"),
                                   window["member_ids"], "routine", NOTIFY)
        second = resolve_recipients(svc.state, svc.state.get_window("w1"),
                                    window["member_ids"], "routine", NOTIFY)
        self.assertEqual(first["recipients"], second["recipients"])


# ========== 4. 双签门槛 ==========

class ApprovalGateTest(unittest.TestCase):
    def test_dispatch_requires_both_signatures(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        with self.assertRaisesRegex(Exception, "现场"):
            svc.dispatch(cid, at=NOTIFY)
        svc.field_confirm(cid, at=NOTIFY)
        with self.assertRaisesRegex(Exception, "伦理"):
            svc.dispatch(cid, at=NOTIFY)
        svc.ethics_approve(cid, at=NOTIFY)
        self.assertTrue(svc.dispatch(cid, at=NOTIFY)["tasks"])

    def test_approvals_are_idempotent(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        again = svc.dispatch(cid, at=NOTIFY)
        self.assertEqual(again["tasks"], [])
        self.assertEqual(again["reason"], "all_members_already_notified")


# ========== 5. 消息快照 ==========

class SnapshotTest(unittest.TestCase):
    def test_snapshot_only_mentions_covered_members_and_is_hashed(self):
        svc = build_family()
        svc.ingest_window(routine_window(members=["kid1", "kid2"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        task = svc.tasks[dispatched["tasks"][0]]
        self.assertEqual(task["recipient_id"], "mom")
        self.assertEqual(sorted(task["snapshot"]["member_ids"]), ["kid1", "kid2"])
        self.assertEqual(len(task["snapshot"]["content_hash"]), 64)
        # 正文不含任何成员标识，只用关系称谓
        for other in ("kid1", "kid2", "dad"):
            self.assertNotIn(other, task["snapshot"]["body"])
        self.assertIn("孩子", task["snapshot"]["body"])

    def test_minimal_alert_omits_sensitive_detail(self):
        svc = build_family()
        svc.ingest_window(urgent_window(members=["kid1"]))
        cid = svc.scan_window("wu", at=NOTIFY)["candidate_id"]
        result = svc.emergency_send(cid, at=NOTIFY)
        task = svc.tasks[result["tasks"][0]]
        self.assertEqual(task["kind"], "minimal_alert")
        self.assertNotIn("300", task["snapshot"]["body"])
        self.assertNotIn("PM2.5", task["snapshot"]["body"])
        self.assertTrue(task["snapshot"]["body"].startswith("【紧急健康提示】"))


# ========== 6. 紧急先行 + 补齐复核 ==========

class EmergencyReviewTest(unittest.TestCase):
    def test_emergency_send_then_full_review(self):
        svc = build_family()
        svc.ingest_window(urgent_window(members=["kid1"]))
        cid = svc.scan_window("wu", at=NOTIFY)["candidate_id"]
        svc.emergency_send(cid, at=NOTIFY)
        self.assertEqual(svc.candidates[cid]["status"], "sent_pending_review")
        minimal = [t for t in task_ids(svc, cid).values() if t["kind"] == "minimal_alert"]
        self.assertTrue(minimal)
        # 补齐复核
        svc.field_confirm(cid, at="2026-09-20T12:00Z")
        svc.ethics_approve(cid, at="2026-09-20T12:05Z")
        svc.dispatch(cid, at="2026-09-20T12:10Z")
        svc.run_due_tasks(at="2026-09-20T12:11Z")
        kinds = {t["kind"]: t["status"] for t in task_ids(svc, cid).values()}
        self.assertEqual(kinds, {"minimal_alert": "delivered", "full": "delivered"})
        self.assertEqual(svc.candidates[cid]["status"], "completed")

    def test_non_urgent_cannot_emergency_send(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        with self.assertRaisesRegex(Exception, "紧急"):
            svc.emergency_send(cid, at=NOTIFY)


# ========== 7. 重排只动未完成任务，已送达不可改写 ==========

class ReplanTest(unittest.TestCase):
    def _setup_with_one_delivered_one_pending(self):
        transport = ScriptedTransport(invalid_addresses={"+200"})
        svc = build_family(transport)
        svc.ingest_window(routine_window(members=["mom", "dad"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        svc.run_due_tasks(at=NOTIFY)
        return svc, cid

    def test_invalid_contact_reroutes_but_keeps_delivered(self):
        svc, cid = self._setup_with_one_delivered_one_pending()
        statuses = [(t["recipient_id"], t["status"]) for t in task_ids(svc, cid).values()]
        # mom 送达；dad 号码失效 -> 原任务 superseded，无替代渠道 -> 不可达后续流程
        self.assertIn(("mom", "delivered"), statuses)
        dad_tasks = [t for t in task_ids(svc, cid).values() if t["recipient_id"] == "dad"]
        self.assertTrue(dad_tasks and all(t["status"] == "superseded" for t in dad_tasks))
        # mom 已送达快照内容未被改写
        mom_task = next(t for t in task_ids(svc, cid).values() if t["recipient_id"] == "mom")
        self.assertEqual(mom_task["status"], "delivered")
        unreachable = [f for f in svc.followups if f["type"] == "unreachable_member"]
        self.assertTrue(any(e["member_id"] == "dad" for f in unreachable for e in f["excluded"]))

    def test_invalid_contact_falls_back_to_alternate_recipient(self):
        # 两孩暴露使 mom（覆盖两人）成为首选；其号码失效后 kid1 改由 dad，kid2 不可达
        svc = build_family(ScriptedTransport(invalid_addresses={"+100"}))
        svc.ingest_window(routine_window(members=["kid1", "kid2"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        svc.run_due_tasks(at=NOTIFY)        # mom 发送失败、停用号码、重排
        svc.run_due_tasks(at=NOTIFY)        # 改道后的 dad 任务发送
        delivered = [t for t in task_ids(svc, cid).values() if t["status"] == "delivered"]
        self.assertEqual([(t["recipient_id"], t["covers"]) for t in delivered],
                         [("dad", ["kid1"])])
        superseded = [t for t in task_ids(svc, cid).values() if t["status"] == "superseded"]
        self.assertEqual(len(superseded), 1)
        unreachable = [f for f in svc.followups if f["type"] == "unreachable_member"]
        self.assertTrue(any(e["member_id"] == "kid2" for f in unreachable for e in f["excluded"]))

    def test_consent_revoke_replans_open_task_only(self):
        svc = build_family(ScriptedTransport())
        svc.ingest_window(routine_window(members=["mom", "dad"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        # 先送达 mom，dad 仍待发
        svc.attempt_delivery(next(t["task_id"] for t in task_ids(svc, cid).values()
                                  if t["recipient_id"] == "mom"), at=NOTIFY)
        # dad 撤回同意 -> 待发任务被取代，不产生新通知
        svc.revoke_consent("c-dad", end="2026-09-20T11:45Z")
        dad_tasks = [t for t in task_ids(svc, cid).values() if t["recipient_id"] == "dad"]
        self.assertTrue(all(t["status"] == "superseded" for t in dad_tasks))
        mom = next(t for t in task_ids(svc, cid).values() if t["recipient_id"] == "mom")
        self.assertEqual(mom["status"], "delivered")

    def test_relocation_replans_open_tasks(self):
        svc = build_family(ScriptedTransport())
        svc.ingest_window(routine_window(members=["mom"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        before = next(iter(task_ids(svc, cid).values()))
        self.assertEqual(before["status"], "pending")
        svc.relocate_household("H1", "H9", at="2026-09-20T12:00Z")
        self.assertEqual(before["status"], "superseded")
        new_tasks = [t for t in task_ids(svc, cid).values() if t["status"] == "pending"]
        self.assertEqual(len(new_tasks), 1)
        self.assertEqual(svc.state.household_of("mom", "2026-09-20T12:01Z"), "H9")

    def test_replan_does_not_reset_deadline(self):
        svc = build_family(ScriptedTransport())
        svc.ingest_window(routine_window(members=["mom"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        first = next(iter(task_ids(svc, cid).values()))
        original_deadline = first["deadline_at"]
        svc.relocate_household("H1", "H9", at="2026-09-20T12:00Z")
        new_task = next(t for t in task_ids(svc, cid).values() if t["status"] == "pending")
        self.assertEqual(new_task["deadline_at"], original_deadline)


# ========== 8. 幂等与规则版本差异 ==========

class DedupAndRuleDiffTest(unittest.TestCase):
    def test_same_rule_rescan_is_idempotent(self):
        svc = build_family()
        svc.ingest_window(routine_window())
        first = svc.scan_window("w1", at=NOTIFY)
        second = svc.scan_window("w1", at="2026-09-20T12:00Z")
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["candidate_id"], second["candidate_id"])

    def test_new_rule_version_creates_diffed_candidate(self):
        quality.RULES["r-test"] = {
            "rule_version": "r-test", "label": "试验规则", "threshold": 10,
            "min_duration_min": 20, "level_thresholds": {"urgent": 200, "routine": 10},
        }
        try:
            svc = build_family()
            svc.ingest_window(routine_window())
            cid1 = svc.scan_window("w1", rule_version="r1", at=NOTIFY)["candidate_id"]
            result = svc.scan_window("w1", rule_version="r-test", at="2026-09-20T12:00Z")
            self.assertTrue(result["created"])
            self.assertEqual(result["diff_from"], cid1)
            fields = {d["field"]: (d["old"], d["new"]) for d in result["diff"]}
            self.assertEqual(fields["threshold"], (35, 10))
        finally:
            del quality.RULES["r-test"]


# ========== 9. 拒收 / 失败 / 回执冲突 ==========

class OutcomeFlowTest(unittest.TestCase):
    def test_opt_out_terminates_and_replans_to_other_guardian(self):
        # 两孩同时暴露：mom 覆盖两人故为最小接收人；拒收后 kid1 改由 dad，kid2 不可达
        svc = build_family(ScriptedTransport())
        svc.ingest_window(routine_window(members=["kid1", "kid2"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        dispatched = approve_and_dispatch(svc, cid)
        first = svc.tasks[dispatched["tasks"][0]]
        self.assertEqual(first["recipient_id"], "mom")
        svc.opt_out(first["task_id"], at="2026-09-20T11:31Z")
        self.assertEqual(first["status"], "optout")
        self.assertTrue(any(f["type"] == "recipient_optout" for f in svc.followups))
        # 重排后：kid1 由 dad 接收并送达；kid2 无其他监护人进入不可达流程
        svc.run_due_tasks(at="2026-09-20T11:32Z")
        dad_task = next(t for t in task_ids(svc, cid).values()
                        if t["recipient_id"] == "dad" and t["status"] == "delivered")
        self.assertEqual(dad_task["covers"], ["kid1"])
        unreachable = [f for f in svc.followups if f["type"] == "unreachable_member"]
        self.assertTrue(any(e["member_id"] == "kid2" for f in unreachable for e in f["excluded"]))
        # mom 已被拒收，不再收到新任务
        self.assertFalse(any(
            t["recipient_id"] == "mom" and t["status"] == "pending"
            for t in task_ids(svc, cid).values()))

    def test_persistent_failure_retries_then_followup(self):
        svc = build_family(ScriptedTransport(fail_addresses={"+100"}))
        svc.ingest_window(routine_window(members=["mom"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        tid = approve_and_dispatch(svc, cid)["tasks"][0]
        at = parse(NOTIFY)
        from risknotify.service import RETRY_BACKOFF, MAX_ATTEMPTS
        for attempt in range(1, MAX_ATTEMPTS):
            at = at + RETRY_BACKOFF
            result = svc.run_due_tasks(at=at.isoformat().replace("+00:00", "Z"))
            self.assertEqual(result[0]["status"], "retry_scheduled")
        at = at + RETRY_BACKOFF
        result = svc.run_due_tasks(at=at.isoformat().replace("+00:00", "Z"))
        self.assertEqual(result[0]["status"], "terminal_failure")
        self.assertEqual(svc.tasks[tid]["attempts"], MAX_ATTEMPTS)
        self.assertTrue(any(f["type"] == "delivery_failed" for f in svc.followups))

    def test_receipt_conflict_is_frozen_and_queued(self):
        svc = build_family()
        svc.ingest_window(routine_window(members=["mom"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        tid = approve_and_dispatch(svc, cid)["tasks"][0]
        svc.run_due_tasks(at=NOTIFY)
        svc.report_receipt_conflict(tid, "供应商称退信，接收人称已读", at="2026-09-20T12:00Z")
        self.assertEqual(svc.tasks[tid]["status"], "conflict")
        self.assertTrue(any(f["type"] == "receipt_conflict" for f in svc.followups))

    def test_confirm_before_delivery_is_conflict(self):
        svc = build_family()
        svc.ingest_window(routine_window(members=["mom"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        tid = approve_and_dispatch(svc, cid)["tasks"][0]
        with self.assertRaises(ConflictError):
            svc.confirm_receipt(tid, at=NOTIFY)


# ========== 10. 升级时限与重启续跑 ==========

class TimerRestartTest(unittest.TestCase):
    def test_pending_delivery_and_escalation_survive_restart(self):
        store = tempfile.mkdtemp()
        path = os.path.join(store, "audit.log.jsonl")

        def open_service(transport=None):
            return RiskNotificationService(audit=AuditLog(path),
                                           transport=transport or ScriptedTransport())

        svc = build_family(ScriptedTransport(fail_addresses={"+100"}), audit=AuditLog(path))
        svc.ingest_window(urgent_window(members=["mom"]))
        cid = svc.scan_window("wu", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        tid = list(task_ids(svc, cid))[0]
        first_deadline = svc.tasks[tid]["deadline_at"]

        # 重启：待投递任务仍在，时限继续推进
        svc2 = open_service()
        self.assertEqual(svc2.tasks[tid]["status"], "pending")
        esc1 = svc2.advance_timers(at="2026-09-20T14:00Z")  # 超过 2h 紧急时限
        self.assertEqual(esc1[0]["escalation"], 1)
        self.assertEqual(svc2.tasks[tid]["deadline_at"], first_deadline)

        # 再次重启继续升级到上限并进入后续流程
        svc3 = open_service()
        esc2 = svc3.advance_timers(at="2026-09-20T15:00Z")
        self.assertEqual(esc2[0]["escalation"], 2)
        self.assertTrue(any(f["type"] == "escalation_exhausted" for f in svc3.followups))


# ========== 11. 社区汇总隐私门槛 ==========

class CommunitySummaryTest(unittest.TestCase):
    def test_small_communities_suppressed(self):
        svc = build_family()
        # east 社区 3 个窗口各通知 1 人 -> 可见；north 1 人 -> 抑制
        for i in range(3):
            wid = f"we{i}"
            svc.ingest_window(routine_window(wid, community="east", members=["mom"]))
            cid = svc.scan_window(wid, at=NOTIFY)["candidate_id"]
            tid = approve_and_dispatch(svc, cid)["tasks"][0]
            svc.run_due_tasks(at=NOTIFY)
            svc.confirm_receipt(tid, at=NOTIFY)
        svc.ingest_window(routine_window("wn1", community="north", members=["mom"]))
        cid = svc.scan_window("wn1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        svc.run_due_tasks(at=NOTIFY)
        summary = svc.community_summary()
        self.assertEqual(summary["notifications_delivered"], {"east": 3})
        self.assertEqual(summary["suppressed_communities"], ["north"])
        self.assertEqual(summary["threshold"], 3)


# ========== 12. 审计追溯与篡改检测 ==========

class AuditTraceTest(unittest.TestCase):
    def test_trace_covers_quality_authorization_content_and_confirmation(self):
        svc = build_family()
        # 两孩暴露使 mom 成为首选接收人，便于核验其本人/监护双重授权依据
        svc.ingest_window(routine_window(members=["kid1", "kid2"]))
        cid = svc.scan_window("w1", at=NOTIFY)["candidate_id"]
        approve_and_dispatch(svc, cid)
        svc.run_due_tasks(at=NOTIFY)
        tid = next(iter(task_ids(svc, cid)))
        svc.confirm_receipt(tid, at="2026-09-20T12:00Z")
        trace = svc.trace(cid)
        self.assertTrue(trace["window"]["quality"]["passed"])
        self.assertEqual(trace["rule"]["version"], "r1")
        self.assertIsNotNone(trace["approvals"]["field"])
        self.assertIsNotNone(trace["approvals"]["ethics"])
        mom_auth = trace["recipient_selection"]["mom"]
        self.assertIn("c-mom", mom_auth["consent_ids_used"])
        self.assertEqual(mom_auth["guardianship_ids_used"], ["g-mom-k1", "g-mom-k2"])
        self.assertEqual(mom_auth["contacts_used"], ["ct-mom"])
        self.assertEqual(trace["messages"][0]["status"], "confirmed")
        self.assertEqual(len(trace["messages"][0]["content_hash"]), 64)
        actions = {e["action"] for e in trace["timeline"]}
        self.assertIn("window_ingested", actions)
        self.assertIn("consent_granted", actions)
        self.assertIn("guardianship_added", actions)
        self.assertIn("ethics_approved", actions)
        self.assertIn("task_confirmed", actions)
        self.assertEqual(trace["final_status"], "completed")

    def test_tampered_log_is_detected_on_load(self):
        store = tempfile.mkdtemp()
        path = os.path.join(store, "audit.log.jsonl")
        svc = build_family(audit=AuditLog(path))
        svc.ingest_window(routine_window())
        svc.scan_window("w1", at=NOTIFY)
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        record = json.loads(lines[3])
        record["payload"] = {"forged": True}
        lines[3] = json.dumps(record, ensure_ascii=False)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        with self.assertRaises(TamperError):
            AuditLog(path)


# ========== 13. HTTP 冒烟 ==========

class HttpApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.server, cls.api = build_server(0, store_dir=cls.tmp)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _post(self, path, payload):
        req = Request(self.base + path, data=json.dumps(payload).encode("utf-8"),
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=3) as response:
            return response.status, json.load(response)

    def _get(self, path):
        with urlopen(self.base + path, timeout=3) as response:
            return response.status, json.load(response)

    def test_full_flow_over_http(self):
        def cmd(command, **args):
            status, body = self._post("/api/commands",
                                      {"command": command, "args": args, "actor": "test"})
            self.assertEqual(status, 200, body)
            return body["result"]

        cmd("register_member", member_id="m1", household_id="H1", role="adult", at=T)
        cmd("grant_consent", consent_id="c1", member_id="m1", scope=["self"],
            channels=["sms"], start=T)
        cmd("add_contact", contact_id="ct1", person_id="m1", channel="sms",
            address="+1", start=T)
        window = routine_window("wh", members=["m1"])
        cmd("ingest_window", window=window)
        cid = cmd("scan_window", window_id="wh", at=NOTIFY)["candidate_id"]
        cmd("field_confirm", candidate_id=cid, at=NOTIFY)
        cmd("ethics_approve", candidate_id=cid, at=NOTIFY)
        cmd("dispatch", candidate_id=cid, at=NOTIFY)
        cmd("run_due_tasks", at=NOTIFY)
        status, trace = self._get(f"/api/trace?candidate_id={cid}")
        self.assertEqual(status, 200)
        self.assertEqual(trace["final_status"], "completed")
        status, verify = self._get("/api/verify")
        self.assertTrue(verify["ok"])
        status, summary = self._get("/api/summary")
        self.assertEqual(status, 200)
        self.assertIn("threshold", summary)


if __name__ == "__main__":
    unittest.main()
