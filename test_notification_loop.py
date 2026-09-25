"""风险通知闭环领域服务测试。

覆盖需求要点：质量门槛、版本化候选与差异、双时点授权解析与最小接收人、
两级复核与紧急先发、成员隔离消息、投递/重排/升级/重启续跑、
拒收/失败/回执冲突后续、隐私门槛汇总与端到端审计。
"""

import os
import tempfile
import unittest
from datetime import datetime

from notification_loop import (
    DEFAULT_K,
    DomainError,
    NotificationService,
    REVIEW_SLA_SECONDS,
    TASK_CANCELLED,
    TASK_DELIVERED,
    TASK_FAILED,
    TASK_PENDING,
    TASK_REFUSED,
    TASK_SENT,
    TASK_SUPERSEDED,
)

T0 = "2026-09-20T08:00:00+00:00"
T1 = "2026-09-20T10:00:00+00:00"
NOTICE = "2026-09-23T09:00:00+00:00"
LATER = "2026-09-23T12:00:00+00:00"


class FixedClock:
    def __init__(self, value=NOTICE):
        self.value = value

    def __call__(self):
        return datetime.fromisoformat(self.value)

    def set(self, value):
        self.value = value


def make_service(path=None, clock=None):
    return NotificationService(path=path, clock=clock or FixedClock())


def seed_household(svc, members=("A",), children=(), community="C1"):
    svc.register_household({"household_id": "H1", "community_id": community})
    for mid in members + children:
        svc.register_member({"member_id": mid, "household_id": "H1",
                             "is_child": mid in children})


def seed_adult(svc, mid="A", community="C1", consent_scope=None):
    svc.register_household({"household_id": "H1", "community_id": community})
    svc.register_member({"member_id": mid, "household_id": "H1", "pregnant": True})
    scope = consent_scope or {"risk_notification": True}
    svc.add_consent({"consent_id": f"c{mid}", "member_id": mid,
                     "version": "v1", "start": T0, "scope": scope})
    svc.add_contact({"contact_id": f"p{mid}", "member_id": mid,
                     "channel": "sms", "start": T0, "priority": 1})


def seed_window(svc, passed=True, wid="W1", household="H1", values=(("A", 150),),
                metric="pm25"):
    checks = [{"name": "coverage", "passed": passed}]
    if passed:
        checks.append({"name": "calibration", "passed": True})
    svc.register_window({
        "window_id": wid, "household_id": household, "start": T0, "end": T1,
        "checks": checks,
        "points": [{"member_id": m, "metric": metric, "value": v} for m, v in values],
    })


def seed_rule(svc, level="urgent", threshold=100, metric="pm25", version="1",
              rule_id="r1", template="tpl"):
    svc.register_rule({"rule_id": rule_id, "version": version,
                       "predicate": "max_threshold",
                       "params": {"metric": metric, "threshold": threshold},
                       "risk_level": level, "template_id": template})


def approve_candidate(svc, cid, researcher="res1", officer="eth1"):
    svc.field_confirm(cid, researcher)
    return svc.ethics_approve(cid, officer)


class QualityGateTest(unittest.TestCase):
    def test_rules_never_run_on_unqualified_data(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc, passed=False, values=(("A", 900),))
        seed_rule(svc)
        self.assertEqual(svc.run_rules("W1"), [])
        self.assertFalse(svc.quality["W1"]["passed"])

    def test_window_without_checks_does_not_pass(self):
        svc = make_service()
        seed_adult(svc)
        svc.register_window({"window_id": "W1", "household_id": "H1",
                             "start": T0, "end": T1, "checks": [],
                             "points": [{"member_id": "A", "metric": "pm25", "value": 9}]})
        seed_rule(svc)
        self.assertEqual(svc.run_rules("W1"), [])

    def test_quality_fingerprint_recorded_on_candidate(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        self.assertEqual(svc.candidates[cid]["quality_fingerprint"],
                         svc.quality["W1"]["fingerprint"])


class CandidateRuleVersionTest(unittest.TestCase):
    def _approved_candidate(self, svc):
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        return cid

    def test_rerun_same_rule_is_idempotent(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        first = svc.run_rules("W1")[0]
        second = svc.run_rules("W1")[0]
        self.assertFalse(first["deduped"])
        self.assertTrue(second["deduped"])
        self.assertEqual(first["candidate_id"], second["candidate_id"])

    def test_registered_rule_version_is_immutable(self):
        svc = make_service()
        seed_rule(svc, threshold=100)
        with self.assertRaises(DomainError) as ctx:
            seed_rule(svc, threshold=200)  # 同版本不同内容
        self.assertEqual(ctx.exception.code, "rule_version_conflict")

    def test_rule_change_creates_new_candidate_with_diff(self):
        svc = make_service()
        cid1 = self._approved_candidate(svc)
        svc.deliver_due()
        # 阈值降低：仍是同一成员 -> diff 记录版本变化；内容不变且已送达 -> 不重发
        seed_rule(svc, threshold=120, version="2")
        results = svc.run_rules("W1")
        self.assertEqual(len(results), 1)
        cid2 = results[0]["candidate_id"]
        self.assertNotEqual(cid1, cid2)
        self.assertEqual(results[0]["diff"]["rule_version_from"], "1")
        self.assertEqual(results[0]["diff"]["rule_version_to"], "2")
        approve_candidate(svc, cid2)
        self.assertEqual(svc.candidates[cid1]["diff"], None)

    def test_rule_change_level_change_is_flagged_in_diff(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc, level="advisory")
        svc.run_rules("W1")
        seed_rule(svc, level="emergency", version="2")
        diff = svc.run_rules("W1")[0]["diff"]
        self.assertTrue(diff["level_changed"])


class RecipientResolutionTest(unittest.TestCase):
    def test_consent_withdrawn_before_notice_excludes_recipient(self):
        svc = make_service()
        seed_adult(svc)
        svc.add_consent({"consent_id": "cA2", "member_id": "A", "version": "v2",
                         "start": "2026-09-22T00:00:00+00:00",
                         "scope": {"risk_notification": False}})
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid, at=NOTICE)
        self.assertEqual(evidence["selected"], [])
        self.assertIn("consent_scope",
                      evidence["considerations"][0]["exclusion_reasons"])

    def test_consent_missing_at_exposure_blocks_notice(self):
        svc = make_service()
        # 同意在暴露窗口之后才签署
        svc.register_household({"household_id": "H1", "community_id": "C1"})
        svc.register_member({"member_id": "A", "household_id": "H1"})
        svc.add_consent({"consent_id": "cA", "member_id": "A", "version": "v1",
                         "start": "2026-09-21T00:00:00+00:00"})
        svc.add_contact({"contact_id": "pA", "member_id": "A", "channel": "sms",
                         "start": T0})
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid, at=NOTICE)
        self.assertEqual(evidence["selected"], [])

    def test_child_uses_single_minimal_guardian(self):
        svc = make_service()
        seed_household(svc, members=("G1", "G2"), children=("B",))
        svc.add_consent({"consent_id": "cB", "member_id": "B", "version": "v1",
                         "start": T0})
        for g in ("G1", "G2"):
            svc.add_consent({"consent_id": f"c{g}", "member_id": g,
                             "version": "v1", "start": T0})
            svc.add_contact({"contact_id": f"p{g}", "member_id": g,
                             "channel": "sms", "start": T0})
            svc.add_guardianship({"id": f"gr{g}", "guardian_member_id": g,
                                  "child_member_id": "B", "start": T0})
        seed_window(svc, values=(("B", 200),))
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid, at=NOTICE)
        self.assertEqual(len(evidence["selected"]), 1)
        chosen = evidence["selected"][0]["recipient_member_id"]
        other = next(c for c in evidence["considerations"]
                     if c["recipient_member_id"] != chosen and c["role"] != "none")
        self.assertFalse(other["included"])
        self.assertIn("minimized_single_guardian", other["exclusion_reasons"])

    def test_guardian_change_between_exposure_and_notice_is_fail_safe(self):
        svc = make_service()
        seed_household(svc, members=("G1", "G2"), children=("B",))
        svc.add_consent({"consent_id": "cB", "member_id": "B", "version": "v1",
                         "start": T0})
        svc.add_consent({"consent_id": "cG1", "member_id": "G1", "version": "v1",
                         "start": T0})
        svc.add_consent({"consent_id": "cG2", "member_id": "G2", "version": "v1",
                         "start": "2026-09-22T00:00:00+00:00"})
        for g in ("G1", "G2"):
            svc.add_contact({"contact_id": f"p{g}", "member_id": g,
                             "channel": "sms", "start": T0})
        svc.add_guardianship({"id": "gr1", "guardian_member_id": "G1",
                              "child_member_id": "B", "start": T0,
                              "end": "2026-09-22T00:00:00+00:00"})
        svc.add_guardianship({"id": "gr2", "guardian_member_id": "G2",
                              "child_member_id": "B",
                              "start": "2026-09-22T00:00:00+00:00"})
        seed_window(svc, values=(("B", 200),))
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid, at=NOTICE)
        self.assertEqual(evidence["selected"], [])  # 无人在两时点都有效
        g1 = next(c for c in evidence["considerations"]
                  if c["recipient_member_id"] == "G1")
        self.assertIn("relationship_not_valid_at_both_times",
                      g1["exclusion_reasons"])

    def test_opt_out_and_channel_preference_exclude(self):
        svc = make_service()
        seed_adult(svc)
        svc.add_preference({"member_id": "A", "start": "2026-09-21T00:00:00+00:00",
                            "allowed_channels": ["voice"]})  # 只有 sms 联系方式
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid, at=NOTICE)
        self.assertEqual(evidence["selected"], [])
        self.assertIn("no_available_channel",
                      evidence["considerations"][0]["exclusion_reasons"])


class ReviewWorkflowTest(unittest.TestCase):
    def test_formal_message_requires_both_reviews(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        svc.field_confirm(cid, "res1")
        with self.assertRaises(DomainError) as ctx:
            svc._issue_messages(cid)
        self.assertEqual(ctx.exception.code, "review_incomplete")

    def test_approvals_cannot_be_rewritten(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        svc.field_confirm(cid, "res1")
        svc.ethics_approve(cid, "eth1")
        with self.assertRaises(DomainError):
            svc.field_confirm(cid, "res2")
        with self.assertRaises(DomainError):
            svc.ethics_approve(cid, "eth2")

    def test_ethics_can_set_lower_level(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc, level="urgent")
        cid = svc.run_rules("W1")[0]["candidate_id"]
        svc.field_confirm(cid, "res1")
        messages = svc.ethics_approve(cid, "eth1", level="advisory")
        self.assertEqual(messages[0]["risk_level"], "advisory")

    def test_messages_are_member_isolated(self):
        svc = make_service()
        seed_household(svc, members=("A", "G"), children=("B",))
        for mid in ("A", "B", "G"):
            svc.add_consent({"consent_id": f"c{mid}", "member_id": mid,
                             "version": "v1", "start": T0})
            svc.add_contact({"contact_id": f"p{mid}", "member_id": mid,
                             "channel": "sms", "start": T0})
        svc.add_guardianship({"id": "gr", "guardian_member_id": "G",
                              "child_member_id": "B", "start": T0})
        seed_window(svc, values=(("A", 150), ("B", 200)))
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        messages = approve_candidate(svc, cid)
        a_body = next(m["body"] for m in messages if m["recipient_member_id"] == "A")
        g_body = next(m["body"] for m in messages if m["recipient_member_id"] == "G")
        self.assertNotIn("B", a_body)
        self.assertNotIn("G", a_body)
        self.assertNotIn("B", g_body)      # 不点名儿童
        self.assertNotIn("A", g_body)      # 不泄露其他成员
        self.assertIn("儿童", g_body)


class EmergencyPathTest(unittest.TestCase):
    def _emergency(self, svc):
        seed_adult(svc)
        seed_window(svc, values=(("A", 80),), metric="co")
        seed_rule(svc, level="emergency", threshold=50, metric="co", template="etpl")
        cid = svc.run_rules("W1")[0]["candidate_id"]
        return cid

    def test_emergency_sends_minimal_notice_before_review(self):
        svc = make_service()
        cid = self._emergency(svc)
        issued = svc.send_emergency_notice(cid, "field01")
        self.assertEqual(len(issued), 1)
        self.assertTrue(issued[0]["provisional"])
        self.assertNotIn("孕妇", issued[0]["body"])  # 不泄露敏感标签
        status = svc.review_status(cid)
        self.assertFalse(status["completed"])

    def test_emergency_requires_emergency_level(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc, level="urgent")
        cid = svc.run_rules("W1")[0]["candidate_id"]
        with self.assertRaises(DomainError) as ctx:
            svc.send_emergency_notice(cid, "f")
        self.assertEqual(ctx.exception.code, "not_emergency")

    def test_review_sla_escalates_then_completes(self):
        clock = FixedClock()
        svc = make_service(clock=clock)
        cid = self._emergency(svc)
        svc.send_emergency_notice(cid, "field01")
        review = svc.reviews[cid]["emergency"]
        # SLA 之内不升级
        self.assertEqual(svc.sweep()["escalations"], [])
        clock.set(review["review_due_at"])
        escalations = svc.sweep()["escalations"]
        self.assertEqual(len(escalations), 1)
        self.assertEqual(escalations[0]["kind"], "review_overdue")
        # 补齐复核
        approve_candidate(svc, cid)
        self.assertTrue(svc.review_status(cid)["completed"])
        # 正式消息不同于紧急提示并链接之
        provisional = next(m for m in svc.messages.values() if m["provisional"])
        formal = next(m for m in svc.messages.values() if not m["provisional"])
        self.assertEqual(formal["follows_message_id"], provisional["message_id"])
        self.assertNotEqual(formal["body"], provisional["body"])


class DeliveryAndFollowupTest(unittest.TestCase):
    def _ready_task(self, svc, failing=False):
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        if failing:
            svc.transport = lambda contact, message: {"ok": False, "error": "down"}
        return cid

    def test_success_path_sent_then_delivered(self):
        svc = make_service()
        self._ready_task(svc)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        self.assertEqual(task["status"], TASK_SENT)
        result = svc.record_receipt(task["task_id"], "delivered",
                                    token=task["receipt_token"])
        self.assertEqual(result["status"], TASK_DELIVERED)
        # 重复回执幂等
        again = svc.record_receipt(task["task_id"], "delivered",
                                   token=task["receipt_token"])
        self.assertTrue(again.get("idempotent"))

    def test_receipt_token_required(self):
        svc = make_service()
        self._ready_task(svc)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        with self.assertRaises(DomainError) as ctx:
            svc.record_receipt(task["task_id"], "delivered", token="forged")
        self.assertEqual(ctx.exception.code, "bad_receipt_token")

    def test_failure_retries_with_backoff_then_followup(self):
        clock = FixedClock()
        svc = make_service(clock=clock)
        self._ready_task(svc, failing=True)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        self.assertEqual(task["status"], TASK_PENDING)
        self.assertEqual(task["attempts"], 1)
        # 退避未到不重试
        svc.deliver_due()
        self.assertEqual(task["attempts"], 1)
        clock.set("2026-09-23T09:01:00+00:00")
        svc.deliver_due()
        self.assertEqual(task["attempts"], 2)
        clock.set("2026-09-23T09:03:00+00:00")
        svc.deliver_due()
        self.assertEqual(task["status"], TASK_FAILED)
        self.assertTrue(any(f["kind"] == "failure" for f in svc.followups))

    def test_reroute_failed_task_to_backup_contact(self):
        clock = FixedClock()
        svc = make_service(clock=clock)
        self._ready_task(svc, failing=True)
        svc.add_contact({"contact_id": "pA2", "member_id": "A", "channel": "voice",
                         "start": T0, "priority": 2})
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        self.assertEqual(task["attempts"], 1)
        clock.set("2026-09-23T09:01:00+00:00")
        svc.deliver_due()
        self.assertEqual(task["attempts"], 2)
        clock.set("2026-09-23T09:05:00+00:00")
        svc.deliver_due()
        self.assertEqual(task["status"], TASK_FAILED)
        svc.transport = None
        svc.reroute_task(task["task_id"])
        self.assertEqual(task["contact_id"], "pA2")
        svc.deliver_due()
        self.assertEqual(task["status"], TASK_SENT)

    def test_refusal_after_sent_freezes_content(self):
        svc = make_service()
        self._ready_task(svc)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        svc.record_receipt(task["task_id"], "refused", token=task["receipt_token"])
        self.assertEqual(task["status"], TASK_REFUSED)
        message = svc.messages[task["message_id"]]
        snapshot = message["body"]
        # 已拒收（已送达）的内容不可改写
        svc.invalidate_contact("pA", at=NOTICE)
        self.assertEqual(svc.messages[task["message_id"]]["body"], snapshot)
        self.assertEqual(task["status"], TASK_REFUSED)

    def test_refusal_before_delivery_cancels_pending(self):
        svc = make_service()
        self._ready_task(svc)
        task = list(svc.tasks.values())[0]
        result = svc.record_receipt(task["task_id"], "refused",
                                    token=task["receipt_token"])
        self.assertEqual(result["status"], TASK_CANCELLED)
        self.assertTrue(any(f["kind"] == "refusal" for f in svc.followups))

    def test_receipt_conflict_enters_reconciliation(self):
        svc = make_service()
        self._ready_task(svc)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        svc.record_receipt(task["task_id"], "delivered", token=task["receipt_token"])
        conflict = svc.record_receipt(task["task_id"], "refused")
        self.assertTrue(conflict["conflict"])
        self.assertTrue(any(f["kind"] == "receipt_conflict" and f["status"] == "open"
                            for f in svc.followups))
        svc.reconcile_receipt(task["task_id"], "delivered", "ethics2")
        self.assertEqual(task["status"], TASK_DELIVERED)
        self.assertFalse(any(f["kind"] == "receipt_conflict" and f["status"] == "open"
                             for f in svc.followups))

    def test_refusal_followup_registers_opt_out(self):
        svc = make_service()
        self._ready_task(svc)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        svc.record_receipt(task["task_id"], "refused", token=task["receipt_token"])
        followup = next(f for f in svc.followups if f["kind"] == "refusal")
        svc.resolve_followup(followup["followup_id"],
                             {"register_opt_out": True}, "staff")
        # 新候选解析时 A 被 opt_out 排除
        seed_rule(svc, level="emergency", threshold=10, version="2",
                  rule_id="r2", template="tpl2")
        cid2 = svc.run_rules("W1")[0]["candidate_id"]
        evidence = svc.resolve_recipients(cid2)
        self.assertEqual(evidence["selected"], [])

    def test_opt_out_stops_other_pending_tasks_for_member(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc, values=(("A", 150),))
        seed_rule(svc)
        cid1 = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid1)
        first_task = list(svc.tasks.values())[0]
        # 第一条先送达
        svc.deliver_due()
        self.assertEqual(first_task["status"], TASK_SENT)
        # 第二个更紧急规则形成另一条待发任务（尚未发出）
        seed_rule(svc, level="emergency", threshold=10, version="1",
                  rule_id="r2", template="tpl2")
        cid2 = next(r["candidate_id"] for r in svc.run_rules("W1") if not r.get("deduped"))
        approve_candidate(svc, cid2)
        second_task = next(t for t in svc.tasks.values()
                           if t["candidate_id"] == cid2)
        self.assertEqual(second_task["status"], TASK_PENDING)
        # 第一条被拒收并登记 opt-out
        svc.record_receipt(first_task["task_id"], "refused",
                           token=first_task["receipt_token"])
        followup = next(f for f in svc.followups if f["kind"] == "refusal")
        svc.resolve_followup(followup["followup_id"],
                             {"register_opt_out": True}, "staff")
        # 第二条未发出的任务立即作废，且不被投递
        self.assertEqual(second_task["status"], TASK_SUPERSEDED)


class RearrangementTest(unittest.TestCase):
    def _two_member_setup(self, svc):
        seed_household(svc, members=("A",))
        svc.add_consent({"consent_id": "cA", "member_id": "A", "version": "v1",
                         "start": T0})
        svc.add_contact({"contact_id": "pA1", "member_id": "A", "channel": "sms",
                         "start": T0, "priority": 1})
        svc.add_contact({"contact_id": "pA2", "member_id": "A", "channel": "voice",
                         "start": T0, "priority": 2})
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        return cid

    def test_contact_invalidated_recontacts_pending_task(self):
        svc = make_service()
        self._two_member_setup(svc)
        task = list(svc.tasks.values())[0]
        self.assertEqual(task["contact_id"], "pA1")
        result = svc.invalidate_contact("pA1")
        self.assertEqual(task["status"], TASK_PENDING)
        self.assertEqual(task["contact_id"], "pA2")
        self.assertTrue(any(a["action"] == "recontacted"
                            for a in result["rearranged_tasks"]))

    def test_sent_task_is_never_rewritten_on_contact_change(self):
        svc = make_service()
        self._two_member_setup(svc)
        task = list(svc.tasks.values())[0]
        svc.deliver_due()
        self.assertEqual(task["status"], TASK_SENT)
        svc.invalidate_contact("pA1")
        self.assertEqual(task["status"], TASK_SENT)
        self.assertEqual(task["contact_id"], "pA1")

    def test_guardianship_change_supersedes_pending_child_task(self):
        svc = make_service()
        seed_household(svc, members=("G1",), children=("B",))
        for mid in ("B", "G1"):
            svc.add_consent({"consent_id": f"c{mid}", "member_id": mid,
                             "version": "v1", "start": T0})
            svc.add_contact({"contact_id": f"p{mid}", "member_id": mid,
                             "channel": "sms", "start": T0})
        svc.add_guardianship({"id": "gr1", "guardian_member_id": "G1",
                              "child_member_id": "B", "start": T0})
        seed_window(svc, values=(("B", 200),))
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        task = list(svc.tasks.values())[0]
        svc.end_guardianship("gr1", at=NOTICE)
        self.assertEqual(task["status"], TASK_SUPERSEDED)

    def test_relocation_ends_location_bound_contacts(self):
        svc = make_service()
        seed_adult(svc)
        svc.add_contact({"contact_id": "pAhome", "member_id": "A", "channel": "voice",
                         "start": T0, "bound_to_location": True, "priority": 2})
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        result = svc.relocate_household("H1")
        self.assertIn("pAhome", result["ended_contacts"])
        self.assertNotIn("pA", result["ended_contacts"])  # 普通联系方式保留

    def test_lost_channel_holds_task_until_new_contact_added(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        task = list(svc.tasks.values())[0]
        # 唯一联系方式失效且无备用：授权仍在 -> 挂起等待，不作废、不投递
        result = svc.invalidate_contact("pA")
        self.assertEqual(task["status"], TASK_PENDING)
        self.assertEqual(task["held_reason"], "no_available_channel")
        self.assertTrue(any(a["action"] == "held_awaiting_channel"
                            for a in result["rearranged_tasks"]))
        svc.deliver_due()
        self.assertEqual(task["attempts"], 0)
        # 新联系方式就绪 -> 自动恢复并可投递
        out = svc.add_contact({"contact_id": "pAnew", "member_id": "A",
                               "channel": "voice", "start": NOTICE})
        self.assertIn(task["task_id"], out["resumed_tasks"])
        self.assertNotIn("held_reason", task)
        svc.deliver_due()
        self.assertEqual(task["status"], TASK_SENT)


class SummaryAndAuditTest(unittest.TestCase):
    def test_small_community_counts_are_suppressed(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        svc.deliver_due()
        summary = svc.community_summary(k=DEFAULT_K)
        cell = summary["communities"]["C1"]
        self.assertTrue(cell["suppressed"])
        self.assertIsNone(cell["households"])

    def _community_with_households(self, svc, n, community):
        for i in range(n):
            hid = f"H{i}"
            svc.register_household({"household_id": hid, "community_id": community})
            svc.register_member({"member_id": f"M{i}", "household_id": hid})
            svc.add_consent({"consent_id": f"c{i}", "member_id": f"M{i}",
                             "version": "v1", "start": T0})
            svc.add_contact({"contact_id": f"p{i}", "member_id": f"M{i}",
                             "channel": "sms", "start": T0})
            svc.register_window({"window_id": f"W{i}", "household_id": hid,
                                 "start": T0, "end": T1,
                                 "checks": [{"name": "coverage", "passed": True}],
                                 "points": [{"member_id": f"M{i}", "metric": "pm25",
                                             "value": 150}]})
            seed_rule(svc)
            cid = svc.run_rules(f"W{i}")[0]["candidate_id"]
            approve_candidate(svc, cid)
            svc.deliver_due()

    def test_counts_show_once_threshold_met(self):
        svc = make_service()
        self._community_with_households(svc, 5, "C1")
        cell = svc.community_summary(k=5)["communities"]["C1"]
        self.assertFalse(cell["suppressed"])
        self.assertEqual(cell["households"], 5)
        self.assertEqual(cell["notified_tasks"], 5)

    def test_trace_covers_gate_consent_recipients_content_and_receipts(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        cid = svc.run_rules("W1")[0]["candidate_id"]
        approve_candidate(svc, cid)
        svc.deliver_due()
        task = list(svc.tasks.values())[0]
        svc.record_receipt(task["task_id"], "delivered", token=task["receipt_token"])
        trace = svc.notification_trace(cid)
        self.assertTrue(trace["quality_gate"]["passed"])
        self.assertEqual(trace["rule"]["version"], "1")
        self.assertTrue(trace["review"]["completed"])
        self.assertEqual(len(trace["messages"]), 1)
        self.assertEqual(trace["tasks"][0]["status"], TASK_DELIVERED)
        event_types = {e["type"] for e in trace["audit_events"]}
        self.assertIn("quality_evaluated", event_types)
        self.assertIn("candidate_created", event_types)
        self.assertIn("message_snapshot_created", event_types)
        self.assertIn("receipt_delivered", event_types)

    def test_audit_chain_detects_tampering(self):
        svc = make_service()
        seed_adult(svc)
        seed_window(svc)
        seed_rule(svc)
        ok, _ = svc.verify_audit_chain()
        self.assertTrue(ok)
        svc.events[2]["details"]["household_id"] = "FORGED"
        ok, broken = svc.verify_audit_chain()
        self.assertFalse(ok)
        self.assertEqual(broken, 3)


class PersistenceRestartTest(unittest.TestCase):
    def test_pending_deadlines_continue_after_restart(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(path)
        clock = FixedClock()
        try:
            svc = NotificationService(path=path, clock=clock)
            seed_adult(svc)
            seed_window(svc, values=(("A", 80),), metric="co")
            seed_rule(svc, level="emergency", threshold=50, metric="co")
            cid = svc.run_rules("W1")[0]["candidate_id"]
            svc.send_emergency_notice(cid, "f1")
            svc.save()

            restarted = NotificationService(path=path, clock=clock)
            self.assertTrue(restarted.verify_audit_chain()[0])
            self.assertEqual(len(restarted.tasks), 1)
            # 重启后 SLA 到期照常升级
            clock.set("2026-09-23T11:00:00+00:00")
            st = restarted.sweep()
            self.assertTrue(any(e["kind"] == "review_overdue"
                                for e in st["escalations"]))
        finally:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
