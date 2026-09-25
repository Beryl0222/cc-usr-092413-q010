"""风险通知闭环主服务。

以哈希链审计日志作为唯一事件源：所有目录变更、窗口摄入、候选、
审批、快照、投递、回执、重排与升级都作为只增事件写入，重启时
重放重建全部运行态，因此待投递任务与升级时限在重启后继续推进。

关键不变量：
- 风险候选只来自通过质量门槛的窗口；
- 同一 (窗口, 规则版本) 幂等，规则版本变化产生带差异的新候选；
- 接收人按暴露时与通知时两版本授权解析为最小集合；
- 已送达/已确认任务及其快照永不变更，重排只替换未完成任务；
- 紧急可先发最低必要提示，随后必须补齐现场与伦理复核；
- 同一成员同一内容类型至多通知一次，重算绝不重复打扰。
"""

import json
import os
from datetime import timedelta

from . import messages, quality, recipients, timeutil
from .auditlog import AuditLog
from .state import State

ROUTINE_DEADLINE = timedelta(hours=48)
URGENT_DEADLINE = timedelta(hours=2)
RETRY_BACKOFF = timedelta(minutes=30)
MAX_ATTEMPTS = 3
MAX_ESCALATIONS = 2
COMMUNITY_PRIVACY_THRESHOLD = 3

# 任务终态：内容不可改写
IMMUTABLE_TASK_STATES = {"delivered", "confirmed", "optout", "conflict", "superseded"}
OPEN_TASK_STATES = {"pending", "sending", "failed"}


class ConflictError(RuntimeError):
    """回执与当前任务状态冲突。"""


class RuleError(RuntimeError):
    """业务规则不允许当前操作。"""


def _iso(moment):
    return moment.isoformat().replace("+00:00", "Z")


def _due_at(level, at):
    moment = timeutil.parse(at)
    delta = URGENT_DEADLINE if level == "urgent" else ROUTINE_DEADLINE
    return _iso(moment + delta)


def _finished(task):
    if task["status"] in IMMUTABLE_TASK_STATES:
        return True
    # 重试次数耗尽的失败任务进入后续流程，不再占用完成态
    return task["status"] == "failed" and task["attempts"] >= MAX_ATTEMPTS


class RiskNotificationService:
    def __init__(self, store_dir=None, audit=None, transport=None, clock=timeutil.now):
        self._clock = clock
        self._transport = transport or _NullTransport()
        if audit is None:
            audit = AuditLog(os.path.join(store_dir, "audit.log.jsonl") if store_dir else None)
        self.audit = audit
        self.state = State()
        self.candidates = {}   # candidate_id -> candidate
        self.tasks = {}        # task_id -> task
        self._dedup = {}       # (window_id, rule_version) -> candidate_id
        self.followups = []    # 后续流程队列（拒收/失败/冲突/不可达/升级耗尽）
        self.optouts = set()   # 已拒收的 person_id（不再向其投递）
        self._replaying = True
        self._replay()
        self._replaying = False

    # ========== 事件溯源 ==========

    def _replay(self):
        for record in self.audit.all():
            self._apply(record["action"], record["payload"], record["ts"], record["actor"])

    def _emit(self, action, payload, actor="system", at=None):
        record = self.audit.append(action, payload, actor=actor, ts=at or self._clock())
        self._apply(action, payload, record["ts"], actor)
        return record

    def _apply(self, action, p, ts, actor):
        replay = self._replaying
        # ---------- 目录事件 ----------
        if action == "member_registered":
            self.state.register_member(p["member_id"], p["household_id"], p["role"], p.get("sensitive"), p["at"])
        elif action == "guardianship_added":
            self.state.add_guardianship(p["child_id"], p["guardian_id"], p["start"], p.get("end"), p.get("gid"))
        elif action == "guardianship_ended":
            self.state.end_guardianship(p["gid"], p["end"])
            if not replay:
                child = next((g["child_id"] for g in self.state.guardianships if g["id"] == p["gid"]), None)
                guardian = next((g["guardian_id"] for g in self.state.guardianships if g["id"] == p["gid"]), None)
                self._replan_all({child, guardian} - {None}, "监护变更", ts)
        elif action == "consent_granted":
            self.state.grant_consent(p["consent_id"], p["member_id"], p["scope"], p["channels"], p["start"], p.get("end"))
        elif action == "consent_revoked":
            self.state.revoke_consent(p["consent_id"], p["end"])
            if not replay:
                holder = next((c["member_id"] for c in self.state.consents if c["consent_id"] == p["consent_id"]), None)
                affected = {holder}
                for link in self.state.guardianships:
                    if link["guardian_id"] == holder and timeutil.is_valid(link, ts):
                        affected.add(link["child_id"])
                self._replan_all(affected - {None}, "同意撤回", ts)
        elif action == "contact_added":
            self.state.add_contact(p["contact_id"], p["person_id"], p["channel"], p["address"], p["start"], p.get("end"))
        elif action == "contact_disabled":
            person = next((c["person_id"] for c in self.state.contacts if c["contact_id"] == p["contact_id"]), None)
            self.state.disable_contact(p["contact_id"], p["end"], p.get("reason", "失效"))
            if not replay:
                self._replan_all({person} - {None}, "联系方式失效", ts)
        elif action == "preference_set":
            self.state.set_preference(p["person_id"], p["pref"], p["start"], p.get("end"))
        elif action == "household_relocated":
            moved = self.state.relocate_household(p["household_id"], p["new_household_id"], p["at"])
            if not replay:
                # 搬迁是显式重排触发：按新家庭上下文重建未完成任务
                self._replan_all(set(moved), "家庭搬迁", ts, force=True)
        elif action == "window_ingested":
            self.state.upsert_window(p["window"])
        # ---------- 工作流事件 ----------
        elif action == "candidate_created":
            self.candidates[p["candidate_id"]] = {
                "candidate_id": p["candidate_id"],
                "window_id": p["window_id"],
                "rule_version": p["rule_version"],
                "level": p["level"],
                "risk": p["risk"],
                "member_ids": list(p["member_ids"]),
                "status": "candidate",
                "created_at": ts,
                "diff_from": p.get("diff_from"),
                "diff": p.get("diff"),
                "emergency": False,
                "field_confirmation": None,
                "approval": None,
            }
            self._dedup[(p["window_id"], p["rule_version"])] = p["candidate_id"]
        elif action == "candidate_rejected_quality":
            pass
        elif action == "field_confirmed":
            self.candidates[p["candidate_id"]].update(
                status="field_confirmed",
                field_confirmation={"researcher": actor, "at": ts,
                                    "household_id": p.get("household_id"), "note": p.get("note")},
            )
        elif action == "ethics_approved":
            cand = self.candidates[p["candidate_id"]]
            cand["status"] = "approved"
            cand["approval"] = {"officer": actor, "at": ts, "level": p["level"], "note": p.get("note")}
        elif action == "tasks_created":
            for item in p["tasks"]:
                task = dict(item)
                task.setdefault("history", [])
                task["history"].append({"at": ts, "event": "created"})
                self.tasks[task["task_id"]] = task
            cand = self.candidates[p["candidate_id"]]
            if p.get("emergency"):
                cand["emergency"] = True
                if cand["status"] == "candidate":
                    cand["status"] = "sent_pending_review"
            elif cand["status"] == "approved":
                cand["status"] = "dispatched"
        elif action == "task_superseded":
            task = self.tasks[p["task_id"]]
            task["status"] = "superseded"
            task["history"].append({"at": ts, "event": "superseded", "reason": p["reason"]})
        elif action == "task_sending":
            self.tasks[p["task_id"]]["status"] = "sending"
        elif action == "task_failed_attempt":
            task = self.tasks[p["task_id"]]
            task["attempts"] = p["attempts"]
            task["scheduled_at"] = p["scheduled_at"]
            task["status"] = "failed" if p["terminal"] else "pending"
            task["history"].append({"at": ts, "event": "attempt_failed", "reason": p["reason"]})
        elif action == "task_delivered":
            task = self.tasks[p["task_id"]]
            task["status"] = "delivered"
            task["sent_at"] = ts
            task["provider_ref"] = p.get("provider_ref")
            task["history"].append({"at": ts, "event": "delivered"})
        elif action == "task_confirmed":
            task = self.tasks[p["task_id"]]
            task["status"] = "confirmed"
            task["history"].append({"at": ts, "event": "confirmed"})
        elif action == "task_optout":
            task = self.tasks[p["task_id"]]
            task["status"] = "optout"
            task["history"].append({"at": ts, "event": "optout"})
            self.optouts.add(task["recipient_id"])
        elif action == "task_conflict":
            task = self.tasks[p["task_id"]]
            task["status"] = "conflict"
            task["history"].append({"at": ts, "event": "conflict", "claim": p["claim"]})
        elif action == "task_escalated":
            task = self.tasks[p["task_id"]]
            task["escalations"] = p["escalations"]
            task["scheduled_at"] = p["scheduled_at"]
            task["history"].append({"at": ts, "event": "escalated", "level": p["escalations"]})
        elif action == "followup_queued":
            self.followups.append(dict(p, at=ts))
            if p.get("type", "").startswith("recipient_optout") and p.get("person_id"):
                self.optouts.add(p["person_id"])
        elif action == "candidate_completed":
            self.candidates[p["candidate_id"]]["status"] = "completed"
            self.candidates[p["candidate_id"]]["completed_at"] = ts
        else:
            raise RuntimeError(f"未知事件类型: {action}")

    # ========== 目录命令 ==========

    def register_member(self, member_id, household_id, role, sensitive=None, at=None, actor="field"):
        at = at or self._clock()
        return self._emit(
            "member_registered",
            {"member_id": member_id, "household_id": household_id, "role": role,
             "sensitive": list(sensitive or []), "at": at},
            actor=actor, at=at,
        )

    def add_guardianship(self, child_id, guardian_id, start, end=None, gid=None, actor="field"):
        return self._emit(
            "guardianship_added",
            {"child_id": child_id, "guardian_id": guardian_id, "start": start, "end": end, "gid": gid},
            actor=actor, at=start,
        )

    def end_guardianship(self, gid, end=None, actor="field"):
        end = end or self._clock()
        return self._emit("guardianship_ended", {"gid": gid, "end": end}, actor=actor, at=end)

    def grant_consent(self, consent_id, member_id, scope, channels, start, end=None, actor="field"):
        return self._emit(
            "consent_granted",
            {"consent_id": consent_id, "member_id": member_id, "scope": list(scope),
             "channels": list(channels), "start": start, "end": end},
            actor=actor, at=start,
        )

    def revoke_consent(self, consent_id, end=None, actor="member"):
        end = end or self._clock()
        return self._emit("consent_revoked", {"consent_id": consent_id, "end": end}, actor=actor, at=end)

    def add_contact(self, contact_id, person_id, channel, address, start, end=None, actor="field"):
        return self._emit(
            "contact_added",
            {"contact_id": contact_id, "person_id": person_id, "channel": channel,
             "address": address, "start": start, "end": end},
            actor=actor, at=start,
        )

    def disable_contact(self, contact_id, reason="失效", end=None, actor="system"):
        end = end or self._clock()
        return self._emit("contact_disabled", {"contact_id": contact_id, "end": end, "reason": reason},
                          actor=actor, at=end)

    def set_preference(self, person_id, pref, start=None, end=None, actor="member"):
        start = start or self._clock()
        return self._emit(
            "preference_set", {"person_id": person_id, "pref": pref, "start": start, "end": end},
            actor=actor, at=start,
        )

    def relocate_household(self, household_id, new_household_id, at=None, actor="field"):
        at = at or self._clock()
        return self._emit(
            "household_relocated",
            {"household_id": household_id, "new_household_id": new_household_id, "at": at},
            actor=actor, at=at,
        )

    # ========== 数据摄入与候选 ==========

    def ingest_window(self, window, actor="sensor-gateway"):
        """登记暴露窗口并固化质量门槛结论。"""
        passed, reasons = quality.evaluate_quality(window)
        record = dict(window)
        record["quality"] = {"passed": passed, "reasons": reasons}
        self._emit("window_ingested", {"window": record}, actor=actor, at=window["end"])
        return record

    def scan_window(self, window_id, rule_version=quality.DEFAULT_RULE_VERSION, at=None, actor="risk-engine"):
        """在窗口上跑规则：同版本幂等不重复打扰，新版本产生带差异的新候选。"""
        at = at or self._clock()
        window = self.state.get_window(window_id)
        if not window:
            raise RuleError(f"未知窗口: {window_id}")
        key = (window_id, rule_version)
        if key in self._dedup:
            return {"candidate_id": self._dedup[key], "created": False, "reason": "same_rule_already_scanned"}

        if not window["quality"]["passed"]:
            self._emit(
                "candidate_rejected_quality",
                {"window_id": window_id, "rule_version": rule_version, "reasons": window["quality"]["reasons"]},
                actor=actor, at=at,
            )
            return {"created": False, "reason": "quality_gate_failed", "reasons": window["quality"]["reasons"]}

        risk = quality.evaluate_risk(window, rule_version)
        if risk is None:
            return {"created": False, "reason": "no_risk"}

        diff_from, diff = None, None
        prior = sorted(
            (c for c in self.candidates.values() if c["window_id"] == window_id),
            key=lambda c: c["created_at"],
        )
        if prior:
            diff_from = prior[-1]["candidate_id"]
            diff = self._diff_risk(prior[-1]["risk"], risk)

        candidate_id = f"ntf-{window_id}-{rule_version}"
        self._emit(
            "candidate_created",
            {"candidate_id": candidate_id, "window_id": window_id, "rule_version": rule_version,
             "level": risk["level"], "risk": risk, "member_ids": list(window["member_ids"]),
             "diff_from": diff_from, "diff": diff},
            actor=actor, at=at,
        )
        return {"candidate_id": candidate_id, "created": True, "diff_from": diff_from, "diff": diff}

    @staticmethod
    def _diff_risk(old, new):
        changes = []
        for field in ("level", "avg_pm25", "threshold", "rule_label", "min_duration_min"):
            if old.get(field) != new.get(field):
                changes.append({"field": field, "old": old.get(field), "new": new.get(field)})
        return changes

    # ========== 双签 ==========

    def field_confirm(self, candidate_id, household_id=None, note=None, at=None, actor="field-researcher"):
        cand = self._require_candidate(candidate_id)
        if cand["field_confirmation"]:
            return cand["field_confirmation"]
        at = at or self._clock()
        self._emit("field_confirmed",
                   {"candidate_id": candidate_id, "household_id": household_id, "note": note},
                   actor=actor, at=at)
        return self.candidates[candidate_id]["field_confirmation"]

    def ethics_approve(self, candidate_id, level=None, note=None, at=None, actor="ethics-officer"):
        cand = self._require_candidate(candidate_id)
        if cand["approval"]:
            return cand["approval"]
        at = at or self._clock()
        level = level or cand["level"]
        if level not in ("routine", "urgent"):
            raise RuleError(f"未知通知级别: {level}")
        self._emit("ethics_approved",
                   {"candidate_id": candidate_id, "level": level, "note": note},
                   actor=actor, at=at)
        return self.candidates[candidate_id]["approval"]

    # ========== 快照与投递任务 ==========

    def dispatch(self, candidate_id, at=None, actor="dispatcher"):
        """完成双签后解析最小接收人、生成完整快照与投递任务（幂等）。"""
        at = at or self._clock()
        cand = self._require_candidate(candidate_id)
        if not cand["field_confirmation"]:
            raise RuleError("缺少现场研究员确认")
        if not cand["approval"]:
            raise RuleError("缺少伦理值班批准")
        return self._create_tasks(cand, messages.KIND_FULL, at, actor, emergency=False)

    def emergency_send(self, candidate_id, at=None, actor="dispatcher"):
        """紧急先行：只发最低必要提示；事后必须补齐现场确认与伦理批准。"""
        at = at or self._clock()
        cand = self._require_candidate(candidate_id)
        if cand["level"] != "urgent":
            raise RuleError("仅紧急风险可先行发送")
        created = self._create_tasks(cand, messages.KIND_MINIMAL_ALERT, at, actor, emergency=True)
        for task_id in created["tasks"]:
            self._attempt_delivery(self.tasks[task_id], at, actor)
        return created

    def _deadline_for(self, cand):
        """重排不重置时限：沿用候选下最早的截止时间，时限继续推进。"""
        existing = [t["deadline_at"] for t in self.tasks.values()
                    if t["candidate_id"] == cand["candidate_id"]]
        return min(existing) if existing else _due_at(cand["level"], cand["created_at"])

    def _covered_members(self, candidate_id, kind=None):
        covered = set()
        for task in self.tasks.values():
            if task["candidate_id"] != candidate_id:
                continue
            if kind and task["kind"] != kind:
                continue
            if task["status"] in ("delivered", "confirmed"):
                covered.update(task["covers"])
        return covered

    def _assigned_members(self, candidate_id, kind):
        """已存在未被取代的同类任务的成员（含在途/失败重试/终态），不可重复建任务。"""
        assigned = set()
        for task in self.tasks.values():
            if task["candidate_id"] != candidate_id or task["kind"] != kind:
                continue
            if task["status"] != "superseded":
                assigned.update(task["covers"])
        return assigned

    def _build_task_records(self, cand, kind, member_ids, at, seq_tag):
        window = self.state.get_window(cand["window_id"])
        result = recipients.resolve_recipients(
            self.state, window, member_ids, cand["level"], at, exclude_persons=self.optouts
        )
        chosen = list(result["recipients"])
        opted_out_members = set()
        for recipient in result["recipients"]:
            if recipient["person_id"] in self.optouts:
                opted_out_members.update(recipient["covers"])
        records = []
        covered_now = set()
        for index, recipient in enumerate(chosen):
            snapshot = messages.render_snapshot(
                self.state, recipient, window, cand["risk"], kind,
                snapshot_id=f"{cand['candidate_id']}:{kind}:{seq_tag}:{recipient['person_id']}", at=at,
            )
            leaks = messages.find_leaks(snapshot, list(self.state.members))
            if leaks:
                raise RuleError(f"快照存在越权成员信息: {leaks}")
            records.append({
                "task_id": f"task-{cand['candidate_id']}-{kind}-{seq_tag}-{index}-{recipient['person_id']}",
                "candidate_id": cand["candidate_id"],
                "recipient_id": recipient["person_id"],
                "channel": recipient["channel"],
                "address": recipient["address"],
                "contact_id": recipient["contact_id"],
                "covers": recipient["covers"],
                "consent_ids": recipient["consent_ids"],
                "guardianship_ids": recipient["guardianship_ids"],
                "snapshot": snapshot,
                "kind": kind,
                "level": cand["level"],
                "status": "pending",
                "attempts": 0,
                "escalations": 0,
                "scheduled_at": at,
                "deadline_at": self._deadline_for(cand),
                "created_at": at,
            })
            covered_now.update(recipient["covers"])
        unreachable = [e for e in result["excluded"]]
        for member_id in opted_out_members - covered_now:
            unreachable.append({"member_id": member_id, "reason": "唯一接收人已拒收"})
        return records, unreachable

    def _create_tasks(self, cand, kind, at, actor, emergency):
        # 补齐复核发送完整通知时：尚未发出的最低必要提示一律取消改发完整版；
        # 已送达的提示保留不可改写。
        if kind == messages.KIND_FULL and not emergency:
            for task in self.tasks.values():
                if (task["candidate_id"] == cand["candidate_id"]
                        and task["kind"] == messages.KIND_MINIMAL_ALERT
                        and task["status"] in OPEN_TASK_STATES and not _finished(task)):
                    self._emit("task_superseded",
                               {"task_id": task["task_id"], "reason": "复核完成，改发完整通知"},
                               actor=actor, at=at)
        # 只通知尚未收到同类型内容的成员：同窗口重算不重复打扰
        remaining = [m for m in cand["member_ids"]
                     if m not in self._covered_members(cand["candidate_id"], kind)
                     and m not in self._assigned_members(cand["candidate_id"], kind)]
        if not remaining:
            return {"tasks": [], "excluded": [], "reason": "all_members_already_notified"}
        records, unreachable = self._build_task_records(cand, kind, remaining, at, seq_tag="v1")
        self._emit(
            "tasks_created",
            {"candidate_id": cand["candidate_id"], "tasks": records, "emergency": emergency,
             "excluded": unreachable},
            actor=actor, at=at,
        )
        if unreachable:
            self._emit(
                "followup_queued",
                {"candidate_id": cand["candidate_id"], "type": "unreachable_member", "excluded": unreachable},
                actor="dispatcher", at=at,
            )
        self._maybe_complete(cand["candidate_id"], at)
        return {"tasks": [t["task_id"] for t in records], "excluded": unreachable}

    # ========== 投递结果：送达 / 失败 / 拒收 / 冲突 ==========

    def attempt_delivery(self, task_id, at=None, actor="transport"):
        at = at or self._clock()
        return self._attempt_delivery(self.tasks[task_id], at, actor)

    def _attempt_delivery(self, task, at, actor):
        if task["status"] not in OPEN_TASK_STATES or _finished(task):
            return {"task_id": task["task_id"], "status": task["status"], "sent": False}
        if timeutil.parse(task["scheduled_at"]) > timeutil.parse(at):
            return {"task_id": task["task_id"], "status": "scheduled_later", "sent": False}
        self._emit("task_sending", {"task_id": task["task_id"]}, actor=actor, at=at)
        outcome = self._transport.send(task)
        if outcome["ok"]:
            self._emit("task_delivered",
                       {"task_id": task["task_id"], "provider_ref": outcome.get("provider_ref")},
                       actor=actor, at=at)
            self._maybe_complete(task["candidate_id"], at)
            return {"task_id": task["task_id"], "status": "delivered", "sent": True}
        if outcome.get("invalid_contact"):
            # 联系方式失效：先停用（触发只重排未完成任务，尝试其他渠道/接收人），
            # 当前在途任务在重排中被取代；若无替代渠道则进入不可达后续流程。
            reason = outcome.get("reason", "联系方式失效")
            self.disable_contact(task["contact_id"], reason=reason, end=at, actor="transport")
            return {"task_id": task["task_id"], "status": "rerouted", "sent": False}
        return self._record_failure(task, outcome.get("reason", "未知失败"), at, actor)

    def _record_failure(self, task, reason, at, actor):
        attempts = task["attempts"] + 1
        terminal = attempts >= MAX_ATTEMPTS
        scheduled = None if terminal else _iso(timeutil.parse(at) + RETRY_BACKOFF)
        self._emit(
            "task_failed_attempt",
            {"task_id": task["task_id"], "attempts": attempts, "scheduled_at": scheduled,
             "reason": reason, "terminal": terminal},
            actor=actor, at=at,
        )
        if terminal:
            self._emit(
                "followup_queued",
                {"candidate_id": task["candidate_id"], "type": "delivery_failed",
                 "task_id": task["task_id"], "reason": reason},
                actor="transport", at=at,
            )
            self._maybe_complete(task["candidate_id"], at)
        return {"task_id": task["task_id"],
                "status": "terminal_failure" if terminal else "retry_scheduled", "sent": False}

    def confirm_receipt(self, task_id, at=None, actor="recipient"):
        at = at or self._clock()
        task = self.tasks[task_id]
        if task["status"] not in ("delivered", "confirmed"):
            raise ConflictError(f"任务尚未送达，不能确认回执: {task['status']}")
        if task["status"] == "confirmed":
            return {"task_id": task_id, "status": "confirmed", "changed": False}
        self._emit("task_confirmed", {"task_id": task_id}, actor=actor, at=at)
        self._maybe_complete(task["candidate_id"], at)
        return {"task_id": task_id, "status": "confirmed", "changed": True}

    def report_receipt_conflict(self, task_id, claim, at=None, actor="transport"):
        """送达与回执互相矛盾（供应商称退信但收件人称收到等）：冻结并转人工。"""
        at = at or self._clock()
        task = self.tasks[task_id]
        self._emit("task_conflict", {"task_id": task_id, "claim": claim}, actor=actor, at=at)
        self._emit(
            "followup_queued",
            {"candidate_id": task["candidate_id"], "type": "receipt_conflict",
             "task_id": task_id, "claim": claim},
            actor=actor, at=at,
        )
        self._maybe_complete(task["candidate_id"], at)
        return {"task_id": task_id, "status": "conflict"}

    def opt_out(self, task_id, at=None, actor="recipient"):
        """拒收：未发送任务终止并重排其覆盖成员；已送达则只登记、不改写内容。"""
        at = at or self._clock()
        task = self.tasks[task_id]
        if task["status"] in ("delivered", "confirmed"):
            self._emit(
                "followup_queued",
                {"candidate_id": task["candidate_id"], "type": "recipient_optout_after_delivery",
                 "task_id": task_id, "person_id": task["recipient_id"]},
                actor=actor, at=at,
            )
            self.optouts.add(task["recipient_id"])
            return {"task_id": task_id, "status": task["status"], "opted_out": True}
        self._emit("task_optout", {"task_id": task_id}, actor=actor, at=at)
        self._emit(
            "followup_queued",
            {"candidate_id": task["candidate_id"], "type": "recipient_optout",
             "task_id": task_id, "person_id": task["recipient_id"], "covers": list(task["covers"])},
            actor=actor, at=at,
        )
        # 该接收人原覆盖的成员需按当前授权重新解析（任务本身已终止，不属于 open_tasks）
        self._replan_candidate(self.candidates[task["candidate_id"]], "接收人拒收重排", at,
                               lost_members=list(task["covers"]))
        return {"task_id": task_id, "status": "optout"}

    # ========== 重排：只替换未完成任务，已送达内容不可改写 ==========

    def _replan_all(self, affected_ids, reason, at, force=False):
        """affected_ids 为受影响的成员/接收人标识；只动与其相关的候选。"""
        affected = set(affected_ids)
        for cand in list(self.candidates.values()):
            if cand["status"] == "completed":
                continue
            open_tasks = [t for t in self.tasks.values()
                          if t["candidate_id"] == cand["candidate_id"] and t["status"] in OPEN_TASK_STATES
                          and not _finished(t)]
            if not open_tasks:
                continue
            if force or any(
                t["recipient_id"] in affected or affected & set(t["covers"]) for t in open_tasks
            ):
                self._replan_candidate(cand, reason, at, force=force)

    def _task_still_valid(self, task, at):
        """以当前授权状态重新解析该任务覆盖的成员，判断原接收人/渠道是否仍成立。"""
        if task["recipient_id"] in self.optouts:
            return False
        cand = self.candidates[task["candidate_id"]]
        window = self.state.get_window(cand["window_id"])
        result = recipients.resolve_recipients(
            self.state, window, task["covers"], task["level"], at
        )
        return any(
            r["person_id"] == task["recipient_id"]
            and r["contact_id"] == task["contact_id"]
            and r["channel"] == task["channel"]
            for r in result["recipients"]
        )

    def _replan_candidate(self, cand, reason, at, force=False, lost_members=None):
        candidate_id = cand["candidate_id"]
        # 紧急先行尚未补齐复核时，重排仍只能使用最低必要提示
        kind = messages.KIND_MINIMAL_ALERT if cand["emergency"] and not cand["approval"] else messages.KIND_FULL

        open_tasks = [t for t in self.tasks.values()
                      if t["candidate_id"] == candidate_id and t["status"] in OPEN_TASK_STATES
                      and not _finished(t)]
        # 只取代真正受影响的任务；仍有效的无关待发任务原样保留
        if force:
            to_supersede = list(open_tasks)
        else:
            to_supersede = [t for t in open_tasks if not self._task_still_valid(t, at)]
        retained = [t for t in open_tasks if t not in to_supersede]
        for task in to_supersede:
            self._emit("task_superseded", {"task_id": task["task_id"], "reason": reason},
                       actor="dispatcher", at=at)

        lost = set(lost_members or ())
        for task in to_supersede:
            lost.update(task["covers"])
        retained_members = set()
        for task in retained:
            retained_members.update(task["covers"])
        already = self._covered_members(candidate_id, kind) | retained_members
        remaining = [m for m in cand["member_ids"] if m in lost and m not in already]
        if not remaining:
            self._maybe_complete(candidate_id, at)
            return {"superseded": [t["task_id"] for t in to_supersede], "created": []}

        records, unreachable = self._build_task_records(
            cand, kind, remaining, at, seq_tag=f"replan{len(self.followups) + len(self.tasks)}"
        )
        self._emit(
            "tasks_created",
            {"candidate_id": candidate_id, "tasks": records, "emergency": False,
             "reason": reason, "excluded": unreachable},
            actor="dispatcher", at=at,
        )
        if unreachable:
            self._emit(
                "followup_queued",
                {"candidate_id": candidate_id, "type": "unreachable_member",
                 "reason": reason, "excluded": unreachable},
                actor="dispatcher", at=at,
            )
        self._maybe_complete(candidate_id, at)
        return {"superseded": [t["task_id"] for t in open_tasks],
                "created": [t["task_id"] for t in records]}

    # ========== 定时器：重启后继续推进 ==========

    def run_due_tasks(self, at=None):
        """发送所有到期（scheduled_at <= at）的待投递任务；崩溃残留的 sending 也在此重试。"""
        at = at or self._clock()
        results = []
        for task in list(self.tasks.values()):
            if task["status"] not in ("pending", "sending"):
                continue
            if task["status"] == "sending" or timeutil.parse(task["scheduled_at"]) <= timeutil.parse(at):
                results.append(self._attempt_delivery(task, at, "scheduler"))
        return results

    def advance_timers(self, at=None):
        """推进升级时限：超时未完成任务升级，达上限进入后续流程。"""
        at = at or self._clock()
        moment = timeutil.parse(at)
        results = []
        for task in list(self.tasks.values()):
            if task["status"] not in OPEN_TASK_STATES or _finished(task):
                continue
            if timeutil.parse(task["deadline_at"]) > moment:
                continue
            if task["escalations"] >= MAX_ESCALATIONS:
                continue
            escalations = task["escalations"] + 1
            scheduled = _iso(moment + RETRY_BACKOFF)
            self._emit(
                "task_escalated",
                {"task_id": task["task_id"], "escalations": escalations,
                 "scheduled_at": scheduled, "deadline_at": task["deadline_at"]},
                actor="scheduler", at=at,
            )
            if escalations >= MAX_ESCALATIONS:
                self._emit(
                    "followup_queued",
                    {"candidate_id": task["candidate_id"], "type": "escalation_exhausted",
                     "task_id": task["task_id"]},
                    actor="scheduler", at=at,
                )
                self._maybe_complete(task["candidate_id"], at)
            results.append({"task_id": task["task_id"], "escalation": escalations})
        return results

    # ========== 完成态 ==========

    def _members_with_followups(self, candidate_id):
        members = set()
        for item in self.followups:
            if item.get("candidate_id") != candidate_id:
                continue
            if item["type"] == "unreachable_member":
                members.update(e["member_id"] for e in item.get("excluded", []))
            elif "covers" in item:
                members.update(item["covers"])
            elif item.get("task_id"):
                task = self.tasks.get(item["task_id"])
                if task:
                    members.update(task["covers"])
        return members

    def _maybe_complete(self, candidate_id, at):
        if self._replaying:
            return
        cand = self.candidates.get(candidate_id)
        if not cand or cand["status"] == "completed":
            return
        # 紧急先行但复核尚未补齐：保持"待复核"，不得闭环
        if cand["emergency"] and not cand["approval"]:
            return
        tasks = [t for t in self.tasks.values() if t["candidate_id"] == candidate_id]
        if not tasks:
            return
        if not all(_finished(t) for t in tasks):
            return
        accounted = self._covered_members(candidate_id) | self._members_with_followups(candidate_id)
        if set(cand["member_ids"]) <= accounted:
            self._emit("candidate_completed", {"candidate_id": candidate_id}, actor="dispatcher", at=at)

    # ========== 社区汇总：小单元格抑制 ==========

    def community_summary(self, threshold=COMMUNITY_PRIVACY_THRESHOLD):
        counts = {}
        for task in self.tasks.values():
            if task["status"] not in ("delivered", "confirmed"):
                continue
            cand = self.candidates.get(task["candidate_id"])
            window = self.state.get_window(cand["window_id"]) if cand else None
            community = (window or {}).get("community", "unknown")
            counts[community] = counts.get(community, 0) + 1
        visible, suppressed = {}, []
        for community, count in sorted(counts.items()):
            if count >= threshold:
                visible[community] = count
            else:
                suppressed.append(community)
        return {
            "threshold": threshold,
            "notifications_delivered": visible,
            "suppressed_communities": suppressed,
            "note": f"低于 {threshold} 条的社区数量不予显示，防止小群体反识别",
        }

    # ========== 审计追溯：一次通知追到全部依据 ==========

    def trace(self, candidate_id):
        cand = self._require_candidate(candidate_id)
        window = self.state.get_window(cand["window_id"])
        candidate_tasks = [t for t in self.tasks.values() if t["candidate_id"] == candidate_id]
        authorization = {}
        for task in candidate_tasks:
            person_id = task["recipient_id"]
            entry = authorization.setdefault(person_id, {
                "role": (self.state.get_member(person_id) or {}).get("role"),
                "consent_ids_used": set(),
                "guardianship_ids_used": set(),
                "contacts_used": set(),
            })
            entry["consent_ids_used"].update(task["consent_ids"])
            entry["guardianship_ids_used"].update(task["guardianship_ids"])
            entry["contacts_used"].add(task["contact_id"])
        for entry in authorization.values():
            entry["consent_ids_used"] = sorted(entry["consent_ids_used"])
            entry["guardianship_ids_used"] = sorted(entry["guardianship_ids_used"])
            entry["contacts_used"] = sorted(entry["contacts_used"])

        timeline = []
        related_persons = set(cand["member_ids"]) | set(authorization.keys())
        related_consents = {c for entry in authorization.values() for c in entry["consent_ids_used"]}
        related_contacts = {c for entry in authorization.values() for c in entry["contacts_used"]}
        related_guardians = {g for entry in authorization.values() for g in entry["guardianship_ids_used"]}
        for record in self.audit.all():
            p = record["payload"]
            include = candidate_id in json.dumps(p, ensure_ascii=False)
            if not include and record["action"] == "window_ingested" \
                    and p.get("window", {}).get("window_id") == cand["window_id"]:
                include = True
            if not include and record["action"] in (
                    "consent_granted", "consent_revoked", "contact_added", "contact_disabled",
                    "guardianship_added", "guardianship_ended", "preference_set"):
                include = (
                    p.get("member_id") in related_persons
                    or p.get("person_id") in related_persons
                    or p.get("child_id") in related_persons
                    or p.get("consent_id") in related_consents
                    or p.get("contact_id") in related_contacts
                    or p.get("gid") in related_guardians
                )
            if include:
                timeline.append(_timeline_entry(record))
        return {
            "candidate_id": candidate_id,
            "window": {"window_id": cand["window_id"], "quality": window["quality"],
                       "span": [window["start"], window["end"]], "community": window.get("community")},
            "rule": {"version": cand["rule_version"], "risk": cand["risk"],
                     "diff_from": cand["diff_from"], "diff": cand["diff"]},
            "approvals": {"field": cand["field_confirmation"], "ethics": cand["approval"],
                          "emergency_sent_before_review": cand["emergency"]},
            "recipient_selection": authorization,
            "messages": [
                {"task_id": t["task_id"], "recipient_id": t["recipient_id"], "covers": t["covers"],
                 "channel": t["channel"], "kind": t["kind"], "status": t["status"],
                 "content_hash": t["snapshot"]["content_hash"], "body": t["snapshot"]["body"]}
                for t in candidate_tasks
            ],
            "final_status": cand["status"],
            "timeline": timeline,
        }

    def verify_audit(self):
        return self.audit.verify()

    def _require_candidate(self, candidate_id):
        if candidate_id not in self.candidates:
            raise RuleError(f"未知候选: {candidate_id}")
        return self.candidates[candidate_id]


def _timeline_entry(record):
    return {"seq": record["seq"], "ts": record["ts"], "actor": record["actor"],
            "action": record["action"], "payload": record["payload"],
            "record_hash": record["hash"]}


class _NullTransport:
    """默认传输层：投递由 attempt_delivery 显式驱动，默认成功。"""

    def send(self, task):
        return {"ok": True, "provider_ref": f"sim-{task['task_id']}"}


class ScriptedTransport:
    """测试用传输层：按地址脚本化返回成功、临时失败、永久失效。"""

    def __init__(self, fail_addresses=(), fail_times=None, invalid_addresses=()):
        self.fail_addresses = set(fail_addresses)
        self.fail_times = dict(fail_times or {})
        self.invalid_addresses = set(invalid_addresses)
        self.calls = []

    def send(self, task):
        self.calls.append((task["task_id"], task["address"]))
        if task["address"] in self.invalid_addresses:
            return {"ok": False, "reason": "联系方式失效", "invalid_contact": True}
        if task["address"] in self.fail_addresses:
            return {"ok": False, "reason": "供应商退信"}
        remaining = self.fail_times.get(task["address"], 0)
        if remaining > 0:
            self.fail_times[task["address"]] = remaining - 1
            return {"ok": False, "reason": "临时网络错误"}
        return {"ok": True, "provider_ref": f"prov-{len(self.calls)}"}
