"""社区暴露风险通知闭环领域服务。

闭环覆盖：质量门槛 -> 版本化规则候选 -> 双时点授权解析（最小接收人）->
现场/伦理两级复核 -> 成员隔离的消息快照与可验证投递 -> 拒收/失败/回执冲突
后续流程 -> 隐私门槛汇总 -> 哈希链审计。

仅依赖 Python 标准库；所有时间戳为绝对 ISO 时间，状态可 JSON 持久化，
进程重启后待投递重试与升级时限继续推进。
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------- 常量

RISK_LEVELS = ("info", "advisory", "urgent", "emergency")
LEVEL_RANK = {level: i for i, level in enumerate(RISK_LEVELS)}

TASK_PENDING = "pending"
TASK_SENT = "sent"
TASK_DELIVERED = "delivered"
TASK_FAILED = "failed"
TASK_REFUSED = "refused"
TASK_SUPERSEDED = "superseded"
TASK_CANCELLED = "cancelled"

# 已触及接收人的任务：内容不可改写，重排只能作用于未触及的任务。
FROZEN_STATES = frozenset({TASK_SENT, TASK_DELIVERED, TASK_REFUSED})
UNFINISHED_STATES = frozenset({TASK_PENDING, TASK_FAILED})
FINAL_STATES = frozenset(
    {TASK_DELIVERED, TASK_REFUSED, TASK_SUPERSEDED, TASK_CANCELLED}
)

REVIEW_SLA_SECONDS = 3600          # 紧急先发后，复核补齐时限
TASK_ESCALATE_SECONDS = 1800       # 待投递升级时限
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 30
DEFAULT_K = 5                     # 社区汇总隐私门槛

GENESIS_HASH = hashlib.sha256("risk-notification-genesis".encode("utf-8")).hexdigest()


class DomainError(Exception):
    """带稳定错误码的领域异常，便于 API 层映射 4xx。"""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- 工具

def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _fingerprint(payload) -> str:
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:16]


def _json_default(obj):
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    raise TypeError(f"不可序列化的对象: {type(obj)!r}")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _valid_at(record, t: datetime) -> bool:
    """半开区间 [start, end)；end 为空表示持续有效。"""
    start = record.get("start")
    end = record.get("end")
    if start is not None and t < _parse(start):
        return False
    if end is not None and t >= _parse(end):
        return False
    return True


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------- 主服务

class NotificationService:
    def __init__(self, path=None, clock=utcnow):
        self.path = path
        self.clock = clock
        self.lock = threading.RLock()
        # 可注入的发送通道：transport(contact, message) -> {"ok": bool, "provider_ref": str}
        self.transport = None

        self.households = {}          # hid -> household
        self.members = {}             # mid -> {member_id, household_id, is_child, pregnant}
        self.windows = {}             # wid -> 窗口（含测点）
        self.quality = {}             # wid -> 质量门槛评估
        self.rules = {}               # rule_id -> {version: rule}
        self.consents = []            # 同意版本（时态）
        self.guardianships = []       # 监护关系（时态）
        self.contacts = []            # 联系方式（时态）
        self.preferences = []         # 安全偏好（时态）

        self.candidates = {}          # cid -> 候选
        self.candidate_chain = {}     # (window_id, rule_id) -> [cid 时间顺序]
        self.reviews = {}             # cid -> 复核记录
        self.messages = {}            # mid -> 不可变消息快照
        self.tasks = {}               # tid -> 投递任务
        self.followups = []           # 拒收/失败/回执冲突后续流程
        self.escalations = []         # 升级记录
        self.events = []              # 审计哈希链
        self._prev_hash = GENESIS_HASH

        if path and os.path.exists(path):
            self._load()

    # ------------------------------------------------------------ 时间/审计

    def now(self) -> str:
        return _iso(self.clock())

    def _audit(self, event_type, **details):
        # 深拷贝固化：审计事件不得随后续业务对象变更而改变（保证哈希链可重放）
        details = json.loads(json.dumps(details, ensure_ascii=False, default=_json_default))
        event = {
            "seq": len(self.events) + 1,
            "at": self.now(),
            "type": event_type,
            "details": details,
        }
        event["hash"] = hashlib.sha256(
            (self._prev_hash + _canonical({k: v for k, v in event.items()})).encode("utf-8")
        ).hexdigest()
        self.events.append(event)
        self._prev_hash = event["hash"]
        self._persist()
        return event

    def verify_audit_chain(self):
        """重放哈希链，返回 (是否完整, 首个断裂序号或 None)。"""
        prev = GENESIS_HASH
        for event in self.events:
            stored = event["hash"]
            body = {k: v for k, v in event.items() if k != "hash"}
            expected = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
            if not _constant_time_eq(stored, expected):
                return False, event["seq"]
            prev = stored
        return True, None

    # ------------------------------------------------------------ 持久化

    def _snapshot(self):
        return {
            "households": self.households,
            "members": self.members,
            "windows": self.windows,
            "quality": self.quality,
            "rules": self.rules,
            "consents": self.consents,
            "guardianships": self.guardianships,
            "contacts": self.contacts,
            "preferences": self.preferences,
            "candidates": self.candidates,
            "candidate_chain": {f"{k[0]}|{k[1]}": v for k, v in self.candidate_chain.items()},
            "reviews": self.reviews,
            "messages": self.messages,
            "tasks": self.tasks,
            "followups": self.followups,
            "escalations": self.escalations,
            "events": self.events,
            "prev_hash": self._prev_hash,
        }

    def _restore(self, data):
        self.households = data["households"]
        self.members = data["members"]
        self.windows = data["windows"]
        self.quality = data["quality"]
        self.rules = data["rules"]
        self.consents = data["consents"]
        self.guardianships = data["guardianships"]
        self.contacts = data["contacts"]
        self.preferences = data["preferences"]
        self.candidates = data["candidates"]
        self.candidate_chain = {
            tuple(k.split("|", 1)): v for k, v in data.get("candidate_chain", {}).items()
        }
        self.reviews = data["reviews"]
        self.messages = data["messages"]
        self.tasks = data["tasks"]
        self.followups = data["followups"]
        self.escalations = data["escalations"]
        self.events = data["events"]
        self._prev_hash = data.get("prev_hash", GENESIS_HASH)

    def save(self):
        self._persist(force=True)

    def _persist(self, force=False):
        if not self.path:
            return
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._snapshot(), fh, ensure_ascii=False)
        os.replace(tmp, self.path)

    def _load(self):
        with open(self.path, encoding="utf-8") as fh:
            self._restore(json.load(fh))

    # ------------------------------------------------------------ 主数据

    def register_household(self, household):
        with self.lock:
            hid = household["household_id"]
            self.households[hid] = {
                "household_id": hid,
                "community_id": household.get("community_id"),
            }
            self._audit("household_registered", household_id=hid)
            return hid

    def register_member(self, member):
        with self.lock:
            mid = member["member_id"]
            self.members[mid] = {
                "member_id": mid,
                "household_id": member["household_id"],
                "is_child": bool(member.get("is_child", False)),
                "pregnant": bool(member.get("pregnant", False)),
            }
            self._audit("member_registered", member_id=mid,
                        household_id=member["household_id"])
            return mid

    def add_consent(self, record):
        """登记同意版本：{consent_id, member_id, version, start, end, scope:{...}}。"""
        with self.lock:
            required = ("consent_id", "member_id", "version", "start")
            self._require_fields(record, required, "consent")
            for existing in self.consents:
                if existing["consent_id"] == record["consent_id"]:
                    raise DomainError("duplicate_consent", "同意版本 ID 已存在")
            row = {
                "consent_id": record["consent_id"],
                "member_id": record["member_id"],
                "version": record["version"],
                "start": record["start"],
                "end": record.get("end"),
                "scope": dict(record.get("scope", {"risk_notification": True})),
            }
            self.consents.append(row)
            self._audit("consent_version_added",
                        consent_id=row["consent_id"], member_id=row["member_id"],
                        version=row["version"])
            return row["consent_id"]

    def add_guardianship(self, record):
        with self.lock:
            self._require_fields(record, ("id", "guardian_member_id", "child_member_id", "start"),
                                 "guardianship")
            row = {
                "id": record["id"],
                "guardian_member_id": record["guardian_member_id"],
                "child_member_id": record["child_member_id"],
                "relation": record.get("relation", "guardian"),
                "start": record["start"],
                "end": record.get("end"),
            }
            self.guardianships.append(row)
            self._audit("guardianship_added", **row)
            return row["id"]

    def end_guardianship(self, guardianship_id, at=None, reason=""):
        """监护变更：终止关系并重排受影响家庭的未完成任务。"""
        with self.lock:
            at = at or self.now()
            row = self._find(self.guardianships, id=guardianship_id)
            if row["end"] is None or _parse(row["end"]) > _parse(at):
                row["end"] = at
            household_id = self.members[row["child_member_id"]]["household_id"]
            self._audit("guardianship_ended", guardianship_id=guardianship_id,
                        at=at, reason=reason)
            affected = self._reconcile_household(household_id, at,
                                                 reason="guardianship_change")
            return {"ended": guardianship_id, "rearranged_tasks": affected}

    def add_contact(self, record):
        with self.lock:
            self._require_fields(record, ("contact_id", "member_id", "channel", "start"),
                                 "contact")
            row = {
                "contact_id": record["contact_id"],
                "member_id": record["member_id"],
                "channel": record["channel"],
                "address": record.get("address", ""),
                "priority": int(record.get("priority", 100)),
                "start": record["start"],
                "end": record.get("end"),
                "bound_to_location": bool(record.get("bound_to_location", False)),
            }
            self.contacts.append(row)
            self._audit("contact_added", contact_id=row["contact_id"],
                        member_id=row["member_id"], channel=row["channel"])
            # 新联系方式当前有效时，自动恢复此前"等待通道"的挂起任务
            resumed = []
            if _valid_at(row, _parse(self.now())):
                resumed = self._resume_held_for_member(row["member_id"])
            return {"contact_id": row["contact_id"], "resumed_tasks": resumed}

    def invalidate_contact(self, contact_id, at=None, reason=""):
        """联系方式失效：仅重排尚未触达接收人的任务。"""
        with self.lock:
            at = at or self.now()
            row = self._find(self.contacts, contact_id=contact_id)
            if row["end"] is None or _parse(row["end"]) > _parse(at):
                row["end"] = at
            member = self.members[row["member_id"]]
            self._audit("contact_invalidated", contact_id=contact_id, at=at, reason=reason)
            affected = self._reconcile_household(member["household_id"], at,
                                                 reason="contact_invalid")
            return {"invalidated": contact_id, "rearranged_tasks": affected}

    def relocate_household(self, household_id, at=None):
        """家庭搬迁：位置绑定的联系方式失效，随后重排未完成任务。"""
        with self.lock:
            at = at or self.now()
            ended = []
            for contact in self.contacts:
                if (self.members[contact["member_id"]]["household_id"] == household_id
                        and contact.get("bound_to_location")
                        and _valid_at(contact, _parse(at))):
                    contact["end"] = at
                    ended.append(contact["contact_id"])
            self._audit("household_relocated", household_id=household_id,
                        at=at, ended_contacts=ended)
            affected = self._reconcile_household(household_id, at,
                                                 reason="household_relocated")
            return {"ended_contacts": ended, "rearranged_tasks": affected}

    def add_preference(self, record):
        """安全偏好：opt_out / 允许渠道 / 主题屏蔽，均为时态记录。"""
        with self.lock:
            self._require_fields(record, ("member_id", "start"), "preference")
            row = {
                "id": record.get("id", _new_id("pref")),
                "member_id": record["member_id"],
                "start": record["start"],
                "end": record.get("end"),
                "opt_out": bool(record.get("opt_out", False)),
                "allowed_channels": list(record.get("allowed_channels", [])),
                "blocked_topics": list(record.get("blocked_topics", [])),
            }
            self.preferences.append(row)
            self._audit("preference_added", **row)
            return row["id"]

    # ------------------------------------------------------------ 质量门槛

    def register_window(self, window):
        with self.lock:
            wid = window["window_id"]
            self._require_fields(window, ("window_id", "household_id", "start", "end"),
                                 "window")
            if wid in self.windows:
                raise DomainError("duplicate_window", "数据窗口已登记")
            self.windows[wid] = {
                "window_id": wid,
                "household_id": window["household_id"],
                "start": window["start"],
                "end": window["end"],
                "checks": list(window.get("checks", [])),
                "points": list(window.get("points", [])),
            }
            self._audit("window_registered", window_id=wid,
                        household_id=window["household_id"])
            return wid

    def evaluate_quality(self, window_id):
        """质量门槛：全部检查通过（且至少存在一项检查）才放行。"""
        with self.lock:
            window = self._require(self.windows, window_id, "window")
            checks = window["checks"]
            passed = len(checks) > 0 and all(c.get("passed") for c in checks)
            evaluation = {
                "window_id": window_id,
                "passed": passed,
                "at": self.now(),
                "checks": [
                    {"name": c["name"], "passed": bool(c.get("passed")),
                     "detail": c.get("detail", "")}
                    for c in checks
                ],
                "fingerprint": _fingerprint(checks),
            }
            self.quality[window_id] = evaluation
            self._audit("quality_evaluated", **evaluation)
            return evaluation

    # ------------------------------------------------------------ 规则与候选

    def register_rule(self, rule):
        """登记不可变规则版本；同 ID+版本内容也必须一致。"""
        with self.lock:
            self._require_fields(
                rule, ("rule_id", "version", "predicate", "risk_level", "template_id"),
                "rule")
            if rule["risk_level"] not in RISK_LEVELS:
                raise DomainError("bad_level", f"未知风险级别 {rule['risk_level']}")
            versions = self.rules.setdefault(rule["rule_id"], {})
            version = str(rule["version"])
            normalized = {
                "rule_id": rule["rule_id"],
                "version": version,
                "predicate": rule["predicate"],
                "params": dict(rule.get("params", {})),
                "risk_level": rule["risk_level"],
                "template_id": rule["template_id"],
            }
            if version in versions:
                if _canonical(versions[version]) != _canonical(normalized):
                    raise DomainError("rule_version_conflict",
                                      "同一规则版本内容不一致，版本不可变")
                return version
            versions[version] = normalized
            self._audit("rule_registered", **normalized)
            return version

    def _evaluate_rule(self, rule, window):
        params = rule["params"]
        metric = params.get("metric")
        threshold = float(params.get("threshold"))
        mode = rule["predicate"]  # max_threshold / mean_threshold
        per_member = {}
        for point in window["points"]:
            if metric is not None and point.get("metric") != metric:
                continue
            per_member.setdefault(point["member_id"], []).append(float(point["value"]))
        findings = []
        for member_id in sorted(per_member):
            values = per_member[member_id]
            score = max(values) if mode == "max_threshold" else sum(values) / len(values)
            if score >= threshold:
                findings.append({"member_id": member_id, "metric": metric,
                                 "value": round(score, 6)})
        return findings

    def _finding_set(self, findings):
        return sorted((f["member_id"], f["metric"], f["value"]) for f in findings)

    def run_rules(self, window_id=None):
        """只在通过质量门槛的窗口上运行；幂等，规则变化产生带差异的新候选。"""
        with self.lock:
            results = []
            window_ids = [window_id] if window_id else list(self.windows)
            for wid in window_ids:
                window = self._require(self.windows, wid, "window")
                quality = self.quality.get(wid) or self.evaluate_quality(wid)
                if not quality["passed"]:
                    self._audit("candidate_gate_rejected", window_id=wid,
                                quality_fingerprint=quality["fingerprint"])
                    continue
                for rule_id, versions in self.rules.items():
                    rule = versions[sorted(versions)[-1]]  # 最新版本
                    findings = self._evaluate_rule(rule, window)
                    if not findings:
                        continue
                    fingerprint = _fingerprint({
                        "window": wid, "rule": rule_id,
                        "version": rule["version"], "findings": self._finding_set(findings),
                    })
                    chain = self.candidate_chain.setdefault((wid, rule_id), [])
                    prior = next((self.candidates[c] for c in reversed(chain)
                                  if self.candidates[c]["fingerprint"] == fingerprint), None)
                    if prior is not None:
                        self._audit("candidate_deduped", window_id=wid, rule_id=rule_id,
                                    fingerprint=fingerprint, identical_to=prior["candidate_id"])
                        results.append({"candidate_id": prior["candidate_id"], "deduped": True})
                        continue
                    diff = None
                    if chain:
                        previous = self.candidates[chain[-1]]
                        prev_set = {x[0] for x in self._finding_set(previous["findings"])}
                        cur_set = {x[0] for x in self._finding_set(findings)}
                        diff = {
                            "rule_version_from": previous["rule_version"],
                            "rule_version_to": rule["version"],
                            "members_added": sorted(cur_set - prev_set),
                            "members_removed": sorted(prev_set - cur_set),
                            "level_changed": previous["risk_level"] != rule["risk_level"],
                        }
                    cid = _new_id("cand")
                    candidate = {
                        "candidate_id": cid,
                        "window_id": wid,
                        "household_id": window["household_id"],
                        "rule_id": rule_id,
                        "rule_version": rule["version"],
                        "risk_level": rule["risk_level"],
                        "template_id": rule["template_id"],
                        "findings": findings,
                        "exposure_start": window["start"],
                        "exposure_end": window["end"],
                        "quality_fingerprint": quality["fingerprint"],
                        "fingerprint": fingerprint,
                        "diff": diff,
                        "created_at": self.now(),
                    }
                    self.candidates[cid] = candidate
                    chain.append(cid)
                    self.reviews[cid] = {
                        "field": None, "ethics": None,
                        "completed_at": None,
                        "emergency": None,
                        "resolution": None,
                    }
                    self._audit("candidate_created",
                                **{k: v for k, v in candidate.items()})
                    results.append({"candidate_id": cid, "deduped": False, "diff": diff})
            return results

    # ------------------------------------------------------------ 授权解析

    def _consent_at(self, member_id, t: datetime):
        rows = [c for c in self.consents
                if c["member_id"] == member_id and _valid_at(c, t)]
        if not rows:
            return None
        return sorted(rows, key=lambda c: (c["version"], c["consent_id"]))[-1]

    def _preference_at(self, member_id, t: datetime):
        rows = [p for p in self.preferences
                if p["member_id"] == member_id and _valid_at(p, t)]
        return sorted(rows, key=lambda p: p["id"])[-1] if rows else None

    def resolve_recipients(self, candidate_id, at=None):
        """按暴露时 + 通知时双时点解析最小接收人，返回选择与完整证据。"""
        with self.lock:
            candidate = self._require(self.candidates, candidate_id, "candidate")
            notice_t = _parse(at) if at else _parse(self.now())
            exposure_t = _parse(candidate["exposure_start"])
            considerations = []
            selected = []

            for finding in candidate["findings"]:
                about = finding["member_id"]
                member = self.members[about]
                targets = []  # (接收人成员, 关系说明, 监护记录, 暴露时有效, 通知时有效)
                if member["is_child"]:
                    # 收集在任一相关时点存在过的监护关系，逐条留证两时点有效性
                    guards = [g for g in self.guardianships
                              if g["child_member_id"] == about
                              and (_valid_at(g, exposure_t) or _valid_at(g, notice_t))]
                    guards.sort(key=lambda g: (g["start"], g["id"]))
                    for g in guards:
                        targets.append((g["guardian_member_id"],
                                        f"guardian_of:{about}", g,
                                        _valid_at(g, exposure_t),
                                        _valid_at(g, notice_t)))
                else:
                    targets.append((about, "self", None, True, True))

                eligible = [t for t in targets if t[3] and t[4]]
                if not eligible:
                    considerations.append({
                        "about_member_id": about,
                        "recipient_member_id": None,
                        "role": "none",
                        "guardianship_id": None,
                        "guardianship_at_exposure": None,
                        "guardianship_at_notice": None,
                        "included": False,
                        "exclusion_reasons": ["no_relationship_valid_at_both_times"],
                    })

                chosen_recipient = eligible[0][0] if eligible else None
                for recipient_id, role, guardianship, g_at_exp, g_at_now in targets:
                    entry = {
                        "about_member_id": about,
                        "recipient_member_id": recipient_id,
                        "role": role,
                        "guardianship_id": guardianship["id"] if guardianship else None,
                        "guardianship_at_exposure": g_at_exp,
                        "guardianship_at_notice": g_at_now,
                    }
                    reasons = []
                    if member["is_child"] and not (g_at_exp and g_at_now):
                        reasons.append("relationship_not_valid_at_both_times")

                    c_exp = self._consent_at(recipient_id, exposure_t)
                    c_now = self._consent_at(recipient_id, notice_t)
                    entry["consent_at_exposure"] = c_exp["consent_id"] if c_exp else None
                    entry["consent_version_at_exposure"] = c_exp["version"] if c_exp else None
                    entry["consent_at_notice"] = c_now["consent_id"] if c_now else None
                    entry["consent_version_at_notice"] = c_now["version"] if c_now else None

                    # 数据主体（儿童）自身的同意范围在两个时点也必须覆盖研究通知
                    subject_exp = self._consent_at(about, exposure_t)
                    subject_now = self._consent_at(about, notice_t)
                    entry["subject_consent_at_exposure"] = subject_exp["consent_id"] if subject_exp else None
                    entry["subject_consent_at_notice"] = subject_now["consent_id"] if subject_now else None

                    scope_ok = lambda c: bool(c and c["scope"].get("risk_notification", True))
                    consent_failed = False
                    if member["is_child"]:
                        if not (scope_ok(c_exp) and scope_ok(c_now)
                                and scope_ok(subject_exp) and scope_ok(subject_now)):
                            consent_failed = True
                    else:
                        if not (scope_ok(c_exp) and scope_ok(c_now)):
                            consent_failed = True
                    if consent_failed:
                        reasons.append("consent_scope")

                    pref = self._preference_at(recipient_id, notice_t)
                    entry["preference_id"] = pref["id"] if pref else None
                    allowed_channels = pref["allowed_channels"] if pref else []
                    if pref and pref.get("opt_out"):
                        reasons.append("opt_out")

                    contact = self._pick_contact(recipient_id, notice_t, allowed_channels)
                    entry["contact_id"] = contact["contact_id"] if contact else None
                    entry["channel"] = contact["channel"] if contact else None
                    if contact is None:
                        reasons.append("no_available_channel")

                    # 儿童：只保留确定性选出的第一名监护人，其余留证但不发送
                    included = not reasons
                    if member["is_child"] and recipient_id != chosen_recipient:
                        included = False
                        if "minimized_single_guardian" not in reasons:
                            reasons.append("minimized_single_guardian")

                    entry["included"] = included
                    entry["exclusion_reasons"] = reasons
                    considerations.append(entry)
                    if included:
                        selected.append({
                            "about_member_id": about,
                            "recipient_member_id": recipient_id,
                            "contact_id": contact["contact_id"],
                            "channel": contact["channel"],
                            "guardianship_id": guardianship["id"] if guardianship else None,
                        })

            evidence = {
                "candidate_id": candidate_id,
                "exposure_at": candidate["exposure_start"],
                "resolved_at": self.now() if not at else at,
                "considerations": considerations,
                "selected": selected,
            }
            return evidence

    def _pick_contact(self, member_id, t: datetime, allowed_channels):
        rows = [c for c in self.contacts
                if c["member_id"] == member_id and _valid_at(c, t)
                and (not allowed_channels or c["channel"] in allowed_channels)]
        rows.sort(key=lambda c: (c["priority"], c["contact_id"]))
        return rows[0] if rows else None

    # ------------------------------------------------------------ 两级复核

    def field_confirm(self, candidate_id, researcher_id, notes=""):
        with self.lock:
            self._require(self.candidates, candidate_id, "candidate")
            review = self.reviews[candidate_id]
            if review["field"] is not None:
                raise DomainError("already_confirmed", "现场确认已存在，不可改写")
            review["field"] = {"by": researcher_id, "at": self.now(), "notes": notes}
            self._audit("field_confirmed", candidate_id=candidate_id,
                        researcher_id=researcher_id, notes=notes)
            self._maybe_complete(candidate_id)
            return review["field"]

    def ethics_approve(self, candidate_id, officer_id, level=None, notes=""):
        with self.lock:
            candidate = self._require(self.candidates, candidate_id, "candidate")
            review = self.reviews[candidate_id]
            if review["ethics"] is not None:
                raise DomainError("already_approved", "伦理批准已存在，不可改写")
            level = level or candidate["risk_level"]
            if level not in RISK_LEVELS:
                raise DomainError("bad_level", f"未知风险级别 {level}")
            review["ethics"] = {"by": officer_id, "at": self.now(),
                                "level": level, "notes": notes}
            self._audit("ethics_approved", candidate_id=candidate_id,
                        officer_id=officer_id, level=level, notes=notes)
            self._maybe_complete(candidate_id)
            return self._issue_messages(candidate_id)

    def send_emergency_notice(self, candidate_id, actor_id):
        """紧急路径：复核完成前先发最低必要提示；复核必须在 SLA 内补齐。"""
        with self.lock:
            candidate = self._require(self.candidates, candidate_id, "candidate")
            review = self.reviews[candidate_id]
            if LEVEL_RANK[candidate["risk_level"]] < LEVEL_RANK["emergency"]:
                raise DomainError("not_emergency", "仅紧急风险可走先发路径")
            if review["emergency"] is not None:
                raise DomainError("emergency_already_sent", "紧急提示已发送")
            review["emergency"] = {
                "by": actor_id,
                "sent_at": self.now(),
                "review_due_at": _iso(_parse(self.now()) + timedelta(seconds=REVIEW_SLA_SECONDS)),
                "completed_at": None,
            }
            issued = self._issue_messages(candidate_id, provisional=True)
            self._audit("emergency_notice_sent", candidate_id=candidate_id,
                        actor_id=actor_id, review_due_at=review["emergency"]["review_due_at"],
                        message_ids=[m["message_id"] for m in issued])
            return issued

    def _maybe_complete(self, candidate_id):
        review = self.reviews[candidate_id]
        if review["field"] and review["ethics"] and review["completed_at"] is None:
            review["completed_at"] = self.now()
            if review["emergency"] is not None and review["emergency"]["completed_at"] is None:
                review["emergency"]["completed_at"] = review["completed_at"]
            self._audit("review_completed", candidate_id=candidate_id, at=review["completed_at"])

    def review_status(self, candidate_id):
        with self.lock:
            candidate = self._require(self.candidates, candidate_id, "candidate")
            review = self.reviews[candidate_id]
            return {
                "candidate_id": candidate_id,
                "field_confirmed": review["field"] is not None,
                "ethics_approved": review["ethics"] is not None,
                "completed": review["completed_at"] is not None,
                "emergency": review["emergency"],
            }

    # ------------------------------------------------------------ 消息与任务

    def _render_body(self, candidate, about_id, recipient_id, provisional):
        member = self.members[about_id]
        if about_id == recipient_id:
            who = "您本人"
        elif member["is_child"]:
            who = "您监护的儿童"
        else:
            who = "您的家庭成员"
        if provisional:
            subject = "【紧急】请立即开窗通风并带离烟雾环境"
            body = (f"{who}所在居室刚出现高危烟雾信号，请立即开窗通风、远离吸烟点。"
                    "详细健康建议将在复核后补发。")
        else:
            level_text = {"info": "提示", "advisory": "建议", "urgent": "较高",
                          "emergency": "紧急"}[candidate["risk_level"]]
            subject = f"【{level_text}暴露提醒】请改善室内通风"
            body = (f"研究传感器显示{who}在近期一个持续时段内处于较高二手烟暴露水平。"
                    "建议避免室内吸烟、加强通风；如需帮助可联系现场研究员。"
                    "回复 N 可拒收后续通知。")
        return subject, body

    def _issue_messages(self, candidate_id, provisional=False):
        candidate = self._require(self.candidates, candidate_id, "candidate")
        review = self.reviews[candidate_id]
        if not provisional and review["completed_at"] is None:
            raise DomainError("review_incomplete", "两级复核未完成，不得生成正式通知")

        evidence = self.resolve_recipients(candidate_id)
        review["resolution"] = evidence
        issued = []

        def _already_exists(about_id, recipient_id, provisional_flag):
            return any(
                m["candidate_id"] == candidate_id
                and m["about_member_id"] == about_id
                and m["recipient_member_id"] == recipient_id
                and m["provisional"] is provisional_flag
                for m in self.messages.values())

        for sel in evidence["selected"]:
            # 幂等：同阶段（紧急提示/正式通知）消息只生成一次，补齐复核不重复打扰
            if _already_exists(sel["about_member_id"], sel["recipient_member_id"], provisional):
                continue
            subject, body = self._render_body(
                candidate, sel["about_member_id"], sel["recipient_member_id"], provisional)
            level = review["ethics"]["level"] if review["ethics"] else candidate["risk_level"]

            # 同一风险窗口重算（含规则版本变化）：内容实质未变且已触达，则不重复打扰
            content_key = _fingerprint({
                "about": sel["about_member_id"], "recipient": sel["recipient_member_id"],
                "level": level, "template": candidate["template_id"],
                "provisional": provisional, "subject": subject, "body": body,
            })
            if self._was_notified_with_content(candidate["window_id"], content_key):
                self._audit("notification_suppressed_unchanged",
                            candidate_id=candidate_id,
                            about_member_id=sel["about_member_id"],
                            recipient_member_id=sel["recipient_member_id"],
                            content_fingerprint=content_key)
                continue

            fp_payload = {
                "candidate": candidate_id,
                "about": sel["about_member_id"],
                "recipient": sel["recipient_member_id"],
                "level": level,
                "template": candidate["template_id"],
                "provisional": provisional,
                "subject": subject, "body": body,
            }
            fingerprint = _fingerprint(fp_payload)

            follows = None
            if not provisional:
                prior_provisional = next((m for m in self.messages.values()
                                          if m["candidate_id"] == candidate_id
                                          and m["about_member_id"] == sel["about_member_id"]
                                          and m["recipient_member_id"] == sel["recipient_member_id"]
                                          and m["provisional"]), None)
                if prior_provisional is not None:
                    follows = prior_provisional["message_id"]
                    prior_provisional["finalized_at"] = self.now()

            mid = _new_id("msg")
            message = {
                "message_id": mid,
                "candidate_id": candidate_id,
                "about_member_id": sel["about_member_id"],
                "recipient_member_id": sel["recipient_member_id"],
                "contact_id": sel["contact_id"],
                "channel": sel["channel"],
                "subject": subject,
                "body": body,
                "risk_level": fp_payload["level"],
                "template_id": candidate["template_id"],
                "provisional": provisional,
                "finalized_at": None,
                "follows_message_id": follows,
                "fingerprint": fingerprint,
                "content_fingerprint": content_key,
                "created_at": self.now(),
            }
            self.messages[mid] = message
            task = self._create_task(message)
            issued.append(message)
            self._audit("message_snapshot_created",
                        message_id=mid, candidate_id=candidate_id,
                        about_member_id=sel["about_member_id"],
                        recipient_member_id=sel["recipient_member_id"],
                        channel=sel["channel"], fingerprint=fingerprint,
                        provisional=provisional, task_id=task["task_id"],
                        follows_message_id=follows,
                        resolution_evidence=evidence)
        return issued

    def _was_notified_with_content(self, window_id, content_fingerprint):
        """同窗口内是否已有相同实质内容的消息触达（sent 即视为已打扰）。"""
        candidate_ids = {c["candidate_id"] for c in self.candidates.values()
                         if c["window_id"] == window_id}
        touched = {t["message_id"] for t in self.tasks.values()
                   if t["candidate_id"] in candidate_ids and t["status"] in FROZEN_STATES}
        return any(m["message_id"] in touched
                   and m.get("content_fingerprint") == content_fingerprint
                   for m in self.messages.values()
                   if m["candidate_id"] in candidate_ids)

    def _create_task(self, message):
        tid = _new_id("task")
        now = self.now()
        task = {
            "task_id": tid,
            "message_id": message["message_id"],
            "candidate_id": message["candidate_id"],
            "recipient_member_id": message["recipient_member_id"],
            "about_member_id": message["about_member_id"],
            "contact_id": message["contact_id"],
            "channel": message["channel"],
            "status": TASK_PENDING,
            "attempts": 0,
            "not_before": now,
            "escalate_at": _iso(_parse(now) + timedelta(seconds=TASK_ESCALATE_SECONDS)),
            "receipt_token": uuid.uuid4().hex,
            "provider_ref": None,
            "last_error": None,
            "created_at": now,
            "sent_at": None,
            "finalized_at": None,
        }
        self.tasks[tid] = task
        return task

    # ------------------------------------------------------------ 投递

    def _default_transport(self, contact, message):
        return {"ok": True, "provider_ref": _new_id("ref")}

    def deliver_due(self, now=None):
        """尝试投递所有到期的待发任务；由 sweep 与接口共同驱动，重启后可续跑。"""
        with self.lock:
            moment = _parse(now) if now else _parse(self.now())
            acted = []
            for task in self.tasks.values():
                if task["status"] != TASK_PENDING:
                    continue
                if task.get("held_reason"):
                    continue  # 挂起等待通道/授权，不空耗投递尝试
                if _parse(task["not_before"]) > moment:
                    continue
                acted.append(self._attempt(task, moment))
            return acted

    def _attempt(self, task, moment):
        message = self.messages[task["message_id"]]
        contact = next((c for c in self.contacts if c["contact_id"] == task["contact_id"]), None)
        task["attempts"] += 1
        try:
            if contact is None or not _valid_at(contact, moment):
                raise RuntimeError("contact_unavailable")
            transport = self.transport or self._default_transport
            result = transport(contact, message)
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "transport_failed"))
        except Exception as exc:  # 通道异常 -> 失败重试/后续流程
            task["last_error"] = str(exc)
            if task["attempts"] >= MAX_ATTEMPTS or contact is None:
                task["status"] = TASK_FAILED
                task["finalized_at"] = self.now()
                self._open_followup("failure", task, reason=str(exc))
                self._audit("delivery_failed", task_id=task["task_id"],
                            attempts=task["attempts"], error=str(exc))
            else:
                backoff = BACKOFF_SECONDS * (2 ** (task["attempts"] - 1))
                task["not_before"] = _iso(moment + timedelta(seconds=backoff))
                self._audit("delivery_retry_scheduled", task_id=task["task_id"],
                            attempts=task["attempts"], not_before=task["not_before"])
            return {"task_id": task["task_id"], "status": task["status"]}

        task["status"] = TASK_SENT
        task["provider_ref"] = result.get("provider_ref")
        task["sent_at"] = self.now()
        self._audit("delivery_sent", task_id=task["task_id"],
                    message_id=task["message_id"], provider_ref=task["provider_ref"],
                    fingerprint=message["fingerprint"])
        return {"task_id": task["task_id"], "status": TASK_SENT}

    def record_receipt(self, task_id, receipt_status, token=None, source="recipient"):
        """登记回执：delivered / refused；与现状冲突进入对账流程。"""
        with self.lock:
            task = self._require(self.tasks, task_id, "task")
            if token is not None and token != task["receipt_token"]:
                raise DomainError("bad_receipt_token", "回执令牌不匹配")
            status = task["status"]

            if receipt_status == "delivered":
                if status == TASK_DELIVERED:
                    return {"task_id": task_id, "status": status, "idempotent": True}
                if status == TASK_REFUSED:
                    self._open_followup("receipt_conflict", task,
                                        reason="delivered_after_refusal", source=source)
                    return {"task_id": task_id, "status": status, "conflict": True}
                if status != TASK_SENT:
                    self._open_followup("receipt_conflict", task,
                                        reason=f"delivered_while_{status}", source=source)
                    return {"task_id": task_id, "status": status, "conflict": True}
                task["status"] = TASK_DELIVERED
                task["finalized_at"] = self.now()
                self._audit("receipt_delivered", task_id=task_id,
                            candidate_id=task["candidate_id"], source=source)
                return {"task_id": task_id, "status": TASK_DELIVERED}

            if receipt_status == "refused":
                if status == TASK_REFUSED:
                    return {"task_id": task_id, "status": status, "idempotent": True}
                if status == TASK_DELIVERED:
                    self._open_followup("receipt_conflict", task,
                                        reason="refusal_after_delivery", source=source)
                    return {"task_id": task_id, "status": status, "conflict": True}
                if status == TASK_SENT:
                    # 已发出后被拒收：内容冻结不可改写
                    task["status"] = TASK_REFUSED
                    task["finalized_at"] = self.now()
                    self._open_followup("refusal", task,
                                        reason="recipient_refused", source=source)
                    self._audit("receipt_refused", task_id=task_id,
                                candidate_id=task["candidate_id"], source=source,
                                previously_sent=True)
                    return {"task_id": task_id, "status": TASK_REFUSED}
                if status in (TASK_PENDING, TASK_FAILED):
                    # 尚未触达接收人即拒收：取消任务（内容从未送达），走拒收流程
                    task["status"] = TASK_CANCELLED
                    task["finalized_at"] = self.now()
                    self._open_followup("refusal", task,
                                        reason="refused_before_delivery", source=source)
                    self._audit("receipt_refused_before_delivery", task_id=task_id,
                                candidate_id=task["candidate_id"], source=source)
                    return {"task_id": task_id, "status": TASK_CANCELLED}
                self._open_followup("receipt_conflict", task,
                                    reason=f"refusal_while_{status}", source=source)
                return {"task_id": task_id, "status": status, "conflict": True}

            if receipt_status == "failed":
                if status in (TASK_SENT, TASK_DELIVERED, TASK_REFUSED):
                    self._open_followup("receipt_conflict", task,
                                        reason=f"failure_while_{status}", source=source)
                    return {"task_id": task_id, "status": status, "conflict": True}
                task["last_error"] = "provider_failure_receipt"
                task["status"] = TASK_FAILED
                task["finalized_at"] = self.now()
                self._open_followup("failure", task, reason="provider_failure_receipt")
                self._audit("receipt_failed", task_id=task_id,
                            candidate_id=task["candidate_id"], source=source)
                return {"task_id": task_id, "status": TASK_FAILED}

            raise DomainError("bad_receipt", f"未知回执状态 {receipt_status}")

    def _open_followup(self, kind, task, reason, source=""):
        record = {
            "followup_id": _new_id("fu"),
            "kind": kind,  # refusal / failure / receipt_conflict
            "task_id": task["task_id"],
            "candidate_id": task["candidate_id"],
            "reason": reason,
            "source": source,
            "status": "open",
            "created_at": self.now(),
            "resolution": None,
        }
        self.followups.append(record)
        self._audit("followup_opened", **record)
        return record

    def resolve_followup(self, followup_id, resolution, actor_id):
        with self.lock:
            row = self._find(self.followups, followup_id=followup_id)
            if row["status"] != "open":
                raise DomainError("followup_closed", "后续流程已关闭")
            row["status"] = "resolved"
            row["resolution"] = {"by": actor_id, "at": self.now(), "action": resolution}
            self._audit("followup_resolved", followup_id=followup_id,
                        resolution=row["resolution"])
            # 拒收处理落地为安全偏好（opt_out），并立即停止该成员其他未发出任务
            rearranged = []
            if row["kind"] == "refusal" and resolution.get("register_opt_out"):
                task = self.tasks[row["task_id"]]
                pref_id = self.add_preference({
                    "member_id": task["recipient_member_id"],
                    "start": self.now(),
                    "opt_out": True,
                })
                row["resolution"]["preference_id"] = pref_id
                household_id = self.members[task["recipient_member_id"]]["household_id"]
                rearranged = self._reconcile_household(
                    household_id, self.now(), reason="opt_out_after_refusal")
                row["resolution"]["rearranged_tasks"] = rearranged
            return row

    def reconcile_receipt(self, task_id, decision, actor_id):
        """回执冲突人工对账：delivered / refused 为终局判定。"""
        with self.lock:
            task = self._require(self.tasks, task_id, "task")
            conflicts = [f for f in self.followups
                         if f["task_id"] == task_id and f["kind"] == "receipt_conflict"
                         and f["status"] == "open"]
            if not conflicts:
                raise DomainError("no_conflict", "该任务没有待对账的回执冲突")
            if decision not in ("delivered", "refused"):
                raise DomainError("bad_decision", "对账判定必须是 delivered 或 refused")
            task["status"] = TASK_DELIVERED if decision == "delivered" else TASK_REFUSED
            task["finalized_at"] = self.now()
            for row in conflicts:
                row["status"] = "resolved"
                row["resolution"] = {"by": actor_id, "at": self.now(), "decision": decision}
            self._audit("receipt_reconciled", task_id=task_id, decision=decision,
                        followup_ids=[f["followup_id"] for f in conflicts])
            return {"task_id": task_id, "status": task["status"]}

    # ------------------------------------------------------------ 重排

    def _resume_held_for_member(self, member_id):
        """新联系方式就绪后，恢复该成员仍挂起等待通道的任务。"""
        resumed = []
        for task in self.tasks.values():
            if (task["recipient_member_id"] == member_id
                    and task["status"] == TASK_PENDING
                    and task.get("held_reason") == "no_available_channel"):
                # 重新解析，确认授权/关系仍成立并选取当前通道
                evidence = self.resolve_recipients(task["candidate_id"])
                sel = next((s for s in evidence["selected"]
                            if s["about_member_id"] == task["about_member_id"]
                            and s["recipient_member_id"] == member_id), None)
                if sel is None:
                    continue
                task["contact_id"] = sel["contact_id"]
                task["channel"] = sel["channel"]
                task["not_before"] = self.now()
                task.pop("held_reason", None)
                resumed.append(task["task_id"])
                self._audit("task_resumed_with_channel", task_id=task["task_id"],
                            contact_id=sel["contact_id"])
        return resumed

    def reroute_task(self, task_id, contact_id=None, reason="manual_reroute"):
        """失败任务换用备用联系方式；任务未触达，消息快照不变。"""
        with self.lock:
            task = self._require(self.tasks, task_id, "task")
            if task["status"] not in UNFINISHED_STATES:
                raise DomainError("task_not_reroutable",
                                  f"任务处于 {task['status']}，不可重排")
            if contact_id is None:
                member_id = task["recipient_member_id"]
                alt = next((c for c in sorted(self.contacts,
                                              key=lambda c: (c["priority"], c["contact_id"]))
                            if c["member_id"] == member_id
                            and c["contact_id"] != task["contact_id"]
                            and _valid_at(c, _parse(self.now()))), None)
                if alt is None:
                    raise DomainError("no_alternate_contact", "无可用备用联系方式")
                contact_id = alt["contact_id"]
            new_contact = self._find(self.contacts, contact_id=contact_id)
            if new_contact["member_id"] != task["recipient_member_id"]:
                raise DomainError("contact_member_mismatch", "备用联系方式不属于原接收人")
            task["contact_id"] = contact_id
            task["channel"] = new_contact["channel"]
            task["status"] = TASK_PENDING
            task["attempts"] = 0
            task["last_error"] = None
            task["not_before"] = self.now()
            task["escalate_at"] = _iso(
                _parse(self.now()) + timedelta(seconds=TASK_ESCALATE_SECONDS))
            self._audit("task_rerouted", task_id=task_id, contact_id=contact_id, reason=reason)
            return task

    def _reconcile_household(self, household_id, at, reason):
        """联系方式失效/监护变更/搬迁：只重排未触达任务，已送达内容保持原样。"""
        at = _parse(at) if isinstance(at, str) else at
        rearranged = []
        candidates = [c for c in self.candidates.values()
                      if c["household_id"] == household_id
                      and self.reviews[c["candidate_id"]]["completed_at"] is not None]
        for candidate in candidates:
            cid = candidate["candidate_id"]
            evidence = self.resolve_recipients(cid, at=_iso(at))
            selected_pairs = {(s["about_member_id"], s["recipient_member_id"]): s
                              for s in evidence["selected"]}
            # 逐接收人留证：区分"授权/关系失效"与"仅暂无可用通道"
            consideration_by_pair = {}
            for entry in evidence["considerations"]:
                if entry.get("recipient_member_id") is None:
                    continue
                key = (entry["about_member_id"], entry["recipient_member_id"])
                consideration_by_pair.setdefault(key, []).append(entry)
            for task in list(self.tasks.values()):
                if task["candidate_id"] != cid:
                    continue
                if task["status"] not in UNFINISHED_STATES:
                    continue  # 已发送/送达/拒收：冻结，不重写
                pair = (task["about_member_id"], task["recipient_member_id"])
                if pair not in selected_pairs:
                    entries = consideration_by_pair.get(pair, [])
                    reasons = {r for e in entries for r in e.get("exclusion_reasons", [])}
                    if reasons and reasons <= {"no_available_channel"}:
                        # 授权仍在，仅通道暂缺：挂起任务等待新联系方式，时限继续推进
                        task["held_reason"] = "no_available_channel"
                        rearranged.append({"task_id": task["task_id"],
                                           "action": "held_awaiting_channel"})
                        self._audit("task_held_awaiting_channel",
                                    task_id=task["task_id"], reason=reason)
                        continue
                    task["status"] = TASK_SUPERSEDED
                    task["finalized_at"] = self.now()
                    task.pop("held_reason", None)
                    rearranged.append({"task_id": task["task_id"], "action": "superseded"})
                    self._audit("task_superseded", task_id=task["task_id"], reason=reason,
                                exclusion_reasons=sorted(reasons))
                    continue
                target = selected_pairs[pair]
                if target["contact_id"] != task["contact_id"] or task.get("held_reason"):
                    task["contact_id"] = target["contact_id"]
                    task["channel"] = target["channel"]
                    task["status"] = TASK_PENDING
                    task["not_before"] = _iso(at)
                    task.pop("held_reason", None)
                    rearranged.append({"task_id": task["task_id"],
                                       "action": "recontacted",
                                       "contact_id": target["contact_id"]})
                    self._audit("task_recontacted", task_id=task["task_id"],
                                contact_id=target["contact_id"], reason=reason)
            # 新增的合法接收人（例如新监护生效）补排任务，复用既有审批与消息模板
            open_pairs = {(t["about_member_id"], t["recipient_member_id"])
                          for t in self.tasks.values()
                          if t["candidate_id"] == cid and t["status"] not in FINAL_STATES}
            frozen_pairs = {(t["about_member_id"], t["recipient_member_id"])
                            for t in self.tasks.values()
                            if t["candidate_id"] == cid and t["status"] in FROZEN_STATES}
            for pair, sel in selected_pairs.items():
                if pair in open_pairs or pair in frozen_pairs:
                    continue
                self._issue_one_message(candidate, sel, evidence, reason)
                rearranged.append({"pair": pair, "action": "new_task"})
        return rearranged

    def _issue_one_message(self, candidate, sel, evidence, reason):
        review = self.reviews[candidate["candidate_id"]]
        subject, body = self._render_body(
            candidate, sel["about_member_id"], sel["recipient_member_id"], False)
        level = review["ethics"]["level"] if review["ethics"] else candidate["risk_level"]
        content_key = _fingerprint({
            "about": sel["about_member_id"], "recipient": sel["recipient_member_id"],
            "level": level, "template": candidate["template_id"],
            "provisional": False, "subject": subject, "body": body})
        mid = _new_id("msg")
        message = {
            "message_id": mid,
            "candidate_id": candidate["candidate_id"],
            "about_member_id": sel["about_member_id"],
            "recipient_member_id": sel["recipient_member_id"],
            "contact_id": sel["contact_id"],
            "channel": sel["channel"],
            "subject": subject,
            "body": body,
            "risk_level": level,
            "template_id": candidate["template_id"],
            "provisional": False,
            "finalized_at": self.now(),
            "follows_message_id": None,
            "fingerprint": content_key,
            "content_fingerprint": content_key,
            "created_at": self.now(),
        }
        self.messages[mid] = message
        task = self._create_task(message)
        self._audit("message_snapshot_created", message_id=mid,
                    candidate_id=candidate["candidate_id"],
                    about_member_id=sel["about_member_id"],
                    recipient_member_id=sel["recipient_member_id"],
                    channel=sel["channel"], fingerprint=message["fingerprint"],
                    provisional=False, task_id=task["task_id"],
                    reason=reason, resolution_evidence=evidence)

    # ------------------------------------------------------------ 升级/扫表

    def sweep(self, now=None):
        """推进到期事项：紧急复核 SLA、投递升级、到期重试。重启后继续有效。"""
        with self.lock:
            moment = _parse(now) if now else _parse(self.now())
            result = {"sent": [], "escalations": []}

            for cid, review in self.reviews.items():
                em = review["emergency"]
                if em and em["completed_at"] is None and _parse(em["review_due_at"]) <= moment:
                    if not any(e.get("candidate_id") == cid and e["kind"] == "review_overdue"
                               and e["status"] == "open" for e in self.escalations):
                        record = {"escalation_id": _new_id("esc"), "kind": "review_overdue",
                                  "candidate_id": cid, "at": self.now(), "status": "open"}
                        self.escalations.append(record)
                        result["escalations"].append(record)
                        self._audit("escalation_opened", **record)

            result["sent"] = self.deliver_due(now=_iso(moment))

            for task in self.tasks.values():
                # 升级时限：仍未发出（pending），或已失败但补救流程长时间无人接手；
                # 已发出等待回执、已送达/拒收/取消/作废均不在投递升级范围。
                overdue_eligible = task["status"] == TASK_PENDING or (
                    task["status"] == TASK_FAILED
                    and any(f["task_id"] == task["task_id"] and f["kind"] == "failure"
                            and f["status"] == "open" for f in self.followups))
                if overdue_eligible and task.get("escalate_at"):
                    if _parse(task["escalate_at"]) <= moment and not any(
                            e.get("task_id") == task["task_id"] and e["status"] == "open"
                            for e in self.escalations):
                        kind = ("delivery_overdue" if task["status"] == TASK_PENDING
                                else "remediation_overdue")
                        record = {"escalation_id": _new_id("esc"), "kind": kind,
                                  "task_id": task["task_id"], "candidate_id": task["candidate_id"],
                                  "at": self.now(), "status": "open"}
                        self.escalations.append(record)
                        result["escalations"].append(record)
                        self._audit("escalation_opened", **record)
            return result

    def resolve_escalation(self, escalation_id, actor_id, note=""):
        with self.lock:
            row = self._find(self.escalations, escalation_id=escalation_id)
            row["status"] = "resolved"
            row["resolution"] = {"by": actor_id, "at": self.now(), "note": note}
            self._audit("escalation_resolved", **row)
            return row

    # ------------------------------------------------------------ 汇总/审计视图

    def community_summary(self, k=DEFAULT_K):
        """社区级计数：低于隐私门槛 k 的单元抑制，只返回达标数量。"""
        def _cell():
            return {"candidates": 0, "notified_tasks": 0, "households": set()}

        counts = {}
        for candidate in self.candidates.values():
            household = self.households[candidate["household_id"]]
            comm = household.get("community_id") or "unknown"
            cell = counts.setdefault(comm, _cell())
            cell["candidates"] += 1
            cell["households"].add(candidate["household_id"])
        for task in self.tasks.values():
            if task["status"] in (TASK_SENT, TASK_DELIVERED):
                candidate = self.candidates[task["candidate_id"]]
                comm = (self.households[candidate["household_id"]].get("community_id")
                        or "unknown")
                counts.setdefault(comm, _cell())["notified_tasks"] += 1

        summary = {}
        for comm, cell in counts.items():
            suppressed = False
            row = {}
            for metric in ("candidates", "notified_tasks", "households"):
                value = len(cell[metric]) if metric == "households" else cell[metric]
                if 0 < value < k:
                    suppressed = True
                    row[metric] = None  # None 表示因隐私门槛抑制
                else:
                    row[metric] = value
            row["suppressed"] = suppressed
            summary[comm] = row
        return {"k": k, "communities": summary}

    def notification_trace(self, candidate_id):
        """从一次通知追到：数据质量、规则、授权、接收人选择、消息内容与确认。"""
        with self.lock:
            candidate = self._require(self.candidates, candidate_id, "candidate")
            quality = self.quality.get(candidate["window_id"])
            review = self.reviews[candidate_id]
            review_view = {
                "field": review["field"],
                "ethics": review["ethics"],
                "completed": review["completed_at"] is not None,
                "completed_at": review["completed_at"],
                "emergency": review["emergency"],
                "resolution": review["resolution"],
            }
            messages = [m for m in self.messages.values() if m["candidate_id"] == candidate_id]
            tasks = [t for t in self.tasks.values() if t["candidate_id"] == candidate_id]
            return {
                "candidate": candidate,
                "quality_gate": quality,
                "rule": self.rules[candidate["rule_id"]][candidate["rule_version"]],
                "review": review_view,
                "messages": messages,
                "tasks": tasks,
                "audit_events": [
                    {"seq": e["seq"], "at": e["at"], "type": e["type"],
                     "hash": e["hash"][:12]}
                    for e in self.events
                    if e["details"].get("candidate_id") == candidate_id
                    or e["details"].get("window_id") == candidate["window_id"]
                ],
            }

    # ------------------------------------------------------------ 辅助

    def _require_fields(self, record, fields, kind):
        missing = [f for f in fields if record.get(f) in (None, "")]
        if missing:
            raise DomainError("bad_request", f"{kind} 缺少字段: {', '.join(missing)}")

    def _require(self, table, key, kind):
        if key not in table:
            raise DomainError("not_found", f"{kind} 不存在: {key}")
        return table[key]

    def _find(self, rows, **criteria):
        for row in rows:
            if all(row.get(k) == v for k, v in criteria.items()):
                return row
        raise DomainError("not_found", f"未找到匹配记录: {criteria}")


def _constant_time_eq(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0
