"""最小接收人解析。

对同一风险窗口，按"暴露发生时"与"通知发出时"两个时点的
同意版本、监护关系与安全偏好，求出覆盖全部受影响成员所需的
最小接收人集合；每个被排除的成员都记录可审计的理由。

授权规则：
- 成年/孕期成员：本人接收，要求"self"同意在两个时点均有效。
- 儿童：由监护人接收，要求监护关系在两个时点均有效，且监护人
  对该儿童的同意（child:<id> 或 dependents）在两个时点均有效。
- 安全偏好以通知时为准：do_not_contact 绝对排除；min_level 过滤
  低级别通知；allowed_channels 与同意渠道、有效联系方式求交。
"""

from . import timeutil

URGENT = "urgent"
ROUTINE = "routine"

_LEVEL_RANK = {ROUTINE: 1, URGENT: 2}


def _consent_covers(consents, scope_pred):
    return [c for c in consents if any(scope_pred(s) for s in c["scope"])]


def _self_scope(scope):
    return scope == "self"


def _child_scope(child_id):
    return lambda scope: scope == "dependents" or scope == f"child:{child_id}"


def _authorized_recipients(state, member, exposure_at, notify_at):
    """返回 (候选接收人列表, 排除理由或 None)。

    候选接收人: {"person_id", "consent_ids", "guardianship_ids"}
    """
    role = member["role"]
    if role in ("adult", "pregnant_adult"):
        versions = state.consent_versions_between(member["member_id"], exposure_at, notify_at)
        at_exp = _consent_covers(versions["at_exposure"], _self_scope)
        at_now = _consent_covers(versions["at_notify"], _self_scope)
        if not at_exp:
            return [], "暴露发生时本人无有效 self 同意"
        if not at_now:
            return [], "通知时本人 self 同意已失效或被撤回"
        return [
            {
                "person_id": member["member_id"],
                "consent_ids": sorted({c["consent_id"] for c in at_exp + at_now}),
                "guardianship_ids": [],
            }
        ], None

    # 儿童：逐监护人检查
    candidates = []
    reasons = []
    for link in state.guardians_of(member["member_id"], exposure_at):
        gid = link["guardian_id"]
        still_valid = any(
            g["guardian_id"] == gid for g in state.guardians_of(member["member_id"], notify_at)
        )
        if not still_valid:
            reasons.append(f"监护人 {gid} 的监护关系在通知时已终止")
            continue
        versions = state.consent_versions_between(gid, exposure_at, notify_at)
        pred = _child_scope(member["member_id"])
        at_exp = _consent_covers(versions["at_exposure"], pred)
        at_now = _consent_covers(versions["at_notify"], pred)
        if not at_exp:
            reasons.append(f"监护人 {gid} 在暴露发生时无对该儿童的同意")
            continue
        if not at_now:
            reasons.append(f"监护人 {gid} 对该儿童的同意在通知时已失效")
            continue
        candidates.append(
            {
                "person_id": gid,
                "consent_ids": sorted({c["consent_id"] for c in at_exp + at_now}),
                "guardianship_ids": [link["id"]],
            }
        )
    if not candidates:
        if not reasons:
            reasons.append("暴露发生时无有效监护关系")
        return [], "；".join(reasons)
    return candidates, None


def _apply_preferences(state, person_id, notify_at, level):
    """返回 (允许的渠道集合或 None 表示不限, 排除理由或 None 表示可联系)。"""
    pref = state.preference_at(person_id, notify_at)
    if pref.get("do_not_contact"):
        return None, "安全偏好设置为不联系"
    min_level = pref.get("min_level")
    if min_level and _LEVEL_RANK[level] < _LEVEL_RANK[min_level]:
        return None, f"安全偏好仅接收 {min_level} 级别"
    allowed = pref.get("allowed_channels")
    return (set(allowed) if allowed else None), None


def _pick_channel(state, person_id, notify_at, consent_ids, pref_channels):
    """在同意渠道、偏好渠道与有效联系方式的交集中选择渠道。"""
    consent_channels = set()
    for record in state.consents:
        if record["consent_id"] in consent_ids and timeutil.is_valid(record, notify_at):
            consent_channels.update(record["channels"])
    if pref_channels is not None:
        consent_channels &= pref_channels
    for contact in state.contacts_for(person_id, notify_at):
        if contact["channel"] in consent_channels:
            return contact["channel"], contact["address"], contact["contact_id"]
    return None, None, None


def resolve_recipients(state, window, member_ids, level, notify_at, exclude_persons=()):
    """求最小接收人集合。

    exclude_persons 中的人（如已拒收者）不参与解析。
    返回 {
      "recipients": [{person_id, covers, channel, address, contact_id,
                      consent_ids, guardianship_ids}],
      "excluded": [{member_id, reason}],
    }
    """
    excluded_persons = set(exclude_persons)
    # 暴露发生时取窗口起点：暴露后才生效的同意不能追溯覆盖该次暴露
    exposure_at = window["start"]
    # person_id -> {"covers": set, "consent_ids": set, "guardianship_ids": set,
    #               "channel"/"address"/"contact_id"}
    coverage_info = {}
    excluded = []
    for member_id in member_ids:
        member = state.get_member(member_id)
        if not member:
            excluded.append({"member_id": member_id, "reason": "未知成员"})
            continue
        candidates, reason = _authorized_recipients(state, member, exposure_at, notify_at)
        if not candidates:
            excluded.append({"member_id": member_id, "reason": reason})
            continue
        usable = []
        blocked = []
        for cand in candidates:
            if cand["person_id"] in excluded_persons:
                blocked.append(f"{cand['person_id']}: 已拒收")
                continue
            pref_channels, pref_reason = _apply_preferences(
                state, cand["person_id"], notify_at, level
            )
            if pref_reason:
                blocked.append(f"{cand['person_id']}: {pref_reason}")
                continue
            channel, address, contact_id = _pick_channel(
                state, cand["person_id"], notify_at, cand["consent_ids"], pref_channels
            )
            if not channel:
                continue
            usable.append({**cand, "channel": channel, "address": address, "contact_id": contact_id})
        if not usable:
            detail = "；".join(blocked) if blocked else "候选接收人均无可用联系方式/渠道"
            excluded.append({"member_id": member_id, "reason": detail})
            continue
        for cand in usable:
            info = coverage_info.setdefault(cand["person_id"], {
                "covers": set(), "consent_ids": set(), "guardianship_ids": set(),
                "channel": None, "address": None, "contact_id": None,
            })
            info["covers"].add(member_id)
            info["consent_ids"].update(cand["consent_ids"])
            info["guardianship_ids"].update(cand["guardianship_ids"])
            # 确定性选择第一个可用渠道（usable 已按候选顺序生成）
            if info["channel"] is None:
                info["channel"] = cand["channel"]
                info["address"] = cand["address"]
                info["contact_id"] = cand["contact_id"]

    # 2) 贪心最小集合覆盖（确定性：覆盖数降序，再按 person_id 升序）
    uncovered = set()
    for info in coverage_info.values():
        uncovered |= info["covers"]
    uncovered -= set(e["member_id"] for e in excluded)
    recipients = []
    while uncovered:
        best = min(
            coverage_info,
            key=lambda p: (-len(coverage_info[p]["covers"] & uncovered), p),
        )
        covered = coverage_info[best]["covers"] & uncovered
        if not covered:
            break
        info = coverage_info[best]
        recipients.append(
            {
                "person_id": best,
                "covers": sorted(covered),
                "channel": info["channel"],
                "address": info["address"],
                "contact_id": info["contact_id"],
                "consent_ids": sorted(info["consent_ids"]),
                "guardianship_ids": sorted(info["guardianship_ids"]),
            }
        )
        uncovered -= covered
    return {"recipients": recipients, "excluded": excluded}
