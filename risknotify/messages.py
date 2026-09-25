"""消息快照。

批准（或紧急先行）时为每个接收人生成一次性的消息快照：
- 只包含该接收人获授权了解的成员信息，其他成员一律不出现；
- 快照生成后不可改写（已送达内容尤其如此），以 content_hash 锚定；
- 紧急先行时使用"最低必要提示"模板，不含敏感细节。
"""

import hashlib
import json

from . import timeutil

KIND_FULL = "full"
KIND_MINIMAL_ALERT = "minimal_alert"


def _member_label(state, recipient_id, member_id):
    member = state.get_member(member_id)
    if member_id == recipient_id:
        return "您本人"
    if member and member["role"] == "child":
        return "您监护的孩子"
    return "家庭成员"


def render_snapshot(state, recipient, window, risk, kind, snapshot_id=None, at=None):
    """为单个接收人生成消息快照（只含其获授权的成员）。"""
    at = at or timeutil.now()
    covers = list(recipient["covers"])
    level = risk["level"]
    span = f"{window['start']} 至 {window['end']}"

    if kind == KIND_MINIMAL_ALERT:
        body = (
            "【紧急健康提示】您家中刚刚监测到需要尽快处理的室内空气风险。"
            "请立即开窗通风，并让家人（尤其是孩子和孕妇）暂时远离烟雾来源。"
            "研究团队将尽快与您联系说明详情。"
        )
    elif level == "urgent":
        body = (
            f"【紧急】您家中在 {span} 监测到严重二手烟暴露"
            f"（平均 PM2.5 约 {risk['avg_pm25']:.0f} μg/m³，持续 {risk['duration_min']} 分钟）。"
            "请立即开窗通风并让家人远离烟雾来源。"
        )
    else:
        body = (
            f"您家中在 {span} 监测到持续偏高的二手烟暴露"
            f"（平均 PM2.5 约 {risk['avg_pm25']:.0f} μg/m³，持续 {risk['duration_min']} 分钟），"
            "建议开窗通风并减少室内吸烟。"
        )

    if kind != KIND_MINIMAL_ALERT:
        lines = []
        for member_id in covers:
            label = _member_label(state, recipient["person_id"], member_id)
            lines.append(f"· {label}在此期间暴露于上述环境。")
        if lines:
            body += "\n受影响家人：\n" + "\n".join(lines)

    snapshot = {
        "snapshot_id": snapshot_id or f"snap-{recipient['person_id']}-{at}",
        "recipient_id": recipient["person_id"],
        "member_ids": sorted(covers),
        "kind": kind,
        "level": level,
        "body": body,
        "created_at": at,
    }
    snapshot["content_hash"] = hashlib.sha256(
        json.dumps(
            {k: v for k, v in snapshot.items() if k != "content_hash"},
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return snapshot


def find_leaks(snapshot, all_member_ids):
    """检查快照正文是否出现接收人授权范围之外的成员标识。

    返回违规标识列表（空列表表示通过）。
    """
    allowed = set(snapshot["member_ids"]) | {snapshot["recipient_id"]}
    forbidden = set(all_member_ids) - allowed
    return [mid for mid in forbidden if mid in snapshot["body"]]
