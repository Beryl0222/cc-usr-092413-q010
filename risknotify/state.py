"""事件溯源的状态投影。

所有目录信息（成员、监护关系、同意、联系方式、安全偏好、家庭归属、
数据窗口质量）都以带有效期的版本保存，因此可以回答任意历史时刻
（尤其是"暴露发生时"与"通知发出时"两个时点）的状态。

状态本身只保存事实与版本；业务判定见 recipients / quality / service。
"""

from . import timeutil


class State:
    def __init__(self):
        # member_id -> {member_id, role, sensitive, household_id, household_history}
        self.members = {}
        # [{id, child_id, guardian_id, start, end}]
        self.guardianships = []
        # [{consent_id, member_id, scope, channels, start, end}]
        self.consents = []
        # [{contact_id, person_id, channel, address, start, end, disabled_reason}]
        self.contacts = []
        # person_id -> [{start, end, pref}]
        self.preferences = {}
        # window_id -> 最近一次窗口记录（含质量结论）
        self.windows = {}
        # 窗口质量结论的历史版本
        self.window_history = {}

    # ---------- 变更 ----------

    def register_member(self, member_id, household_id, role, sensitive=None, at=None):
        if member_id in self.members:
            raise ValueError(f"成员已存在: {member_id}")
        if role not in ("adult", "child", "pregnant_adult"):
            raise ValueError(f"未知成员角色: {role}")
        at = at or timeutil.now()
        self.members[member_id] = {
            "member_id": member_id,
            "role": role,
            "sensitive": list(sensitive or []),
            "household_id": household_id,
            "household_history": [{"household_id": household_id, "start": at, "end": None}],
        }
        return self.members[member_id]

    def add_guardianship(self, child_id, guardian_id, start, end=None, gid=None):
        if child_id not in self.members:
            raise ValueError(f"未知成员: {child_id}")
        if guardian_id not in self.members:
            raise ValueError(f"未知成员: {guardian_id}")
        record = {
            "id": gid or f"g-{child_id}-{guardian_id}-{start}",
            "child_id": child_id,
            "guardian_id": guardian_id,
            "start": start,
            "end": end,
        }
        self.guardianships.append(record)
        return record

    def end_guardianship(self, gid, end):
        for record in self.guardianships:
            if record["id"] == gid:
                record["end"] = end
                return record
        raise ValueError(f"未知监护关系: {gid}")

    def grant_consent(self, consent_id, member_id, scope, channels, start, end=None):
        if member_id not in self.members:
            raise ValueError(f"未知成员: {member_id}")
        record = {
            "consent_id": consent_id,
            "member_id": member_id,
            "scope": list(scope),
            "channels": list(channels),
            "start": start,
            "end": end,
        }
        self.consents.append(record)
        return record

    def revoke_consent(self, consent_id, end):
        for record in self.consents:
            if record["consent_id"] == consent_id:
                record["end"] = end
                return record
        raise ValueError(f"未知同意版本: {consent_id}")

    def add_contact(self, contact_id, person_id, channel, address, start, end=None):
        if person_id not in self.members:
            raise ValueError(f"未知成员: {person_id}")
        record = {
            "contact_id": contact_id,
            "person_id": person_id,
            "channel": channel,
            "address": address,
            "start": start,
            "end": end,
            "disabled_reason": None,
        }
        self.contacts.append(record)
        return record

    def disable_contact(self, contact_id, end, reason="失效"):
        for record in self.contacts:
            if record["contact_id"] == contact_id:
                record["end"] = end
                record["disabled_reason"] = reason
                return record
        raise ValueError(f"未知联系方式: {contact_id}")

    def set_preference(self, person_id, pref, start, end=None):
        if person_id not in self.members:
            raise ValueError(f"未知成员: {person_id}")
        self.preferences.setdefault(person_id, []).append(
            {"start": start, "end": end, "pref": dict(pref)}
        )

    def relocate_household(self, household_id, new_household_id, at):
        moved = []
        for member in self.members.values():
            if member["household_id"] != household_id:
                continue
            member["household_history"][-1]["end"] = at
            member["household_history"].append(
                {"household_id": new_household_id, "start": at, "end": None}
            )
            member["household_id"] = new_household_id
            moved.append(member["member_id"])
        if not moved:
            raise ValueError(f"家庭中无成员: {household_id}")
        return moved

    def upsert_window(self, record):
        """登记或更新一个暴露窗口及其质量结论（保留历史版本）。"""
        window_id = record["window_id"]
        self.window_history.setdefault(window_id, []).append(dict(record))
        self.windows[window_id] = dict(record)
        return self.windows[window_id]

    # ---------- 时点查询 ----------

    def get_member(self, member_id):
        return self.members.get(member_id)

    def household_of(self, member_id, at):
        member = self.members.get(member_id)
        if not member:
            return None
        current = None
        for item in member["household_history"]:
            if timeutil.parse(item["start"]) <= timeutil.parse(at) and (
                not item["end"] or timeutil.parse(at) < timeutil.parse(item["end"])
            ):
                current = item["household_id"]
        return current

    def guardians_of(self, child_id, at):
        """在 at 时点对 child_id 具有监护关系的成年人。"""
        result = []
        for record in self.guardianships:
            if record["child_id"] != child_id:
                continue
            if timeutil.is_valid(record, at):
                result.append(record)
        return result

    def consents_for(self, member_id, at):
        """member_id 在 at 时点有效的全部同意版本。"""
        return [
            dict(record)
            for record in self.consents
            if record["member_id"] == member_id and timeutil.is_valid(record, at)
        ]

    def consent_versions_between(self, member_id, exposure_at, notify_at):
        """返回暴露时与通知时各自有效的同意版本（可能为不同版本）。"""
        return {
            "at_exposure": self.consents_for(member_id, exposure_at),
            "at_notify": self.consents_for(member_id, notify_at),
        }

    def contacts_for(self, person_id, at):
        return [
            dict(record)
            for record in self.contacts
            if record["person_id"] == person_id and timeutil.is_valid(record, at)
        ]

    def preference_at(self, person_id, at):
        versions = self.preferences.get(person_id, [])
        for version in reversed(versions):
            if timeutil.is_valid(version, at):
                return dict(version["pref"])
        return {}

    def get_window(self, window_id):
        record = self.windows.get(window_id)
        return dict(record) if record else None
