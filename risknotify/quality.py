"""数据质量门槛与风险规则评估。

风险规则只能在通过质量门槛的数据上产生候选：窗口必须具备完整的
传感覆盖、最小持续时长与通过质控。规则以显式版本发布，规则变化时
重新评估会产生带差异的新候选。
"""

# 质量门槛常量
MIN_COVERAGE = 0.9
MIN_DURATION_MIN = 20


def evaluate_quality(window):
    """返回 (passed: bool, reasons: list[str])。"""
    reasons = []
    coverage = window.get("sensor_coverage", 0)
    duration = window.get("duration_min", 0)
    if not window.get("sensor_ids"):
        reasons.append("缺少传感设备")
    if coverage < MIN_COVERAGE:
        reasons.append(f"传感覆盖率 {coverage:.0%} 低于门槛 {MIN_COVERAGE:.0%}")
    if duration < MIN_DURATION_MIN:
        reasons.append(f"持续 {duration} 分钟低于门槛 {MIN_DURATION_MIN} 分钟")
    if window.get("qc_status") not in ("passed", None):
        reasons.append(f"质控未通过: {window.get('qc_status')}")
    elif window.get("qc_status") is None:
        reasons.append("缺少质控结论")
    return (len(reasons) == 0, reasons)


# 已发布的风险规则版本（单调递增）。
RULES = {
    "r1": {
        "rule_version": "r1",
        "label": "持续高 PM2.5 暴露",
        "threshold": 35,  # μg/m³ 窗口均值
        "min_duration_min": 20,
        "level_thresholds": {"urgent": 250, "routine": 35},
    },
}
DEFAULT_RULE_VERSION = "r1"


def evaluate_risk(window, rule_version=DEFAULT_RULE_VERSION):
    """在"假定已通过质量门槛"的窗口上评估风险。

    返回 None（不构成风险）或 {level: urgent|routine, metrics...}。
    """
    rule = RULES[rule_version]
    avg = window.get("avg_pm25", 0)
    duration = window.get("duration_min", 0)
    if duration < rule["min_duration_min"]:
        return None
    if avg < rule["threshold"]:
        return None
    if avg >= rule["level_thresholds"]["urgent"]:
        level = "urgent"
    else:
        level = "routine"
    return {
        "rule_version": rule_version,
        "rule_label": rule["label"],
        "level": level,
        "avg_pm25": avg,
        "duration_min": duration,
        "threshold": rule["threshold"],
    }
