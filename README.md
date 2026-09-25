# 二手烟暴露干预研究

服务用于组织社区二手烟传感、家庭同意与干预分析，在保护成员身份的同时维持数据质量。

本服务在健康检查之上实现了**社区暴露风险通知闭环**：从通过质量门槛的传感数据产生风险候选，
按暴露发生时与通知时两个时点的同意版本、监护关系与安全偏好解析最小接收人，经现场研究员确认、
伦理值班人员批准后生成成员隔离的消息快照与可验证投递任务，并完整保留拒收、失败、回执冲突、
重排与升级的处理轨迹。

## 闭环规则（与伦理要求对应）

- **质量门槛**：规则只在全部质量检查通过（且至少有一项检查）的数据窗口上运行；未过关窗口不产生候选，候选记录所用质量结果指纹。
- **版本化规则与候选**：规则版本不可变；同一窗口同一规则版本重算幂等；规则版本变化生成带 `diff`（成员增删、级别变化、版本区间）的新候选。
- **双时点最小接收人**：同意范围、监护关系在“暴露时”和“通知时”都必须有效；联系方式与安全偏好在通知时解析。成人只通知本人；儿童按确定性顺序仅选一名监护人。授权交集为空时 fail-safe 不发送，全部考虑与排除原因留证。
- **两级复核**：现场研究员确认家庭上下文、伦理值班人员批准通知级别（可降级）后方生成正式消息；确认与批准均不可改写。
- **紧急先发**：`emergency` 级别可在复核前发送“最低必要提示”（不含儿童/孕妇等敏感标签与其他成员信息），但必须在 SLA（默认 1 小时）内补齐复核，逾期自动升级；正式消息链接到紧急提示。
- **成员隔离快照**：消息按 (关于谁, 发给谁) 单独渲染，不点名其他成员、不泄露其暴露情况；快照带内容指纹，生成后不可变。
- **不重复打扰**：同一风险窗口重算（含规则变化）时，实质内容相同且已触达接收人的消息被抑制；补齐复核不重发紧急提示。
- **只重排未完成任务**：联系方式失效、监护变更、家庭搬迁只影响未触达任务——换通道续发、授权失效作废（superseded）；仅暂无通道时挂起等待，新联系方式就绪自动恢复。已发送/送达/拒收的内容永不改写。
- **三类后续流程**：拒收 → opt-out 偏好（立即停止该成员其他待发任务）；投递失败 → 退避重试，超限进入补救流程；回执状态冲突 → 人工对账裁决。
- **升级时限**：待投递超时、失败补救长期无人接手、紧急复核逾期分别开出升级单；时限以绝对时间戳持久化，进程重启后 `sweep` 继续推进。
- **隐私门槛汇总**：社区计数（候选数、已通知数、家庭数）低于门槛 `k`（默认 5）的单元以 `null` 抑制，达标后才显示数量。
- **端到端审计**：所有状态变化写入 SHA-256 哈希链；`notification_trace` 可从一次通知追到数据质量、规则版本、双时点授权证据、接收人选择、消息内容指纹与最终回执；`verify_audit_chain` 检测任何篡改。

状态以 JSON 原子落盘（临时文件 + rename），默认纯内存；设置 `RISK_STATE_FILE` 指向状态文件即可持久化并在重启后续跑。发送通道可注入（默认本地假成功），真实部署时替换为短信/语音网关适配。

## 运行

```bash
# 配置自检
python3 service.py --check

# 启动 HTTP 服务（可选：RISK_STATE_FILE=state.json RISK_SWEEP_SECONDS=30）
python3 service.py --port 8000
```

- `GET /health`：稳定服务身份。
- `POST /api`：动作网关，请求体为 `{"action": "<动作>", ...参数}`，返回 `{"ok": true, "result": ...}`；
  领域错误返回 `{"ok": false, "error": {"code", "message"}}`（400/404/409）。

主要动作分组：

| 阶段 | 动作 |
| --- | --- |
| 家庭与授权 | `register_household` `register_member` `add_consent` `add_guardianship` `end_guardianship` `add_contact` `invalidate_contact` `relocate_household` `add_preference` |
| 质量与规则 | `register_window` `evaluate_quality` `register_rule` `run_rules` |
| 接收人与复核 | `resolve_recipients` `field_confirm` `ethics_approve` `send_emergency_notice` `review_status` |
| 投递与后续 | `deliver_due` `sweep` `record_receipt` `reconcile_receipt` `resolve_followup` `reroute_task` `resolve_escalation` |
| 汇总与审计 | `community_summary` `notification_trace` `verify_audit_chain` |

所有时间参数为带时区的 ISO 8601；同意、监护、联系方式、偏好均为带 `start`/`end` 的半开有效区间记录。
投递回执需携带任务的一次性 `receipt_token`。

### HTTP 示例

```bash
curl -s -X POST http://127.0.0.1:8000/api -H 'Content-Type: application/json' -d '{
  "action": "register_rule",
  "rule": {"rule_id": "pm25_high", "version": "3",
           "predicate": "max_threshold",
           "params": {"metric": "pm25", "threshold": 75},
           "risk_level": "urgent", "template_id": "tpl_ventilation"}
}'
```

## 测试与构建

执行完整测试（47 个用例，含领域闭环与 HTTP 契约）：

```bash
npm test
```

执行编译检查：

```bash
python3 -m compileall -q .
```

两条命令都可在单个 Linux 应用容器内直接运行，不需要额外服务。
