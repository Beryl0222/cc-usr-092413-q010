# 二手烟暴露干预研究

服务用于组织社区二手烟传感、家庭同意与干预分析，并提供**风险通知闭环**：
在保护成员（尤其儿童与孕妇）身份与授权的同时，把经质控确认的高暴露窗口
安全、可审计地通知给"此刻仍有授权"的最小接收人集合。

## 闭环与隐私保证

```
传感窗口(质量门槛) → 风险候选 → 现场研究员确认 → 伦理值班批准
   → 双时点授权解析最小接收人 → 消息快照(不泄露其他成员)
   → 可验证投递任务 → 送达/回执/拒收/失败分流 → 升级时限 → 完成
```

- **质量门槛**：覆盖率、最短时长、质控结论任一不达标，规则不产生候选。
- **双时点授权**：按"暴露发生时"与"通知发出时"两个版本的同意、监护关系与
  安全偏好解析；监护终止、同意撤回后按当前联系人通知，不会把儿童/孕妇的
  敏感暴露发给已失去授权的人。
- **最小接收人**：在全部有效授权接收人上求最小集合覆盖，排除项记录理由。
- **消息快照**：每条消息只含该接收人获授权了解的成员，并做越权标识检查；
  快照以 `content_hash` 锚定，**已送达内容不可改写**。
- **紧急先行**：紧急风险可先发"最低必要提示"（无敏感细节），但必须补齐
  现场确认与伦理批准，再发完整通知。
- **只重排未完成任务**：联系方式失效、监护变更、同意撤回、家庭搬迁只令
  未完成任务被取代（superseded）并按当前授权重新解析；已送达/已确认不变。
- **不重复打扰**：同一 (窗口, 规则版本) 重算幂等；规则版本变化才产生
  **带差异（diff）的新候选**；同一成员同类内容至多通知一次。
- **后续分流**：拒收、投递失败（重试耗尽）、回执冲突、不可达、升级耗尽
  分别进入 `followups` 队列。
- **社区汇总**：只有送达量达到小单元格门槛（默认 3）的社区才显示数量，
  防止小群体反识别。
- **重启续跑**：哈希链审计日志是唯一事件源，重启重放后待投递任务与
  升级时限继续推进；日志任何插入/删改都会在校验时暴露。
- **端到端追溯**：`/api/trace` 可从一次通知追到数据质量结论、所用同意/
  监护/联系方式版本、接收人选择、消息内容哈希与最终确认。

## 运行

```bash
python3 service.py --check          # 配置与模块自检
python3 service.py --port 8000      # 启动（审计日志默认写入 ./data）
curl http://localhost:8000/health
```

设置 `RISKNOTIFY_STORE` 或 `--store-dir` 指定持久化目录；传 `--store-dir ""`
为纯内存模式（数据不落盘，仅用于测试）。

## HTTP 接口

- `POST /api/commands`：统一命令入口，请求体
  `{"command": "...", "args": {...}, "actor": "...", "at": "ISO-8601"}`。
  命令包括目录维护（`register_member`/`add_guardianship`/`grant_consent`/
  `add_contact`/`set_preference`/`relocate_household` 等）、`ingest_window`、
  `scan_window`、`field_confirm`、`ethics_approve`、`dispatch`、
  `emergency_send`、`attempt_delivery`、`confirm_receipt`、
  `report_receipt_conflict`、`opt_out`、`run_due_tasks`。
- `POST /api/timers/advance`：推进升级时限（定时调用）。
- `GET /api/trace?candidate_id=...`：完整审计追溯。
- `GET /api/summary`：社区汇总（含抑制清单）。
- `GET /api/followups`、`/api/candidates`、`/api/tasks`、`/api/verify`。

## 测试与构建

```bash
npm test                 # 运行 service_contract 与 test_risknotify 全部用例
python3 -m compileall -q .
```

两条命令都可在单个 Linux 应用容器内直接运行，仅依赖 Python 标准库。
