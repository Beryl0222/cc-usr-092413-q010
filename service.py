"""二手烟暴露干预研究的运行入口。

默认提供健康检查与风险通知闭环 API：
- GET  /health            服务身份
- POST /api/commands      目录/候选/审批/投递等全部写操作（白名单命令）
- POST /api/timers/advance 推进升级时限
- GET  /api/trace?candidate_id=...  一次通知的完整审计追溯
- GET  /api/summary       社区汇总（含小单元格抑制）
- GET  /api/followups|candidates|tasks|verify  运维巡检
"""

import argparse
import json
import os
from http.server import ThreadingHTTPServer

from risknotify.web import RiskNotifyApi, make_handler

SERVICE_ID = "secondhand-smoke-study"
SERVICE_NAME = "二手烟暴露干预研究"


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def build_server(port, store_dir=None):
    api = RiskNotifyApi(store_dir=store_dir)
    return ThreadingHTTPServer(("0.0.0.0", port), make_handler(api)), api


# 向后兼容：健康检查契约测试直接引用 Handler（默认内存模式，不落盘）
Handler = make_handler(RiskNotifyApi(store_dir=None))


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--store-dir", default=os.environ.get("RISKNOTIFY_STORE", "./data"),
                        help="审计日志与运行态目录（设为空串则仅内存模式）")
    args = parser.parse_args()
    if args.check:
        assert health_payload()["service"] == SERVICE_ID
        # 同时确认闭环模块可装配、审计链初始有效
        api = RiskNotifyApi(store_dir=None)
        assert api.service.verify_audit()
        print("基础检查通过")
        return
    store_dir = args.store_dir or None
    if store_dir:
        os.makedirs(store_dir, exist_ok=True)
    server, _api = build_server(args.port, store_dir=store_dir)
    server.serve_forever()


if __name__ == "__main__":
    main()
