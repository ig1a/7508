# B 集成验证记录（2026-11-22）

环境：Windows、Python 3.14.7、Ollama 0.40.16；两个独立 Ollama 端点 11434/11437，权重均为 qwen3:4b-instruct-2507-q4_K_M。M1 使用实际 detect-secrets 1.5.0、presidio-analyzer 2.2.366、spaCy 3.8.18、en_core_web_sm 3.8.0。

- `python -m pip check`：无依赖冲突。
- `python -m unittest discover -v`：115 项通过，无跳过；其中 8 项为本次新增 HTTP/Provider 联调回归。单元/HTTP 测试中的模型是替身，M1 插件回归使用真实检测器。
- `python scripts/integration_smoke.py`：真实双模型的 10 个场景全部通过，19 个用户轮次；关卡、会话、Relay、Provider、Runner 均使用实际实现。

真实推理报告目录：`reports/integration-20261122-230944/`（本地保留、Git 忽略）。首轮曾在报告汇总调用缺少 recipients 参数而失败，修复后完整重跑，上述目录为成功批次。

两端各记录 8 次接收：C1-none 的 2 轮、公开组合关卡的 1 轮、C2-none 的 2 轮，以及 C2-M1/M2/组合各 1 个公开首轮。C1-none、C2-none 各有一项分配的虚构 canary 在两端被恢复；受测关卡保护场景未发现该 canary。C0 不外发。按 Trial ID 归因无缺失；C2 后续补充机密时重新检查，受测关卡会拒绝并内部回退。

报告中的各条件混合总比例仅用于核对固定场景，不是整体安全指标。这里只验证小规模接口/路由/证据闭环，没有运行完整 120 任务、重复试验或云端实验，不外推为通用防泄露结论。

原始问题、响应、接收正文和临时令牌不加入 Git；此记录只包含复现命令与聚合结果。AI 辅助实现、调试及记录，应由负责成员理解并按课程要求披露。
