# B Integration Validation Record (2026-11-22)

*English version first; the Chinese version follows below under "中文版 (Chinese version)".*

> Scope of this record: the real-model validation of commit `bf15667` (B's integration of modules A, C,
> D and E). The integrated branch `feat/a-integration` adds A's runner hardening and leak-scan
> connection on top; on 2026-11-23 its automated suite passed 129/129 tests, but the real-model smoke
> test has not been re-run on it. See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md).

Environment: Windows, Python 3.14.7, Ollama 0.40.16; two independent Ollama endpoints on 11434 and
11437, both with qwen3:4b-instruct-2507-q4_K_M weights. M1 used the real detect-secrets 1.5.0,
presidio-analyzer 2.2.366, spaCy 3.8.18 and en_core_web_sm 3.8.0.

- `python -m pip check`: no dependency conflicts.
- `python -m unittest discover -v`: 115 tests passed, none skipped; 8 of them are new HTTP/provider
  integration regressions added in this change. Models in the unit/HTTP tests are stand-ins; the M1
  plugin regressions use the real detectors.
- `python scripts/integration_smoke.py`: all 10 real two-model scenarios passed, 19 user turns; the
  gate, sessions, relay, provider and runner all used their real implementations.

Real-inference report directory: `reports/integration-20261122-230944/` (kept locally, ignored by
Git). The first attempt failed because a report-summary call was missing the recipients argument;
after the fix the whole run was repeated, and the directory above is the successful batch.

Each receiver recorded 8 receipts: 2 turns of C1-none, 1 turn of the public combined-gate scenario,
2 turns of C2-none, and 1 public first turn each for C2-M1, C2-M2 and the combined gate. In C1-none
and C2-none, one assigned fictional canary was recovered at both receivers; it was not found in any
scenario protected by the gate under test. C0 sent nothing outbound. Attribution by trial ID had no
gaps; when confidential data was supplied later in C2, it was re-checked, and the gate under test
denied it and fell back internally.

The mixed overall rates across conditions in the report are only for checking the fixed scenarios and
are not an overall security metric. This validates only a small-scale interface/routing/evidence loop;
the full 120 tasks, repeated trials and cloud experiments were not run, and no general leak-prevention
conclusion should be drawn from it.

Raw questions, responses, received bodies and temporary tokens are not added to Git; this record
contains only the reproduction commands and aggregate results. The implementation, debugging and this
record were AI-assisted; the responsible member should understand them and disclose this as the course
requires.

---

## 中文版 (Chinese version)

### B 集成验证记录（2026-11-22）

> 本记录范围：提交 `bf15667`（B 对 A、C、D、E 模块的集成）的真实模型验证。集成分支 `feat/a-integration` 在此之上加入了 A 的 Runner 加固和泄漏扫描连接；2026-11-23 其自动测试 129/129 通过，但尚未在该分支上重跑真实模型 smoke 测试。见 [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)。

环境：Windows、Python 3.14.7、Ollama 0.40.16；两个独立 Ollama 端点 11434/11437，权重均为 qwen3:4b-instruct-2507-q4_K_M。M1 使用实际 detect-secrets 1.5.0、presidio-analyzer 2.2.366、spaCy 3.8.18、en_core_web_sm 3.8.0。

- `python -m pip check`：无依赖冲突。
- `python -m unittest discover -v`：115 项通过，无跳过；其中 8 项为本次新增 HTTP/Provider 联调回归。单元/HTTP 测试中的模型是替身，M1 插件回归使用真实检测器。
- `python scripts/integration_smoke.py`：真实双模型的 10 个场景全部通过，19 个用户轮次；关卡、会话、Relay、Provider、Runner 均使用实际实现。

真实推理报告目录：`reports/integration-20261122-230944/`（本地保留、Git 忽略）。首轮曾在报告汇总调用缺少 recipients 参数而失败，修复后完整重跑，上述目录为成功批次。

两端各记录 8 次接收：C1-none 的 2 轮、公开组合关卡的 1 轮、C2-none 的 2 轮，以及 C2-M1/M2/组合各 1 个公开首轮。C1-none、C2-none 各有一项分配的虚构 canary 在两端被恢复；受测关卡保护场景未发现该 canary。C0 不外发。按 Trial ID 归因无缺失；C2 后续补充机密时重新检查，受测关卡会拒绝并内部回退。

报告中的各条件混合总比例仅用于核对固定场景，不是整体安全指标。这里只验证小规模接口/路由/证据闭环，没有运行完整 120 任务、重复试验或云端实验，不外推为通用防泄露结论。

原始问题、响应、接收正文和临时令牌不加入 Git；此记录只包含复现命令与聚合结果。AI 辅助实现、调试及记录，应由负责成员理解并按课程要求披露。
