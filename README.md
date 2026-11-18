# DASE7508 — D 模块 Security Gateway

本分支实现 D 模块 Security Gateway，并接入现有助手、会话管理、路由和模型后端。
当前可演示：本地模型问答 → 多轮记忆 → 提议外部调用 → Gateway 检查 → 内部回退。

**已接入 M1 内容检测和 M2 会话来源标签。完整中转站和独立外部模型仍待接入。**
本分支的结果是组件验证，不能作为防泄露实验结论。

## 环境与首次安装

已验证环境：Windows、Python 3.14.7、Ollama 0.40.16、RTX 4060 Laptop 8 GB、约 16 GB 内存。
其他 Python/操作系统版本尚未验证。依赖版本固定在 `requirements.txt`。

在仓库根目录的 PowerShell 中运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen3:4b-instruct-2507-q4_K_M
```

也可用 `scripts/setup.ps1` 创建虚拟环境并安装 Python 依赖。
Ollama 从 https://ollama.com/download/windows 安装，模型约 2.5 GB。
本机安装路径为 `D:\Ollama`；安装路径可自定义，但必须启动本机 Ollama 服务。
如命令未找到，可新开终端或使用实际安装路径调用 `ollama.exe`。

## 启动与一键演示

终端一：

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

保持终端一运行，在终端二执行：

```powershell
.\.venv\Scripts\python.exe scripts/demo.py
```

已有后端占用 8000 端口时不必重复启动。开发时可加 `--reload`，但修改代码会清空内存会话。
对应 PowerShell 脚本为 `scripts/start.ps1` 和 `scripts/demo.ps1`。
若电脑的脚本执行策略阻止 `.ps1`，直接使用上述 Python 命令，无需修改系统策略。

演示依次检查内部路径、跨轮记忆、会话隔离、关卡拒绝后的内部回退和会话删除，
只使用固定虚构资料，最后清理自身创建的会话。报告写入 `reports/demo.json`，不纳入 Git。
成功时显示五条 `PASS` 和 `Result: passed`。首次模型加载可能明显慢于后续问答。

手动操作页面：http://127.0.0.1:8000/docs 。示例见 [QUICKSTART.md](QUICKSTART.md)。

## 自动检查（不需要下载模型）

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_backend test_routing
```

16 项检查使用模拟模型和本机临时 HTTP 接收器，覆盖会话隔离、上下文保留、拒绝不发送、
获准请求字节一致、关卡异常、后续轮次重新检查、重定向阻止及外部失败回退。
运行测试需要允许访问本机临时端口，不访问第三方模型。

## 文件分工

| 文件 | 作用 |
|---|---|
| `main.py` | API 输入校验、会话处理和响应字段 |
| `sessions.py` | 内存历史、四轮限制、会话删除 |
| `model_backend.py` | 构建 Ollama 请求，发送和解析结果 |
| `routing.py` | 内部/外部候选路由、检查后发送、内部回退 |
| `gate.py` | 关卡接口和 Security Gateway |
| `test_backend.py`、`test_routing.py` | 组件和本地传输检查 |
| `scripts/demo.py` | 调用真实模型的一键演示 |

接口及待集成事项见 [INTEGRATION.md](INTEGRATION.md)。
内存会话要求单进程，不能添加多个 workers；服务未实现用户鉴权，仅绑定本机使用。
这是开发原型；来源标签和元数据审计已接入，完整实验仍需 Runner/Relay 联调。

## AI 使用记录

本分支由 AI 辅助实现和调试。负责成员需理解代码、复核结果，并按课程要求在最终提交中如实披露。
检查通过只代表所覆盖场景；完整实验结果由后续集成运行产生。

## Security Gateway

M1 使用 detect-secrets、Presidio 和编码变体扫描；M2 单调合并 PUBLIC / CONFIDENTIAL / UNKNOWN 会话标签。默认 M1_M2，检测失败关闭外发，拒绝后沿用内部回退。检查与发送使用相同请求字节，删除会话同时删除标签。仅跳过本地构造器固定的模型元数据，完整对话和动态字段仍被扫描。审计只写元数据至被忽略的 reports/。

安装 requirements.txt 后运行 `python -m spacy download en_core_web_sm`。缺少插件或模型时 M1 拒绝外发。

POST /chat 新增 source_label、gate_mode（none / M1 / M2 / M1_M2）、relay_mode（passive / active）。提交标签、使用非默认关卡模式或指定 Relay 模式，需要 X-Experiment-Token 与服务端 BRANDAI_RUNNER_TOKEN 环境变量匹配。令牌须随机生成并仅留本机；无标签请求按 UNKNOWN 处理。共享令牌仅适用本机受控实验，不替代生产身份认证。X-Trial-Id 传播至外发请求及 Gate 审计；BRANDAI_RELAY_URL 可配置 Relay 地址。

```powershell
python -m pip check
python -m unittest -v test_backend test_routing tests_security_gateway test_m1_regression test_m1_live_plugins
python -m evaluation.benchmark_m1 --tasks data/generated/tasks.jsonl
```

本次 65/65 测试通过，包含真实插件和原有 HTTP 传输测试。真实插件测试与 benchmark 依赖 A 分支 Task Set：在 feat/a-threat-model 工作目录运行 `python -m taskset.build`，仅将生成的 tasks.jsonl 放入本分支 data/generated/（已忽略）。当前 main 尚不含 Task Set，本 PR 不重复添加。benchmark 不调用模型、不读取 canaries，仅输出聚合统计。

| 类型 | 结果 | 证据范围 |
|---|---|---|
| C0 模型效用 | 84/108；Public 38/40 | 最终验证包聚合结果，本次未重跑模型 |
| M1 离线检测 | Confidential 61/80；Public false positive 5/40 | 本次使用 A 分支 Task Set 重现，不是实际泄漏率 |
| 完整本地工程自动测试 | 88/88 PASS | 用户已完成的完整工程结果，不是本 PR 测试数量 |
| 端到端验收 | 11/11 PASS | 最终验证包记录的 Trial-ID 关联验收，本次未重跑 Relay/Provider |

evaluation/results/ 保存用户最终验证评估包中的脱敏统计。验收共 16 Relay、16 Provider、17 Gate audit 事件。仅对整个 Trial 都拒绝的样本支持有限零外发结论；混合 ALLOW/DENY Trial 缺少 Turn ID，不能推导每轮确切字节。Public 0/0 canaries 为 N/A。Relay/Provider 是本地模拟边界，不是独立云服务。旧批次因 Trial ID 缺失产生的零泄漏率无效。

A 分支 Runner 当前仅发送 message/route_mode 和 Trial ID，现有实现还需添加认证头、来源标签、gate_mode 和 relay_mode；不能仅凭配置名称声称运行了 M1/M2/none。本 PR 不复制 runner/、taskset/、威胁模型或 Relay。合并 A 分支时保留其 README 和忽略规则并合并本节。QUICKSTART/INTEGRATION 中占位关卡描述属于初始接口说明，当前 Gateway 接口以本节为准。

