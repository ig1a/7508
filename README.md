# DASE7508 — BrandAI Provider-Side Forwarding Gate

本仓库是 DASE7508 Security of Intelligent Systems 小组项目的本地实验平台，用于研究：

> LLM 服务商在外部调用边界加入转发关卡后，能否阻止机密提示词到达不可信中转站或外部 AI 服务，同时保留正常任务效用？

当前仓库包含：

- FastAPI 助手、内存会话、内部/外部候选路由和 Ollama 后端；
- 明确的威胁模型、六类主动中转站注入和七个实验配置；
- 可重复生成的 120 个任务、168 条记录和 368 个 canary；
- C0 基线实验 runner、效用评分、结果摘要和自动测试；
- 占位关卡拒绝后的内部回退演示。

**当前仍是实验框架而非完整防泄露系统。** `PlaceholderGate` 会拒绝全部外发；M1/M2、被动/主动中转站、独立外部模型、ingress 日志和 leak extractor 仍待集成。因此目前只能报告组件验证和 C0 基线，不能把占位关卡结果当作 M1/M2 防泄露结论。

设计与接口说明：

- [威胁模型](docs/threat_model.md)
- [任务、语料和 canary 格式](docs/task_format.md)
- [助手快速入门](QUICKSTART.md)
- [队友集成接口](INTEGRATION.md)

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
本机安装路径为 `D:\Ollama`；队友无需使用相同路径，但必须启动本机 Ollama 服务。
如命令未找到，可新开终端或使用实际安装路径调用 `ollama.exe`。

## 生成实验输入

任务集采用固定种子 `7508`，生成后会先自动验证：

```powershell
.\.venv\Scripts\python.exe -m taskset.build
```

成功时应显示：

```text
120 tasks, 168 records, 368 canaries -> ...\data\generated
```

输出位于 `data/generated/`。这些文件包含外观类似真实凭证的合成秘密，因此不提交到 Git；队友应在本机重新生成。助手、关卡和 labeller 不得读取 `canaries.jsonl`。

## 启动助手与一键演示

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

## 运行 C0 基线

先保持助手运行，再在另一终端执行：

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C0
```

常用的短测试和结果摘要：

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C0 --tasks "C-cred-*" --limit 5
.\.venv\Scripts\python.exe -m runner.run --summary reports\runs\<结果文件>.jsonl
```

结果写入 `reports/runs/`，其中可能包含完整合成秘密，因此不提交到 Git。

Runner 也接受 `C1-none`、`C1-M1`、`C1-M2`、`C2-none`、`C2-M1` 和 `C2-M2`，但这些名称目前只记录请求的配置，不会自动启动或验证中转站与关卡。运行非 C0 配置前，必须先完成对应组件集成和配置证明。

## 自动检查

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_backend test_routing test_taskset test_runner
```

目前共 29 项检查，不需要下载或运行模型。测试使用模拟模型和本机临时 HTTP 接收器，覆盖：

- 会话隔离、上下文限制、删除和失败回滚；
- 拒绝不发送、获准请求字节一致、关卡异常和内部回退；
- 后续轮次重新检查、阻止重定向和外部失败；
- 任务集确定性、大小限制、公开任务无 canary 和 labeller 输入隔离；
- C0 runner、trial ID、错误清理、主动注入后的 compliance turn 和效用评分。

运行传输测试需要允许访问本机临时端口，但不会访问第三方模型。

## 仓库结构

| 文件 | 作用 |
|---|---|
| `main.py` | API 输入校验、会话处理和响应字段 |
| `sessions.py` | 内存历史、四轮限制、会话删除 |
| `model_backend.py` | 构建 Ollama 请求，发送和解析结果 |
| `routing.py` | 内部/外部候选路由、检查后发送、内部回退 |
| `gate.py` | 关卡接口和默认拒绝占位实现 |
| `docs/threat_model.md` | 资产、边界、攻击者、假设、安全属性和实验配置 |
| `docs/task_format.md` | 任务、语料、标签、canary 和注入格式 |
| `data/attacks/injections.jsonl` | 六个主动中转站攻击文本 |
| `taskset/build.py` | 确定性生成语料、任务和 canary registry |
| `taskset/validate.py` | 检查任务覆盖、限制和 canary 隔离 |
| `runner/run.py` | 重放试验、记录结果、效用评分和摘要 |
| `test_*.py` | 后端、路由、任务集和 runner 自动检查 |
| `scripts/demo.py` | 调用真实模型的一键演示 |

## 当前限制与待集成事项

- `gate.py` 仍为全拒绝占位实现，不能代表 M1 或 M2。
- `/chat` 尚未接收可信 PUBLIC/CONFIDENTIAL 标签，session 也没有 sticky label 状态。
- 尚无 `:11435` 中转站、独立外部 Ollama、provider ingress 日志或 leak extractor。
- Runner 发送 `X-Trial-Id`，但助手尚未读取并传播到其他组件。
- `DELETE /sessions/{id}` 只清除助手历史，尚未重置标签、中转站、外部模型和日志。
- 内存会话要求单进程，不能添加多个 workers；服务没有用户鉴权，只能绑定本机使用。
- C1/C2 和 M1/M2 的完整实验、置信区间和人工语义泄漏检查尚未完成。

详细缺口和建议负责人见 [威胁模型 §8](docs/threat_model.md#8-current-integration-gaps)。

## AI 使用记录

本项目使用 AI 协助设计、编码、调试和文档整理。各负责成员必须理解并人工复核自己提交的内容，在 pull request 中记录验证命令和结果，并在最终报告中如实说明 AI 协助及每位成员的实际贡献。

自动检查通过只代表所覆盖场景；完整安全结论必须来自完成集成后的受控实验及保留的证据。
