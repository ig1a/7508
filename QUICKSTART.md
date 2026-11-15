# BrandAI 快速入门

当前仓库实现最多四轮的内部问答、会话隔离、删除重置、路由和关卡调用接口，
并加入威胁模型、攻击案例、确定性任务集和实验 runner。

关卡目前是拒绝所有外发的占位实现；M1/M2、中转站、独立外部模型、ingress 日志和
leak extractor 仍待小组集成。当前可运行助手演示和 C0 内部基线，但不能得出防泄露结论。

## 启动

在项目目录的 PowerShell 中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen3:4b-instruct-2507-q4_K_M
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

已有虚拟环境和模型时，不必重复创建或下载。Ollama 需保持运行。
本机 Ollama 安装在 `D:\Ollama`，新终端可使用 `ollama`；若未找到命令，使用完整路径。

## 手动体验

1. 打开 http://127.0.0.1:8000/docs 。
2. 展开 `POST /chat`，点击 `Try it out`。
3. 请求内容填写 `{"message":"请用一句话解释什么是人工智能。"}`。
4. 点击 `Execute`，查看 `Response body` 中的 `answer`。

返回字段：`answer` 为回答，`model` 为配置的模型，`route` 为实际使用的 `internal` 或 `external`，
`session_id` 为会话编号，`turn_count` 为成功完成的用户轮数。
`latency_ms` 为后端处理时间（包含首次加载模型时间，不等于关卡延迟）。
`GET /health` 仅检测后端存活，不代表模型服务已就绪。

## 如何理解代码

- `main.py`：检查输入、调用模型模块、返回结构化结果。
- `model_backend.py`：向本机 `127.0.0.1:11434/api/chat` 发送请求。
- 不传 `session_id` 创建新会话；传入返回的 ID 可续聊。
- 历史仅保存在当前 Python 进程的内存中，重启或代码自动重载会清空。
- 起步配置上下文 16384 tokens、最多生成 512 tokens；历史和新问题总计最多 12000 UTF-8 字节。超限拒绝，不自动裁掉旧历史。正式实验需进一步检查 token 使用和输出截断。
- 每个会话最多四轮；最多 128 个会话。模型失败不保存该轮问题或回答。
- 当前单进程串行处理，启动时不要增加 `--workers`。没有用户登录鉴权，仅供本机实验，保持默认 `127.0.0.1` 监听。
- 仅使用虚构测试资料。这里的路由字段不是完整安全防护机制。

本起步代码由 AI 辅助编写；提交前应由负责成员理解、验证，并按课程要求更新 AI 使用声明。

## 两轮记忆实验

第一次调用 `POST /chat`：

```json
{"message":"虚构项目的编号是 DEMO-482，请记住。"}
```

复制响应中的 `session_id`，第二次调用：

```json
{"message":"刚才项目的编号是什么？","session_id":"替换为上次返回的编号"}
```

不传 ID 问同一个问题，应该无法知道其他会话的资料。
调用 `DELETE /sessions/{session_id}` 删除历史，旧 ID 随后返回 404。
注意：会话 ID 是本机实验中的历史查找键，不是用户身份认证机制。

运行助手与路由检查：

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_backend test_routing
```

## 外发拒绝与回退实验

在 `POST /chat` 输入：

```json
{"message":"虚构内部编号是 DEMO-482，请只回答编号。","route_mode":"external_candidate"}
```

预期 `gate_decision=deny`、`route=internal`、`fallback=true`、
`fallback_reason=gate_denied`、`external_attempted=false`，回答仍包含编号。
不传 `route_mode` 默认走 `internal_only`，关卡显示 `not_checked`。

这只能证明路由接线和回退工作，不能证明敏感内容检测有效：当前占位关卡也拒绝公开任务。
`external_attempted` 只表示是否调用了发送函数；外部真正收到什么必须由队友的 ingress 日志确认。
`gate_latency_ms` 仅计算检查耗时；`latency_ms` 包含排队、模型加载和推理等整个处理时间。
外部失败后内部回退仍保留 `external_attempted=true`，因为请求可能已经到达对方。

队友接入说明见 `INTEGRATION.md`。

## 生成任务集

在仓库根目录运行：

```powershell
.\.venv\Scripts\python.exe -m taskset.build
```

成功时显示：

```text
120 tasks, 168 records, 368 canaries -> ...\data\generated
```

生成内容位于 `data/generated/`，不会提交到 Git。它只包含合成数据，但格式可能触发 GitHub
secret scanning。助手、关卡和 labeller 不得读取 `canaries.jsonl`；该文件只供 leak extractor
和 scorer 使用。

## 运行 C0 内部基线

保持助手在 `127.0.0.1:8000` 运行，然后在另一终端执行：

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C0
```

短测试：

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C0 --tasks "C-cred-*" --limit 5
```

结果写入 `reports/runs/`，不会提交到 Git。重新打印摘要：

```powershell
.\.venv\Scripts\python.exe -m runner.run --summary reports\runs\<结果文件>.jsonl
```

非 C0 配置不会由 runner 自动部署或验证。只有在对应 gate、relay、外部模型和日志系统完成
配置后，才可以运行并报告 `C1-*` 或 `C2-*`。

## 运行全部自动检查

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_backend test_routing test_taskset test_runner
```

目前共 29 项检查，不需要启动 Ollama。检查成功只证明对应组件行为，不代表完整实验已经完成。
