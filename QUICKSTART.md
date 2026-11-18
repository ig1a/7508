# 内部助手快速入门

当前实现最多四轮的内部问答、会话隔离、删除重置、路由和关卡调用接口。
默认关卡已使用 `SecurityForwardingGate`，实现 M1 Content Detection 和 M2 Session Provenance，默认策略为 `M1_M2`。
Gate DENY 后不发送外部请求，改用 Internal Fallback。Relay/Provider 服务及 Runner 实验字段的对接要求见 `INTEGRATION.md`。

## 启动

在项目目录的 PowerShell 中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
.\.venv\Scripts\python.exe -m pip check
ollama pull qwen3:4b-instruct-2507-q4_K_M
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

已有虚拟环境和模型时，不必重复创建或下载。Ollama 需保持运行。
`requirements.txt` 包含 detect-secrets、presidio-analyzer 和 spaCy；M1 还需要英文模型 `en_core_web_sm`。检测依赖缺失或扫描不完整时，M1 按 Fail-Closed 拒绝外发。
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

- `main.py`：检查输入及实验请求认证，更新会话来源标签，调用 Router 并返回结构化结果。
- `routing.py`：默认调用 `SecurityForwardingGate.inspect()`，仅在 ALLOW 后发送被检查的请求；DENY 或关卡异常时内部回退。
- M1 检测完整对话及动态字段中的敏感内容；M2 按会话合并来源标签。默认 `M1_M2` 要求扫描完整且未发现敏感内容，同时会话标签为 PUBLIC。
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
调用 `DELETE /sessions/{session_id}` 同时删除历史和 Session Security Label，旧 ID 随后返回 404。
注意：会话 ID 是本机实验中的历史查找键，不是用户身份认证机制。

运行自动检查：

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_backend test_routing tests_security_gateway test_m1_regression test_m1_live_plugins
```

`test_m1_live_plugins` 需要真实检测插件、英文模型及 `data/generated/tasks.jsonl`；缺少前置条件时会跳过，跳过不等于验证通过。固定任务由现有 `feat/a-threat-model` 分支的 `python -m taskset.build` 生成；将该分支生成的 `tasks.jsonl` 放在上述路径即可，不需要复制 Task Set 实现。其余测试使用模拟模型及本机临时 HTTP 接收器，不需要运行 Ollama 推理。

## 外发拒绝与回退实验

在 `POST /chat` 输入：

```json
{"message":"虚构内部编号是 DEMO-482，请只回答编号。","route_mode":"external_candidate"}
```

预期 `gate_decision=deny`、`route=internal`、`fallback=true`、
`fallback_reason=gate_denied`、`external_attempted=false`，回答仍包含编号。
不传 `route_mode` 默认走 `internal_only`，关卡显示 `not_checked`。

此示例没有 `source_label`，会话按 UNKNOWN 处理，默认 `M1_M2` 因而拒绝外发；这不是占位关卡，也不能据此认定 M1 检出了编号。回答内容仍取决于内部模型。

可信实验客户端可以提交 `source_label`（PUBLIC / CONFIDENTIAL / UNKNOWN）、`gate_mode`（none / M1 / M2 / M1_M2）及 `relay_mode`（passive / active）。显式提交标签、使用非默认关卡模式或指定 Relay 模式时，必须携带与服务端 `BRANDAI_RUNNER_TOKEN` 匹配的 `X-Experiment-Token`，否则返回 HTTP 401。省略标签时按 UNKNOWN 处理；详见接口文档。

ALLOW 才会向 `BRANDAI_RELAY_URL` 指定的地址发送，默认地址为 `http://127.0.0.1:11435/api/chat`；本分支不提供 Relay/Provider 服务。
`external_attempted` 只表示是否调用了发送函数；外部真正收到什么必须由接收端 ingress 日志确认。
`gate_latency_ms` 仅计算检查耗时；`latency_ms` 包含排队、模型加载和推理等整个处理时间。
外部失败后内部回退仍保留 `external_attempted=true`，因为请求可能已经到达对方。

接口说明见 `INTEGRATION.md`。
