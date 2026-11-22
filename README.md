# DASE7508 — B 模块与全链路联调

本分支接入队友的 A（任务集/Runner）、C（中转站/泄漏提取）、D（M1/M2）及 E（离线评分）代码，保留各自提交历史。B 本次补齐运行器到助手的实验参数、独立外部 Provider，以及跨模块联调；未直接修改远程 main。

```text
Runner → B Assistant/API → D Gateway → C Relay → Provider → External Ollama
                 └──── deny/error → Internal Ollama
```

两个 Ollama 使用独立进程/端口和相同模型权重，会话及接收日志分开。这是本地模拟边界，不是独立云服务。

## 本次实现

- Runner 每轮发送来源标签、关卡策略、中转模式及认证头，检查服务端回显，避免仅凭配置名称声称已执行策略。
- B 保留完整历史、隔离会话；每次外发重新检查，拒绝/异常时内部回退。检查后的正文和应用请求头保持一致；不自动重试或跟随重定向。
- Relay 按请求切换 C1/C2，按 Trial ID 隔离注入计数；修复 upstream 已包含 /api/chat 时路径重复的问题。
- provider.py 提供独立接收端，在模型调用前记录 ingress；上游推理失败也保留已接收证据，拒绝接回内部模型端口。
- scripts/integration_smoke.py 用固定虚构资料跑 10 个真实模型场景，核对两端日志、审计及泄漏提取，自动清理临时 HTTP 服务和会话。

## 安装与运行

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
.\.venv\Scripts\python.exe -m taskset.build
```

本机已验证 Python 3.14.7、Ollama 0.40.16、qwen3:4b-instruct-2507-q4_K_M。详细步骤见 [联调指南](docs/B_INTEGRATION.md)，基础问答见 [QUICKSTART.md](QUICKSTART.md)，协议见 [INTEGRATION.md](INTEGRATION.md)。

保持内部 Ollama 监听 11434，另开终端启动外部模型：

```powershell
$env:OLLAMA_HOST = '127.0.0.1:11437'
& 'D:\Ollama\ollama.exe' serve
```

在项目目录的新终端执行：

```powershell
.\.venv\Scripts\python.exe scripts/integration_smoke.py
```

临时 Assistant/Relay/Provider 自动分配本机端口；报告写入新的 reports/integration-时间/。脚本自行生成临时认证令牌，不打印、不转发到外部，也不写入报告。

## 验证范围

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -v
```

真实 M1 插件测试要求英文模型和生成任务集；缺失时跳过，不算通过。自动测试中的模型推理使用替身；10 场景 smoke 才调用两个真实本地模型。

2026-11-22 本次真实模型 smoke：10/10 场景通过，包括公开放行、无关卡对照、M1/M2/组合拦截、机密历史后的公开追问、C2 注入及下一轮重新检查。这不替代完整实验矩阵。

evaluation/results/ 为 D 分支继承的历史聚合结果，与本次 smoke 分开；本次未重跑其全量实验，不把历史数字当作本次结果。

## 分工与资料

| 模块 | 入口 |
|---|---|
| A 威胁模型/任务集/Runner | docs/threat_model.md、docs/task_format.md、taskset/、runner/ |
| B 助手/路由/后端/Provider | main.py、sessions.py、routing.py、model_backend.py、provider.py |
| C 中转站/泄漏提取 | relay7508/、docs/PART_C.md |
| D Security Gateway | security_gateway/、gate.py |
| E 离线评分 | evaluation/compare_acceptance.py |

仅供本机单进程实验，不增加 workers。完整日志只使用虚构资料，保存在 Git 忽略的 reports/、logs/。代码及本次联调由 AI 辅助完成，负责成员应理解实现、复核证据并按课程要求披露。
