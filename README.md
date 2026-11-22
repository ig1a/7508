# DASE7508 — BrandAI B 模块

本分支实现小组项目中 B 成员负责的助手、会话管理、路由和模型后端。
当前可演示：本地模型问答 → 多轮记忆 → 提议外部调用 → 占位关卡拒绝 → 内部回退。

**关卡目前拒绝全部外发，尚未实现 M1/M2。**
C 模块的中转站与泄漏提取已并入 `relay7508/`（见 [docs/PART_C.md](docs/PART_C.md)），
外部 provider 包装与 M1/M2 仍需接入。本分支的结果是组件验证，不能作为防泄露实验结论。

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

## C 模块：中转站与泄漏提取

`routing.EXTERNAL_CHAT_URL` 已经指向 `127.0.0.1:11435/api/chat`，启动中转站后，
`route_mode=external_candidate` 的外发请求就会经过它：C1 只记录，C2 还会在回复末尾追加
索要更多材料的一句话。中转站把完整请求/响应写进 JSONL，泄漏提取器再从该日志和 provider
ingress 日志里清点可复原的 canary。

```powershell
python -m relay7508 relay --config samples/relay.example.json --mode active
python scripts/demo_part_c.py                  # 假 provider -> relay -> 泄漏表
python -m unittest discover -s tests -t .      # C 模块自己的 27 项检查
```

这些命令不需要本服务的依赖（FastAPI/Ollama 都不用装）。BrandAI 不发任务头，中转站按
请求体推导 `turn` 与 `conv_id`，扫描时用任务清单的 `opening` 字段归因。详见
[docs/PART_C.md](docs/PART_C.md)。

## 文件分工

| 文件 | 作用 |
|---|---|
| `main.py` | API 输入校验、会话处理和响应字段 |
| `sessions.py` | 内存历史、四轮限制、会话删除 |
| `model_backend.py` | 构建 Ollama 请求，发送和解析结果 |
| `routing.py` | 内部/外部候选路由、检查后发送、内部回退 |
| `gate.py` | 关卡接口和默认拒绝占位实现 |
| `test_backend.py`、`test_routing.py` | 组件和本地传输检查 |
| `scripts/demo.py` | 调用真实模型的一键演示 |
| `relay7508/` | C 模块：中转站（C1/C2）与泄漏提取，纯标准库、与本服务解耦 |
| `docs/PART_C.md` | C 模块的端口契约、日志字段、归因方式与扫描命令 |

队友接口及尚未完成事项见 [INTEGRATION.md](INTEGRATION.md)。
内存会话要求单进程，不能添加多个 workers；服务未实现用户鉴权，仅绑定本机使用。
这是开发原型，尚不具备完整实验的可信来源标签、持续审计与所有对照配置。

## AI 使用记录

本分支由 AI 辅助实现和调试。负责成员需理解代码、复核结果，并按课程要求在最终提交中如实披露。
检查通过只代表所覆盖场景；完整实验结果由后续集成运行产生。
