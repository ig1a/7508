# DASE7508 — BrandAI Provider-Side Forwarding Gate

*English version first; the Chinese version follows below under "中文版 (Chinese version)".*

DASE7508 Security of Intelligent Systems group project. The research question:

> If an LLM service provider places a forwarding gate at its external-call boundary, can it stop
> confidential prompt content from reaching an untrusted relay or an external AI service, while keeping
> normal task utility?

The `feat/a-integration` branch integrates all five modules (A–E) into one runnable testbed. Every
module's commit history is preserved.

```text
Runner (A) → Assistant/API (B) → Security Gateway (D) → Relay (C) → Provider (B) → External Ollama
                     └──── deny / error → Internal Ollama (internal fallback)
Leak scoring: runner/leakscan.py (A) → relay7508 scan (C);  offline comparisons: evaluation/ (E)
```

The two Ollama instances run as separate processes on separate ports with the same model weights;
sessions and ingress logs are kept apart. This is a simulated local boundary, not an independent cloud
service. All secrets are synthetic.

## Modules

| Module | Responsibility | Main files | Commit author |
|---|---|---|---|
| A Threat model, task set, runner | Threat model and seven-configuration design; deterministic task set (120 tasks, 368 canaries) and six relay injections; experiment runner, utility scoring, leak-scan entry point | `docs/threat_model.md`, `docs/task_format.md`, `taskset/`, `data/attacks/`, `runner/` | Yau Hung Kei |
| B Assistant, routing, provider | FastAPI assistant, sessions, internal/external routing with fallback, independent external provider, end-to-end smoke test | `main.py`, `sessions.py`, `routing.py`, `model_backend.py`, `provider.py`, `integration_stack.py`, `scripts/` | ssss1112-ss |
| C Relay, leak extraction | Logging relay (passive C1 / active C2), canary leak extractor | `relay7508/`, `docs/PART_C.md` | duan111222333 |
| D Security Gateway | M1 content detection, M2 session provenance, policy, authentication, audit | `security_gateway/`, `gate.py` | CHANGXUAN SUN |
| E Offline evaluation | M1 offline detection benchmark, acceptance-count comparison, token-encoding fix for D | `evaluation/` | Elan Li |

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
.\.venv\Scripts\python.exe -m taskset.build
ollama pull qwen3:4b-instruct-2507-q4_K_M
```

`taskset.build` must print `120 tasks, 168 records, 368 canaries`. The generated files in
`data/generated/` are git-ignored because the synthetic secrets look real; everyone rebuilds them
locally. Verified with Python 3.13–3.14, Ollama 0.40.16 and qwen3:4b-instruct-2507-q4_K_M on Windows.

## Run

The [integration guide](docs/INTEGRATION_GUIDE.md) gives the full steps. In short:

1. **Smoke test (10 fixed scenarios, real models).** Keep the internal Ollama on 11434, start a second
   Ollama on 11437 (`$env:OLLAMA_HOST = '127.0.0.1:11437'; ollama serve`), then run
   `.\.venv\Scripts\python.exe scripts/integration_smoke.py`.
2. **Experiments on the task set.** Start the provider (11436), relay (11435) and assistant (8000), set
   the same random `BRANDAI_RUNNER_TOKEN` for the assistant and runner, then run for example
   `.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --runs 5`. After every C1/C2 batch the
   runner scores leakage with module C's extractor and writes `.leak.json` / `.leak.csv` next to the
   results in `reports/runs/`.
3. **Utility baseline.** `.\.venv\Scripts\python.exe -m runner.run --config C0` (assistant only).

Basic assistant usage is in [QUICKSTART.md](QUICKSTART.md); the HTTP and gate contracts are in
[INTEGRATION.md](INTEGRATION.md).

## Experiment design

Seven preregistered configurations form the main matrix (120 tasks × 7 × 5 runs = 4,200 trials):
C0 (internal only), C1-none / C1-M1 / C1-M2 (passive relay), C2-none / C2-M1 / C2-M2 (active relay).
`C1-M1_M2` and `C2-M1_M2` test the deployed combined policy and are reported separately. Details are
in the [threat model](docs/threat_model.md) §7.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -v
```

| Check | Result | Scope |
|---|---|---|
| Automated tests on `feat/a-integration` | 129/129 pass, none skipped (2026-11-23) | Model inference uses stand-ins; HTTP stack, gateway, relay, provider and real M1 detectors are real |
| Real two-model smoke test | 10/10 scenarios (2026-11-22, B's commit `bf15667`) | Fixed fictional scenarios; [validation record](docs/B_VALIDATION_20261122.md); not re-run on this branch |
| C0 pilot utility | 84/108; public 38/40 | Historical aggregate in `evaluation/results/`, not re-run |
| M1 offline detection | Confidential 61/80; public false positives 5/40 | Detection rate on the task set, not a leak rate |

GitHub Actions currently runs only module C's tests (`tests/`); run the full suite locally.

## Current status and open items

- The full 4,200-trial matrix has not been run yet, so there is no headline leak-rate result.
- The relay appends one fixed injection (INJ-01). The task set defines six, including a prepended one
  (INJ-03) and label laundering (INJ-04, property P5); the relay must support them, or the threat model
  must be narrowed, before C2 results are reported.
- The leak extractor matches exact, case-folded, whitespace-removed, URL-encoded and base64 forms;
  near-match and semantic leakage still need a separate (manual) review.
- Single-process, local-only service: no user authentication, do not add workers.

More detail is in the [threat model](docs/threat_model.md) §8.

## Documentation

| Document | Contents |
|---|---|
| [docs/threat_model.md](docs/threat_model.md) | Assets, boundaries, adversary, assumptions, properties, configurations, open gaps |
| [docs/task_format.md](docs/task_format.md) | Task, corpus, canary and injection formats |
| [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | Running the integrated stack, ports, reports |
| [INTEGRATION.md](INTEGRATION.md) | HTTP, gate, routing and audit interface specification |
| [QUICKSTART.md](QUICKSTART.md) | Using the assistant on its own |
| [docs/PART_C.md](docs/PART_C.md) | Relay and leak extractor |
| [docs/B_VALIDATION_20261122.md](docs/B_VALIDATION_20261122.md) | Real-model integration validation record |

## AI use

This project used AI assistance for design, coding, debugging and documentation. Each responsible member
must understand and review their own contribution, record verification commands and results in pull
requests, and disclose AI assistance and each member's actual contribution in the final report. Passing
automated checks covers only the tested scenarios; security conclusions must come from the controlled
experiments and their retained evidence.

---

## 中文版 (Chinese version)

### DASE7508 — BrandAI 服务商侧转发关卡

DASE7508 Security of Intelligent Systems 小组项目。研究问题：

> LLM 服务商在外部调用边界加入转发关卡后，能否阻止机密提示词到达不可信中转站或外部 AI 服务，同时保留正常任务效用？

`feat/a-integration` 分支把五个模块（A–E）集成为一个可运行的实验平台，并保留各模块的提交历史。

```text
Runner (A) → Assistant/API (B) → Security Gateway (D) → Relay (C) → Provider (B) → External Ollama
                     └──── deny / error → Internal Ollama (internal fallback)
Leak scoring: runner/leakscan.py (A) → relay7508 scan (C);  offline comparisons: evaluation/ (E)
```

两个 Ollama 使用独立进程/端口和相同模型权重，会话及接收日志分开。这是本地模拟边界，不是独立云服务。所有秘密均为合成数据。

### 模块

| 模块 | 职责 | 主要文件 | 提交作者 |
|---|---|---|---|
| A 威胁模型、任务集、Runner | 威胁模型和七配置设计；确定性任务集（120 个任务、368 个 canary）和六种中转站注入；实验 Runner、效用评分、泄漏扫描入口 | `docs/threat_model.md`、`docs/task_format.md`、`taskset/`、`data/attacks/`、`runner/` | Yau Hung Kei |
| B 助手、路由、Provider | FastAPI 助手、会话、内部/外部路由及回退、独立外部 Provider、端到端 smoke 测试 | `main.py`、`sessions.py`、`routing.py`、`model_backend.py`、`provider.py`、`integration_stack.py`、`scripts/` | ssss1112-ss |
| C 中转站、泄漏提取 | 记录型中转站（被动 C1 / 主动 C2）、canary 泄漏提取器 | `relay7508/`、`docs/PART_C.md` | duan111222333 |
| D Security Gateway | M1 内容检测、M2 会话来源标签、策略、认证、审计 | `security_gateway/`、`gate.py` | CHANGXUAN SUN |
| E 离线评估 | M1 离线检测 benchmark、接受计数比较、D 的令牌编码修正 | `evaluation/` | Elan Li |

### 安装

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
.\.venv\Scripts\python.exe -m taskset.build
ollama pull qwen3:4b-instruct-2507-q4_K_M
```

`taskset.build` 应显示 `120 tasks, 168 records, 368 canaries`。`data/generated/` 中的合成秘密外观逼真，因此不提交到 Git，每人在本机重新生成。已在 Windows、Python 3.13–3.14、Ollama 0.40.16、qwen3:4b-instruct-2507-q4_K_M 上验证。

### 运行

完整步骤见[集成指南](docs/INTEGRATION_GUIDE.md)。简要如下：

1. **Smoke 测试（10 个固定场景，真实模型）**：内部 Ollama 保持在 11434，另启动一个 Ollama 在 11437（`$env:OLLAMA_HOST = '127.0.0.1:11437'; ollama serve`），然后运行 `.\.venv\Scripts\python.exe scripts/integration_smoke.py`。
2. **任务集实验**：启动 Provider（11436）、Relay（11435）和 Assistant（8000），为 Assistant 和 Runner 设置同一个随机 `BRANDAI_RUNNER_TOKEN`，再运行例如 `.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --runs 5`。每个 C1/C2 批次结束后，Runner 调用 C 模块的提取器评分泄漏，并在 `reports/runs/` 的结果文件旁写出 `.leak.json` / `.leak.csv`。
3. **效用基线**：`.\.venv\Scripts\python.exe -m runner.run --config C0`（只需 Assistant）。

助手的基本用法见 [QUICKSTART.md](QUICKSTART.md)；HTTP 与关卡契约见 [INTEGRATION.md](INTEGRATION.md)。

### 实验设计

七个预注册配置构成主矩阵（120 个任务 × 7 × 5 次 = 4,200 个 trial）：C0（仅内部）、C1-none / C1-M1 / C1-M2（被动中转）、C2-none / C2-M1 / C2-M2（主动中转）。`C1-M1_M2` 和 `C2-M1_M2` 用于检验实际部署的组合策略，单独报告。详见[威胁模型](docs/threat_model.md) §7。

### 验证

```powershell
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -v
```

| 检查 | 结果 | 范围 |
|---|---|---|
| `feat/a-integration` 自动测试 | 129/129 通过，无跳过（2026-11-23） | 模型推理使用替身；HTTP 链路、Gateway、Relay、Provider 和真实 M1 检测器均为实际实现 |
| 真实双模型 smoke 测试 | 10/10 场景（2026-11-22，B 的提交 `bf15667`） | 固定虚构场景；见[验证记录](docs/B_VALIDATION_20261122.md)；本分支未重跑 |
| C0 pilot 效用 | 84/108；Public 38/40 | `evaluation/results/` 的历史聚合结果，未重跑 |
| M1 离线检测 | Confidential 61/80；Public 误报 5/40 | 任务集上的检测率，不是泄漏率 |

GitHub Actions 目前只运行 C 模块的测试（`tests/`）；完整测试请在本机运行。

### 当前状态与待办

- 尚未运行完整的 4,200-trial 矩阵，因此还没有总体泄漏率结果。
- 中转站只追加一条固定注入（INJ-01）。任务集定义了六种，包括前置注入（INJ-03）和标签洗白（INJ-04，对应属性 P5）；报告 C2 结果前，需要让中转站支持这些注入，或收窄威胁模型。
- 泄漏提取器匹配原文、大小写折叠、去空白、URL 编码和 base64 形式；近似匹配和语义泄漏仍需单独（人工）检查。
- 服务为单进程、仅限本机：没有用户鉴权，不要增加 workers。

更多细节见[威胁模型](docs/threat_model.md) §8。

### 文档

| 文档 | 内容 |
|---|---|
| [docs/threat_model.md](docs/threat_model.md) | 资产、边界、攻击者、假设、安全属性、实验配置、待解决缺口 |
| [docs/task_format.md](docs/task_format.md) | 任务、语料、canary 和注入格式 |
| [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | 运行集成链路、端口、报告 |
| [INTEGRATION.md](INTEGRATION.md) | HTTP、关卡、路由和审计接口说明 |
| [QUICKSTART.md](QUICKSTART.md) | 单独使用助手 |
| [docs/PART_C.md](docs/PART_C.md) | 中转站与泄漏提取器 |
| [docs/B_VALIDATION_20261122.md](docs/B_VALIDATION_20261122.md) | 真实模型集成验证记录 |

### AI 使用记录

本项目使用 AI 协助设计、编码、调试和文档整理。各负责成员必须理解并人工复核自己的贡献，在 pull request 中记录验证命令和结果，并在最终报告中如实说明 AI 协助及每位成员的实际贡献。自动检查通过只代表所覆盖场景；安全结论必须来自受控实验及保留的证据。
