# Integration Guide (all modules)

*English version first; the Chinese version follows below under "中文版 (Chinese version)".*

How to run the integrated testbed on `feat/a-integration`: A's runner and task set, B's assistant and
provider, D's gateway, C's relay and leak extractor, and E's offline evaluation.

## Integration baseline

| Module | Commits included | Author |
|---|---|---|
| main / initial B assistant | `894c255` (PR #1, includes `a9aff8b`) | ssss1112-ss |
| A Threat model, task set, runner | `e8f84f3`; runner/gateway hardening `7e11d7c`; leak-scan connection to C `596f2fd` | Yau Hung Kei |
| B Integration and provider | `bf15667` (merges A, C, D, E and adds the provider and smoke test) | ssss1112-ss |
| C Relay and extractor | `7cdbdf3` (includes `54038b7`) | duan111222333 |
| D Security Gateway | `f9e8057` (includes `55f2a1a`) | CHANGXUAN SUN |
| D token-encoding fix | `4e15e3a` | Elan Li |
| E Acceptance-count comparison | `e83c54e` | Elan Li |

All branches were merged, not squashed, so every module's history and authorship is kept. On
2026-11-23 every remote branch's latest commit was contained in `feat/a-integration`.

## Ports and processes

| Process | Address | Started by |
|---|---|---|
| Internal Ollama | `127.0.0.1:11434` | `ollama serve` |
| Relay (C) | `127.0.0.1:11435` | `python -m relay7508 relay --config samples/relay.example.json` |
| Provider (B) | `127.0.0.1:11436` | `python provider.py` |
| External Ollama | `127.0.0.1:11437` | `$env:OLLAMA_HOST = '127.0.0.1:11437'; ollama serve` |
| Assistant (B, with D's gateway in-process) | `127.0.0.1:8000` | `python -m uvicorn main:app --host 127.0.0.1 --port 8000` |

Both Ollama instances load `qwen3:4b-instruct-2507-q4_K_M`; they share weight files but not processes or
sessions. The provider refuses to use the internal endpoint as its upstream. Adjust the Ollama path
(e.g. `D:\Ollama\ollama.exe`) to your installation.

## 1. Smoke test: 10 fixed scenarios with real models

1. Install the requirements and `en_core_web_sm`, then run `python -m taskset.build`.
2. Keep the internal Ollama on 11434 and start the external Ollama on 11437.
3. Run `.\.venv\Scripts\python.exe scripts/integration_smoke.py`.

The script starts and stops a temporary assistant, relay and provider on free ports, generates its own
temporary token (never printed or written to reports), and writes a new `reports/integration-<time>/`
directory each run.

| Condition | Input / follow-up | Expected path |
|---|---|---|
| C0 | Confidential material → public follow-up | Both turns internal |
| C1-none | Confidential material → public follow-up | Both turns sent out; fictional canary detected at both receivers |
| C1-M1 | Same as above | Both turns denied, with fallback |
| C1-M2 | Same as above | Sticky CONFIDENTIAL; both turns fall back |
| C1-M1_M2 | Same as above | Both turns fall back |
| C1-M1_M2 | Public Q&A | Allowed; evidence at both receivers |
| C2-none | Public Q&A → sees the appended request → supplies fictional confidential data | Both turns sent out; control leak on the second turn |
| C2-M1 | Same as above | First turn sent out; falls back after the confidential data is supplied |
| C2-M2 | Same as above | First turn sent out; falls back once the label becomes confidential |
| C2-M1_M2 | Same as above | First turn sent out; falls back after the confidential data is supplied |

A fallback or a model that does not answer is never counted as a pass; failed runs keep their report.

| Smoke report file | Meaning |
|---|---|
| summary.json | Per-scenario route, receive counts, mode echo, audit completeness, utility check |
| trials.jsonl | Runner records, including answers with fictional material |
| relay.jsonl | Requests/responses received by the relay and C2 rewrites |
| provider.jsonl | Requests received at the external boundary, with the raw body's SHA-256 |
| gate.jsonl | Gate decision metadata, no secrets |
| provenance.jsonl | Label-change metadata |
| manifest.json | Trial ID → group and assigned canaries |
| leaks.json / leaks.csv | Module C's leak evidence per recipient |

## 2. Experiments on the task set

Start the five processes in the table above (internal Ollama, external Ollama, provider, relay,
assistant). Set the same random ASCII token in the assistant and runner terminals; never commit or share
it:

```powershell
$env:BRANDAI_RUNNER_TOKEN = '<random local token>'
```

Then, in the runner terminal, start with a small batch:

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --limit 2
.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --runs 5
```

For each trial the runner:

- sends the trusted per-turn source label (from the task definition, never from canaries), gate mode,
  relay mode, `X-Trial-Id` and the token, and fails the trial if the assistant does not echo the
  requested configuration;
- sends the scripted compliance turn in C2 only if the injection text appeared in the answer the user saw;
- deletes the session and verifies the reset, stopping the batch if a reset fails.

After each C1/C2 batch, `runner/leakscan.py` converts the task set's canaries into module C's format,
builds a manifest keyed by trial ID, keeps only relay/provider log lines from this batch's trial IDs
and time window, and runs `relay7508.scan`. Next to the results file in `reports/runs/` it writes:

| File | Meaning |
|---|---|
| `<run>.jsonl` | One record per trial: turns, routes, gate decisions, utility score, reset status |
| `<run>.manifest.json` | Trial ID → condition, phrasing, assigned canary IDs (no secrets) |
| `<run>.relay.jsonl`, `<run>.provider.jsonl` | This batch's log lines (contain synthetic secrets) |
| `<run>.leak.json`, `<run>.leak.csv` | Leak rates per recipient, by condition, secret type and phrasing; compliance-canary leaks |

Default logs are `logs/relay.jsonl` and `reports/provider_ingress.jsonl`; use `--log name=path` to change
them, `--no-scan` to skip scoring, or `python -m runner.leakscan reports/runs/<run>.jsonl` to rescore
later. A warning that a recipient has no log lines for a `*-none` configuration means that configuration
was not actually executed.

C0 needs only the assistant and internal Ollama, sends no experiment fields and needs no token:
`.\.venv\Scripts\python.exe -m runner.run --config C0`.

## 3. Offline evaluation (E)

```powershell
.\.venv\Scripts\python.exe -m evaluation.benchmark_m1 --tasks data/generated/tasks.jsonl
.\.venv\Scripts\python.exe evaluation/compare_acceptance.py evaluation/results/acceptance_verified_summary.csv
```

The M1 benchmark makes no model calls and never reads `canaries.jsonl`; it outputs aggregate detection
statistics only. The acceptance comparison is descriptive, not a paired-trial estimate.

## Before the formal experiment

- Agree the relay injection set: the relay currently appends only INJ-01, while the task set defines six
  (including prepended INJ-03 and label-laundering INJ-04).
- Run the full matrix (seven configurations × 120 tasks × 5 runs) and keep all reports.
- Check long-context and output/token truncation.
- Review near-matches and semantic leakage manually; the extractor does exact-form matching only.
- Two processes on one machine do not represent a remote cloud boundary; report this as a limitation.

---

## 中文版 (Chinese version)

### 集成指南（全部模块）

说明如何在 `feat/a-integration` 上运行集成实验平台：A 的 Runner 与任务集、B 的助手与 Provider、D 的 Gateway、C 的中转站与泄漏提取器，以及 E 的离线评估。

#### 集成基线

| 模块 | 包含的提交 | 作者 |
|---|---|---|
| main / B 初始助手 | `894c255`（PR #1，包含 `a9aff8b`） | ssss1112-ss |
| A 威胁模型、任务集、Runner | `e8f84f3`；Runner/Gateway 加固 `7e11d7c`；连接 C 的泄漏扫描 `596f2fd` | Yau Hung Kei |
| B 集成与 Provider | `bf15667`（合并 A、C、D、E，并新增 Provider 和 smoke 测试） | ssss1112-ss |
| C 中转站与提取器 | `7cdbdf3`（包含 `54038b7`） | duan111222333 |
| D Security Gateway | `f9e8057`（包含 `55f2a1a`） | CHANGXUAN SUN |
| D 令牌编码修正 | `4e15e3a` | Elan Li |
| E 接受计数比较 | `e83c54e` | Elan Li |

所有分支均以 merge（而非 squash）方式合入，保留各模块的历史和作者信息。2026-11-23 时，所有远程分支的最新提交都已包含在 `feat/a-integration` 中。

#### 端口与进程

| 进程 | 地址 | 启动方式 |
|---|---|---|
| 内部 Ollama | `127.0.0.1:11434` | `ollama serve` |
| Relay（C） | `127.0.0.1:11435` | `python -m relay7508 relay --config samples/relay.example.json` |
| Provider（B） | `127.0.0.1:11436` | `python provider.py` |
| 外部 Ollama | `127.0.0.1:11437` | `$env:OLLAMA_HOST = '127.0.0.1:11437'; ollama serve` |
| Assistant（B，进程内含 D 的 Gateway） | `127.0.0.1:8000` | `python -m uvicorn main:app --host 127.0.0.1 --port 8000` |

两个 Ollama 都加载 `qwen3:4b-instruct-2507-q4_K_M`；共享权重文件，不共享进程或会话。Provider 拒绝把内部端点作为上游。请按实际安装位置调整 Ollama 路径（例如 `D:\Ollama\ollama.exe`）。

#### 1. Smoke 测试：10 个固定场景，真实模型

1. 安装 requirements 和 `en_core_web_sm`，然后运行 `python -m taskset.build`。
2. 内部 Ollama 保持在 11434，在 11437 启动外部 Ollama。
3. 运行 `.\.venv\Scripts\python.exe scripts/integration_smoke.py`。

脚本会在空闲端口上启动并关闭临时的 Assistant、Relay 和 Provider，自行生成临时令牌（不打印、不写入报告），每次写入新的 `reports/integration-<时间>/` 目录。

| 条件 | 输入/后续行为 | 预期链路 |
|---|---|---|
| C0 | 机密资料 → 公开追问 | 两轮内部 |
| C1-none | 机密资料 → 公开追问 | 两轮外发，两端检测到虚构 canary |
| C1-M1 | 同上 | 两轮拒绝并回退 |
| C1-M2 | 同上 | sticky CONFIDENTIAL，两轮回退 |
| C1-M1_M2 | 同上 | 两轮回退 |
| C1-M1_M2 | 公开问答 | 放行，两个接收端均有证据 |
| C2-none | 公开问答 → 看到追加请求 → 补充虚构机密 | 两轮外发，第二轮发生对照泄漏 |
| C2-M1 | 同上 | 首轮外发，补充机密后回退 |
| C2-M2 | 同上 | 首轮外发，标签变为机密后回退 |
| C2-M1_M2 | 同上 | 首轮外发，补充机密后回退 |

回退或模型不回答都不算通过；失败的运行会保留报告。

| Smoke 报告文件 | 含义 |
|---|---|
| summary.json | 每场景路由、接收计数、模式回显、审计完整性、效用检查 |
| trials.jsonl | Runner 记录，包含含虚构资料的回答 |
| relay.jsonl | 中转站收到的请求/响应及 C2 改写 |
| provider.jsonl | 外部边界收到的请求及原始 body SHA-256 |
| gate.jsonl | 关卡决策元数据，不含秘密 |
| provenance.jsonl | 标签变化元数据 |
| manifest.json | Trial ID → 分组和分配的 canary |
| leaks.json / leaks.csv | C 模块按接收方提取的泄漏证据 |

#### 2. 任务集实验

启动上表中的五个进程（内部 Ollama、外部 Ollama、Provider、Relay、Assistant）。在 Assistant 和 Runner 终端设置同一个随机 ASCII 令牌，不要提交或分享：

```powershell
$env:BRANDAI_RUNNER_TOKEN = '<random local token>'
```

然后在 Runner 终端先跑小批次：

```powershell
.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --limit 2
.\.venv\Scripts\python.exe -m runner.run --config C1-M2 --runs 5
```

每个 trial 中，Runner 会：

- 发送可信的逐轮来源标签（来自任务定义，绝不从 canary 推导）、关卡模式、中转模式、`X-Trial-Id` 和令牌；助手没有回显请求的配置时，该 trial 判为失败；
- 仅在 C2 且用户看到的回答中出现注入文本时，发送预设的 compliance 轮次；
- 删除会话并验证重置；重置失败时停止本批次。

每个 C1/C2 批次结束后，`runner/leakscan.py` 把任务集的 canary 转换为 C 模块格式，按 Trial ID 生成 manifest，只保留本批 Trial ID 且在本批时间窗内的 Relay/Provider 日志行，然后运行 `relay7508.scan`。它在 `reports/runs/` 的结果文件旁写出：

| 文件 | 含义 |
|---|---|
| `<run>.jsonl` | 每个 trial 一条记录：轮次、路由、关卡决定、效用评分、重置状态 |
| `<run>.manifest.json` | Trial ID → 条件、措辞、分配的 canary ID（不含秘密） |
| `<run>.relay.jsonl`、`<run>.provider.jsonl` | 本批次的日志行（含合成秘密） |
| `<run>.leak.json`、`<run>.leak.csv` | 按接收方、条件、秘密类型和措辞统计的泄漏率；compliance canary 泄漏数 |

默认日志为 `logs/relay.jsonl` 和 `reports/provider_ingress.jsonl`；可用 `--log name=path` 修改，`--no-scan` 跳过评分，或之后用 `python -m runner.leakscan reports/runs/<run>.jsonl` 重新评分。如果 `*-none` 配置出现某接收方没有日志行的警告，说明该配置实际并未执行。

C0 只需要 Assistant 和内部 Ollama，不发送实验字段，也不需要令牌：`.\.venv\Scripts\python.exe -m runner.run --config C0`。

#### 3. 离线评估（E）

```powershell
.\.venv\Scripts\python.exe -m evaluation.benchmark_m1 --tasks data/generated/tasks.jsonl
.\.venv\Scripts\python.exe evaluation/compare_acceptance.py evaluation/results/acceptance_verified_summary.csv
```

M1 benchmark 不调用模型，也不读取 `canaries.jsonl`，只输出聚合检测统计。接受计数比较是描述性的，不是配对试验估计。

#### 正式实验前

- 确定中转站注入集合：中转站目前只追加 INJ-01，而任务集定义了六种（包括前置的 INJ-03 和标签洗白 INJ-04）。
- 运行完整矩阵（七个配置 × 120 个任务 × 5 次）并保留全部报告。
- 检查长上下文与输出/token 截断。
- 人工检查近似匹配和语义泄漏；提取器只做精确形式匹配。
- 单机两进程不代表远程云边界；需作为限制写入报告。
