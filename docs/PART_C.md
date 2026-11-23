# Module C: Relay and Leak Extraction

*English version first; the Chinese version follows below under "中文版 (Chinese version)".*

> Status on the integrated branch (`feat/a-integration`): the router sends X-Trial-Id and
> X-Relay-Mode; the relay switches mode per request and isolates logs and injection counts by full
> trial ID, so the opening-based derivation in §3 is only a fallback for headerless clients. Module
> B's `provider.py` (11436) is the relay's upstream, with an independent Ollama on 11437. Module A's
> `runner/leakscan.py` builds the task manifest (§6 item 3) from the task set and runs `scan` after
> every C1/C2 batch. See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) for running the full stack.

Covers items 2 (relay / transfer station) and 5 (leak extractor) of the proposal's §3 "Build".
Implemented with the standard library only (`http.server` + `http.client`), so any teammate's machine
can start it with `python relay`; no mitmproxy, FastAPI or other third-party package is needed.

## 1. Ports and protocol contract

| Component | Address | Notes |
|---|---|---|
| BrandAI internal model | `127.0.0.1:11434/api/chat` | `model_backend.OLLAMA_CHAT_URL`; does not go through the relay |
| **Relay (this module)** | `127.0.0.1:11435/api/chat` | `routing.EXTERNAL_CHAT_URL` already points here |
| External provider wrapper (B/D) | `127.0.0.1:11436/api/chat` | The relay's upstream; must keep its own ingress log |

When the backend uses `external_candidate` and the gate allows the request, `routing.send_payload()`
POSTs Ollama's native chat JSON to 11435; the relay **forwards it unchanged** to 11436 and writes the
full request/response to `logs/relay.jsonl`. As long as the response body has one of three shapes,
Ollama `{"message": {"content": "..."}}`, OpenAI `{"choices": [{"message": {"content": "..."}}]}` or
`{"response": "..."}`, the C2 appended sentence can be written back and `Content-Length` updated to
the new length.

`stream: false` is a precondition (BrandAI's `build_payload()` already fixes it); this implementation
does not parse SSE.

## 2. Running the three conditions

| Condition | Configuration |
|---|---|
| C0 baseline | `route_mode=internal_only`; does not go through the relay, no log |
| C1 passive relay | relay `mode=passive`: records only, no rewriting |
| C2 active relay | relay `mode=active`: appends `active.append_text` to the end of the reply |

The `active` policy is controlled by `config.ActivePolicy`: `min_turn` (from which turn to start
appending), `max_appends_per_task` (per-task limit) and `only_if_absent` (do not append again if the
reply already contains the sentence).

```powershell
# C1
python -m relay7508 relay --config samples/relay.example.json
# C2
python -m relay7508 relay --config samples/relay.example.json --mode active
```

## 3. Attribution when BrandAI sends no task header

`routing.py` sends only `Content-Type`, with no `X-Task-Id`, so the relay derives two values from the
request body:

- `turn` = the number of `role=user` messages in the request body. BrandAI resends the full history
  every turn, so this count is exact and stateless;
- `conv_id` = the first 12 hex digits of the SHA-1 of the first user message (after whitespace
  normalisation), stable across all turns of a session.

`scan` recomputes the same hash from the `opening` field in the task manifest to map conversations in
the log back to `task_id`; older tasks without `opening` in the manifest fall back to `unknown-task`
and are flagged in the report by `tasks_missing_from_manifest` (evidence is never dropped silently).

If `X-Task-Id` / `X-Condition` / `X-Turn` headers are added to the backend later, the relay uses the
headers first and this derivation steps aside automatically, with no code change.

## 4. Logs and leak detection

Each record in `logs/relay.jsonl`:

```json
{"flow_id": "...", "ts": "...", "recipient": "relay", "method": "POST",
 "path": "/api/chat", "task_id": "t1", "conv_id": "9f2c...", "condition": "C2", "turn": 2,
 "request":  {"headers": {...}, "body": {...}},
 "response": {"status": 200, "headers": {...}, "body": {...}},
 "rewrite":  {"applied": true, "paths": ["/message/content"], "appended": "...", "reason": "active"},
 "error": null}
```

The extractor scans both the **request** and the **response** of every record and compares each
canary against six representations: verbatim, case-folded, whitespace-removed, URL-encoded, base64,
and decoding any base64 strings found in the log before comparing (`canary.py` priority:
verbatim > casefold > whitespace > url_encoded > base64). A hit records `{turn, forms, direction}`,
with `turn` taken from the earliest occurrence.

```powershell
python -m relay7508 scan --canaries samples/canaries.example.json `
    --log relay=logs/relay.jsonl --log provider=logs/provider.jsonl `
    --tasks samples/tasks.example.json --out reports/leak.json --csv reports/leak.csv
```

## 5. Mapping outputs to the proposal's §4 metrics

| Report field | Proposal metric |
|---|---|
| `totals[recipient].leak_rate` | Leak rate, **reported separately per recipient** |
| `totals[recipient].canaries_leaked` / `tasks_affected` | Numerator and extent |
| `extra_leakage_after_turn_1[recipient]` | C2 extra leakage (canaries absent from the first turn that leak in later turns) |
| `by_secret_type` / `by_phrasing` | Grouped by the 4 secret types and 4 phrasings |
| `by_condition` | C1 vs C2 comparison |
| `tasks[].calls` | Requests per task; usable as the denominator for latency / extra-call cost |
| `totals[].off_manifest_leaks` | Canaries found under a task they were not assigned to (usually a mistyped ID) |

## 6. Only three things are needed to connect to BrandAI

1. The relay listens on 11435 with `upstream` pointing at your provider wrapper (default 11436);
2. The provider wrapper writes its own ingress log with the fields `recipient`, `task_id` (or
   `conv_id`), `turn` and `request.body`; pass it to `scan` with `--log provider=...`;
3. The task manifest adds three fields: `opening` (the user's exact first-turn text, for
   attribution), `assigned` (which canary IDs were planted in the task) and `condition` / `phrasing`
   (for grouped statistics); other fields are free-form.

## 7. Tests and demo

```powershell
python -m unittest discover -s tests -t .   # 27 tests, none depending on third-party packages
python scripts/demo_part_c.py               # fake provider -> relay -> leak table
```

Coverage: the six canary representations and false positives, forwarding and full-body logging, C2
appending with `rewrite` bookkeeping, `min_turn` leaving the first turn unchanged, attribution by
`opening` when the log has no task ID, scan grouping, and C2 extra leakage.

## 8. Known limitations

- SSE streaming is not supported (BrandAI fixes `stream: false`, which is enough for now);
- `mitm_addon.py` is an optional HTTPS version that has only been verified for import and logic reuse,
  never actually run;
- The relay does not retry or follow redirects; on upstream failure it logs the error and returns 502;
- Active mode appends a single configured text (`active.append_text`, aligned with A's INJ-01); the
  other five injections in `data/attacks/injections.jsonl`, including the prepended INJ-03 and the
  label-laundering INJ-04, are not yet supported;
- Matching covers exact, case-folded, whitespace-removed, URL-encoded and base64 forms; near-matches
  and paraphrases are not detected.

Resolved since the C branch: the real backend (Ollama + provider wrapper) is integrated and was
validated with real models on 2026-11-22, and the no-gate control exists as `gate_mode=none`
(configurations C1-none and C2-none).

---

## 中文版 (Chinese version)

### C 模块：中转站与泄漏提取

> 集成分支（`feat/a-integration`）现状：Router 发送 X-Trial-Id 与 X-Relay-Mode；Relay 按每个请求的模式切换，并按完整 Trial ID 隔离日志与注入次数，因此 §3 的 opening 推导只作为无头客户端的后备。B 模块的 `provider.py`（11436）是中转站的上游，其后是独立 Ollama（11437）。A 模块的 `runner/leakscan.py` 根据任务集生成任务清单（§6 第 3 项），并在每个 C1/C2 批次后运行 `scan`。运行完整链路见 [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)。

对应提案 §3 "Build" 的第 2 项（relay / transfer station）与第 5 项（leak extractor）。
纯标准库实现（`http.server` + `http.client`），任何队友机器 `python relay` 即可启动，
不需要 mitmproxy、FastAPI 或任何第三方包。

#### 1. 端口与协议契约

| 组件 | 地址 | 说明 |
|---|---|---|
| BrandAI 内部模型 | `127.0.0.1:11434/api/chat` | `model_backend.OLLAMA_CHAT_URL`，不经过中转 |
| **中转站（本模块）** | `127.0.0.1:11435/api/chat` | `routing.EXTERNAL_CHAT_URL` 已经指向这里 |
| 外部 provider 包装（B/D） | `127.0.0.1:11436/api/chat` | 中转站的上游，需自带 ingress 日志 |

后端走 `external_candidate` 且关卡放行时，`routing.send_payload()` 把 Ollama 原生 chat JSON
POST 到 11435；中转站**原样转发**给 11436，并把请求/响应完整写进 `logs/relay.jsonl`。
响应体只要符合 Ollama `{"message": {"content": "..."}}`、OpenAI
`{"choices": [{"message": {"content": "..."}}]}` 或 `{"response": "..."}` 三种形态之一，
C2 的追加句就能写回去并把 `Content-Length` 改成新长度。

`stream: false` 是前提（BrandAI 的 `build_payload()` 已经固定），本实现不解析 SSE。

#### 2. 三种条件怎么跑

| 条件 | 怎么配置 |
|---|---|
| C0 基线 | `route_mode=internal_only`，不经过中转站，无日志 |
| C1 被动中转 | relay `mode=passive`：只记录，不改写 |
| C2 主动中转 | relay `mode=active`：在回复末尾追加 `active.append_text` |

`active` 策略由 `config.ActivePolicy` 控制：`min_turn`（第几轮起才追加）、
`max_appends_per_task`（每任务上限）、`only_if_absent`（回复里已有该句子就不重复追加）。

```powershell
# C1
python -m relay7508 relay --config samples/relay.example.json
# C2
python -m relay7508 relay --config samples/relay.example.json --mode active
```

#### 3. 归因：BrandAI 不发任务头怎么办

`routing.py` 只发 `Content-Type`，没有 `X-Task-Id`，所以中转站从请求体推导两个值：

- `turn` = 请求体里 `role=user` 的消息条数。BrandAI 每轮都重发完整历史，所以这个计数
  是精确的，且无状态；
- `conv_id` = 第一条 user 消息（空白归一化后）的 SHA-1 前 12 位，同一会话各轮稳定。

`scan` 用任务清单里的 `opening` 字段重算同样的哈希，把日志里的会话映射回 `task_id`；
清单里没有 `opening` 的旧任务会退化为 `unknown-task` 并在报告里被
`tasks_missing_from_manifest` 警告出来（不会静默丢证据）。

如果后续给后端加上 `X-Task-Id` / `X-Condition` / `X-Turn` 头，中转站会优先用头，
这条推导路径自动让位，无需改代码。

#### 4. 日志与泄漏判定

`logs/relay.jsonl` 每条记录：

```json
{"flow_id": "...", "ts": "...", "recipient": "relay", "method": "POST",
 "path": "/api/chat", "task_id": "t1", "conv_id": "9f2c...", "condition": "C2", "turn": 2,
 "request":  {"headers": {...}, "body": {...}},
 "response": {"status": 200, "headers": {...}, "body": {...}},
 "rewrite":  {"applied": true, "paths": ["/message/content"], "appended": "...", "reason": "active"},
 "error": null}
```

提取器对每条记录扫**请求**和**响应**两个方向，把每个 canary 与六种表示比对：
原文、大小写折叠、去掉空白、URL 编码、base64、以及日志里出现 base64 串时反解后再比对
（`canary.py` 优先级 verbatim > casefold > whitespace > url_encoded > base64）。
命中即记录 `{turn, forms, direction}`，`turn` 取最早一次。

```powershell
python -m relay7508 scan --canaries samples/canaries.example.json `
    --log relay=logs/relay.jsonl --log provider=logs/provider.jsonl `
    --tasks samples/tasks.example.json --out reports/leak.json --csv reports/leak.csv
```

#### 5. 输出与提案 §4 指标的对应

| 报告字段 | 提案里的指标 |
|---|---|
| `totals[recipient].leak_rate` | 泄漏率，**按接收方分别统计** |
| `totals[recipient].canaries_leaked` / `tasks_affected` | 分子与影响面 |
| `extra_leakage_after_turn_1[recipient]` | C2 的额外泄漏（首轮没出现、后续轮才漏的 canary 数） |
| `by_secret_type` / `by_phrasing` | 按 4 种密钥类型、4 种措辞分组 |
| `by_condition` | C1 vs C2 对比 |
| `tasks[].calls` | 每任务请求数，可作延迟/额外调用成本的分母 |
| `totals[].off_manifest_leaks` | 出现在未分配给该任务的 canary（多半是 id 打错） |

#### 6. 与 BrandAI 对接只需要三件事

1. relay 监听 11435，`upstream` 指向你们的 provider 包装（默认 11436）；
2. provider 包装自己写一份 ingress 日志，字段含 `recipient`、`task_id`（或 `conv_id`）、
   `turn`、`request.body`；交给 `scan` 时用 `--log provider=...`；
3. 任务清单补三个字段：`opening`（首轮用户原话，用于归因）、`assigned`（该任务种了哪些
   canary id）、`condition` / `phrasing`（分组统计用），其余字段自由。

#### 7. 测试与演示

```powershell
python -m unittest discover -s tests -t .   # 27 项，全部不依赖第三方包
python scripts/demo_part_c.py               # 假 provider -> relay -> 泄漏表
```

覆盖：canary 六种表示与误报、转发与完整 body 落盘、C2 追加且 `rewrite` 记账、
`min_turn` 不改首轮、日志里无任务 id 时按 `opening` 归因、扫描分组与 C2 额外泄漏。

#### 8. 已知限制

- 不支持 SSE 流式（BrandAI 固定 `stream: false`，当前够用）；
- `mitm_addon.py` 是可选 HTTPS 版本，只做过 import 与逻辑复用验证，没有实跑；
- 中转站不重试、不跟随重定向，上游失败时把错误写进日志并返回 502；
- 主动模式只追加一条配置文本（`active.append_text`，与 A 的 INJ-01 对齐）；`data/attacks/injections.jsonl` 中其余五种注入（包括前置的 INJ-03 和标签洗白 INJ-04）尚不支持；
- 匹配覆盖原文、大小写折叠、去空白、URL 编码和 base64 形式；不检测近似匹配和改写。

C 分支之后已解决：真实后端（Ollama + provider 包装）已联调，并于 2026-11-22 用真实模型验证；"无关卡"对照已通过 `gate_mode=none` 实现（配置 C1-none 和 C2-none）。
