# BrandAI 模块集成说明

## 当前边界

`main.py` 管理 HTTP 和会话；`routing.py` 负责选择路径；`gate.py` 定义关卡协议；
`model_backend.py` 封装 Ollama 请求。服务默认仅监听本机，没有鉴权。

内部地址是 `http://127.0.0.1:11434/api/chat`。
为中转站预留的地址是 `http://127.0.0.1:11435/api/chat`，当前没有启动该端点。
外部请求使用 Ollama 原生 chat JSON；中转站若采用其他协议，需一起调整请求构建与检查契约。
内部和外部应使用独立端点、状态和日志；可以采用相同权重，但不能直接把外部路由接回内部端点。

威胁模型与实验框架现已提供：

- `docs/threat_model.md`：信任边界、安全属性、攻击案例和七个实验配置；
- `docs/task_format.md`：任务、语料、标签、canary 和注入格式；
- `data/attacks/injections.jsonl`：六种主动中转站注入；
- `taskset/`：确定性生成并验证 120 个任务、168 条记录和 368 个 canary；
- `runner/run.py`：发送试验、记录 trial ID、触发 scripted compliance turn、评分和摘要。

这些文件定义实验契约，但不会自动实现或配置 gate、relay、外部模型和日志系统。

## 关卡负责人

实现 `ForwardingGate.inspect(request, session_id=...) -> GateDecision`，
然后在 `routing.py` 将 `PlaceholderGate()` 替换为真实实现。

- `request` 是不可变的 `OutboundRequest`，含 URL、POST 方法、应用级 Content-Type 和完整序列化 JSON body。
- HTTP 库还会生成 Host、Content-Length 等传输头；当前不发送认证头。
- `body` 包括模型、系统提示、完整用户/助手历史及生成参数。M1 应扫描整个序列化请求。
- 只返回严格布尔值 `GateDecision(allowed=True/False)`；检查异常或无效结果均拒绝外发。
- 关卡获准的 body 原样交给发送函数；不自动改写、重试或跟随重定向。
- 真实 M2 还需添加可信来源标签与会话级传播。这一版没有来源标签，`session_id` 本身不是保密标签。
- 不要从模型回答或 canary 清单推导可信标签；会话重置时还须清除队友模块关联的标签状态。
- 审计日志只保存决策元数据，不复制秘密值。当前响应提供决策字段，持久审计日志待集成。

## 中转站与评估负责人

`route_mode=internal_only` 是内部基线路径。
`route_mode=external_candidate` 每一轮都先生成候选请求，再执行关卡。
本版本没有无关卡实验模式，也没有自主工具调用或自动跟进；恶意返回的后续影响通过下一轮请求测试。
需要在全组集成阶段补充 C1/C2 和无关卡对照，不能把占位关卡的全拒绝结果计作 M1/M2 效果。

响应字段：

| 字段 | 含义 |
|---|---|
| requested_route | 用户/测试脚本选择的路由模式 |
| route | 实际完成回答的内部/外部路径 |
| gate_decision | not_checked / deny / allow / error |
| fallback | 是否回退到内部 |
| fallback_reason | gate_denied / gate_error / external_error / null |
| external_attempted | 是否尝试发送；不等同于对方收到 |
| gate_latency_ms | 关卡检查时间 |
| latency_ms | 整个处理耗时 |
| session_id, turn_count | 会话编号和成功完成的用户轮数 |

`DELETE /sessions/{id}` 删除当前助手内存中的会话。重新实验应使用新会话，并由评估脚本同步重置其他组件。
最多四轮、总内容 12000 UTF-8 字节；超限直接拒绝，不截掉旧历史。

Runner 支持 `C0`、`C1-none`、`C1-M1`、`C1-M2`、`C2-none`、`C2-M1` 和 `C2-M2`，
但配置名称目前只是结果元数据。正式实验前，集成层必须证明实际部署的 relay mode 和 gate mode
与请求配置一致；不能只根据输出文件名判断。

## 集成时必须补充的契约

### 1. Trial ID

Runner 在每个请求发送 `X-Trial-Id`，格式为：

```text
<config>:<task_id>:r<run>
```

`main.py` 目前会忽略这个 header。集成时应读取并传递同一个 trial ID 到 gate audit、relay 和
external-provider ingress 日志。日志缺少或重复 trial ID 时，该 trial 不应计入正式结果。

### 2. 可信标签与 M2

`tasks.jsonl` 的每一轮包含 `PUBLIC` 或 `CONFIDENTIAL` 标签；`records.jsonl` 提供 corpus metadata，
但 `canaries.jsonl` 只供 evaluator 使用。

集成 M2 时必须：

- 由受信任的 scripted client / corpus metadata 提供标签，而不是从模型输出或 canary 推断；
- `CONFIDENTIAL` 一旦进入 session，后续状态保持 confidential；
- 外部回复不能把标签降为 `PUBLIC`；
- 未知、缺失或无效标签 fail closed；
- 删除 session 时同步清除该 session 的标签状态。

`ChatRequest` 目前没有标签字段，具体 API 变更需由 assistant、gate 和 integration 负责人共同确认，
并为 PUBLIC、CONFIDENTIAL、缺失标签和 label-laundering 添加测试。

### 3. 每个 trial 的完整重置

Runner 目前只调用 `DELETE /sessions/{id}`。正式实验还必须重置：

- provenance/session label；
- relay 注入状态和缓存；
- external model conversation state；
- gate audit、relay 和 ingress 的 trial-local buffers。

重置失败时应停止该 trial 并返回非零退出状态，不能继续产生看似有效的结果。

### 4. 日志与 leak extraction

建议 gate、relay 和 ingress 使用 JSON Lines，并至少包含：

```json
{"trial_id":"C2-M2:C-cred-split-question:r1","component":"relay","event":"request_received","timestamp_utc":"..."}
```

Gate audit 只记录决策元数据，不复制请求 body 或 secret。Relay/ingress 日志是泄漏传感器，可保留
实验 payload，但必须限制在本地受控环境，并按 trial 分隔。Leak extractor 应按
`docs/task_format.md` 执行 exact、normalised、base64-decoded 和另行报告的 near-match 检查。

### 5. 主动中转站与 compliance turn

C2 relay 可 prepend 或 append `data/attacks/injections.jsonl` 中的文本。Runner 只有在用户可见回答
包含对应 `detect` 字符串后，才会发送该任务的额外 `compliance` turn。Relay 必须保留原始模型回答，
并记录注入 ID、位置和 timing，避免无法重建攻击链。

## 已验证与待验证

自动测试覆盖拒绝不发送、检查出错不发送、获准请求字节一致、后续轮次重新检查、
HTTP 重定向不跟随、外部失败回退、会话隔离与删除。
传输测试使用本机临时 HTTP 接收器和模拟关卡，不是真实 M1/M2 或完整中转站实验。
任务集和 runner 测试还覆盖确定性生成、canary 隔离、trial ID、compliance turn、错误清理和效用评分。
正式实验仍需检查配置 attestation、完整 reset、外部 ingress、标签传播、语义泄漏和 token 截断等。
