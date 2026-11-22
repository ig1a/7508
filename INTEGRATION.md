# 模块接口说明

## 当前边界

`main.py` 管理 HTTP、实验请求认证和会话标签；`routing.py` 负责路径选择、关卡调用及发送；
`gate.py` 定义协议并导出 `SecurityForwardingGate`；`model_backend.py` 封装 Ollama 请求。
服务仅供本机实验，没有用户登录鉴权；可信来源标签及实验控制字段已使用 `X-Experiment-Token` 认证。

内部地址是 `http://127.0.0.1:11434/api/chat`。
外部地址通过 `BRANDAI_RELAY_URL` 配置，默认 `http://127.0.0.1:11435/api/chat`。本分支已接入 `relay7508/`，新增 `provider.py`（11436），其上游是独立 Ollama（11437）。内部地址可用 `BRANDAI_INTERNAL_URL` 配置，Provider 拒绝复用该内部端点。
外部请求使用 Ollama 原生 chat JSON；若接收端采用其他协议，需要适配请求构建与检查契约。
内部和外部应使用独立端点、状态和日志；可以采用相同权重，但不能直接把外部路由接回内部端点。

## 关卡接口

`ForwardingGate.inspect(request, *, session_id=...) -> GateDecision` 已由 `SecurityForwardingGate` 实现。
Router 默认实例为 `SecurityForwardingGate()`；`PlaceholderGate` 仅保留用于兼容，不是默认实现。

- `request` 是不可变的 `OutboundRequest`：包含 URL、POST 方法、headers、完整序列化 JSON body，以及 `gate_mode`（默认 M1_M2）、`trial_id`、`relay_mode`（默认 passive）。
- `GateDecision` 包含严格布尔值 `allowed`，以及 `reason_code`、`session_label`、`detection_types`、`inspection_complete`、`latency_ms`。Router 拒绝类型不正确的结果。
- M1 Content Detection 已实现：使用 detect-secrets、Presidio 和编码变体扫描，检查完整用户/助手对话、系统提示及动态字段。固定模型和生成元数据不参与内容检测；URL userinfo/query 和非固定应用请求头也会检查。固定 Content-Type、X-Trial-Id、X-Relay-Mode 被排除。HTTP 库生成的 Host、Content-Length 不属于应用候选请求头。
- M2 Session Provenance 已实现：读取当前会话的来源标签；CONFIDENTIAL 或 UNKNOWN 均拒绝外发，只有 PUBLIC 可通过 M2。
- M1 模式要求扫描完整且无敏感发现；M2 模式只检查会话标签；默认 M1_M2 要求两者都通过。扫描不完整、依赖不可用、检测超时、无效策略或 Gateway 内部异常均 Fail-Closed。检测超时后该 Gate 实例持续拒绝 M1 请求，直至服务重启。
- 获准的 body 和应用请求头原样交给 `send_payload()`，不在检查后重建请求，不自动重试或跟随重定向。

## HTTP 与会话接口

`POST /chat` 保留 `message`、`session_id`、`route_mode`，并支持：

| 字段 | 值及默认行为 |
|---|---|
| source_label | PUBLIC / CONFIDENTIAL / UNKNOWN；默认省略，按 UNKNOWN 合并 |
| gate_mode | none / M1 / M2 / M1_M2；默认 M1_M2 |
| relay_mode | passive / active；默认省略，传给 Router 时为 passive |

显式提交非空 `source_label`、选择非默认 `gate_mode` 或显式提交 `relay_mode` 时，
必须携带 `X-Experiment-Token`，与服务端环境变量 `BRANDAI_RUNNER_TOKEN` 做恒定时间比较。
服务端令牌未配置、请求头缺失或不匹配时返回 HTTP 401，且发生在创建/更新会话之前。
该认证也适用于 internal_only 请求中的这些字段；普通无标签、默认模式请求不需要该头。
这是本机实验认证，不是用户身份认证。`X-Experiment-Token` 不转发给 Relay/Provider。

`X-Trial-Id` 是可选请求头，必须符合 `<config>:<task_id>:r<run>` 的受限字符及长度格式。
API 和 Gateway 都会拒绝无效或不一致的值，避免未扫描 header 成为外发通道。有效 ID 会传给 Router 和 `OutboundRequest.trial_id`；
Gateway 检查审计写入 `trial_id`，外发时非空值作为 `X-Trial-Id` 发送。
Router 同时发送 `X-Relay-Mode`。Trial ID 本身不授予标签或模式控制权限。

来源标签由可信客户端提供，不从模型回答或 Canary Registry 推导。
输入和上下文限制检查通过后，API 在调用 Router 前更新 Session Security Label，内部路径也会更新：
首轮建立标签；此后 CONFIDENTIAL 优先，其次 UNKNOWN，PUBLIC 不能把它们降级。
省略来源标签的后续请求会合并 UNKNOWN。模型失败不保存该轮消息；
已有会话的保守标签更新不会回滚，新建会话遇到模型错误时会清理历史和标签。

`DELETE /sessions/{session_id}` 在同一把会话锁内删除历史及标签，未知 ID 返回 404。
会话保持单进程、最多四轮、总内容 12000 UTF-8 字节；超限拒绝，不截掉旧历史。

## Router、实验模式与回退

`route_mode=internal_only` 直接调用内部模型，不构建外部请求，也不调用 Gateway。
`route_mode=external_candidate` 每轮构建候选请求；除 none 模式外，调用
`SecurityForwardingGate.inspect()` 后再决定是否发送。

| 情况 | 外发行为 | 响应与回退 |
|---|---|---|
| Gate DENY | 不调用外部发送函数 | deny / gate_denied；Internal Fallback，external_attempted=false |
| Gate ALLOW | 发送同一候选请求 | 成功时 external / allow；external_attempted=true |
| Gateway 内部异常或扫描不完整 | 返回不完整决定，不外发 | error / gate_error；具体原因保存在 Gate 审计 |
| inspect 抛出未捕获异常或返回无效结果 | 不外发 | error / gate_error；Internal Fallback |
| 外部发送失败 | 可能已到达接收端 | allow / external_error；Internal Fallback，external_attempted=true |
| gate_mode=none | Router 直接生成 ALLOW，不调用 Gateway | 用于受认证控制实验；外部失败仍按上述逻辑回退 |

回退复用完整对话；内部模型本身失败时 API 返回对应模型错误，不能保证返回成功回答。
none 模式和 internal_only 路径不产生 Gateway 检查审计；来源标签更新仍遵循会话规则。
没有自主工具调用或自动跟进；恶意返回的后续影响通过下一轮请求检查。

响应字段：

| 字段 | 含义 |
|---|---|
| requested_route | 请求选择的路由模式 |
| route | 实际完成回答的内部/外部路径 |
| gate_decision | not_checked / deny / allow / error |
| fallback | 是否回退到内部 |
| fallback_reason | gate_denied / gate_error / external_error / null |
| external_attempted | 是否尝试发送；不等同于对方收到 |
| gate_latency_ms | Router 测量的关卡决策耗时 |
| latency_ms | 整个处理耗时 |
| session_id, turn_count | 会话编号和成功完成的用户轮数 |
| effective_gate_mode | 服务端执行的关卡模式；内部路径为 not_checked |
| relay_mode, trial_id | 服务端接受的中转模式及关联标识，供 Runner 校验 |

`GateDecision` 的细分原因和标签不直接加入当前 `ChatResponse`；可从审计中查看。
外部接收情况需要 ingress 证据确认，Internal Fallback 不会撤回已发送的请求。

## 安全审计

`SecurityAuditLogger` 已向 `reports/security_audit.jsonl` 追加决策元数据：
时间、session_id、trial_id、模式、ALLOW/DENY、原因、会话标签、检测器/实体类型、
扫描完整性、payload 字节数和延迟，不记录 payload 或秘密原文。
正常决策审计写入失败也会进入 Gateway 的拒绝路径；错误审计会尽力写入，不能保证在存储故障时留有记录。

会话标签建立或变化时，`SessionStore` 向 `reports/provenance_audit.jsonl` 写入
前一标签、传入标签、结果标签及来源等元数据。该日志没有 Trial ID，不记录会话内容；
删除会话会清除内存状态，但不会删除已追加的审计记录。

## 待对接接口与验证范围

- Runner 在 C1/C2 提交逐轮 source_label、gate_mode、relay_mode 和 X-Experiment-Token，并校验服务端回显。旧后端缺少回显时试验标为 error，不能仅凭配置名称计为已执行。C0 不提交这些实验字段、不需要令牌，与 C0 pilot 基线保持一致。
- Runner 在每个 trial 结束时验证 `DELETE /sessions/{id}` 响应；重置失败使该 trial 为 error，并停止后续 trial、返回非零状态。
- C1/C2 批次结束后，Runner 调用 `runner/leakscan.py`：按 Trial ID 生成 C 的 manifest（每个 trial 分配该任务全部 canary，含 compliance），只截取本批 Trial ID 且在本批时间窗内的 Relay/Provider 日志行，再运行 `relay7508.scan`。输出与结果文件同名的 `.manifest.json`、`.relay.jsonl`、`.provider.jsonl`、`.leak.json` 和 `.leak.csv`；失败 trial 不计入泄漏率，并作为 missing-from-manifest 显示。默认日志为 `logs/relay.jsonl` 与 `reports/provider_ingress.jsonl`，可用 `--log name=path` 修改，`--no-scan` 跳过；也可对已有结果运行 `python -m runner.leakscan reports/runs/<文件>.jsonl`。
- 预注册主矩阵为七个配置（4,200 trials）；`C1-M1_M2` 和 `C2-M1_M2` 仅用于补充组合策略验收，单独报告。
- Relay 已处理 X-Relay-Mode，将 X-Trial-Id 传播至 Provider；两端日志按完整 Trial ID 区分重复试验。Provider 接收非流式 Ollama chat JSON，先写 ingress 再调用独立外部模型。上游失败不抹去已收到请求的证据。
- 既有自动测试覆盖拒绝不发送、异常关闭、获准请求字节一致、后续轮次重新检查、重定向阻止、外部失败回退、来源标签和认证。真实 M1 插件测试另需检测依赖、英文模型和生成的任务输入，安装与测试命令见 `QUICKSTART.md`。
- 2026-11-22 已跑通 10 个真实双模型集成场景，核对两端接收记录、模式执行、审计、Trial-ID 关联及泄漏提取。范围为固定虚构场景，不等于完整统计实验；步骤和报告说明见 docs/B_INTEGRATION.md。
