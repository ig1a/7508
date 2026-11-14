# B 模块对接说明

## 当前边界

`main.py` 管理 HTTP 和会话；`routing.py` 负责选择路径；`gate.py` 定义关卡协议；
`model_backend.py` 封装 Ollama 请求。服务默认仅监听本机，没有鉴权。

内部地址是 `http://127.0.0.1:11434/api/chat`。
为中转站预留的地址是 `http://127.0.0.1:11435/api/chat`，当前没有启动该端点。
外部请求使用 Ollama 原生 chat JSON；中转站若采用其他协议，需一起调整请求构建与检查契约。
内部和外部应使用独立端点、状态和日志；可以采用相同权重，但不能直接把外部路由接回内部端点。

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

## 已验证与待验证

自动测试覆盖拒绝不发送、检查出错不发送、获准请求字节一致、后续轮次重新检查、
HTTP 重定向不跟随、外部失败回退、会话隔离与删除。
传输测试使用本机临时 HTTP 接收器和模拟关卡，不是真实 M1/M2 或完整中转站实验。
正式实验还需检查任务完成率、外部 ingress 日志、标签传播、语义泄漏和 token 截断等。
