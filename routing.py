"""唯一的外部调用入口：先检查，获准后才发送；拒绝或出错时内部回退。"""

from dataclasses import dataclass
from time import perf_counter

from gate import ForwardingGate, GateDecision, OutboundRequest, PlaceholderGate
from model_backend import ModelBackendError, build_payload, generate_answer, send_payload

# 为队友的中转站预留独立端口，不与内部 Ollama 的 11434 混用。
# 当前没有启动此端点；完整中转站/外部模型由小组集成阶段提供。
EXTERNAL_CHAT_URL = "http://127.0.0.1:11435/api/chat"
gate: ForwardingGate = PlaceholderGate()


@dataclass(frozen=True)
class RoutingResult:
    answer: str
    route: str
    gate_decision: str
    fallback_reason: str | None
    external_attempted: bool
    gate_latency_ms: float


def run_assistant(messages: list[dict[str, str]], *, session_id: str, route_mode: str) -> RoutingResult:
    if route_mode == "internal_only":
        return RoutingResult(generate_answer(messages), "internal", "not_checked", None, False, 0.0)
    if route_mode != "external_candidate":
        raise ValueError("Unknown route mode")

    candidate = OutboundRequest(url=EXTERNAL_CHAT_URL, body=build_payload(messages))
    started = perf_counter()
    try:
        decision = gate.inspect(candidate, session_id=session_id)
        # 对格式错误的结果也拒绝外发，避免把字符串 'false' 当成真。
        if not isinstance(decision, GateDecision) or type(decision.allowed) is not bool:
            raise ValueError("Invalid gate decision")
    except Exception:
        # 不把异常内容写进响应，异常可能含请求中的秘密。
        gate_ms = round((perf_counter() - started) * 1000, 3)
        return RoutingResult(generate_answer(messages), "internal", "error", "gate_error", False, gate_ms)

    gate_ms = round((perf_counter() - started) * 1000, 3)
    if not decision.allowed:
        return RoutingResult(generate_answer(messages), "internal", "deny", "gate_denied", False, gate_ms)

    try:
        # 不在检查后重新构建请求，不重试，也不跟随重定向。
        answer = send_payload(candidate.url, candidate.body)
        return RoutingResult(answer, "external", "allow", None, True, gate_ms)
    except ModelBackendError:
        # 请求可能已到达外部端点；回退不代表撤回，故保留 attempted=True。
        return RoutingResult(generate_answer(messages), "internal", "allow", "external_error", True, gate_ms)
