"""队友的 M1/M2 接口位置；当前只提供拒绝所有外发的占位关卡。"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class OutboundRequest:
    # 不可变对象，关卡检查与发送使用同一份字节。
    url: str
    body: bytes
    method: str = "POST"
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)


@dataclass(frozen=True)
class GateDecision:
    allowed: bool


class ForwardingGate(Protocol):
    def inspect(self, request: OutboundRequest, *, session_id: str) -> GateDecision:
        ...


class PlaceholderGate:
    def inspect(self, request: OutboundRequest, *, session_id: str) -> GateDecision:
        # 这不是 M1/M2，也不能作为安全实验结论。
        return GateDecision(allowed=False)
