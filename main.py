"""BrandAI 的内部助手：接收问题，并调用本机 Ollama。"""

from time import perf_counter
from typing import Annotated, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, StringConstraints

from model_backend import MODEL_NAME, ModelBackendError
from routing import run_assistant
from sessions import MAX_CONTEXT_BYTES, MAX_TURNS, store
from security_gateway.trust import RUNNER_TOKEN_HEADER, is_trusted_runner

# 创建应用对象，启动命令中的 main:app 就是本文件中的 app。
app = FastAPI(title="BrandAI Assistant", version="0.4.0")


class ChatRequest(BaseModel):
    # 自动拒绝空问题，并限制这一阶段的输入长度。
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    # 第一次留空；后续填写上次响应返回的 ID。
    session_id: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    route_mode: Literal["internal_only", "external_candidate"] = "internal_only"
    # Set only by the trusted local experiment runner / labelling pipeline.
    source_label: Literal["PUBLIC", "CONFIDENTIAL", "UNKNOWN"] | None = None
    gate_mode: Literal["none", "M1", "M2", "M1_M2"] = "M1_M2"
    relay_mode: Literal["passive", "active"] | None = None


class ChatResponse(BaseModel):
    answer: str
    model: str
    route: str
    latency_ms: float
    session_id: str
    turn_count: int
    requested_route: str
    gate_decision: str
    fallback: bool
    fallback_reason: str | None
    external_attempted: bool
    gate_latency_ms: float


# 浏览器访问 /health 时，FastAPI 会调用下面的函数。
@app.get("/health")
def health():
    # 字典会自动转换为 JSON 响应；这里只检查服务是否运行。
    return {"status": "ok", "service": "BrandAI Assistant"}


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest, x_trial_id: Annotated[str | None, Header()] = None,
         x_experiment_token: Annotated[str | None, Header(alias=RUNNER_TOKEN_HEADER)] = None):
    """最多四轮的内部问答；省略 session_id 创建新会话。"""
    started = perf_counter()
    # source_label is privileged experiment metadata, not a user-controlled field.
    privileged_experiment_request = (
        request.source_label is not None
        or request.gate_mode != "M1_M2"
        or request.relay_mode is not None
    )
    if privileged_experiment_request and not is_trusted_runner(x_experiment_token):
        raise HTTPException(401, "Trusted experiment runner authentication required.")
    with store.lock:
        session_id, history = store.get_or_create(request.session_id)
        if len(history) // 2 >= MAX_TURNS:
            raise HTTPException(409, "本实验每个会话最多四轮，请开始新会话。")
        # 构建副本：只有模型成功回答，才一起保存问题和回答。
        messages = history + [{"role": "user", "content": request.message}]
        if sum(len(m["content"].encode("utf-8")) for m in messages) > MAX_CONTEXT_BYTES:
            if request.session_id is None:
                store.delete(session_id)
            raise HTTPException(413, "会话内容超出起步版长度限制，请缩短输入或开始新会话。")
        # Labels are supplied by the trusted local task runner, not inferred from canaries.
        store.update_security_label(session_id, request.source_label,
                                    source="trusted_runner" if request.source_label is not None else "unlabelled_request")
        try:
            result = run_assistant(
                messages, session_id=session_id, route_mode=request.route_mode,
                gate_mode=request.gate_mode, trial_id=x_trial_id,
                relay_mode=request.relay_mode or "passive",
            )
            answer = result.answer
        except ModelBackendError as exc:
            if request.session_id is None:
                store.delete(session_id)
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
        history.extend([
            {"role": "user", "content": request.message},
            {"role": "assistant", "content": answer},
        ])
        turn_count = len(history) // 2
    return ChatResponse(
        answer=answer,
        model=MODEL_NAME,
        route=result.route,
        latency_ms=round((perf_counter() - started) * 1000, 1),
        session_id=session_id,
        turn_count=turn_count,
        requested_route=request.route_mode,
        gate_decision=result.gate_decision,
        fallback=result.fallback_reason is not None,
        fallback_reason=result.fallback_reason,
        external_attempted=result.external_attempted,
        gate_latency_ms=result.gate_latency_ms,
    )


@app.delete("/sessions/{session_id}")
def reset_session(session_id: str):
    """删除该会话历史；下一次不带 ID 请求即可开始新实验。"""
    with store.lock:
        if session_id not in store.histories:
            raise HTTPException(404, "会话不存在或已经删除。")
        store.delete(session_id)
    return {"status": "reset", "session_id": session_id}
