"""把模型调用集中在此文件，便于之后对接小组的路由模块。"""

import json
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MODEL_NAME = "qwen3:4b-instruct-2507-q4_K_M"
OLLAMA_CHAT_URL = "http://127.0.0.1:11434/api/chat"


class ModelBackendError(Exception):
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


def build_payload(messages: list[dict[str, str]] | str) -> bytes:
    # 保留字符串形式，便于单独调试模型模块。
    if isinstance(messages, str):
        messages = [{"role": "user", "content": messages}]
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "你是 BrandAI 内部助手。根据用户提供的信息回答问题，不要编造未知事实。"},
        ] + messages,
        "stream": False,  # 等待完整回答，再一次性返回。
        "options": {"num_ctx": 16384, "num_predict": 512, "temperature": 0},
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 不自动把请求转到未经检查的新地址。
        return None


def send_payload(url: str, body: bytes, *, headers: dict[str, str] | None = None) -> str:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    request = Request(
        url,
        data=body,
        headers=request_headers,
        method="POST",
    )
    # 本地模型请求不经过电脑上的 HTTP 代理。
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=120) as response:
            result = json.load(response)
    except HTTPError as exc:
        exc.close()
        if exc.code == 404:
            raise ModelBackendError("本地模型未找到，请先下载配置的 Ollama 模型。", 503) from exc
        raise ModelBackendError("Ollama 模型服务返回错误。", 502) from exc
    except TimeoutError as exc:
        raise ModelBackendError("模型回答超时，请稍后重试。", 504) from exc
    except URLError as exc:
        raise ModelBackendError("无法连接本机 Ollama，请检查它是否正在运行。", 503) from exc
    except (ValueError, UnicodeError) as exc:
        raise ModelBackendError("模型服务返回了无效数据。", 502) from exc

    if not isinstance(result, dict) or not isinstance(result.get("message"), dict):
        raise ModelBackendError("模型服务返回格式不正确。", 502)
    answer = result["message"].get("content")
    if not isinstance(answer, str) or not answer.strip():
        raise ModelBackendError("模型没有返回有效回答。", 502)
    return answer.strip()


def generate_answer(messages: list[dict[str, str]] | str) -> str:
    return send_payload(OLLAMA_CHAT_URL, build_payload(messages))
