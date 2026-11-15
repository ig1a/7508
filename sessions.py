"""单进程、本机实验用的会话存储；不把对话写入磁盘。"""

from threading import RLock
from uuid import uuid4

from fastapi import HTTPException

MAX_TURNS = 4
MAX_SESSIONS = 128
MAX_CONTEXT_BYTES = 12000


class SessionStore:
    def __init__(self):
        self.histories: dict[str, list[dict[str, str]]] = {}
        # 将问答和重置串行执行，避免并发请求覆盖历史。
        self.lock = RLock()

    def get_or_create(self, session_id: str | None):
        if session_id is not None:
            if session_id not in self.histories:
                raise HTTPException(404, "会话不存在或已重置，请不带 session_id 开始新会话。")
            return session_id, self.histories[session_id]
        if len(self.histories) >= MAX_SESSIONS:
            raise HTTPException(503, "会话数量已达上限，请删除不用的会话。")
        session_id = str(uuid4())
        self.histories[session_id] = []
        return session_id, self.histories[session_id]


store = SessionStore()
