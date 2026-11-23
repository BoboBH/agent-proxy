import base64
import json


def make_token(user_id: str = "u888", role: str | None = None, user_name: str = "张三") -> str:
    payload = {"user_id": user_id, "user_name": user_name}
    if role:
        payload["role"] = role
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"stub.{body}.sig"


def sse_line_iter(resp):
    """同一 SSE 响应的共享行迭代器（按响应记忆，只开启一次）。

    httpx 0.28 的 aiter_raw 首次迭代即置 is_stream_consumed，二次调用抛
    StreamConsumed——先读 endpoint 事件再读 message 事件这类「同一响应顺序读」
    必须复用同一条 aiter_lines 迭代器，不得各自 resp.aiter_lines()。
    """
    it = getattr(resp, "_sse_lines", None)
    if it is None:
        it = resp._sse_lines = resp.aiter_lines()
    return it


async def read_first_endpoint_event(resp) -> str:
    """从 SSE 流读取首个 `event: endpoint` 事件块的 data 值（读到块结束空行为止）。

    用于 SSE 握手断言（M3）：经代理应返回改写后的代理地址（/p/{id}...），
    直连 mock 应返回根相对路径（/messages?session_id=...）。
    """
    event = ""
    data = ""
    async for line in sse_line_iter(resp):
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data = line[len("data:"):].strip()
        elif line == "" and event == "endpoint":
            return data
    return ""


async def read_next_message_data(resp) -> dict:
    """读下一个 message 事件的 data 载荷并解析为 JSON（跳过心跳注释行/字段行）。"""
    async for line in sse_line_iter(resp):
        if line.startswith("data:"):
            return json.loads(line[len("data:"):].strip())
    raise AssertionError("SSE 流结束仍未读到 message 事件")
