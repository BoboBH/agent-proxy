"""MCP Streamable HTTP 探测（设计 §6.6 mcp+Streamable 行 / §8.4）。

M4 定稿：**Streamable 转发本身复用 §8.5 统一管线**（POST/DELETE 按上游 origin
根还原走 stream_http_forward；GET 注册端点走 stream_sse_forward 字节透传，见
api/proxy.py 分发注释），本模块只承载 test 接口的端点形态细分（探测式 auto）：

- 先按 Streamable 语义 POST 标准 initialize JSON-RPC；2xx 且响应体（JSON 形态
  直接解析；SSE 形态取首个 message 事件的 data）为含 serverInfo 的 JSON-RPC
  result → ok=true（§6.6 硬性判定）；
- 端点以 405/404/406 拒绝 POST（SSE-only 上游对注册端点 POST 的典型行为）→
  回落 probe_sse_mapping（SSE 握手探测，§8.3）；
- 其余非 2xx（401/500 等）直接判失败不回落——凭据失效等应显式暴露，不掩盖为
  形态回落。

超时语义与 probe_sse_mapping 同规：TEST_PROBE_TIMEOUT 为**总挂钟期限**（send
与读响应共享同一 deadline，读响应仅享剩余量）。探测需解析 initialize 响应体，
出站钉 `accept-encoding: identity` 读明文（与转发管线的 aiter_raw 压缩透传不
冲突——转发不解析载荷，探测是唯一读体路径）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from ..forward.http_forward import TEST_PROBE_TIMEOUT
from ..forward.mcp_sse import probe_sse_mapping
from ..headers import build_outbound_headers

log = logging.getLogger("agent_proxy")

# initialize 响应读取上限：判定只需前缀（serverInfo 响应通常 < 1KB），防异常上游
# 无界响应拖垮探测（超限即止，按截断内容判定）
INITIALIZE_MAX_BYTES = 64 * 1024

_INIT_REQUEST = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "agent-proxy-test", "version": "0"}},
}


class _NotStreamable(Exception):
    """端点拒绝 POST（405/404/406）——SSE-only 上游典型形态，触发回落 SSE 探测。"""


def _first_message_data(raw: bytes) -> bytes | None:
    """SSE 形态取首个 message（或未具名）事件的 data 载荷；空行复位事件名
    （与 SseEndpointRewriter / probe_sse 行解析同规）。

    已知限制（M5 扫尾 b，不实现拼接）：SSE 规范允许多个 data: 行按 \\n 拼接为
    单条载荷，本函数只取首个 data 行——真实 MCP SDK（官方 SDK / Inspector）的
    initialize 响应均为单行 data，探测判定只需取到可解析 JSON；若上游确为多行
    形态则截断内容 JSON 解析失败判 ok=false（显式失败，不误判成功）。拼接实现
    需保留行间分隔语义（\\n join），收益不抵复杂度。回归钉子：mock
    /mcp-multiline-data + test_proxy_mcp_streamable 探测用例 + 单测钉首行行为。
    """
    current_event = ""
    for line in raw.split(b"\n"):
        text = line.decode("utf-8", "replace").rstrip("\r")
        if text.startswith("event:"):
            current_event = text[len("event:"):].strip()
        elif text.startswith("data:") and current_event in ("", "message"):
            return text[len("data:"):].strip().encode("utf-8")
        elif text == "":
            current_event = ""               # 事件块结束，事件名复位
    return None


async def probe_streamable_mapping(app_state, mapping_data: dict) -> dict:
    """mcp+Streamable 类型 test（设计 §6.6）：POST 标准 initialize，硬判定响应
    含 serverInfo（JSON 或短 SSE 两种形态）。上游失败一律 ok=false + detail，
    不抛 502/504；端点拒绝 POST 抛 _NotStreamable 由 probe_mcp_mapping 回落。
    OAuth 绑定用户（M6）以本人凭证走同一规则：注入 Authorization 后复用本函数。
    """
    stored = mapping_data["upstream_headers"] or {}
    headers = build_outbound_headers(stored,
                                     {"Accept": "application/json, text/event-stream"},
                                     "application/json", None, None)
    # 探测需解析响应体：钉 identity 读明文（httpx 默认 gzip 出站 + aiter_raw 会
    # 拿到压缩字节无法解析；转发管线不解析载荷不受影响）
    headers["accept-encoding"] = "identity"
    # 探测连接不复用（与 probe_sse_mapping 同规：读到即断的连接绝不回流 keepalive 池）
    headers["connection"] = "close"
    target = mapping_data["upstream_url"]
    start = time.monotonic()

    def _result(ok: bool, status_code: int | None, detail: str) -> dict:
        return {"ok": ok, "status_code": status_code,
                "latency_ms": int((time.monotonic() - start) * 1000), "detail": detail}

    client: httpx.AsyncClient = app_state.http_client
    try:
        req = client.build_request("POST", target, headers=headers,
                                   content=json.dumps(_INIT_REQUEST).encode("utf-8"),
                                   timeout=TEST_PROBE_TIMEOUT)
        resp = await asyncio.wait_for(client.send(req, stream=True), TEST_PROBE_TIMEOUT)
    except asyncio.TimeoutError as exc:  # 3.11+ 即内置 TimeoutError（wait_for 总期限）
        return _result(False, None,
                       f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s 总期限）: {type(exc).__name__}")
    except httpx.TimeoutException as exc:  # 分项超时先到（connect/read/pool）
        return _result(False, None, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s）: {type(exc).__name__}")
    except httpx.HTTPError as exc:
        return _result(False, None, f"上游不可达: {type(exc).__name__}: {exc}")

    status = resp.status_code
    content_type = next((v for k, v in resp.headers.items()
                         if k.lower() == "content-type"), "")
    # 读段整体 try/finally（Task 5 评审机械修，与 probe_sse_mapping 同规）：
    # CancelledError（调用方超时/断开）穿透时响应流也必然 aclose——连接不滞留池内
    # （aclose 幂等：正常路径 _pump 读到 EOF 已自动关，finally 兜底截断/超限路径）
    try:
        if status in (404, 405, 406):
            raise _NotStreamable()
        if not (200 <= status < 300):
            # 非 2xx 短路（Task 5 评审携带 polish）：不读体直接判失败，detail 明示
            # 「上游拒绝」——凭据失效/服务端错误显式暴露，不误报为「缺少 serverInfo
            # （非 MCP Streamable 端点？）」的形态误导
            return _result(False, status, f"上游拒绝（status={status}）")
        ok, detail = await _judge_initialize_response(resp, status, content_type, start)
        return _result(ok, status, detail)
    finally:
        await resp.aclose()


async def _judge_initialize_response(resp: httpx.Response, status: int,
                                     content_type: str, start: float) -> tuple[bool, str]:
    """读 initialize 响应并硬判定（JSON / 短 SSE 两种形态；§6.6：含 serverInfo）。"""
    buf = bytearray()

    async def _pump() -> None:
        async for chunk in resp.aiter_raw():
            buf.extend(chunk)
            if len(buf) > INITIALIZE_MAX_BYTES:
                return                       # 超限即止：判定只需前缀，截断内容交解析兜底

    remaining = max(TEST_PROBE_TIMEOUT - (time.monotonic() - start), 0.05)
    try:
        await asyncio.wait_for(_pump(), remaining)
    except asyncio.TimeoutError:
        return False, f"上游超时（>{TEST_PROBE_TIMEOUT:.0f}s 总期限，读响应阶段）"
    except httpx.HTTPError as exc:
        return False, f"上游响应读取失败: {type(exc).__name__}: {exc}"

    if "text/event-stream" in content_type.lower():
        data = _first_message_data(bytes(buf))
        if data is None:
            return False, f"initialize SSE 响应无 message 事件（status={status}）"
    else:
        data = bytes(buf)
    try:
        payload = json.loads(data)
    except ValueError:
        return False, (f"initialize 响应非合法 JSON（status={status}，"
                       f"content-type={content_type or '无'}）")
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict) or "serverInfo" not in result:
        return False, (f"initialize 响应缺少 serverInfo（status={status}，"
                       "非 MCP Streamable 端点？）")
    server_info = result["serverInfo"]
    name = server_info.get("name", "?") if isinstance(server_info, dict) else "?"
    return True, f"Streamable initialize 成功（serverInfo.name={name}）"


async def probe_mcp_mapping(app_state, mapping_data: dict) -> dict:
    """mcp 类型 test 探测式 auto（M4 定稿）：先 Streamable（POST initialize 硬判定），
    端点拒绝 POST（405/404/406）回落 SSE 握手探测；detail 前缀回告实际判定的
    端点形态供排障。

    选择理由（评审定稿，替代新增 transport 注册字段）：设计 §5.1 无 transport 列，
    新增将连带 schema/建表/缓存/管理 API 变更且要求用户正确填写传输形态（生态
    并存下易错）；端点路径后缀（/mcp）仅惯例非协议（SSE 服务也可注册在 /mcp）；
    以真实协议行为判定误判面最小。
    """
    try:
        return await probe_streamable_mapping(app_state, mapping_data)
    except _NotStreamable:
        result = await probe_sse_mapping(app_state, mapping_data)
        result["detail"] = ("SSE 端点（Streamable initialize 被拒，回落 SSE 握手）→ "
                            + result["detail"])
        return result
