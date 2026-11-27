"""mcp_streamable 纯逻辑单测：SSE 形态 initialize 响应的首个 message data 提取
（§6.6 硬判定的输入；与 SseEndpointRewriter / probe_sse 的行解析同风格）
+ _judge_initialize_response 判定边缘（M4 Task 5 评审核销 4：畸形 JSON /
非 dict / >64KB 截断）。"""
import time

from app.forward.mcp_streamable import (_first_message_data,
                                                INITIALIZE_MAX_BYTES,
                                                _judge_initialize_response)


def test_first_message_data_explicit_event():
    raw = b"event: message\ndata: {\"result\": 1}\n\n"
    assert _first_message_data(raw) == b'{"result": 1}'


def test_first_message_data_default_unnamed_event_accepted():
    assert _first_message_data(b"data: {\"x\": 2}\n\n") == b'{"x": 2}'


def test_first_message_data_blank_line_resets_event_name():
    """空行复位事件名（与转发解析器同规）：`event: endpoint` 块后的 data 行不被误取。"""
    raw = b"event: endpoint\ndata: /messages\n\ndata: {\"ok\": 3}\n\n"
    assert _first_message_data(raw) == b'{"ok": 3}'


def test_first_message_data_none_without_data_line():
    assert _first_message_data(b": comment only\n\n") is None
    assert _first_message_data(b"event: message\n\n") is None


# ---------- 判定边缘（Task 5 评审核销 4）：_judge_initialize_response 输入兜底 ----------


class _FakeResp:
    """_judge_initialize_response 的最小替身：判定路径只消费 aiter_raw。"""

    def __init__(self, chunks):
        self._chunks = chunks

    async def aiter_raw(self):
        for chunk in self._chunks:
            yield chunk


async def test_judge_malformed_json_ok_false():
    """畸形 JSON（非法字节序列）：判失败 + detail 含状态码与 content-type，不抛异常。"""
    ok, detail = await _judge_initialize_response(
        _FakeResp([b"not-json{"]), 200, "application/json", time.monotonic())
    assert ok is False
    assert "非合法 JSON" in detail
    assert "status=200" in detail and "application/json" in detail


async def test_judge_non_dict_json_ok_false():
    """合法 JSON 但顶层非 dict（如数组）：result 取 None → 缺少 serverInfo 判失败。"""
    ok, detail = await _judge_initialize_response(
        _FakeResp([b"[1,2,3]"]), 200, "application/json", time.monotonic())
    assert ok is False and "缺少 serverInfo" in detail


async def test_judge_over_max_bytes_truncated_ok_false():
    """>64KB 响应（INITIALIZE_MAX_BYTES 超限即止）：截断内容交解析兜底判失败——
    判定只需前缀，异常上游的无界响应不拖垮探测。"""
    head = b'{"result": {"serverInfo": {"name": "x"}}, "pad": "'
    ok, detail = await _judge_initialize_response(
        _FakeResp([head + b"x" * (INITIALIZE_MAX_BYTES + 1)]),
        200, "application/json", time.monotonic())
    assert ok is False and "非合法 JSON" in detail


def test_first_message_data_multiline_data_known_limitation():
    """已知限制钉住（M5 扫尾 b）：多行 data: 不拼接，取首个 data 行——真实 SDK
    （官方 SDK / Inspector）initialize 均为单行 data；多行形态截断后 JSON 解析失败
    判 ok=false（不误判成功）。注释见 _first_message_data，回归面见 mock
    /mcp-multiline-data + test_proxy_mcp_streamable 探测用例。"""
    raw = b'event: message\ndata: {"jsonrpc": "2.0",\ndata: "id": 1}\n\n'
    assert _first_message_data(raw) == b'{"jsonrpc": "2.0",'
