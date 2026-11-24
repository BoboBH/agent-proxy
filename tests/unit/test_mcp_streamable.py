"""mcp_streamable 纯逻辑单测：SSE 形态 initialize 响应的首个 message data 提取
（§6.6 硬判定的输入；与 SseEndpointRewriter / probe_sse 的行解析同风格）。"""
from agent_proxy.forward.mcp_streamable import _first_message_data


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
